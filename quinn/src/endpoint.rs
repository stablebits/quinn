use std::{
    collections::VecDeque,
    fmt,
    future::Future,
    io::{self, IoSliceMut},
    mem,
    net::{SocketAddr, SocketAddrV6},
    pin::Pin,
    str,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, RawWaker, RawWakerVTable, Waker},
};

#[cfg(all(
    not(wasm_browser),
    any(feature = "runtime-tokio", feature = "runtime-smol"),
    any(feature = "aws-lc-rs", feature = "ring"),
))]
use crate::runtime::default_runtime;
use crate::{
    Instant,
    runtime::{AsyncUdpSocket, Runtime, UdpSender, UdpSenderFactory},
    udp_transmit,
};
use bytes::{Bytes, BytesMut};
use pin_project_lite::pin_project;
use proto::{
    self as proto, ClientConfig, ConnectError, ConnectionError, ConnectionHandle, DatagramEvent,
    EndpointEvent, ServerConfig,
};
use rustc_hash::FxHashMap;
#[cfg(all(
    not(wasm_browser),
    any(feature = "runtime-tokio", feature = "runtime-smol"),
    any(feature = "aws-lc-rs", feature = "ring"),
))]
use socket2::{Domain, Protocol, Socket, Type};
use tokio::sync::{Notify, futures::Notified, mpsc};
use tracing::{Instrument, Span};
use udp::{BATCH_SIZE, RecvMeta, is_msg_size_err};

use crate::{
    ConnectionEvent, EndpointConfig, IO_LOOP_BOUND, RECV_TIME_BOUND, VarInt,
    connection::Connecting, incoming::Incoming, work_limiter::WorkLimiter,
};

/// A QUIC endpoint.
///
/// An endpoint corresponds to a single UDP socket, may host many connections, and may act as both
/// client and server for different connections.
///
/// May be cloned to obtain another handle to the same endpoint.
#[derive(Debug, Clone)]
pub struct Endpoint {
    pub(crate) inner: EndpointRef,
    endpoint_driver_runtime: Arc<dyn Runtime>,
    runtime: Arc<dyn Runtime>,
}

/// Runtime configuration for an [`Endpoint`].
///
/// Quinn uses an endpoint driver to receive UDP datagrams and route them to connections, and
/// per-connection drivers for protocol timers, transmission, and application-facing state. Most
/// applications should use [`EndpointRuntimeConfig::single`], but latency-sensitive applications can
/// use [`EndpointRuntimeConfig::new`] to schedule the endpoint driver on a separate runtime.
#[derive(Debug, Clone)]
pub struct EndpointRuntimeConfig {
    endpoint_driver: Arc<dyn Runtime>,
    connection: Arc<dyn Runtime>,
}

impl EndpointRuntimeConfig {
    /// Use `runtime` for both endpoint and connection drivers.
    pub fn single(runtime: Arc<dyn Runtime>) -> Self {
        Self {
            endpoint_driver: runtime.clone(),
            connection: runtime,
        }
    }

    /// Use separate runtimes for the endpoint driver and connection drivers.
    ///
    /// `endpoint_driver` is used to wrap the UDP socket and schedule the endpoint driver. `connection`
    /// is used to schedule per-connection drivers and timers.
    pub fn new(endpoint_driver: Arc<dyn Runtime>, connection: Arc<dyn Runtime>) -> Self {
        Self {
            endpoint_driver,
            connection,
        }
    }
}

impl Endpoint {
    /// Helper to construct an endpoint for use with outgoing connections only
    ///
    /// Note that `addr` is the *local* address to bind to, which should usually be a wildcard
    /// address like `0.0.0.0:0` or `[::]:0`, which allow communication with any reachable IPv4 or
    /// IPv6 address respectively from an OS-assigned port.
    ///
    /// If an IPv6 address is provided, attempts to make the socket dual-stack so as to allow
    /// communication with both IPv4 and IPv6 addresses. As such, calling `Endpoint::client` with
    /// the address `[::]:0` is a reasonable default to maximize the ability to connect to other
    /// address. For example:
    ///
    /// ```
    /// quinn::Endpoint::client((std::net::Ipv6Addr::UNSPECIFIED, 0).into());
    /// ```
    ///
    /// Some environments may not allow creation of dual-stack sockets, in which case an IPv6
    /// client will only be able to connect to IPv6 servers. An IPv4 client is never dual-stack.
    #[cfg(all(
        not(wasm_browser),
        any(feature = "runtime-tokio", feature = "runtime-smol"),
        any(feature = "aws-lc-rs", feature = "ring"), // `EndpointConfig::default()` is only available with these
    ))]
    pub fn client(addr: SocketAddr) -> io::Result<Self> {
        let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
        if addr.is_ipv6()
            && let Err(e) = socket.set_only_v6(false)
        {
            tracing::debug!(%e, "unable to make socket dual-stack");
        }
        socket.bind(&addr.into())?;
        let runtime =
            default_runtime().ok_or_else(|| io::Error::other("no async runtime found"))?;
        Self::new_with_abstract_socket(
            EndpointConfig::default(),
            None,
            runtime.wrap_udp_socket(socket.into())?,
            runtime,
        )
    }

    /// Returns relevant stats from this Endpoint
    pub fn stats(&self) -> EndpointStats {
        self.inner.state.lock().unwrap().stats
    }

    /// Helper to construct an endpoint for use with both incoming and outgoing connections
    ///
    /// Note that `addr` is the *local* address to bind to, which should usually be a wildcard
    /// address like `0.0.0.0:0` or `[::]:0`, which allow communication with any reachable IPv4 or
    /// IPv6 address respectively from an OS-assigned port.
    ///
    /// If an IPv6 address is provided, attempts to make the socket dual-stack so as to allow
    /// communication with both IPv4 and IPv6 clients. As such, calling `Endpoint::server` with
    /// the address `[::]:0` is a reasonable default to maximize the ability to accept connections
    /// from any address.
    ///
    /// Some environments may not allow creation of dual-stack sockets, in which case an IPv6
    /// server will only be able to accept connections from IPv6 clients. An IPv4 server is never
    /// dual-stack.
    #[cfg(all(
        not(wasm_browser),
        any(feature = "runtime-tokio", feature = "runtime-smol"),
        any(feature = "aws-lc-rs", feature = "ring"), // `EndpointConfig::default()` is only available with these
    ))]
    pub fn server(config: ServerConfig, addr: SocketAddr) -> io::Result<Self> {
        let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
        if addr.is_ipv6()
            && let Err(e) = socket.set_only_v6(false)
        {
            tracing::debug!(%e, "unable to make socket dual-stack");
        }
        socket.bind(&addr.into())?;
        let runtime =
            default_runtime().ok_or_else(|| io::Error::other("no async runtime found"))?;
        Self::new_with_abstract_socket(
            EndpointConfig::default(),
            Some(config),
            runtime.wrap_udp_socket(socket.into())?,
            runtime,
        )
    }

    /// Construct an endpoint with arbitrary configuration and socket
    #[cfg(not(wasm_browser))]
    pub fn new(
        config: EndpointConfig,
        server_config: Option<ServerConfig>,
        socket: std::net::UdpSocket,
        runtime: Arc<dyn Runtime>,
    ) -> io::Result<Self> {
        Self::new_with_runtimes(
            config,
            server_config,
            socket,
            EndpointRuntimeConfig::single(runtime),
        )
    }

    /// Construct an endpoint with arbitrary configuration, socket, and runtime configuration
    #[cfg(not(wasm_browser))]
    pub fn new_with_runtimes(
        config: EndpointConfig,
        server_config: Option<ServerConfig>,
        socket: std::net::UdpSocket,
        runtimes: EndpointRuntimeConfig,
    ) -> io::Result<Self> {
        let socket = runtimes.endpoint_driver.wrap_udp_socket(socket)?;
        Self::new_with_abstract_socket_and_runtimes(config, server_config, socket, runtimes)
    }

    /// Construct an endpoint with arbitrary configuration and pre-constructed abstract socket
    ///
    /// Useful when `socket` has additional state (e.g. sidechannels) attached for which shared
    /// ownership is needed.
    pub fn new_with_abstract_socket(
        config: EndpointConfig,
        server_config: Option<ServerConfig>,
        socket: Box<dyn AsyncUdpSocket>,
        runtime: Arc<dyn Runtime>,
    ) -> io::Result<Self> {
        Self::new_with_abstract_socket_and_runtimes(
            config,
            server_config,
            socket,
            EndpointRuntimeConfig::single(runtime),
        )
    }

    /// Construct an endpoint with arbitrary configuration, a pre-constructed abstract socket, and
    /// runtime configuration.
    ///
    /// Useful when `socket` has additional state (e.g. sidechannels) attached for which shared
    /// ownership is needed, and when the endpoint driver should be scheduled separately from
    /// connection drivers.
    pub fn new_with_abstract_socket_and_runtimes(
        config: EndpointConfig,
        server_config: Option<ServerConfig>,
        socket: Box<dyn AsyncUdpSocket>,
        runtimes: EndpointRuntimeConfig,
    ) -> io::Result<Self> {
        let addr = socket.local_addr()?;
        let allow_mtud = !socket.may_fragment();
        let rc = EndpointRef::new(
            socket,
            proto::Endpoint::new(Arc::new(config), server_config.map(Arc::new), allow_mtud),
            addr.is_ipv6(),
            runtimes.connection.clone(),
        );
        let driver = EndpointDriver(rc.clone());
        runtimes.endpoint_driver.spawn(Box::pin(
            async {
                if let Err(e) = driver.await {
                    tracing::error!("I/O error: {}", e);
                }
            }
            .instrument(Span::current()),
        ));
        Ok(Self {
            inner: rc,
            endpoint_driver_runtime: runtimes.endpoint_driver,
            runtime: runtimes.connection,
        })
    }

    /// Get the next incoming connection attempt from a client
    ///
    /// Yields [`Incoming`]s, or `None` if the endpoint is [`close`](Self::close)d. [`Incoming`]
    /// can be `await`ed to obtain the final [`Connection`](crate::Connection), or used to e.g.
    /// filter connection attempts or force address validation, or converted into an intermediate
    /// `Connecting` future which can be used to e.g. send 0.5-RTT data.
    pub fn accept(&self) -> Accept<'_> {
        Accept {
            endpoint: self,
            notify: self.inner.shared.incoming.notified(),
        }
    }

    /// Set the client configuration used by `connect`
    pub fn set_default_client_config(&self, config: ClientConfig) {
        self.inner.0.state.lock().unwrap().default_client_config = Some(config);
    }

    /// Connect to a remote endpoint
    ///
    /// `server_name` must be covered by the certificate presented by the server. This prevents a
    /// connection from being intercepted by an attacker with a valid certificate for some other
    /// server.
    ///
    /// May fail immediately due to configuration errors, or in the future if the connection could
    /// not be established.
    pub fn connect(&self, addr: SocketAddr, server_name: &str) -> Result<Connecting, ConnectError> {
        let Some(config) = self
            .inner
            .0
            .state
            .lock()
            .unwrap()
            .default_client_config
            .clone()
        else {
            return Err(ConnectError::NoDefaultClientConfig);
        };

        self.connect_with(config, addr, server_name)
    }

    /// Connect to a remote endpoint using a custom configuration.
    ///
    /// See [`connect()`] for details.
    ///
    /// [`connect()`]: Endpoint::connect
    pub fn connect_with(
        &self,
        config: ClientConfig,
        addr: SocketAddr,
        server_name: &str,
    ) -> Result<Connecting, ConnectError> {
        let mut endpoint = self.inner.state.lock().unwrap();
        if let Some(sender_factory) = endpoint.sender_factory.clone() {
            return endpoint.connect(
                self.runtime.now(),
                config,
                addr,
                server_name,
                || sender_factory.create_sender(),
                self.runtime.clone(),
            );
        }
        drop(endpoint);

        let recv_io = self.inner.recv_io.lock().unwrap();
        let mut endpoint = self.inner.state.lock().unwrap();
        if let Some(sender_factory) = endpoint.sender_factory.clone() {
            endpoint.connect(
                self.runtime.now(),
                config,
                addr,
                server_name,
                || sender_factory.create_sender(),
                self.runtime.clone(),
            )
        } else {
            endpoint.connect(
                self.runtime.now(),
                config,
                addr,
                server_name,
                || recv_io.socket.create_sender(),
                self.runtime.clone(),
            )
        }
    }

    /// Switch to a new UDP socket
    ///
    /// See [`Endpoint::rebind_abstract()`] for details.
    #[cfg(not(wasm_browser))]
    pub fn rebind(&self, socket: std::net::UdpSocket) -> io::Result<()> {
        self.rebind_abstract(self.endpoint_driver_runtime.wrap_udp_socket(socket)?)
    }

    /// Switch to a new UDP socket
    ///
    /// Allows the endpoint's address to be updated live, affecting all active connections. Incoming
    /// connections and connections to servers unreachable from the new address will be lost.
    ///
    /// On error, the old UDP socket is retained.
    pub fn rebind_abstract(&self, socket: Box<dyn AsyncUdpSocket>) -> io::Result<()> {
        let addr = socket.local_addr()?;
        let sender_factory = socket.sender_factory();
        let mut recv_io = self.inner.recv_io.lock().unwrap();
        let mut inner = self.inner.state.lock().unwrap();
        recv_io.prev_socket = Some(mem::replace(&mut recv_io.socket, socket));
        inner.sender = recv_io.socket.create_sender();
        inner.sender_factory = sender_factory;
        inner.ipv6 = addr.is_ipv6();

        // Update connection socket references
        for sender in inner.recv_state.connections.senders.values() {
            // Ignoring errors from dropped connections
            let new_sender = match &inner.sender_factory {
                Some(sender_factory) => sender_factory.create_sender(),
                None => recv_io.socket.create_sender(),
            };
            let _ = sender.send(ConnectionEvent::Rebind(new_sender));
        }
        if let Some(driver) = inner.driver.take() {
            // Ensure the driver can register for wake-ups from the new socket
            driver.wake();
        }

        Ok(())
    }

    /// Replace the server configuration, affecting new incoming connections only
    ///
    /// Useful for e.g. refreshing TLS certificates without disrupting existing connections.
    pub fn set_server_config(&self, server_config: Option<ServerConfig>) {
        self.inner
            .state
            .lock()
            .unwrap()
            .inner
            .set_server_config(server_config.map(Arc::new))
    }

    /// Get the local `SocketAddr` the underlying socket is bound to
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.recv_io.lock().unwrap().socket.local_addr()
    }

    /// Get the number of connections that are currently open
    pub fn open_connections(&self) -> usize {
        self.inner.state.lock().unwrap().inner.open_connections()
    }

    /// Close all of this endpoint's connections immediately and cease accepting new connections.
    ///
    /// See [`Connection::close()`] for details.
    ///
    /// [`Connection::close()`]: crate::Connection::close
    pub fn close(&self, error_code: VarInt, reason: &[u8]) {
        let reason = Bytes::copy_from_slice(reason);
        let mut endpoint = self.inner.state.lock().unwrap();
        endpoint.recv_state.connections.close = Some((error_code, reason.clone()));
        for sender in endpoint.recv_state.connections.senders.values() {
            // Ignoring errors from dropped connections
            let _ = sender.send(ConnectionEvent::Close {
                error_code,
                reason: reason.clone(),
            });
        }
        self.inner.shared.incoming.notify_waiters();
    }

    /// Wait for all connections on the endpoint to be cleanly shut down
    ///
    /// Waiting for this condition before exiting ensures that a good-faith effort is made to notify
    /// peers of recent connection closes, whereas exiting immediately could force them to wait out
    /// the idle timeout period.
    ///
    /// Does not proactively close existing connections or cause incoming connections to be
    /// rejected. Consider calling [`close()`] if that is desired.
    ///
    /// [`close()`]: Endpoint::close
    pub async fn wait_idle(&self) {
        loop {
            {
                let endpoint = &mut *self.inner.state.lock().unwrap();
                if endpoint.is_idle() {
                    break;
                }
                // Construct future while lock is held to avoid race
                self.inner.shared.idle.notified()
            }
            .await;
        }
    }
}

/// Statistics on [Endpoint] activity
#[non_exhaustive]
#[derive(Debug, Default, Copy, Clone)]
pub struct EndpointStats {
    /// Cumulative number of Quic handshakes accepted by this [Endpoint]
    pub accepted_handshakes: u64,
    /// Cumulative number of Quic handshakes sent from this [Endpoint]
    pub outgoing_handshakes: u64,
    /// Cumulative number of Quic handshakes refused on this [Endpoint]
    pub refused_handshakes: u64,
    /// Cumulative number of Quic handshakes ignored on this [Endpoint]
    pub ignored_handshakes: u64,
}

/// A future that drives IO on an endpoint
///
/// This task functions as the switch point between the UDP socket object and the
/// `Endpoint` responsible for routing datagrams to their owning `Connection`.
/// In order to do so, it also facilitates the exchange of different types of events
/// flowing between the `Endpoint` and the tasks managing `Connection`s. As such,
/// running this task is necessary to keep the endpoint's connections running.
///
/// `EndpointDriver` futures terminate when all clones of the `Endpoint` have been dropped, or when
/// an I/O error occurs.
#[must_use = "endpoint drivers must be spawned for I/O to occur"]
#[derive(Debug)]
pub(crate) struct EndpointDriver(pub(crate) EndpointRef);

impl Future for EndpointDriver {
    type Output = Result<(), io::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let runtime = {
            let mut endpoint = self.0.state.lock().unwrap();
            match endpoint.driver.as_mut() {
                Some(old_waker) => old_waker.clone_from(cx.waker()),
                None => endpoint.driver = Some(cx.waker().clone()),
            }
            endpoint.runtime.clone()
        };

        let now = runtime.now();
        let mut keep_going = self.0.drive_recv(cx, now, &*runtime)?;

        let mut endpoint = self.0.state.lock().unwrap();
        keep_going |= endpoint.handle_events(cx, &self.0.shared);

        if !endpoint.recv_state.incoming.is_empty() {
            self.0.shared.incoming.notify_waiters();
        }

        if self.0.shared.ref_count.load(Ordering::Relaxed) == 0 && endpoint.is_idle() {
            Poll::Ready(Ok(()))
        } else {
            drop(endpoint);
            // If there is more work to do schedule the endpoint task again.
            // `wake_by_ref()` is called outside the lock to minimize
            // lock contention on a multithreaded runtime.
            if keep_going {
                cx.waker().wake_by_ref();
            }
            Poll::Pending
        }
    }
}

impl Drop for EndpointDriver {
    fn drop(&mut self) {
        let mut endpoint = self.0.state.lock().unwrap();
        endpoint.driver_lost = true;
        self.0.shared.incoming.notify_waiters();
        // Drop all outgoing channels, signaling the termination of the endpoint to the associated
        // connections.
        endpoint.recv_state.connections.senders.clear();
        // Clearing the senders is what makes the endpoint idle, but a waiter already parked on
        // `idle` only re-reads that after being notified, and with the driver gone nothing else
        // can wake it. Same reason as the equivalent check in `EndpointInner::accept`.
        if endpoint.is_idle() {
            self.0.shared.idle.notify_waiters();
        }
    }
}

#[derive(Debug)]
pub(crate) struct EndpointInner {
    recv_io: Mutex<RecvIo>,
    pub(crate) state: Mutex<State>,
    pub(crate) shared: Shared,
}

impl EndpointInner {
    pub(crate) fn accept(
        &self,
        incoming: proto::Incoming,
        server_config: Option<Arc<ServerConfig>>,
    ) -> Result<Connecting, ConnectionError> {
        let mut response_buffer = Vec::new();

        // Phase 1: reserve endpoint state for the connection under the lock.
        let accepting = {
            let mut state = self.state.lock().unwrap();
            let now = state.runtime.now();
            match state
                .inner
                .start_accept(incoming, now, &mut response_buffer, server_config)
            {
                Ok(accepting) => {
                    state.pending_accepts += 1;
                    accepting
                }
                Err(error) => {
                    if let Some(transmit) = error.response {
                        respond(transmit, &response_buffer, &mut state.sender);
                    }
                    return Err(error.cause);
                }
            }
        };

        // Phase 2: TLS session setup, connection construction, and first-packet handling,
        // without holding the lock.
        let accepted = accepting.accept();

        // Phase 3: register the connection, or release the reservation, under the lock.
        let mut state = self.state.lock().unwrap();
        let recv_io = if state.sender_factory.is_none() {
            drop(state);
            let recv_io = self.recv_io.lock().unwrap();
            state = self.state.lock().unwrap();
            Some(recv_io)
        } else {
            None
        };
        state.pending_accepts -= 1;
        let result = match state.inner.finish_accept(accepted, &mut response_buffer) {
            Ok((handle, conn)) => {
                if let Some(sender_factory) = state.sender_factory.clone() {
                    Ok(state.finish_accept(handle, conn, || sender_factory.create_sender()))
                } else {
                    let recv_io = recv_io.as_ref().expect("socket locked without a sender factory");
                    Ok(state.finish_accept(handle, conn, || recv_io.socket.create_sender()))
                }
            }
            Err(error) => {
                if let Some(transmit) = error.response {
                    respond(transmit, &response_buffer, &mut state.sender);
                }
                Err(error.cause)
            }
        };
        // Failed accepts and accepts completed after driver loss cannot rely on a Drained event
        // being processed to wake idle waiters.
        if state.is_idle() {
            self.shared.idle.notify_waiters();
        }
        result
    }

    pub(crate) fn refuse(&self, incoming: proto::Incoming) {
        let mut state = self.state.lock().unwrap();
        state.stats.refused_handshakes += 1;
        let mut response_buffer = Vec::new();
        let transmit = state.inner.refuse(incoming, &mut response_buffer);
        respond(transmit, &response_buffer, &mut state.sender);
    }

    pub(crate) fn retry(&self, incoming: proto::Incoming) -> Result<(), proto::RetryError> {
        let mut state = self.state.lock().unwrap();
        let mut response_buffer = Vec::new();
        let transmit = state.inner.retry(incoming, &mut response_buffer)?;
        respond(transmit, &response_buffer, &mut state.sender);
        Ok(())
    }

    pub(crate) fn ignore(&self, incoming: proto::Incoming) {
        let mut state = self.state.lock().unwrap();
        state.stats.ignored_handshakes += 1;
        state.inner.ignore(incoming);
    }

    fn drive_recv(
        &self,
        cx: &mut Context<'_>,
        now: Instant,
        runtime: &dyn Runtime,
    ) -> Result<bool, io::Error> {
        let mut recv_io = self.recv_io.lock().unwrap();
        let get_time = || runtime.now();
        recv_io.recv_limiter.start_cycle(get_time);

        if let Some(mut socket) = recv_io.prev_socket.take() {
            // We don't care about the `PollProgress` from old sockets.
            let poll_res = {
                let RecvIo {
                    recv_buf,
                    recv_limiter,
                    ..
                } = &mut *recv_io;
                poll_socket(self, cx, &mut *socket, recv_buf, recv_limiter, runtime, now)
            };
            if poll_res.is_ok() {
                recv_io.prev_socket = Some(socket);
            }
        };

        let poll_res = {
            let RecvIo {
                socket,
                recv_buf,
                recv_limiter,
                ..
            } = &mut *recv_io;
            poll_socket(
                self,
                cx,
                &mut **socket,
                recv_buf,
                recv_limiter,
                runtime,
                now,
            )
        };
        recv_io.recv_limiter.finish_cycle(get_time);

        let poll_res = poll_res?;
        if poll_res.received_connection_packet {
            // Traffic has arrived on self.socket, therefore there is no need for the abandoned
            // one anymore. TODO: Account for multiple outgoing connections.
            recv_io.prev_socket = None;
        }
        Ok(poll_res.keep_going)
    }
}

struct RecvIo {
    socket: Box<dyn AsyncUdpSocket>,
    /// During an active migration, abandoned_socket receives traffic
    /// until the first packet arrives on the new socket.
    prev_socket: Option<Box<dyn AsyncUdpSocket>>,
    recv_buf: Box<[u8]>,
    recv_limiter: WorkLimiter,
}

impl RecvIo {
    fn new(socket: Box<dyn AsyncUdpSocket>, endpoint: &proto::Endpoint) -> Self {
        let recv_buf = vec![
            0;
            endpoint.config().get_max_udp_payload_size().min(64 * 1024) as usize
                * socket.max_receive_segments()
                * BATCH_SIZE
        ];
        Self {
            socket,
            prev_socket: None,
            recv_buf: recv_buf.into(),
            recv_limiter: WorkLimiter::new(RECV_TIME_BOUND),
        }
    }
}

impl fmt::Debug for RecvIo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecvIo")
            .field("socket", &self.socket)
            .field("prev_socket", &self.prev_socket)
            // recv_buf too large
            .field("recv_limiter", &self.recv_limiter)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub(crate) struct State {
    sender: Pin<Box<dyn UdpSender>>,
    sender_factory: Option<Arc<dyn UdpSenderFactory>>,
    inner: proto::Endpoint,
    recv_state: RecvState,
    driver: Option<Waker>,
    ipv6: bool,
    events: mpsc::UnboundedReceiver<(ConnectionHandle, EndpointEvent)>,
    driver_lost: bool,
    runtime: Arc<dyn Runtime>,
    stats: EndpointStats,
    default_client_config: Option<ClientConfig>,
    /// Connections in the process of being accepted
    pending_accepts: usize,
}

#[derive(Debug)]
pub(crate) struct Shared {
    incoming: Notify,
    idle: Notify,
    /// Number of live handles that can be used to initiate or handle I/O; excludes the driver
    ref_count: AtomicUsize,
}

impl State {
    fn finish_accept(
        &mut self,
        handle: ConnectionHandle,
        conn: proto::Connection,
        create_sender: impl FnOnce() -> Pin<Box<dyn UdpSender>>,
    ) -> Connecting {
        self.stats.accepted_handshakes += 1;
        let sender = create_sender();
        let runtime = self.runtime.clone();
        self.recv_state
            .connections
            .insert(handle, conn, sender, self.driver_lost, runtime)
    }

    fn connect(
        &mut self,
        now: Instant,
        config: ClientConfig,
        addr: SocketAddr,
        server_name: &str,
        create_sender: impl FnOnce() -> Pin<Box<dyn UdpSender>>,
        runtime: Arc<dyn Runtime>,
    ) -> Result<Connecting, ConnectError> {
        if self.driver_lost || self.recv_state.connections.close.is_some() {
            return Err(ConnectError::EndpointStopping);
        }
        if addr.is_ipv6() && !self.ipv6 {
            return Err(ConnectError::InvalidRemoteAddress(addr));
        }
        let addr = if self.ipv6 {
            SocketAddr::V6(ensure_ipv6(addr))
        } else {
            addr
        };

        let (ch, conn) = self.inner.connect(now, config, addr, server_name)?;

        self.stats.outgoing_handshakes += 1;
        Ok(self
            .recv_state
            .connections
            .insert(ch, conn, create_sender(), false, runtime))
    }

    fn handle_events(&mut self, cx: &mut Context<'_>, shared: &Shared) -> bool {
        for _ in 0..IO_LOOP_BOUND {
            let (ch, event) = match self.events.poll_recv(cx) {
                Poll::Ready(Some(x)) => x,
                Poll::Ready(None) => unreachable!("EndpointInner owns one sender"),
                Poll::Pending => {
                    return false;
                }
            };

            if event.is_drained() {
                self.recv_state.connections.senders.remove(&ch);
                if self.is_idle() {
                    shared.idle.notify_waiters();
                }
            }
            let Some(event) = self.inner.handle_event(ch, event) else {
                continue;
            };
            // Ignoring errors from dropped connections that haven't yet been cleaned up
            let _ = self
                .recv_state
                .connections
                .senders
                .get_mut(&ch)
                .unwrap()
                .send(ConnectionEvent::Proto(event));
        }

        true
    }

    fn is_idle(&self) -> bool {
        self.recv_state.connections.is_empty() && self.pending_accepts == 0
    }
}

impl Drop for State {
    fn drop(&mut self) {
        for incoming in self.recv_state.incoming.drain(..) {
            self.inner.ignore(incoming);
        }
    }
}

fn respond(
    transmit: proto::Transmit,
    response_buffer: &[u8],
    sender: &mut Pin<Box<dyn UdpSender>>,
) {
    // Send if there's kernel buffer space; otherwise, drop it
    //
    // As an endpoint-generated packet, we know this is an
    // immediate, stateless response to an unconnected peer,
    // one of:
    //
    // - A version negotiation response due to an unknown version
    // - A `CLOSE` due to a malformed or unwanted connection attempt
    // - A stateless reset due to an unrecognized connection
    // - A `Retry` packet due to a connection attempt when
    //   `use_retry` is set
    //
    // In each case, a well-behaved peer can be trusted to retry a
    // few times, which is guaranteed to produce the same response
    // from us. Repeated failures might at worst cause a peer's new
    // connection attempt to time out, which is acceptable if we're
    // under such heavy load that there's never room for this code
    // to transmit. This is morally equivalent to the packet getting
    // lost due to congestion further along the link, which
    // similarly relies on peer retries for recovery.

    // Copied from rust 1.85's std::task::Waker::noop() implementation for backwards compatibility
    const NOOP: RawWaker = {
        const VTABLE: RawWakerVTable = RawWakerVTable::new(
            // Cloning just returns a new no-op raw waker
            |_| NOOP,
            // `wake` does nothing
            |_| {},
            // `wake_by_ref` does nothing
            |_| {},
            // Dropping does nothing as we don't allocate anything
            |_| {},
        );
        RawWaker::new(std::ptr::null(), &VTABLE)
    };
    // SAFETY: Copied from rust stdlib, the NOOP waker is thread-safe and doesn't violate the RawWakerVTable contract,
    // it doesn't access the data pointer at all.
    let waker = unsafe { Waker::from_raw(NOOP) };
    let mut cx = Context::from_waker(&waker);
    _ = sender.as_mut().poll_send(
        &udp_transmit(&transmit, &response_buffer[..transmit.size]),
        &mut cx,
    );
}

#[inline]
fn proto_ecn(ecn: udp::EcnCodepoint) -> proto::EcnCodepoint {
    match ecn {
        udp::EcnCodepoint::Ect0 => proto::EcnCodepoint::Ect0,
        udp::EcnCodepoint::Ect1 => proto::EcnCodepoint::Ect1,
        udp::EcnCodepoint::Ce => proto::EcnCodepoint::Ce,
    }
}

#[derive(Debug)]
struct ConnectionSet {
    /// Senders for communicating with the endpoint's connections
    senders: FxHashMap<ConnectionHandle, mpsc::UnboundedSender<ConnectionEvent>>,
    /// Stored to give out clones to new ConnectionInners
    sender: mpsc::UnboundedSender<(ConnectionHandle, EndpointEvent)>,
    /// Set if the endpoint has been manually closed
    close: Option<(VarInt, Bytes)>,
}

impl ConnectionSet {
    fn insert(
        &mut self,
        handle: ConnectionHandle,
        conn: proto::Connection,
        sender: Pin<Box<dyn UdpSender>>,
        driver_lost: bool,
        runtime: Arc<dyn Runtime>,
    ) -> Connecting {
        let (send, recv) = mpsc::unbounded_channel();
        if let Some((error_code, reason)) = &self.close {
            send.send(ConnectionEvent::Close {
                error_code: *error_code,
                reason: reason.clone(),
            })
            .unwrap();
        }
        match driver_lost {
            // Close the event channel before spawning the connection driver, so it cannot
            // transmit a handshake after the endpoint driver has stopped.
            true => drop(send),
            false => {
                self.senders.insert(handle, send);
            }
        }
        Connecting::new(handle, conn, self.sender.clone(), recv, sender, runtime)
    }

    fn is_empty(&self) -> bool {
        self.senders.is_empty()
    }
}

fn ensure_ipv6(x: SocketAddr) -> SocketAddrV6 {
    match x {
        SocketAddr::V6(x) => x,
        SocketAddr::V4(x) => SocketAddrV6::new(x.ip().to_ipv6_mapped(), x.port(), 0, 0),
    }
}

pin_project! {
    /// Future produced by [`Endpoint::accept`]
    pub struct Accept<'a> {
        endpoint: &'a Endpoint,
        #[pin]
        notify: Notified<'a>,
    }
}

impl Future for Accept<'_> {
    type Output = Option<Incoming>;
    fn poll(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        let mut endpoint = this.endpoint.inner.state.lock().unwrap();
        if endpoint.driver_lost {
            return Poll::Ready(None);
        }
        if let Some(incoming) = endpoint.recv_state.incoming.pop_front() {
            // Release the mutex lock on endpoint so cloning it doesn't deadlock
            drop(endpoint);
            let incoming = Incoming::new(incoming, this.endpoint.inner.clone());
            return Poll::Ready(Some(incoming));
        }
        if endpoint.recv_state.connections.close.is_some() {
            return Poll::Ready(None);
        }
        loop {
            match this.notify.as_mut().poll(ctx) {
                // `state` lock ensures we didn't race with readiness
                Poll::Pending => return Poll::Pending,
                // Spurious wakeup, get a new future
                Poll::Ready(()) => this
                    .notify
                    .set(this.endpoint.inner.shared.incoming.notified()),
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct EndpointRef(Arc<EndpointInner>);

impl EndpointRef {
    pub(crate) fn new(
        socket: Box<dyn AsyncUdpSocket>,
        inner: proto::Endpoint,
        ipv6: bool,
        runtime: Arc<dyn Runtime>,
    ) -> Self {
        let (sender, events) = mpsc::unbounded_channel();
        let recv_state = RecvState::new(sender, socket.max_receive_segments(), &inner);
        let sender_factory = socket.sender_factory();
        let sender = socket.create_sender();
        let recv_io = RecvIo::new(socket, &inner);
        Self(Arc::new(EndpointInner {
            shared: Shared {
                incoming: Notify::new(),
                idle: Notify::new(),
                ref_count: AtomicUsize::new(0),
            },
            recv_io: Mutex::new(recv_io),
            state: Mutex::new(State {
                sender,
                sender_factory,
                inner,
                ipv6,
                events,
                driver: None,
                driver_lost: false,
                recv_state,
                runtime,
                stats: EndpointStats::default(),
                default_client_config: None,
                pending_accepts: 0,
            }),
        }))
    }
}

impl Clone for EndpointRef {
    fn clone(&self) -> Self {
        self.0.shared.ref_count.fetch_add(1, Ordering::Relaxed);
        Self(self.0.clone())
    }
}

impl Drop for EndpointRef {
    fn drop(&mut self) {
        if self.shared.ref_count.fetch_sub(1, Ordering::Relaxed) > 1 {
            return;
        }

        let endpoint = &mut *self.0.state.lock().unwrap();
        // If the driver is about to be on its own, ensure it can shut down if the last
        // connection is gone.
        if let Some(task) = endpoint.driver.take() {
            task.wake();
        }
    }
}

impl std::ops::Deref for EndpointRef {
    type Target = EndpointInner;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// State directly involved in handling incoming packets
struct RecvState {
    incoming: VecDeque<proto::Incoming>,
    connections: ConnectionSet,
    /// Reused buffer that received datagrams are copied into and split into owned slices.
    datagrams: BytesMut,
}

impl RecvState {
    fn new(
        sender: mpsc::UnboundedSender<(ConnectionHandle, EndpointEvent)>,
        max_receive_segments: usize,
        endpoint: &proto::Endpoint,
    ) -> Self {
        let datagram_capacity = endpoint.config().get_max_udp_payload_size().min(64 * 1024)
            as usize
            * max_receive_segments;
        Self {
            connections: ConnectionSet {
                senders: FxHashMap::default(),
                sender,
                close: None,
            },
            incoming: VecDeque::new(),
            datagrams: BytesMut::with_capacity(datagram_capacity),
        }
    }

    fn handle_recv_batch(
        &mut self,
        endpoint: &mut proto::Endpoint,
        sender: &mut Pin<Box<dyn UdpSender>>,
        metas: &[RecvMeta],
        iovs: &[IoSliceMut<'_>],
        msgs: usize,
        now: Instant,
    ) -> bool {
        let mut received_connection_packet = false;
        // Copy the received batch into `datagrams` and split each datagram off as
        // an owned slice. We can't read directly into `datagrams` and drop
        // `recv_buf`: once a slice has been handed to a connection the allocation
        // is shared, so the next `reserve` must allocate fresh backing memory.
        // Reading in place would therefore mean reserving the worst-case iovec
        // envelope before every poll and reallocating it whenever a prior datagram
        // is still in flight. `recv_buf` stays an allocate-once scratch buffer, and
        // we reserve only the bytes actually received.
        let batch_len = metas.iter().take(msgs).map(|meta| meta.len).sum();
        self.datagrams.reserve(batch_len);
        for (meta, buf) in metas.iter().zip(iovs.iter()).take(msgs) {
            self.datagrams.extend_from_slice(&buf[..meta.len]);
        }
        for meta in metas.iter().take(msgs) {
            let mut data = self.datagrams.split_to(meta.len);
            while !data.is_empty() {
                let buf = data.split_to(meta.stride.min(data.len()));
                let mut response_buffer = Vec::new();
                match endpoint.handle(
                    now,
                    meta.addr,
                    meta.dst_ip,
                    meta.ecn.map(proto_ecn),
                    buf,
                    &mut response_buffer,
                ) {
                    Some(DatagramEvent::NewConnection(incoming)) => {
                        if self.connections.close.is_none() {
                            self.incoming.push_back(incoming);
                        } else {
                            let transmit = endpoint.refuse(incoming, &mut response_buffer);
                            respond(transmit, &response_buffer, sender);
                        }
                    }
                    Some(DatagramEvent::ConnectionEvent(handle, event)) => {
                        // Ignoring errors from dropped connections that haven't yet been cleaned up
                        received_connection_packet = true;
                        let _ = self
                            .connections
                            .senders
                            .get_mut(&handle)
                            .unwrap()
                            .send(ConnectionEvent::Proto(event));
                    }
                    Some(DatagramEvent::Response(transmit)) => {
                        respond(transmit, &response_buffer, sender);
                    }
                    None => {}
                }
            }
        }

        received_connection_packet
    }
}

fn poll_socket(
    endpoint: &EndpointInner,
    cx: &mut Context<'_>,
    socket: &mut dyn AsyncUdpSocket,
    recv_buf: &mut [u8],
    recv_limiter: &mut WorkLimiter,
    runtime: &dyn Runtime,
    now: Instant,
) -> Result<PollProgress, io::Error> {
    let mut progress = PollProgress::default();
    let mut metas = [RecvMeta::default(); BATCH_SIZE];
    let mut iovs: [IoSliceMut<'_>; BATCH_SIZE] = {
        let mut bufs = recv_buf
            .chunks_mut(recv_buf.len() / BATCH_SIZE)
            .map(IoSliceMut::new);

        // expect() safe as recv_buf is chunked into BATCH_SIZE items and iovs
        // will be of size BATCH_SIZE, thus from_fn is called exactly
        // BATCH_SIZE times.
        std::array::from_fn(|_| bufs.next().expect("BATCH_SIZE elements"))
    };
    loop {
        match socket.poll_recv(cx, &mut iovs, &mut metas) {
            Poll::Ready(Ok(msgs)) => {
                recv_limiter.record_work(msgs);
                let received_connection_packet = {
                    let mut state = endpoint.state.lock().unwrap();
                    let State {
                        inner,
                        recv_state,
                        sender,
                        ..
                    } = &mut *state;
                    recv_state.handle_recv_batch(inner, sender, &metas, &iovs, msgs, now)
                };
                progress.received_connection_packet |= received_connection_packet;
            }
            Poll::Pending => return Ok(progress),
            // Ignore ECONNRESET as it's undefined in QUIC and may be injected by an
            // attacker
            Poll::Ready(Err(ref e)) if e.kind() == io::ErrorKind::ConnectionReset => continue,
            // Ignore EMSGSIZE as we're currently not handling ICMPv4 Fragmentation Needed
            // and ICMPv6 Packet Too Big (PTB) messages since they cannot be authenticated,
            // and Datagram Packetization Layer Path MTU Discovery (DPLPMTUD) works without
            // it anyways.
            Poll::Ready(Err(ref e)) if is_msg_size_err(e) => continue,
            Poll::Ready(Err(e)) => return Err(e),
        }
        if !recv_limiter.allow_work(|| runtime.now()) {
            progress.keep_going = true;
            return Ok(progress);
        }
    }
}

impl fmt::Debug for RecvState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecvState")
            .field("incoming", &self.incoming)
            .field("connections", &self.connections)
            .finish_non_exhaustive()
    }
}

#[derive(Default)]
struct PollProgress {
    /// Whether a datagram was routed to an existing connection
    received_connection_packet: bool,
    /// Whether datagram handling was interrupted early by the work limiter for fairness
    keep_going: bool,
}
