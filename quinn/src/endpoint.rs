use std::{
    collections::{HashMap, VecDeque},
    fmt,
    future::Future,
    io::{self, IoSliceMut},
    mem,
    net::{IpAddr, SocketAddr, SocketAddrV6},
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
    runtime::{AsyncUdpSocket, Runtime, UdpSender},
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
use udp::{BATCH_SIZE, RecvMeta};

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
    runtime: Arc<dyn Runtime>,
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
        if addr.is_ipv6() {
            if let Err(e) = socket.set_only_v6(false) {
                tracing::debug!(%e, "unable to make socket dual-stack");
            }
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
        self.inner.proto.lock().unwrap().stats
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
        if addr.is_ipv6() {
            if let Err(e) = socket.set_only_v6(false) {
                tracing::debug!(%e, "unable to make socket dual-stack");
            }
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
        let socket = runtime.wrap_udp_socket(socket)?;
        Self::new_with_abstract_socket(config, server_config, socket, runtime)
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
        let addr = socket.local_addr()?;
        let allow_mtud = !socket.may_fragment();
        let rc = EndpointRef::new(
            socket,
            proto::Endpoint::new(Arc::new(config), server_config.map(Arc::new), allow_mtud),
            addr.is_ipv6(),
            runtime.clone(),
        );
        let driver = EndpointDriver(rc.clone());
        runtime.spawn(Box::pin(
            async {
                if let Err(e) = driver.await {
                    tracing::error!("I/O error: {}", e);
                }
            }
            .instrument(Span::current()),
        ));
        Ok(Self { inner: rc, runtime })
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
        self.inner.0.proto.lock().unwrap().default_client_config = Some(config);
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
            .proto
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
        let (driver_lost, ipv6) = {
            let endpoint = self.inner.proto.lock().unwrap();
            (endpoint.driver_lost, endpoint.ipv6)
        };
        if driver_lost
            || self
                .inner
                .io
                .lock()
                .unwrap()
                .recv_state
                .connections
                .close
                .is_some()
        {
            return Err(ConnectError::EndpointStopping);
        }
        if addr.is_ipv6() && !ipv6 {
            return Err(ConnectError::InvalidRemoteAddress(addr));
        }
        let addr = if ipv6 {
            SocketAddr::V6(ensure_ipv6(addr))
        } else {
            addr
        };

        let (ch, conn) = {
            let mut endpoint = self.inner.proto.lock().unwrap();
            let result = endpoint
                .inner
                .connect(self.runtime.now(), config, addr, server_name)?;
            endpoint.stats.outgoing_handshakes += 1;
            result
        };

        let mut io = self.inner.io.lock().unwrap();
        let sender = io.socket.create_sender();
        Ok(io
            .recv_state
            .connections
            .insert(ch, conn, sender, self.runtime.clone()))
    }

    /// Switch to a new UDP socket
    ///
    /// See [`Endpoint::rebind_abstract()`] for details.
    #[cfg(not(wasm_browser))]
    pub fn rebind(&self, socket: std::net::UdpSocket) -> io::Result<()> {
        self.rebind_abstract(self.runtime.wrap_udp_socket(socket)?)
    }

    /// Switch to a new UDP socket
    ///
    /// Allows the endpoint's address to be updated live, affecting all active connections. Incoming
    /// connections and connections to servers unreachable from the new address will be lost.
    ///
    /// On error, the old UDP socket is retained.
    pub fn rebind_abstract(&self, socket: Box<dyn AsyncUdpSocket>) -> io::Result<()> {
        let addr = socket.local_addr()?;
        {
            let mut io = self.inner.io.lock().unwrap();
            io.prev_socket = Some(mem::replace(&mut io.socket, socket));
            io.recv_state
                .connections
                .send_rebind(|| io.socket.create_sender());
        }
        let driver = {
            let mut proto = self.inner.proto.lock().unwrap();
            proto.ipv6 = addr.is_ipv6();
            proto.driver.take()
        };
        if let Some(driver) = driver {
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
            .proto
            .lock()
            .unwrap()
            .inner
            .set_server_config(server_config.map(Arc::new))
    }

    /// Get the local `SocketAddr` the underlying socket is bound to
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.io.lock().unwrap().socket.local_addr()
    }

    /// Get the number of connections that are currently open
    pub fn open_connections(&self) -> usize {
        self.inner.proto.lock().unwrap().inner.open_connections()
    }

    /// Close all of this endpoint's connections immediately and cease accepting new connections.
    ///
    /// See [`Connection::close()`] for details.
    ///
    /// [`Connection::close()`]: crate::Connection::close
    pub fn close(&self, error_code: VarInt, reason: &[u8]) {
        let reason = Bytes::copy_from_slice(reason);
        let mut endpoint = self.inner.io.lock().unwrap();
        endpoint.recv_state.connections.close = Some((error_code, reason.clone()));
        endpoint
            .recv_state
            .connections
            .send_close(error_code, reason.clone());
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
                let endpoint = &mut *self.inner.io.lock().unwrap();
                if endpoint.recv_state.connections.is_empty() {
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
        {
            let mut endpoint = self.0.proto.lock().unwrap();
            if endpoint.driver.is_none() {
                endpoint.driver = Some(cx.waker().clone());
            }
        }

        let now = self.0.runtime.now();
        let mut keep_going = {
            let mut io = self.0.io.lock().unwrap();
            let keep_going = io.drive_recv(cx, &self.0.proto, &*self.0.runtime, now)?;
            if !io.recv_state.incoming.is_empty() {
                self.0.shared.incoming.notify_waiters();
            }
            keep_going
        };
        keep_going |= self.0.handle_events(cx, &self.0.shared);

        if self.0.shared.ref_count.load(Ordering::Relaxed) == 0
            && self.0.io.lock().unwrap().recv_state.connections.is_empty()
        {
            Poll::Ready(Ok(()))
        } else {
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
        self.0.proto.lock().unwrap().driver_lost = true;
        self.0.shared.incoming.notify_waiters();
        // Drop all outgoing channels, signaling the termination of the endpoint to the associated
        // connections.
        self.0.io.lock().unwrap().recv_state.connections.clear();
    }
}

#[derive(Debug)]
pub(crate) struct EndpointInner {
    pub(crate) proto: Mutex<ProtoState>,
    pub(crate) io: Mutex<IoState>,
    pub(crate) shared: Shared,
    runtime: Arc<dyn Runtime>,
}

impl EndpointInner {
    pub(crate) fn accept(
        &self,
        incoming: proto::Incoming,
        server_config: Option<Arc<ServerConfig>>,
    ) -> Result<Connecting, ConnectionError> {
        let mut response_buffer = Vec::new();
        let now = self.runtime.now();
        let result = {
            self.proto.lock().unwrap().inner.accept(
                incoming,
                now,
                &mut response_buffer,
                server_config,
            )
        };
        match result {
            Ok((handle, conn)) => {
                self.proto.lock().unwrap().stats.accepted_handshakes += 1;
                let mut io = self.io.lock().unwrap();
                let sender = io.socket.create_sender();
                Ok(io
                    .recv_state
                    .connections
                    .insert(handle, conn, sender, self.runtime.clone()))
            }
            Err(error) => {
                if let Some(transmit) = error.response {
                    respond(
                        transmit,
                        &response_buffer,
                        &mut self.io.lock().unwrap().sender,
                    );
                }
                Err(error.cause)
            }
        }
    }

    pub(crate) fn refuse(&self, incoming: proto::Incoming) {
        self.proto.lock().unwrap().stats.refused_handshakes += 1;
        let mut response_buffer = Vec::new();
        let transmit = self
            .proto
            .lock()
            .unwrap()
            .inner
            .refuse(incoming, &mut response_buffer);
        respond(
            transmit,
            &response_buffer,
            &mut self.io.lock().unwrap().sender,
        );
    }

    pub(crate) fn retry(&self, incoming: proto::Incoming) -> Result<(), proto::RetryError> {
        let mut response_buffer = Vec::new();
        let transmit = self
            .proto
            .lock()
            .unwrap()
            .inner
            .retry(incoming, &mut response_buffer)?;
        respond(
            transmit,
            &response_buffer,
            &mut self.io.lock().unwrap().sender,
        );
        Ok(())
    }

    pub(crate) fn ignore(&self, incoming: proto::Incoming) {
        let mut state = self.proto.lock().unwrap();
        state.stats.ignored_handshakes += 1;
        state.inner.ignore(incoming);
    }

    fn handle_events(&self, cx: &mut Context<'_>, shared: &Shared) -> bool {
        for _ in 0..IO_LOOP_BOUND {
            let (ch, event) = {
                let mut state = self.proto.lock().unwrap();
                match state.events.poll_recv(cx) {
                    Poll::Ready(Some(x)) => x,
                    Poll::Ready(None) => unreachable!("EndpointInner owns one sender"),
                    Poll::Pending => {
                        return false;
                    }
                }
            };

            let drained = event.is_drained();
            let retired_seq = event.retired_local_cid_seq();
            let conn_event = self.proto.lock().unwrap().inner.handle_event(ch, event);

            let mut io = self.io.lock().unwrap();
            if let Some(seq) = retired_seq {
                io.recv_state.connections.retire(ch, seq);
            }
            if drained {
                io.recv_state.connections.remove(ch);
                if io.recv_state.connections.is_empty() {
                    shared.idle.notify_waiters();
                }
            }
            if let Some(event) = conn_event {
                let _ = io.recv_state.connections.send_proto(ch, event);
            }
        }

        true
    }
}

#[derive(Debug)]
pub(crate) struct ProtoState {
    inner: proto::Endpoint,
    driver: Option<Waker>,
    ipv6: bool,
    events: mpsc::UnboundedReceiver<(ConnectionHandle, EndpointEvent)>,
    driver_lost: bool,
    stats: EndpointStats,
    default_client_config: Option<ClientConfig>,
}

#[derive(Debug)]
pub(crate) struct IoState {
    socket: Box<dyn AsyncUdpSocket>,
    sender: Pin<Box<dyn UdpSender>>,
    /// During an active migration, abandoned_socket receives traffic
    /// until the first packet arrives on the new socket.
    prev_socket: Option<Box<dyn AsyncUdpSocket>>,
    recv_state: RecvState,
}

#[derive(Debug)]
pub(crate) struct Shared {
    incoming: Notify,
    idle: Notify,
    /// Number of live handles that can be used to initiate or handle I/O; excludes the driver
    ref_count: AtomicUsize,
}

impl IoState {
    fn drive_recv(
        &mut self,
        cx: &mut Context<'_>,
        proto: &Mutex<ProtoState>,
        runtime: &dyn Runtime,
        now: Instant,
    ) -> Result<bool, io::Error> {
        let get_time = || runtime.now();
        self.recv_state.recv_limiter.start_cycle(get_time);
        if let Some(socket) = &mut self.prev_socket {
            // We don't care about the `PollProgress` from old sockets.
            let poll_res = self.recv_state.poll_socket(
                cx,
                proto,
                &mut **socket,
                &mut self.sender,
                runtime,
                now,
            );
            if poll_res.is_err() {
                self.prev_socket = None;
            }
        };
        let poll_res = self.recv_state.poll_socket(
            cx,
            proto,
            &mut *self.socket,
            &mut self.sender,
            runtime,
            now,
        );
        self.recv_state.recv_limiter.finish_cycle(get_time);
        let poll_res = poll_res?;
        if poll_res.received_connection_packet {
            // Traffic has arrived on self.socket, therefore there is no need for the abandoned
            // one anymore. TODO: Account for multiple outgoing connections.
            self.prev_socket = None;
        }
        Ok(poll_res.keep_going)
    }
}

impl Drop for EndpointInner {
    fn drop(&mut self) {
        let io = self.io.get_mut().unwrap();
        let proto = self.proto.get_mut().unwrap();
        for incoming in io.recv_state.incoming.drain(..) {
            proto.inner.ignore(incoming);
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
    connections: FxHashMap<ConnectionHandle, ConnectionRoutes>,
    cids: FxHashMap<proto::ConnectionId, ConnectionHandle>,
    incoming_remotes: HashMap<FourTupleKey, ConnectionHandle>,
    outgoing_remotes: HashMap<SocketAddr, ConnectionHandle>,
    /// Stored to give out clones to new ConnectionInners
    sender: mpsc::UnboundedSender<(ConnectionHandle, EndpointEvent)>,
    /// Set if the endpoint has been manually closed
    close: Option<(VarInt, Bytes)>,
    local_cid_len: usize,
}

#[derive(Debug)]
struct ConnectionRoutes {
    sender: mpsc::UnboundedSender<ConnectionEvent>,
    remote: SocketAddr,
    local_ip: Option<IpAddr>,
    side: proto::Side,
    local_cids: FxHashMap<u64, proto::ConnectionId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
struct FourTupleKey {
    remote: SocketAddr,
    local_ip: Option<IpAddr>,
}

impl ConnectionSet {
    fn insert(
        &mut self,
        handle: ConnectionHandle,
        conn: proto::Connection,
        sender: Pin<Box<dyn UdpSender>>,
        runtime: Arc<dyn Runtime>,
    ) -> Connecting {
        let (send, recv) = mpsc::unbounded_channel();
        if let Some((error_code, ref reason)) = self.close {
            send.send(ConnectionEvent::Close {
                error_code,
                reason: reason.clone(),
            })
            .unwrap();
        }
        let mut local_cids = FxHashMap::default();
        let handshake_cid = conn.handshake_cid();
        if handshake_cid.is_empty() {
            debug_assert_eq!(self.local_cid_len, 0);
            match conn.side() {
                proto::Side::Server => {
                    self.incoming_remotes.insert(
                        FourTupleKey {
                            remote: conn.remote_address(),
                            local_ip: conn.local_ip(),
                        },
                        handle,
                    );
                }
                proto::Side::Client => {
                    self.outgoing_remotes.insert(conn.remote_address(), handle);
                }
            }
        } else {
            local_cids.insert(0, handshake_cid);
            self.cids.insert(handshake_cid, handle);
        }
        self.connections.insert(
            handle,
            ConnectionRoutes {
                sender: send.clone(),
                remote: conn.remote_address(),
                local_ip: conn.local_ip(),
                side: conn.side(),
                local_cids,
            },
        );
        Connecting::new(handle, conn, self.sender.clone(), recv, sender, runtime)
    }

    fn try_route_fast(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        local_ip: Option<IpAddr>,
        ecn: Option<proto::EcnCodepoint>,
        data: BytesMut,
    ) -> Option<BytesMut> {
        let Some(handle) = self.lookup_fast(remote, local_ip, &data) else {
            return Some(data);
        };
        let Some(connection) = self.connections.get_mut(&handle) else {
            return Some(data);
        };
        let _ = connection.sender.send(ConnectionEvent::Datagram {
            now,
            remote,
            ecn,
            data,
        });
        None
    }

    fn lookup_fast(
        &self,
        remote: SocketAddr,
        local_ip: Option<IpAddr>,
        data: &[u8],
    ) -> Option<ConnectionHandle> {
        let cid = fast_path_dst_cid(data, self.local_cid_len)?;
        if cid.is_empty() {
            self.incoming_remotes
                .get(&FourTupleKey { remote, local_ip })
                .copied()
                .or_else(|| self.outgoing_remotes.get(&remote).copied())
        } else {
            self.cids.get(&cid).copied()
        }
    }

    fn send_proto(
        &mut self,
        handle: ConnectionHandle,
        event: proto::ConnectionEvent,
    ) -> Result<(), mpsc::error::SendError<ConnectionEvent>> {
        self.connections
            .get_mut(&handle)
            .unwrap()
            .sender
            .send(ConnectionEvent::Proto(event))
    }

    fn send_close(&self, error_code: VarInt, reason: Bytes) {
        for connection in self.connections.values() {
            let _ = connection.sender.send(ConnectionEvent::Close {
                error_code,
                reason: reason.clone(),
            });
        }
    }

    fn send_rebind(&self, mut make_sender: impl FnMut() -> Pin<Box<dyn UdpSender>>) {
        for connection in self.connections.values() {
            let _ = connection
                .sender
                .send(ConnectionEvent::Rebind(make_sender()));
        }
    }

    fn retire(&mut self, handle: ConnectionHandle, sequence: u64) {
        if let Some(connection) = self.connections.get_mut(&handle) {
            if let Some(cid) = connection.local_cids.remove(&sequence) {
                self.cids.remove(&cid);
            }
        }
    }

    fn remove(&mut self, handle: ConnectionHandle) {
        let Some(connection) = self.connections.remove(&handle) else {
            return;
        };
        for cid in connection.local_cids.values() {
            self.cids.remove(cid);
        }
        match connection.side {
            proto::Side::Server => {
                self.incoming_remotes.remove(&FourTupleKey {
                    remote: connection.remote,
                    local_ip: connection.local_ip,
                });
            }
            proto::Side::Client => {
                self.outgoing_remotes.remove(&connection.remote);
            }
        }
    }

    fn clear(&mut self) {
        self.connections.clear();
        self.cids.clear();
        self.incoming_remotes.clear();
        self.outgoing_remotes.clear();
    }

    fn is_empty(&self) -> bool {
        self.connections.is_empty()
    }
}

fn fast_path_dst_cid(data: &[u8], short_cid_len: usize) -> Option<proto::ConnectionId> {
    let first = *data.first()?;
    if first & 0x80 != 0 {
        let rest = data.get(5..)?;
        let (&len, cid_bytes) = rest.split_first()?;
        let cid = cid_bytes.get(..len as usize)?;
        Some(proto::ConnectionId::new(cid))
    } else {
        Some(proto::ConnectionId::new(data.get(1..1 + short_cid_len)?))
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
        if this.endpoint.inner.proto.lock().unwrap().driver_lost {
            return Poll::Ready(None);
        }
        let mut io = this.endpoint.inner.io.lock().unwrap();
        if let Some(incoming) = io.recv_state.incoming.pop_front() {
            // Release the mutex lock on endpoint so cloning it doesn't deadlock
            drop(io);
            let incoming = Incoming::new(incoming, this.endpoint.inner.clone());
            return Poll::Ready(Some(incoming));
        }
        if io.recv_state.connections.close.is_some() {
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
        let sender = socket.create_sender();
        Self(Arc::new(EndpointInner {
            shared: Shared {
                incoming: Notify::new(),
                idle: Notify::new(),
                ref_count: AtomicUsize::new(0),
            },
            proto: Mutex::new(ProtoState {
                inner,
                ipv6,
                events,
                driver: None,
                driver_lost: false,
                stats: EndpointStats::default(),
                default_client_config: None,
            }),
            io: Mutex::new(IoState {
                socket,
                sender,
                prev_socket: None,
                recv_state,
            }),
            runtime,
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
        if self.shared.ref_count.fetch_sub(1, Ordering::Relaxed) > 0 {
            return;
        }

        let endpoint = &mut *self.0.proto.lock().unwrap();
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
    recv_buf: Box<[u8]>,
    recv_limiter: WorkLimiter,
}

impl RecvState {
    fn new(
        sender: mpsc::UnboundedSender<(ConnectionHandle, EndpointEvent)>,
        max_receive_segments: usize,
        endpoint: &proto::Endpoint,
    ) -> Self {
        let recv_buf = vec![
            0;
            endpoint.config().get_max_udp_payload_size().min(64 * 1024) as usize
                * max_receive_segments
                * BATCH_SIZE
        ];
        Self {
            connections: ConnectionSet {
                connections: FxHashMap::default(),
                cids: FxHashMap::default(),
                incoming_remotes: HashMap::default(),
                outgoing_remotes: HashMap::default(),
                sender,
                close: None,
                local_cid_len: endpoint.local_cid_len(),
            },
            incoming: VecDeque::new(),
            recv_buf: recv_buf.into(),
            recv_limiter: WorkLimiter::new(RECV_TIME_BOUND),
        }
    }

    fn poll_socket(
        &mut self,
        cx: &mut Context<'_>,
        endpoint: &Mutex<ProtoState>,
        socket: &mut dyn AsyncUdpSocket,
        sender: &mut Pin<Box<dyn UdpSender>>,
        runtime: &dyn Runtime,
        now: Instant,
    ) -> Result<PollProgress, io::Error> {
        let mut received_connection_packet = false;
        let mut metas = [RecvMeta::default(); BATCH_SIZE];
        let mut iovs: [IoSliceMut<'_>; BATCH_SIZE] = {
            let mut bufs = self
                .recv_buf
                .chunks_mut(self.recv_buf.len() / BATCH_SIZE)
                .map(IoSliceMut::new);

            // expect() safe as self.recv_buf is chunked into BATCH_SIZE items
            // and iovs will be of size BATCH_SIZE, thus from_fn is called
            // exactly BATCH_SIZE times.
            std::array::from_fn(|_| bufs.next().expect("BATCH_SIZE elements"))
        };
        loop {
            match socket.poll_recv(cx, &mut iovs, &mut metas) {
                Poll::Ready(Ok(msgs)) => {
                    self.recv_limiter.record_work(msgs);
                    for (meta, buf) in metas.iter().zip(iovs.iter()).take(msgs) {
                        let mut data: BytesMut = buf[0..meta.len].into();
                        while !data.is_empty() {
                            let buf = data.split_to(meta.stride.min(data.len()));
                            let Some(buf) = self.connections.try_route_fast(
                                now,
                                meta.addr,
                                meta.dst_ip,
                                meta.ecn.map(proto_ecn),
                                buf,
                            ) else {
                                received_connection_packet = true;
                                continue;
                            };
                            let mut response_buffer = Vec::new();
                            match endpoint.lock().unwrap().inner.handle(
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
                                        let transmit = endpoint
                                            .lock()
                                            .unwrap()
                                            .inner
                                            .refuse(incoming, &mut response_buffer);
                                        respond(transmit, &response_buffer, sender);
                                    }
                                }
                                Some(DatagramEvent::ConnectionEvent(handle, event)) => {
                                    // Ignoring errors from dropped connections that haven't yet been cleaned up
                                    received_connection_packet = true;
                                    let _ = self.connections.send_proto(handle, event);
                                }
                                Some(DatagramEvent::Response(transmit)) => {
                                    respond(transmit, &response_buffer, sender);
                                }
                                None => {}
                            }
                        }
                    }
                }
                Poll::Pending => {
                    return Ok(PollProgress {
                        received_connection_packet,
                        keep_going: false,
                    });
                }
                // Ignore ECONNRESET as it's undefined in QUIC and may be injected by an
                // attacker
                Poll::Ready(Err(ref e)) if e.kind() == io::ErrorKind::ConnectionReset => {
                    continue;
                }
                Poll::Ready(Err(e)) => {
                    return Err(e);
                }
            }
            if !self.recv_limiter.allow_work(|| runtime.now()) {
                return Ok(PollProgress {
                    received_connection_packet,
                    keep_going: true,
                });
            }
        }
    }
}

impl fmt::Debug for RecvState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecvState")
            .field("incoming", &self.incoming)
            .field("connections", &self.connections)
            // recv_buf too large
            .field("recv_limiter", &self.recv_limiter)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fast_path_short_header_cid() {
        let cid = [1, 2, 3, 4];
        let data = [0x40, 1, 2, 3, 4, 0xaa];
        assert_eq!(
            fast_path_dst_cid(&data, cid.len()),
            Some(proto::ConnectionId::new(&cid))
        );
    }

    #[test]
    fn fast_route_delivers_datagram_by_cid() {
        let handle = ConnectionHandle(7);
        let (endpoint_send, _endpoint_recv) = mpsc::unbounded_channel();
        let (conn_send, mut conn_recv) = mpsc::unbounded_channel();
        let cid = proto::ConnectionId::new(&[9, 8, 7, 6]);
        let remote: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let data = BytesMut::from(&[0x40, 9, 8, 7, 6, 0xaa][..]);

        let mut routes = FxHashMap::default();
        let mut local_cids = FxHashMap::default();
        local_cids.insert(0, cid);
        routes.insert(
            handle,
            ConnectionRoutes {
                sender: conn_send,
                remote,
                local_ip: None,
                side: proto::Side::Client,
                local_cids,
            },
        );
        let mut set = ConnectionSet {
            connections: routes,
            cids: FxHashMap::from_iter([(cid, handle)]),
            incoming_remotes: HashMap::default(),
            outgoing_remotes: HashMap::default(),
            sender: endpoint_send,
            close: None,
            local_cid_len: cid.len(),
        };

        assert!(
            set.try_route_fast(Instant::now(), remote, None, None, data.clone())
                .is_none()
        );
        match conn_recv.try_recv().unwrap() {
            ConnectionEvent::Datagram {
                remote: got_remote,
                data: got_data,
                ..
            } => {
                assert_eq!(got_remote, remote);
                assert_eq!(got_data, data);
            }
            event => panic!("unexpected event: {event:?}"),
        }
    }

    #[test]
    fn retired_cid_is_removed_from_fast_routes() {
        let handle = ConnectionHandle(3);
        let (endpoint_send, _endpoint_recv) = mpsc::unbounded_channel();
        let (conn_send, _conn_recv) = mpsc::unbounded_channel();
        let cid = proto::ConnectionId::new(&[1, 3, 3, 7]);
        let remote: SocketAddr = "127.0.0.1:4433".parse().unwrap();

        let mut local_cids = FxHashMap::default();
        local_cids.insert(0, cid);
        let mut set = ConnectionSet {
            connections: FxHashMap::from_iter([(
                handle,
                ConnectionRoutes {
                    sender: conn_send,
                    remote,
                    local_ip: None,
                    side: proto::Side::Client,
                    local_cids,
                },
            )]),
            cids: FxHashMap::from_iter([(cid, handle)]),
            incoming_remotes: HashMap::default(),
            outgoing_remotes: HashMap::default(),
            sender: endpoint_send,
            close: None,
            local_cid_len: cid.len(),
        };

        set.retire(handle, 0);
        assert_eq!(set.lookup_fast(remote, None, &[0x40, 1, 3, 3, 7, 0]), None);
    }
}
