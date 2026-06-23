use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
    time::Instant,
};

use tokio::{
    io::Interest,
    runtime::{Handle, TryCurrentError},
    time::{Sleep, sleep_until},
};

use crate::runtime::{
    AsyncTimer, AsyncUdpSocket, Runtime, UdpSenderFactory, UdpSenderHelper, UdpSenderHelperSocket,
};

/// A Quinn runtime for Tokio
#[derive(Debug)]
pub struct TokioRuntime;

impl Runtime for TokioRuntime {
    fn new_timer(&self, t: Instant) -> Pin<Box<dyn AsyncTimer>> {
        Box::pin(sleep_until(t.into()))
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        tokio::spawn(future);
    }

    fn wrap_udp_socket(&self, sock: std::net::UdpSocket) -> io::Result<Box<dyn AsyncUdpSocket>> {
        Ok(Box::new(UdpSocket {
            inner: Arc::new(udp::UdpSocketState::new((&sock).into())?),
            io: Arc::new(tokio::net::UdpSocket::from_std(sock)?),
        }))
    }

    fn now(&self) -> Instant {
        tokio::time::Instant::now().into_std()
    }
}

/// A Quinn runtime backed by a specific Tokio runtime handle.
///
/// Unlike [`TokioRuntime`], this does not rely on the current Tokio runtime context. This is useful
/// when different parts of an endpoint should be scheduled on different Tokio runtimes.
#[derive(Clone, Debug)]
pub struct TokioRuntimeHandle {
    handle: Handle,
}

impl TokioRuntimeHandle {
    /// Construct a Quinn runtime from a Tokio runtime handle.
    pub fn new(handle: Handle) -> Self {
        Self { handle }
    }

    /// Construct a Quinn runtime from the current Tokio runtime handle.
    pub fn current() -> Result<Self, TryCurrentError> {
        Handle::try_current().map(Self::new)
    }
}

impl Runtime for TokioRuntimeHandle {
    fn new_timer(&self, t: Instant) -> Pin<Box<dyn AsyncTimer>> {
        let _guard = self.handle.enter();
        Box::pin(sleep_until(t.into()))
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        self.handle.spawn(future);
    }

    fn wrap_udp_socket(&self, sock: std::net::UdpSocket) -> io::Result<Box<dyn AsyncUdpSocket>> {
        let _guard = self.handle.enter();
        Ok(Box::new(UdpSocket {
            inner: Arc::new(udp::UdpSocketState::new((&sock).into())?),
            io: Arc::new(tokio::net::UdpSocket::from_std(sock)?),
        }))
    }

    fn now(&self) -> Instant {
        let _guard = self.handle.enter();
        tokio::time::Instant::now().into_std()
    }
}

impl AsyncTimer for Sleep {
    fn reset(self: Pin<&mut Self>, t: Instant) {
        Self::reset(self, t.into())
    }
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        Future::poll(self, cx)
    }
}

#[derive(Debug, Clone)]
struct UdpSocket {
    io: Arc<tokio::net::UdpSocket>,
    inner: Arc<udp::UdpSocketState>,
}

impl UdpSenderHelperSocket for UdpSocket {
    fn max_transmit_segments(&self) -> usize {
        self.inner.max_gso_segments()
    }

    fn try_send(&self, transmit: &udp::Transmit<'_>) -> io::Result<()> {
        self.io.try_io(Interest::WRITABLE, || {
            self.inner.try_send((&self.io).into(), transmit)
        })?;

        Ok(())
    }
}

impl UdpSenderFactory for UdpSocket {
    fn create_sender(&self) -> Pin<Box<dyn crate::runtime::UdpSender>> {
        Box::pin(UdpSenderHelper::new(self.clone(), |socket: &Self| {
            let socket = socket.clone();
            async move { socket.io.writable().await }
        }))
    }
}

impl AsyncUdpSocket for UdpSocket {
    fn create_sender(&self) -> Pin<Box<dyn crate::runtime::UdpSender>> {
        UdpSenderFactory::create_sender(self)
    }

    fn sender_factory(&self) -> Option<Arc<dyn UdpSenderFactory>> {
        Some(Arc::new(self.clone()))
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            ready!(self.io.poll_recv_ready(cx))?;
            match self.io.try_io(Interest::READABLE, || {
                self.inner.recv((&self.io).into(), bufs, meta)
            }) {
                Ok(res) => return Poll::Ready(Ok(res)),
                // `try_io` clears readiness only for `WouldBlock`. Looping on any other
                // error would spin: readiness stays asserted, so `poll_recv_ready`
                // completes at once and the recv fails again, without ever yielding.
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }

    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.io.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.gro_segments()
    }
}
