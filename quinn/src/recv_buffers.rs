use bytes::BytesMut;

/// Supplies the buffers that received datagrams are copied into
///
/// An [`Endpoint`](crate::Endpoint) receives datagrams into a scratch buffer and copies each one
/// (each segment, when segmentation offload is used) into a buffer obtained from this trait
/// before processing it. The returned buffer is split further, and its parts stay allocated for as
/// long as anything refers to them: unread stream data, datagrams queued for the application, or
/// data the application keeps after reading it, such as the [`Bytes`](bytes::Bytes) returned by
/// [`RecvStream::read_chunk()`](crate::RecvStream::read_chunk).
///
/// Applications can install their own implementation with
/// [`Endpoint::set_recv_buffers()`](crate::Endpoint::set_recv_buffers) to control how that memory
/// is allocated and reused, for example by recycling buffers once [`BytesMut::try_reclaim()`]
/// reports that nothing refers to them anymore. Since anything that refers to part of a buffer
/// keeps the whole buffer allocated, implementations that copy several datagrams into one buffer
/// determine how much memory a single retained datagram can keep allocated.
///
/// The default implementation copies datagrams into a pool of buffers of at most one datagram's
/// size, which grows on demand up to a few MiB and reuses a buffer once nothing refers to it.
/// Datagrams that don't fit, or arrive while every pooled buffer is in use, are copied into their
/// own allocation.
pub trait RecvBuffers: Send + 'static {
    /// Called before the datagrams of a received batch are copied, with their total size
    ///
    /// Lets implementations that copy datagrams into a shared buffer make room for the whole
    /// batch at once. Does nothing unless overridden.
    fn reserve(&mut self, total_len: usize) {
        let _ = total_len;
    }

    /// Returns a buffer holding exactly the bytes of `datagram`
    fn copy_datagram(&mut self, datagram: &[u8]) -> BytesMut;
}
