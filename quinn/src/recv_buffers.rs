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
/// The default implementation copies the datagrams of each received batch back to back into one
/// shared buffer.
pub trait RecvBuffers: Send + 'static {
    /// Called before the datagrams of a received batch are copied, with their total size
    ///
    /// Lets implementations that copy datagrams into a shared buffer make room for the whole
    /// batch at once. The default implementation does nothing.
    fn reserve(&mut self, total_len: usize) {
        let _ = total_len;
    }

    /// Returns a buffer holding exactly the bytes of `datagram`
    fn copy_datagram(&mut self, datagram: &[u8]) -> BytesMut;
}

/// Default [`RecvBuffers`]: copies each batch into one reusable buffer
///
/// Each datagram is split off as an owned slice that shares the buffer's allocation. `reserve`
/// reclaims the allocation once all slices of the previous batch have been dropped, so it only
/// reallocates while some datagrams are still in use, and empty polls don't allocate at all.
///
/// Datagrams can't be received into this buffer directly: once a slice has been handed out the
/// allocation is shared, so the next `reserve` must allocate fresh memory. Receiving in place
/// would therefore mean reserving the worst-case size of every receive call and reallocating it
/// whenever a prior datagram is still in use. Instead the socket receives into an allocate-once
/// scratch buffer, and only the bytes actually received are reserved here.
pub(crate) struct SharedRecvBuffers {
    buffer: BytesMut,
}

impl SharedRecvBuffers {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            buffer: BytesMut::with_capacity(capacity),
        }
    }
}

impl RecvBuffers for SharedRecvBuffers {
    fn reserve(&mut self, total_len: usize) {
        self.buffer.reserve(total_len);
    }

    fn copy_datagram(&mut self, datagram: &[u8]) -> BytesMut {
        self.buffer.extend_from_slice(datagram);
        self.buffer.split_to(datagram.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_buffer_slices_batch_from_one_allocation() {
        let mut buffers = SharedRecvBuffers::new(64);
        buffers.reserve(30);
        let first = buffers.copy_datagram(&[1; 10]);
        let second = buffers.copy_datagram(&[2; 20]);
        assert_eq!(&first[..], &[1; 10]);
        assert_eq!(&second[..], &[2; 20]);
        assert_eq!(second.as_ptr(), first.as_ptr().wrapping_add(10));

        // Once every slice has been dropped, the allocation is reclaimed for the next batch
        let first_ptr = first.as_ptr();
        drop((first, second));
        buffers.reserve(64);
        let third = buffers.copy_datagram(&[3; 64]);
        assert_eq!(third.as_ptr(), first_ptr);
        assert_eq!(&third[..], &[3; 64]);
    }
}
