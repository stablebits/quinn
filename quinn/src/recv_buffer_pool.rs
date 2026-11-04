use bytes::BytesMut;

/// Largest buffer the pool hands out, so that one retained slice pins at most this many bytes
///
/// Datagrams larger than the buffer size bypass the pool. With the default maximum UDP payload
/// size every datagram fits.
const MAX_BUFFER_SIZE: usize = 2048;

/// Upper bound on the number of pooled buffers
///
/// Once every pooled buffer is in use and the pool is at this size, datagrams fall back to
/// individual allocations. The pool doesn't shrink, so this also bounds the memory it keeps
/// after a burst.
const MAX_BUFFERS: usize = 4096;

/// Maximum number of buffers checked for reuse per datagram
const MAX_PROBES: usize = 32;

/// Recycles small receive buffers so that each received datagram is backed by a buffer of at most
/// one datagram's size
///
/// Received datagrams are copied out of the socket's scratch buffer into pooled buffers and handed
/// out as owned slices, one per datagram. Any slice that is still alive (for example stream data
/// the application hasn't read yet) keeps its whole buffer allocated, so the buffer size bounds
/// how much memory a single slice can retain.
///
/// A datagram that fits in the space left in the current buffer is copied right after the
/// previous one, so several small datagrams can share a buffer, while a full-size datagram
/// effectively takes a buffer of its own. Sharing never needs more buffers than giving each
/// datagram its own: a retained slice still pins a single buffer, and the datagrams next to it use
/// space that is pinned anyway.
///
/// Buffers are reused in ring order, which is also the order they were filled in, so the buffer
/// after the current one is the one filled longest ago and usually no longer referenced. A buffer
/// is reused once all slices taken from it have been dropped, which [`BytesMut::try_reclaim`]
/// detects without allocating. Buffers that are still referenced keep their place in the ring and
/// are skipped. After warming up, receiving therefore doesn't allocate.
pub(crate) struct RecvBufferPool {
    /// Pooled buffers, reused in ring order
    buffers: Vec<BytesMut>,
    /// Index of the buffer datagrams are currently copied into, if `buffers` isn't empty
    current: usize,
    /// Number of consecutive buffers found in use since a buffer was last reused or added
    busy_streak: usize,
    buffer_size: usize,
    max_buffers: usize,
}

impl RecvBufferPool {
    /// Creates a pool for datagrams of up to `max_datagram_size` bytes
    pub(crate) fn new(max_datagram_size: usize) -> Self {
        Self::with_limits(max_datagram_size.min(MAX_BUFFER_SIZE), MAX_BUFFERS)
    }

    fn with_limits(buffer_size: usize, max_buffers: usize) -> Self {
        Self {
            buffers: Vec::new(),
            current: 0,
            busy_streak: 0,
            buffer_size,
            max_buffers,
        }
    }

    /// Copies `datagram` into a pooled buffer and returns it as an owned slice
    pub(crate) fn copy_from_slice(&mut self, datagram: &[u8]) -> BytesMut {
        if datagram.len() > self.buffer_size || !self.prepare(datagram.len()) {
            return BytesMut::from(datagram);
        }

        let buffer = &mut self.buffers[self.current];
        buffer.extend_from_slice(datagram);
        buffer.split_to(datagram.len())
    }

    /// Points `self.current` at a buffer that can take `len` more bytes
    ///
    /// Returns `false` if no such buffer was found and the pool shouldn't grow, in which case the
    /// caller allocates instead.
    fn prepare(&mut self, len: usize) -> bool {
        let count = self.buffers.len();
        // Keep packing into the current buffer, or rewind it if its slices have all been dropped
        if count > 0 && self.buffers[self.current].try_reclaim(len) {
            self.busy_streak = 0;
            return true;
        }

        for _ in 0..count.min(MAX_PROBES) {
            self.current = (self.current + 1) % count;
            if self.buffers[self.current].try_reclaim(len) {
                self.busy_streak = 0;
                return true;
            }
            self.busy_streak += 1;
        }

        // Grow only once a full pass over the ring found every buffer in use. Until then, long
        // runs of buffers held by unread data just cost this datagram its own allocation, and the
        // next call resumes the pass where this one stopped.
        if self.busy_streak < count || count == self.max_buffers {
            return false;
        }

        // Grow geometrically so that a burst needs few full passes
        let added = (count / 8).clamp(1, self.max_buffers - count);
        let index = if count == 0 { 0 } else { self.current + 1 };
        let new_buffers = (0..added).map(|_| BytesMut::with_capacity(self.buffer_size));
        self.buffers.splice(index..index, new_buffers);
        self.current = index;
        self.busy_streak = 0;
        true
    }

    /// Number of pooled buffers
    #[cfg(test)]
    fn len(&self) -> usize {
        self.buffers.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn datagram(byte: u8, len: usize) -> Vec<u8> {
        vec![byte; len]
    }

    #[test]
    fn reuses_buffer_after_slices_are_dropped() {
        let mut pool = RecvBufferPool::with_limits(1500, 4);
        let first = pool.copy_from_slice(&datagram(1, 1200));
        let first_ptr = first.as_ptr();
        drop(first);

        let second = pool.copy_from_slice(&datagram(2, 1200));
        assert_eq!(second.as_ptr(), first_ptr);
        assert_eq!(&second[..], &datagram(2, 1200)[..]);
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn packs_small_datagrams_into_current_buffer() {
        let mut pool = RecvBufferPool::with_limits(1500, 4);
        let first = pool.copy_from_slice(&datagram(1, 100));
        let second = pool.copy_from_slice(&datagram(2, 100));

        assert_eq!(second.as_ptr(), first.as_ptr().wrapping_add(100));
        assert_eq!(&first[..], &datagram(1, 100)[..]);
        assert_eq!(&second[..], &datagram(2, 100)[..]);
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn skips_buffers_that_are_still_referenced() {
        let mut pool = RecvBufferPool::with_limits(1000, 8);
        let kept_first = pool.copy_from_slice(&datagram(0, 1000));
        let released = pool.copy_from_slice(&datagram(1, 1000));
        let kept_last = pool.copy_from_slice(&datagram(2, 1000));
        let released_ptr = released.as_ptr();
        drop(released);

        // The current and the oldest buffer are still referenced, so the middle one is reused
        let reused = pool.copy_from_slice(&datagram(3, 1000));
        assert_eq!(reused.as_ptr(), released_ptr);
        assert_eq!(pool.len(), 3);

        assert_eq!(&kept_first[..], &datagram(0, 1000)[..]);
        assert_eq!(&kept_last[..], &datagram(2, 1000)[..]);
        assert_eq!(&reused[..], &datagram(3, 1000)[..]);
    }

    #[test]
    fn falls_back_to_allocation_when_exhausted() {
        let mut pool = RecvBufferPool::with_limits(1000, 2);
        let first = pool.copy_from_slice(&datagram(0, 1000));
        let second = pool.copy_from_slice(&datagram(1, 1000));

        let overflow = pool.copy_from_slice(&datagram(2, 1000));
        assert_eq!(pool.len(), 2);
        assert_ne!(overflow.as_ptr(), first.as_ptr());
        assert_ne!(overflow.as_ptr(), second.as_ptr());
        assert_eq!(&overflow[..], &datagram(2, 1000)[..]);

        let first_ptr = first.as_ptr();
        drop(first);
        let reused = pool.copy_from_slice(&datagram(3, 1000));
        assert_eq!(reused.as_ptr(), first_ptr);
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn oversized_datagrams_bypass_pool() {
        let mut pool = RecvBufferPool::with_limits(1000, 2);
        let large = pool.copy_from_slice(&datagram(1, 1500));
        assert_eq!(&large[..], &datagram(1, 1500)[..]);
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn retained_slice_is_never_overwritten() {
        let mut pool = RecvBufferPool::with_limits(1000, 4);
        let retained = pool.copy_from_slice(&datagram(7, 600));
        for i in 0..100u8 {
            let len = 100 + usize::from(i) * 9;
            let slice = pool.copy_from_slice(&datagram(i, len));
            assert_eq!(&slice[..], &datagram(i, len)[..]);
        }
        assert_eq!(&retained[..], &datagram(7, 600)[..]);
        assert!(pool.len() <= 4);
    }

    #[test]
    fn long_held_buffers_dont_grow_pool() {
        let mut pool = RecvBufferPool::with_limits(100, 1024);
        // A run of long-held buffers longer than a single call probes
        let held = (0..3 * MAX_PROBES)
            .map(|i| pool.copy_from_slice(&datagram(i as u8, 100)))
            .collect::<Vec<_>>();

        let mut in_flight = std::collections::VecDeque::new();
        let mut cycle = |pool: &mut RecvBufferPool, iterations: usize| {
            for i in 0..iterations {
                in_flight.push_back(pool.copy_from_slice(&datagram(i as u8, 100)));
                if in_flight.len() > 4 {
                    in_flight.pop_front();
                }
            }
        };

        cycle(&mut pool, 1_000);
        let settled = pool.len();
        assert!(settled <= held.len() * 9 / 8 + 8, "pool grew to {settled}");
        cycle(&mut pool, 10_000);
        assert_eq!(pool.len(), settled);

        for (i, slice) in held.iter().enumerate() {
            assert_eq!(&slice[..], &datagram(i as u8, 100)[..]);
        }
    }

    #[test]
    fn default_limits() {
        let pool = RecvBufferPool::new(1472);
        assert_eq!(pool.buffer_size, 1472);
        let pool = RecvBufferPool::new(65527);
        assert_eq!(pool.buffer_size, MAX_BUFFER_SIZE);
        assert_eq!(pool.max_buffers, MAX_BUFFERS);
    }
}
