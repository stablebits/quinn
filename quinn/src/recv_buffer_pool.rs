use bytes::BytesMut;

/// Largest buffer the pool hands out, so that one retained slice pins at most this many bytes
///
/// Datagrams larger than the buffer size bypass the pool. With the default maximum UDP payload
/// size every datagram fits.
const MAX_BUFFER_SIZE: usize = 2048;

/// Upper bound on the memory held by pooled buffers
///
/// Comparable to the receive scratch buffer of an endpoint using segmentation offload. The pool
/// grows on demand and doesn't shrink. Once every buffer is in use and the pool is at this size,
/// datagrams are copied into their own allocations.
const MAX_POOL_BYTES: usize = 4 * 1024 * 1024;

/// Below this many known-free buffers, the pool looks for released buffers whenever it moves to
/// another buffer
const SWEEP_LOW_WATER: usize = 64;

/// Buffers checked per buffer change while few free buffers are known
const SWEEP_STEP: usize = 4;

/// Buffers checked before the pool grows when no free buffer is known
const MAX_SCAN: usize = 64;

/// Recycles small buffers that received datagrams are copied into
///
/// Received datagrams are copied out of the socket's scratch buffer into pooled buffers and handed
/// out as owned slices, one per datagram. Any slice that is still alive (for example stream data
/// the application hasn't read yet, or data it kept after reading) keeps its whole buffer
/// allocated, so the buffer size bounds how much memory a single slice can retain.
///
/// A datagram that fits in the space left in the current buffer is copied right after the
/// previous one, so several small datagrams can share a buffer, while a full-size datagram
/// effectively takes a buffer of its own.
///
/// A buffer can be reused once all slices taken from it have been dropped, which
/// [`BytesMut::try_reclaim`] detects without allocating. Such a buffer stays free until the pool
/// hands it out again, since only the pool creates new slices of it. A sweep over the pooled
/// buffers moves free buffers to a free list, from which new datagrams take buffers no matter how
/// long other buffers stay in use. The pool only grows when no free buffer is found, so after
/// warming up, receiving doesn't allocate.
pub(crate) struct RecvBufferPool {
    buffers: Vec<BytesMut>,
    /// Whether each buffer is in `free`
    in_free: Vec<bool>,
    /// Buffers known to have no slices left
    free: Vec<usize>,
    /// Buffer that datagrams are currently copied into
    current: Option<usize>,
    /// Next buffer the sweep checks
    cursor: usize,
    buffer_size: usize,
    max_buffers: usize,
}

impl RecvBufferPool {
    /// Creates a pool for datagrams of up to `max_datagram_size` bytes
    pub(crate) fn new(max_datagram_size: usize) -> Self {
        let buffer_size = max_datagram_size.clamp(1, MAX_BUFFER_SIZE);
        Self::with_limits(buffer_size, MAX_POOL_BYTES / buffer_size)
    }

    fn with_limits(buffer_size: usize, max_buffers: usize) -> Self {
        Self {
            buffers: Vec::new(),
            in_free: Vec::new(),
            free: Vec::new(),
            current: None,
            cursor: 0,
            buffer_size,
            max_buffers,
        }
    }

    /// Copies `datagram` into a pooled buffer and returns it as an owned slice
    pub(crate) fn copy_from_slice(&mut self, datagram: &[u8]) -> BytesMut {
        if datagram.len() > self.buffer_size || !self.prepare(datagram.len()) {
            return BytesMut::from(datagram);
        }

        let buffer = &mut self.buffers[self.current.expect("prepared above")];
        buffer.extend_from_slice(datagram);
        buffer.split_to(datagram.len())
    }

    /// Points `self.current` at a buffer that can take `len` more bytes
    ///
    /// Returns `false` if no free buffer was found and the pool is at its size limit.
    fn prepare(&mut self, len: usize) -> bool {
        // Pack after the previous datagram, or rewind if all slices have been dropped
        if let Some(index) = self.current
            && self.buffers[index].try_reclaim(len)
        {
            return true;
        }

        if self.free.len() < SWEEP_LOW_WATER {
            self.sweep(SWEEP_STEP);
        }
        if let Some(index) = self.take_free() {
            self.current = Some(index);
            return true;
        }

        self.sweep(MAX_SCAN);
        if let Some(index) = self.take_free() {
            self.current = Some(index);
            return true;
        }

        self.grow()
    }

    /// Checks up to `budget` buffers for ones whose slices have all been dropped
    fn sweep(&mut self, budget: usize) {
        let count = self.buffers.len();
        for _ in 0..budget.min(count) {
            let index = self.cursor;
            self.cursor = (self.cursor + 1) % count;
            if self.current == Some(index) || self.in_free[index] {
                continue;
            }
            if self.buffers[index].try_reclaim(self.buffer_size) {
                self.in_free[index] = true;
                self.free.push(index);
            }
        }
    }

    fn take_free(&mut self) -> Option<usize> {
        let index = self.free.pop()?;
        self.in_free[index] = false;
        Some(index)
    }

    /// Adds a buffer and makes it current, unless the pool is at its size limit
    fn grow(&mut self) -> bool {
        if self.buffers.len() >= self.max_buffers {
            return false;
        }
        self.buffers.push(BytesMut::with_capacity(self.buffer_size));
        self.in_free.push(false);
        self.current = Some(self.buffers.len() - 1);
        true
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

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
        assert_eq!(pool.buffers.len(), 1);
    }

    #[test]
    fn packs_small_datagrams_into_current_buffer() {
        let mut pool = RecvBufferPool::with_limits(1500, 4);
        let first = pool.copy_from_slice(&datagram(1, 100));
        let second = pool.copy_from_slice(&datagram(2, 100));

        assert_eq!(second.as_ptr(), first.as_ptr().wrapping_add(100));
        assert_eq!(&first[..], &datagram(1, 100)[..]);
        assert_eq!(&second[..], &datagram(2, 100)[..]);
        assert_eq!(pool.buffers.len(), 1);
    }

    #[test]
    fn reuses_released_buffer_among_referenced_ones() {
        let mut pool = RecvBufferPool::with_limits(1000, 64);
        let mut held = (0..20)
            .map(|i| pool.copy_from_slice(&datagram(i, 1000)))
            .collect::<Vec<_>>();
        let released = held.remove(10);
        let released_ptr = released.as_ptr();
        drop(released);

        // Every other buffer is still referenced, so the released one is reused
        let reused = pool.copy_from_slice(&datagram(99, 1000));
        assert_eq!(reused.as_ptr(), released_ptr);
        assert_eq!(pool.buffers.len(), 20);

        for (slice, i) in held.iter().zip((0..20u8).filter(|i| *i != 10)) {
            assert_eq!(&slice[..], &datagram(i, 1000)[..]);
        }
    }

    #[test]
    fn falls_back_to_allocation_when_exhausted() {
        let mut pool = RecvBufferPool::with_limits(1000, 2);
        let first = pool.copy_from_slice(&datagram(0, 1000));
        let second = pool.copy_from_slice(&datagram(1, 1000));

        let overflow = pool.copy_from_slice(&datagram(2, 1000));
        assert_eq!(pool.buffers.len(), 2);
        assert_ne!(overflow.as_ptr(), first.as_ptr());
        assert_ne!(overflow.as_ptr(), second.as_ptr());
        assert_eq!(&overflow[..], &datagram(2, 1000)[..]);

        let first_ptr = first.as_ptr();
        drop(first);
        let reused = pool.copy_from_slice(&datagram(3, 1000));
        assert_eq!(reused.as_ptr(), first_ptr);
        assert_eq!(pool.buffers.len(), 2);
    }

    #[test]
    fn oversized_datagrams_bypass_pool() {
        let mut pool = RecvBufferPool::with_limits(1000, 2);
        let large = pool.copy_from_slice(&datagram(1, 1500));
        assert_eq!(&large[..], &datagram(1, 1500)[..]);
        assert!(pool.buffers.is_empty());
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
        assert!(pool.buffers.len() <= 4);
    }

    #[test]
    fn long_held_buffers_dont_grow_pool() {
        let mut pool = RecvBufferPool::with_limits(100, 4096);
        // Long-held buffers, both in a long run and scattered between short-lived ones
        let mut held = (0..3 * MAX_SCAN)
            .map(|i| pool.copy_from_slice(&datagram(i as u8, 100)))
            .collect::<Vec<_>>();
        let mut in_flight = VecDeque::new();
        let mut cycle = |pool: &mut RecvBufferPool, iterations: usize, held: &mut Vec<BytesMut>| {
            for i in 0..iterations {
                let slice = pool.copy_from_slice(&datagram(i as u8, 100));
                if i % 97 == 0 && held.len() < 4 * MAX_SCAN {
                    held.push(slice.clone());
                }
                in_flight.push_back(slice);
                if in_flight.len() > 8 {
                    in_flight.pop_front();
                }
            }
        };

        cycle(&mut pool, 2_000, &mut held);
        let settled = pool.buffers.len();
        assert!(
            settled <= held.len() + 2 * SWEEP_LOW_WATER,
            "pool grew to {settled}"
        );
        cycle(&mut pool, 20_000, &mut held);
        assert!(
            pool.buffers.len() <= settled,
            "pool kept growing: {} > {settled}",
            pool.buffers.len()
        );
    }

    #[test]
    fn default_limits() {
        let pool = RecvBufferPool::new(1472);
        assert_eq!(pool.buffer_size, 1472);
        assert_eq!(pool.max_buffers, MAX_POOL_BYTES / 1472);
        let pool = RecvBufferPool::new(65527);
        assert_eq!(pool.buffer_size, MAX_BUFFER_SIZE);
    }
}
