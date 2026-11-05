use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::BytesMut;
use tracing::info;

use crate::{Duration, Instant};

/// How often pool statistics are logged
const STATS_INTERVAL: Duration = Duration::from_secs(1);

/// Number of datagrams between checks whether [`STATS_INTERVAL`] has passed
const STATS_CHECK_EVERY: u64 = 4096;

/// Source of the numbers that tell pools of different endpoints apart in the logs
static NEXT_POOL_ID: AtomicUsize = AtomicUsize::new(0);

/// Largest buffer the pool hands out, so that one retained slice pins at most this many bytes
///
/// Datagrams larger than the buffer size bypass the pool. With the default maximum UDP payload
/// size every datagram fits.
const MAX_BUFFER_SIZE: usize = 2048;

/// Upper bound on the memory held by pooled buffers
///
/// Once every pooled buffer is in use and the pool is at this size, datagrams fall back to
/// individual allocations.
const MAX_POOL_BYTES: usize = 256 * 1024 * 1024;

/// Number of buffers the pool keeps even when they are idle
const MIN_BUFFERS: usize = 64;

/// Below this many known-free buffers, the sweep checks [`SWEEP_STEP`] buffers per buffer change
/// instead of one
const SWEEP_LOW_WATER: usize = 64;

/// Buffers checked per buffer change while few free buffers are known
const SWEEP_STEP: usize = 4;

/// Buffers checked before the pool grows when no free buffer is known
const MAX_SCAN: usize = 64;

/// Recycles small receive buffers so that each received datagram is backed by a buffer of at most
/// one datagram's size
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
/// buffers therefore moves free buffers to a free list, from which new datagrams take buffers
/// regardless of how long other buffers stay in use. The sweep advances a little every time the
/// current buffer is full, and faster while few free buffers are known.
///
/// The pool grows when no free buffer is found, up to [`MAX_POOL_BYTES`], and releases free
/// buffers again while more than a quarter of them are known to be free, so that it doesn't keep
/// the memory of a burst. After warming up, receiving therefore doesn't allocate.
pub(crate) struct RecvBufferPool {
    /// Pooled buffers; `None` marks a slot whose buffer was released when the pool shrank
    slots: Vec<Option<BytesMut>>,
    /// Whether each slot is in `free`
    in_free: Vec<bool>,
    /// Slots whose buffers are known to have no slices left
    free: Vec<usize>,
    /// Empty slots, reused when the pool grows
    vacant: Vec<usize>,
    /// Slot that datagrams are currently copied into
    current: Option<usize>,
    /// Next slot the sweep checks
    cursor: usize,
    /// Number of allocated buffers
    live: usize,
    buffer_size: usize,
    max_buffers: usize,
    stats: PoolStats,
}

/// Counters logged every [`STATS_INTERVAL`] while datagrams are received, and when the pool is
/// dropped
#[derive(Default)]
struct PoolStats {
    /// Number identifying the pool in the logs
    id: usize,
    /// Datagrams copied
    copies: u64,
    /// Datagrams larger than the buffer size, copied into their own allocation
    oversized: u64,
    /// Datagrams copied into their own allocation because the pool was exhausted
    exhausted: u64,
    /// Buffers allocated
    grown: u64,
    /// Buffers released
    shrunk: u64,
    /// Largest number of allocated buffers
    high_water: usize,
    last_report: Option<Instant>,
}

impl RecvBufferPool {
    /// Creates a pool for datagrams of up to `max_datagram_size` bytes
    pub(crate) fn new(max_datagram_size: usize) -> Self {
        let buffer_size = max_datagram_size.min(MAX_BUFFER_SIZE);
        Self::with_limits(buffer_size, MAX_POOL_BYTES / buffer_size.max(1))
    }

    fn with_limits(buffer_size: usize, max_buffers: usize) -> Self {
        Self {
            slots: Vec::new(),
            in_free: Vec::new(),
            free: Vec::new(),
            vacant: Vec::new(),
            current: None,
            cursor: 0,
            live: 0,
            buffer_size,
            max_buffers,
            stats: PoolStats {
                id: NEXT_POOL_ID.fetch_add(1, Ordering::Relaxed),
                ..PoolStats::default()
            },
        }
    }

    /// Copies `datagram` into a pooled buffer and returns it as an owned slice
    pub(crate) fn copy_from_slice(&mut self, datagram: &[u8]) -> BytesMut {
        self.stats.copies += 1;
        if self.stats.copies % STATS_CHECK_EVERY == 0 {
            self.maybe_report_stats();
        }

        if datagram.len() > self.buffer_size {
            self.stats.oversized += 1;
            return BytesMut::from(datagram);
        }
        if !self.prepare(datagram.len()) {
            self.stats.exhausted += 1;
            return BytesMut::from(datagram);
        }

        let index = self.current.expect("prepared above");
        let buffer = self.slots[index]
            .as_mut()
            .expect("current slot holds a buffer");
        buffer.extend_from_slice(datagram);
        buffer.split_to(datagram.len())
    }

    /// Points `self.current` at a buffer that can take `len` more bytes
    ///
    /// Returns `false` if no free buffer was found and the pool is at its size limit, in which
    /// case the caller allocates instead.
    fn prepare(&mut self, len: usize) -> bool {
        if let Some(index) = self.current {
            let buffer = self.slots[index]
                .as_ref()
                .expect("current slot holds a buffer");
            // Pack after the previous datagram
            if buffer.capacity() - buffer.len() >= len {
                return true;
            }
        }

        self.maintain();

        if let Some(index) = self.current {
            let buffer = self.slots[index]
                .as_mut()
                .expect("current slot holds a buffer");
            // Rewind the current buffer if its slices have all been dropped
            if buffer.try_reclaim(len) {
                return true;
            }
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

    /// Advances the sweep and releases a surplus free buffer, once per buffer change
    fn maintain(&mut self) {
        let step = match self.free.len() < SWEEP_LOW_WATER {
            true => SWEEP_STEP,
            false => 1,
        };
        self.sweep(step);

        if self.live > MIN_BUFFERS && self.free.len() * 4 > self.live {
            if let Some(index) = self.take_free() {
                self.slots[index] = None;
                self.vacant.push(index);
                self.live -= 1;
                self.stats.shrunk += 1;
            }
        }
    }

    /// Checks up to `budget` slots for buffers whose slices have all been dropped
    fn sweep(&mut self, budget: usize) {
        let count = self.slots.len();
        for _ in 0..budget.min(count) {
            let index = self.cursor;
            self.cursor = (self.cursor + 1) % count;
            if self.current == Some(index) || self.in_free[index] {
                continue;
            }
            let Some(buffer) = self.slots[index].as_mut() else {
                continue;
            };
            if buffer.try_reclaim(self.buffer_size) {
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
        if self.live >= self.max_buffers {
            return false;
        }

        let buffer = Some(BytesMut::with_capacity(self.buffer_size));
        let index = match self.vacant.pop() {
            Some(index) => {
                self.slots[index] = buffer;
                index
            }
            None => {
                self.slots.push(buffer);
                self.in_free.push(false);
                self.slots.len() - 1
            }
        };
        self.live += 1;
        self.current = Some(index);
        self.stats.grown += 1;
        self.stats.high_water = self.stats.high_water.max(self.live);
        true
    }

    /// Logs the counters if [`STATS_INTERVAL`] has passed since the last report
    fn maybe_report_stats(&mut self) {
        let now = Instant::now();
        if self
            .stats
            .last_report
            .is_some_and(|last| now.duration_since(last) < STATS_INTERVAL)
        {
            return;
        }
        self.stats.last_report = Some(now);
        self.report_stats("receive buffer pool");
    }

    fn report_stats(&self, message: &str) {
        let stats = &self.stats;
        info!(
            target: "quinn_recv_pool",
            pool = stats.id,
            buffers = self.live,
            buffer_bytes = self.live * self.buffer_size,
            high_water = stats.high_water,
            known_free = self.free.len(),
            copies = stats.copies,
            exhausted = stats.exhausted,
            oversized = stats.oversized,
            grown = stats.grown,
            shrunk = stats.shrunk,
            "{message}"
        );
    }

    /// Number of allocated buffers
    #[cfg(test)]
    fn len(&self) -> usize {
        self.live
    }
}

impl Drop for RecvBufferPool {
    fn drop(&mut self) {
        if self.stats.copies > 0 {
            self.report_stats("receive buffer pool dropped");
        }
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
        assert_eq!(pool.len(), 20);

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
        let settled = pool.len();
        assert!(
            settled <= held.len() + 2 * MIN_BUFFERS,
            "pool grew to {settled}"
        );
        cycle(&mut pool, 20_000, &mut held);
        assert!(
            pool.len() <= settled,
            "pool kept growing: {} > {settled}",
            pool.len()
        );
    }

    #[test]
    fn shrinks_after_burst() {
        let mut pool = RecvBufferPool::with_limits(100, 4096);
        let burst = (0..2_000)
            .map(|i| pool.copy_from_slice(&datagram(i as u8, 100)))
            .collect::<Vec<_>>();
        assert_eq!(pool.len(), 2_000);
        drop(burst);

        for i in 0..20_000 {
            drop(pool.copy_from_slice(&datagram(i as u8, 100)));
        }
        assert!(
            pool.len() <= 2 * MIN_BUFFERS,
            "pool kept {} buffers",
            pool.len()
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
