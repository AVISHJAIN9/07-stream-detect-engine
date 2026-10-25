use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// State Size Limiter Telemetry
#[derive(Debug, Clone, PartialEq)]
pub struct StateLimiterStats {
    pub current_bytes: usize,
    pub max_bytes: usize,
    pub soft_limit_bytes: usize,
    pub hard_limit_bytes: usize,
    pub total_allocations: u64,
    pub shed_events_triggered: u64,
    pub total_bytes_shed: usize,
    pub rejections_count: u64,
}

/// State Size Limits & Memory Pressure Shedding Controller
///
/// Implements two-tier memory boundaries:
///   1. Soft Limit (default 80%): triggers proactive LRU / cold key shedding
///   2. Hard Limit (default 95%): rejects new state allocations to guarantee zero OOM
pub struct StateSizeLimiter {
    current_bytes: AtomicUsize,
    max_bytes: usize,
    soft_limit_bytes: usize,
    hard_limit_bytes: usize,

    total_allocations: AtomicU64,
    shed_events_triggered: AtomicU64,
    total_bytes_shed: AtomicUsize,
    rejections_count: AtomicU64,
}

impl StateSizeLimiter {
    pub fn new(max_bytes: usize) -> Self {
        assert!(max_bytes > 0, "max_bytes must be > 0");
        let soft_limit_bytes = (max_bytes as f64 * 0.80) as usize;
        let hard_limit_bytes = (max_bytes as f64 * 0.95) as usize;

        Self {
            current_bytes: AtomicUsize::new(0),
            max_bytes,
            soft_limit_bytes,
            hard_limit_bytes,
            total_allocations: AtomicU64::new(0),
            shed_events_triggered: AtomicU64::new(0),
            total_bytes_shed: AtomicUsize::new(0),
            rejections_count: AtomicU64::new(0),
        }
    }

    pub fn with_thresholds(
        max_bytes: usize,
        soft_limit_fraction: f64,
        hard_limit_fraction: f64,
    ) -> Self {
        assert!(max_bytes > 0);
        assert!(soft_limit_fraction > 0.0 && soft_limit_fraction < 1.0);
        assert!(hard_limit_fraction > soft_limit_fraction && hard_limit_fraction <= 1.0);

        let soft_limit_bytes = (max_bytes as f64 * soft_limit_fraction) as usize;
        let hard_limit_bytes = (max_bytes as f64 * hard_limit_fraction) as usize;

        Self {
            current_bytes: AtomicUsize::new(0),
            max_bytes,
            soft_limit_bytes,
            hard_limit_bytes,
            total_allocations: AtomicU64::new(0),
            shed_events_triggered: AtomicU64::new(0),
            total_bytes_shed: AtomicUsize::new(0),
            rejections_count: AtomicU64::new(0),
        }
    }

    /// Checks if a requested memory allocation is permitted under the hard limit
    pub fn can_allocate(&self, requested_bytes: usize) -> bool {
        let current = self.current_bytes.load(Ordering::Acquire);
        current + requested_bytes <= self.hard_limit_bytes
    }

    /// Attempts to track an allocation. Errors if exceeding hard limit.
    pub fn track_alloc(&self, bytes: usize) -> Result<(), String> {
        let mut cur = self.current_bytes.load(Ordering::Acquire);
        while cur + bytes <= self.hard_limit_bytes {
            match self.current_bytes.compare_exchange_weak(
                cur,
                cur + bytes,
                Ordering::Release,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.total_allocations.fetch_add(1, Ordering::Relaxed);
                    return Ok(());
                }
                Err(actual) => cur = actual,
            }
        }

        self.rejections_count.fetch_add(1, Ordering::Relaxed);
        Err(format!(
            "Memory allocation rejected: requested {} bytes, current: {} bytes, hard limit: {} bytes",
            bytes, cur, self.hard_limit_bytes
        ))
    }

    /// Releases tracked memory
    pub fn track_free(&self, bytes: usize) {
        let mut cur = self.current_bytes.load(Ordering::Acquire);
        while cur > 0 {
            let next = cur.saturating_sub(bytes);
            match self.current_bytes.compare_exchange_weak(
                cur,
                next,
                Ordering::Release,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(actual) => cur = actual,
            }
        }
    }

    /// Checks if current memory exceeds the soft limit and invokes eviction callback until restored
    pub fn enforce_limits<F>(&self, mut evict_fn: F) -> usize
    where
        F: FnMut(usize) -> usize, // argument: bytes needed to free; returns: bytes actually freed
    {
        let current = self.current_bytes.load(Ordering::Acquire);
        if current <= self.soft_limit_bytes {
            return 0;
        }

        let needed_to_free = current - self.soft_limit_bytes;
        self.shed_events_triggered.fetch_add(1, Ordering::Relaxed);

        let freed = evict_fn(needed_to_free);
        self.track_free(freed);
        self.total_bytes_shed.fetch_add(freed, Ordering::Relaxed);
        freed
    }

    #[inline]
    pub fn current_bytes(&self) -> usize {
        self.current_bytes.load(Ordering::Acquire)
    }

    #[inline]
    pub fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    #[inline]
    pub fn soft_limit_bytes(&self) -> usize {
        self.soft_limit_bytes
    }

    #[inline]
    pub fn hard_limit_bytes(&self) -> usize {
        self.hard_limit_bytes
    }

    pub fn stats(&self) -> StateLimiterStats {
        StateLimiterStats {
            current_bytes: self.current_bytes.load(Ordering::Relaxed),
            max_bytes: self.max_bytes,
            soft_limit_bytes: self.soft_limit_bytes,
            hard_limit_bytes: self.hard_limit_bytes,
            total_allocations: self.total_allocations.load(Ordering::Relaxed),
            shed_events_triggered: self.shed_events_triggered.load(Ordering::Relaxed),
            total_bytes_shed: self.total_bytes_shed.load(Ordering::Relaxed),
            rejections_count: self.rejections_count.load(Ordering::Relaxed),
        }
    }
}
