use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Memory status returned when evaluating memory allocations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryStatus {
    /// Memory consumption is within normal operating limits (< High Watermark)
    Ok,
    /// Memory consumption exceeded High Watermark (>= 85%); triggers proactive spill
    SpillRequired,
    /// Memory consumption exceeded Critical Watermark (>= 95%); triggers ingress throttling
    Throttle,
}

/// Window Memory Accounting Telemetry
#[derive(Debug, Clone, PartialEq)]
pub struct MemoryManagerStats {
    pub allocated_bytes: usize,
    pub max_memory_limit: usize,
    pub high_watermark_bytes: usize,
    pub critical_watermark_bytes: usize,
    pub total_allocations: u64,
    pub total_deallocations: u64,
    pub spill_triggers: u64,
    pub throttle_triggers: u64,
}

/// Window Memory Accounting & Proactive Spill Pacing Controller
///
/// Tracks heap bytes allocated across active panes, accumulators, and buffers using
/// lock-free atomic counters. Enforces a strict two-tier safety envelope:
///   1. High Watermark (default 85%): enables background disk spilling / compaction
///   2. Critical Watermark (default 95%): stalls ingress via backpressure credit depletion
pub struct WindowMemoryManager {
    allocated_bytes: AtomicUsize,
    max_memory_limit: usize,
    high_watermark_bytes: usize,
    critical_watermark_bytes: usize,

    total_allocations: AtomicU64,
    total_deallocations: AtomicU64,
    spill_triggers: AtomicU64,
    throttle_triggers: AtomicU64,
}

impl WindowMemoryManager {
    pub fn new(max_memory_limit: usize) -> Self {
        assert!(max_memory_limit > 0, "max_memory_limit must be > 0");
        let high_watermark_bytes = (max_memory_limit as f64 * 0.85) as usize;
        let critical_watermark_bytes = (max_memory_limit as f64 * 0.95) as usize;

        Self {
            allocated_bytes: AtomicUsize::new(0),
            max_memory_limit,
            high_watermark_bytes,
            critical_watermark_bytes,
            total_allocations: AtomicU64::new(0),
            total_deallocations: AtomicU64::new(0),
            spill_triggers: AtomicU64::new(0),
            throttle_triggers: AtomicU64::new(0),
        }
    }

    pub fn with_thresholds(
        max_memory_limit: usize,
        high_watermark_fraction: f64,
        critical_watermark_fraction: f64,
    ) -> Self {
        assert!(max_memory_limit > 0);
        assert!(high_watermark_fraction > 0.0 && high_watermark_fraction < 1.0);
        assert!(critical_watermark_fraction > high_watermark_fraction && critical_watermark_fraction <= 1.0);

        let high_watermark_bytes = (max_memory_limit as f64 * high_watermark_fraction) as usize;
        let critical_watermark_bytes = (max_memory_limit as f64 * critical_watermark_fraction) as usize;

        Self {
            allocated_bytes: AtomicUsize::new(0),
            max_memory_limit,
            high_watermark_bytes,
            critical_watermark_bytes,
            total_allocations: AtomicU64::new(0),
            total_deallocations: AtomicU64::new(0),
            spill_triggers: AtomicU64::new(0),
            throttle_triggers: AtomicU64::new(0),
        }
    }

    /// Tracks a new memory allocation and returns the resulting MemoryStatus
    pub fn track_alloc(&self, bytes: usize) -> MemoryStatus {
        let current = self.allocated_bytes.fetch_add(bytes, Ordering::Relaxed) + bytes;
        self.total_allocations.fetch_add(1, Ordering::Relaxed);

        if current >= self.critical_watermark_bytes {
            self.throttle_triggers.fetch_add(1, Ordering::Relaxed);
            MemoryStatus::Throttle
        } else if current >= self.high_watermark_bytes {
            self.spill_triggers.fetch_add(1, Ordering::Relaxed);
            MemoryStatus::SpillRequired
        } else {
            MemoryStatus::Ok
        }
    }

    /// Releases tracked memory
    pub fn track_free(&self, bytes: usize) {
        let mut cur = self.allocated_bytes.load(Ordering::Acquire);
        while cur > 0 {
            let next = cur.saturating_sub(bytes);
            match self.allocated_bytes.compare_exchange_weak(
                cur,
                next,
                Ordering::Release,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.total_deallocations.fetch_add(1, Ordering::Relaxed);
                    break;
                }
                Err(actual) => cur = actual,
            }
        }
    }

    #[inline]
    pub fn current_allocated_bytes(&self) -> usize {
        self.allocated_bytes.load(Ordering::Acquire)
    }

    #[inline]
    pub fn max_memory_limit(&self) -> usize {
        self.max_memory_limit
    }

    #[inline]
    pub fn high_watermark_bytes(&self) -> usize {
        self.high_watermark_bytes
    }

    #[inline]
    pub fn critical_watermark_bytes(&self) -> usize {
        self.critical_watermark_bytes
    }

    pub fn stats(&self) -> MemoryManagerStats {
        MemoryManagerStats {
            allocated_bytes: self.allocated_bytes.load(Ordering::Relaxed),
            max_memory_limit: self.max_memory_limit,
            high_watermark_bytes: self.high_watermark_bytes,
            critical_watermark_bytes: self.critical_watermark_bytes,
            total_allocations: self.total_allocations.load(Ordering::Relaxed),
            total_deallocations: self.total_deallocations.load(Ordering::Relaxed),
            spill_triggers: self.spill_triggers.load(Ordering::Relaxed),
            throttle_triggers: self.throttle_triggers.load(Ordering::Relaxed),
        }
    }
}
