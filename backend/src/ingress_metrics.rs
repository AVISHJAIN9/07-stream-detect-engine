use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Lock-free histogram tracking latencies from 100 ns to 100 ms with microsecond resolution
pub struct LockFreeHistogram {
    // 64 buckets covering power-of-2 / range-indexed nanosecond latency buckets
    buckets: [AtomicU64; 64],
    count: AtomicU64,
    min_nanos: AtomicU64,
    max_nanos: AtomicU64,
    total_nanos: AtomicU64,
}

impl Default for LockFreeHistogram {
    fn default() -> Self {
        Self::new()
    }
}

impl LockFreeHistogram {
    pub fn new() -> Self {
        const INIT_BUCKET: AtomicU64 = AtomicU64::new(0);
        Self {
            buckets: [INIT_BUCKET; 64],
            count: AtomicU64::new(0),
            min_nanos: AtomicU64::new(u64::MAX),
            max_nanos: AtomicU64::new(0),
            total_nanos: AtomicU64::new(0),
        }
    }

    #[inline(always)]
    pub fn record(&self, nanos: u64) {
        let bucket_idx = if nanos == 0 {
            0
        } else {
            std::cmp::min(63, (64 - nanos.leading_zeros()) as usize)
        };

        self.buckets[bucket_idx].fetch_add(1, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
        self.total_nanos.fetch_add(nanos, Ordering::Relaxed);

        // Update min and max with atomic CAS
        let mut cur_min = self.min_nanos.load(Ordering::Relaxed);
        while nanos < cur_min {
            match self.min_nanos.compare_exchange_weak(
                cur_min,
                nanos,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => cur_min = actual,
            }
        }

        let mut cur_max = self.max_nanos.load(Ordering::Relaxed);
        while nanos > cur_max {
            match self.max_nanos.compare_exchange_weak(
                cur_max,
                nanos,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => cur_max = actual,
            }
        }
    }

    pub fn snapshot_percentiles(&self) -> (f64, f64, f64, f64, f64) {
        let total = self.count.load(Ordering::Relaxed);
        if total == 0 {
            return (0.0, 0.0, 0.0, 0.0, 0.0);
        }

        let p50_target = (total as f64 * 0.50) as u64;
        let p90_target = (total as f64 * 0.90) as u64;
        let p99_target = (total as f64 * 0.99) as u64;
        let p999_target = (total as f64 * 0.999) as u64;

        let mut cumulative = 0u64;
        let mut p50 = 0u64;
        let mut p90 = 0u64;
        let mut p99 = 0u64;
        let mut p999 = 0u64;

        for (idx, b) in self.buckets.iter().enumerate() {
            let val = b.load(Ordering::Relaxed);
            cumulative += val;
            let bucket_val = if idx == 0 { 0 } else { 1u64 << (idx - 1) };

            if p50 == 0 && cumulative >= p50_target {
                p50 = bucket_val;
            }
            if p90 == 0 && cumulative >= p90_target {
                p90 = bucket_val;
            }
            if p99 == 0 && cumulative >= p99_target {
                p99 = bucket_val;
            }
            if p999 == 0 && cumulative >= p999_target {
                p999 = bucket_val;
            }
        }

        let mean = (self.total_nanos.load(Ordering::Relaxed) as f64) / (total as f64);

        (
            (p50 as f64) / 1000.0,   // us
            (p90 as f64) / 1000.0,   // us
            (p99 as f64) / 1000.0,   // us
            (p999 as f64) / 1000.0,  // us
            mean / 1000.0,           // us
        )
    }

    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }
}

pub struct IngressMetricsRegistry {
    pub events_received: AtomicU64,
    pub bytes_ingested: AtomicU64,
    pub parse_errors: AtomicU64,
    pub skew_violations: AtomicU64,
    pub dedup_dropped: AtomicU64,
    pub latency_histogram: LockFreeHistogram,
    start_time: Instant,
}

impl Default for IngressMetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl IngressMetricsRegistry {
    pub fn new() -> Self {
        Self {
            events_received: AtomicU64::new(0),
            bytes_ingested: AtomicU64::new(0),
            parse_errors: AtomicU64::new(0),
            skew_violations: AtomicU64::new(0),
            dedup_dropped: AtomicU64::new(0),
            latency_histogram: LockFreeHistogram::new(),
            start_time: Instant::now(),
        }
    }

    #[inline(always)]
    pub fn record_event(&self, bytes: usize, latency_nanos: u64) {
        self.events_received.fetch_add(1, Ordering::Relaxed);
        self.bytes_ingested.fetch_add(bytes as u64, Ordering::Relaxed);
        self.latency_histogram.record(latency_nanos);
    }

    #[inline(always)]
    pub fn record_parse_error(&self) {
        self.parse_errors.fetch_add(1, Ordering::Relaxed);
    }

    #[inline(always)]
    pub fn record_skew_violation(&self) {
        self.skew_violations.fetch_add(1, Ordering::Relaxed);
    }

    #[inline(always)]
    pub fn record_dedup_drop(&self) {
        self.dedup_dropped.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_instantaneous_rates(&self) -> (f64, f64) {
        let elapsed_secs = self.start_time.elapsed().as_secs_f64();
        if elapsed_secs <= 0.0 {
            return (0.0, 0.0);
        }
        let eps = (self.events_received.load(Ordering::Relaxed) as f64) / elapsed_secs;
        let bps = (self.bytes_ingested.load(Ordering::Relaxed) as f64) / elapsed_secs;
        (eps, bps)
    }

    pub fn snapshot_report(&self) -> IngressMetricsSnapshot {
        let (eps, bps) = self.get_instantaneous_rates();
        let (p50, p90, p99, p999, mean) = self.latency_histogram.snapshot_percentiles();

        IngressMetricsSnapshot {
            total_events: self.events_received.load(Ordering::Relaxed),
            total_bytes: self.bytes_ingested.load(Ordering::Relaxed),
            parse_errors: self.parse_errors.load(Ordering::Relaxed),
            skew_violations: self.skew_violations.load(Ordering::Relaxed),
            dedup_dropped: self.dedup_dropped.load(Ordering::Relaxed),
            events_per_sec: eps,
            bytes_per_sec: bps,
            latency_p50_us: p50,
            latency_p90_us: p90,
            latency_p99_us: p99,
            latency_p999_us: p999,
            latency_mean_us: mean,
        }
    }
}

#[derive(Debug, Clone)]
pub struct IngressMetricsSnapshot {
    pub total_events: u64,
    pub total_bytes: u64,
    pub parse_errors: u64,
    pub skew_violations: u64,
    pub dedup_dropped: u64,
    pub events_per_sec: f64,
    pub bytes_per_sec: f64,
    pub latency_p50_us: f64,
    pub latency_p90_us: f64,
    pub latency_p99_us: f64,
    pub latency_p999_us: f64,
    pub latency_mean_us: f64,
}
