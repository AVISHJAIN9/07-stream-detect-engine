use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

/// Typed Watermark Representation
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Watermark {
    pub timestamp_ns: i64,
}

impl Watermark {
    pub fn new(timestamp_ns: i64) -> Self {
        Self { timestamp_ns }
    }
}

/// Generator Telemetry & Progression Snapshot
#[derive(Debug, Clone, PartialEq)]
pub struct WatermarkStats {
    pub max_timestamp_seen: i64,
    pub current_watermark: i64,
    pub total_watermarks_emitted: u64,
    pub idle_punctuations: u64,
}

/// Monotonic Bounded-Out-Of-Order Watermark Generator
///
/// Implements bounded-out-of-orderness heuristic watermarking:
///   W(t) = max(t_seen) - delta
/// Guarantees strict monotonicity (W_{n+1} >= W_n) while providing punctuated ticks
/// during idle stream periods to prevent downstream window stalling.
pub struct BoundedOutOfOrderWatermarkGenerator {
    out_of_orderness_ns: i64,
    idle_timeout_ns: i64,
    max_timestamp_seen: AtomicI64,
    last_emitted_watermark: AtomicI64,
    last_event_sys_time_ns: AtomicI64,
    total_watermarks_emitted: AtomicU64,
    idle_punctuations: AtomicU64,
}

impl BoundedOutOfOrderWatermarkGenerator {
    pub fn new(out_of_orderness_ns: i64, idle_timeout_ns: i64) -> Self {
        Self {
            out_of_orderness_ns: out_of_orderness_ns.abs(),
            idle_timeout_ns: idle_timeout_ns.abs(),
            max_timestamp_seen: AtomicI64::new(i64::MIN),
            last_emitted_watermark: AtomicI64::new(i64::MIN),
            last_event_sys_time_ns: AtomicI64::new(0),
            total_watermarks_emitted: AtomicU64::new(0),
            idle_punctuations: AtomicU64::new(0),
        }
    }

    /// Evaluates an event arrival timestamp and returns an updated watermark if advanced
    pub fn on_event(&self, event_timestamp_ns: i64, current_sys_time_ns: i64) -> Option<Watermark> {
        self.last_event_sys_time_ns
            .store(current_sys_time_ns, Ordering::Release);

        // Monotonically update max_timestamp_seen via CAS loop
        let mut cur_max = self.max_timestamp_seen.load(Ordering::Acquire);
        while event_timestamp_ns > cur_max {
            match self.max_timestamp_seen.compare_exchange_weak(
                cur_max,
                event_timestamp_ns,
                Ordering::Release,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    cur_max = event_timestamp_ns;
                    break;
                }
                Err(actual) => cur_max = actual,
            }
        }

        // Candidate watermark W = max_seen - delta
        let candidate_wm = cur_max.saturating_sub(self.out_of_orderness_ns);

        // Monotonically advance last_emitted_watermark
        let mut last_wm = self.last_emitted_watermark.load(Ordering::Acquire);
        while candidate_wm > last_wm {
            match self.last_emitted_watermark.compare_exchange_weak(
                last_wm,
                candidate_wm,
                Ordering::Release,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.total_watermarks_emitted.fetch_add(1, Ordering::Relaxed);
                    return Some(Watermark::new(candidate_wm));
                }
                Err(actual) => last_wm = actual,
            }
        }

        None
    }

    /// Periodic background tick to inject punctuated watermarks when stream is idle
    pub fn on_periodic_check(&self, current_sys_time_ns: i64) -> Option<Watermark> {
        let last_sys = self.last_event_sys_time_ns.load(Ordering::Acquire);
        if last_sys == 0 {
            return None;
        }

        let idle_delta = current_sys_time_ns.saturating_sub(last_sys);
        if idle_delta >= self.idle_timeout_ns {
            let max_seen = self.max_timestamp_seen.load(Ordering::Acquire);
            if max_seen == i64::MIN {
                return None;
            }

            let candidate_wm = max_seen.saturating_sub(self.out_of_orderness_ns);
            let mut last_wm = self.last_emitted_watermark.load(Ordering::Acquire);

            if candidate_wm > last_wm {
                while candidate_wm > last_wm {
                    match self.last_emitted_watermark.compare_exchange_weak(
                        last_wm,
                        candidate_wm,
                        Ordering::Release,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => {
                            self.idle_punctuations.fetch_add(1, Ordering::Relaxed);
                            self.total_watermarks_emitted.fetch_add(1, Ordering::Relaxed);
                            return Some(Watermark::new(candidate_wm));
                        }
                        Err(actual) => last_wm = actual,
                    }
                }
            }
        }

        None
    }

    #[inline]
    pub fn current_watermark(&self) -> i64 {
        self.last_emitted_watermark.load(Ordering::Acquire)
    }

    #[inline]
    pub fn max_timestamp_seen(&self) -> i64 {
        self.max_timestamp_seen.load(Ordering::Acquire)
    }

    #[inline]
    pub fn out_of_orderness_ns(&self) -> i64 {
        self.out_of_orderness_ns
    }

    pub fn stats(&self) -> WatermarkStats {
        WatermarkStats {
            max_timestamp_seen: self.max_timestamp_seen.load(Ordering::Relaxed),
            current_watermark: self.last_emitted_watermark.load(Ordering::Relaxed),
            total_watermarks_emitted: self.total_watermarks_emitted.load(Ordering::Relaxed),
            idle_punctuations: self.idle_punctuations.load(Ordering::Relaxed),
        }
    }
}
