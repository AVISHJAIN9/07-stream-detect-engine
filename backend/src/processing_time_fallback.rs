use crate::canonical_normalizer::CanonicalEvent;
use crate::types::ValueVariant;
use std::sync::atomic::{AtomicU64, Ordering};

/// Policy governing fallback when event timestamps are corrupt, missing, or skew-violating
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FallbackPolicy {
    /// Use Ingress Timestamp if present (> 0), otherwise use System Monotonic Wall-Clock
    UseIngressTimeOrSystem,
    /// Strictly use System Monotonic Wall-Clock
    UseSystemTime,
    /// Strictly use Ingress Timestamp (errors if ingress time <= 0)
    StrictIngressTime,
    /// Reject event and raise error
    Reject,
}

/// Fallback Gate Performance & Data Quality Telemetry
#[derive(Debug, Clone, PartialEq)]
pub struct FallbackStats {
    pub valid_timestamps: u64,
    pub fallback_events: u64,
    pub zero_timestamps: u64,
    pub skew_violations: u64,
    pub fallback_rate: f64,
}

/// Dynamic Ingestion/Processing-Time Fallback Gate
///
/// Validates incoming record event timestamps against maximum allowed clock skew bounds.
/// When timestamps are absent (<= 0), unparseable, or exceed skew tolerances, seamlessly
/// fails over to ingestion or system processing time with sub-10 microsecond latency,
/// marking provenance metadata to maintain downstream data lineage.
pub struct FallbackTimeGate {
    max_skew_ns: i64,
    fallback_policy: FallbackPolicy,
    valid_timestamps: AtomicU64,
    fallback_count: AtomicU64,
    zero_timestamp_count: AtomicU64,
    skew_violation_count: AtomicU64,
}

impl FallbackTimeGate {
    pub fn new(max_skew_ns: i64, fallback_policy: FallbackPolicy) -> Self {
        Self {
            max_skew_ns: max_skew_ns.abs(),
            fallback_policy,
            valid_timestamps: AtomicU64::new(0),
            fallback_count: AtomicU64::new(0),
            zero_timestamp_count: AtomicU64::new(0),
            skew_violation_count: AtomicU64::new(0),
        }
    }

    /// Resolves and validates the event timestamp, applying fallback policies if required
    pub fn resolve_timestamp(
        &self,
        event: &mut CanonicalEvent,
        sys_time_ns: i64,
    ) -> Result<i64, String> {
        let orig_ts = event.event_timestamp_ns;

        // 1. Check for zero / missing timestamp
        if orig_ts <= 0 {
            self.zero_timestamp_count.fetch_add(1, Ordering::Relaxed);
            return self.apply_fallback(event, orig_ts, sys_time_ns, "ZeroOrMissingTimestamp");
        }

        // 2. Check for clock skew violation
        let skew = (orig_ts - sys_time_ns).abs();
        if skew > self.max_skew_ns {
            self.skew_violation_count.fetch_add(1, Ordering::Relaxed);
            return self.apply_fallback(event, orig_ts, sys_time_ns, "ClockSkewExceeded");
        }

        // 3. Valid event timestamp
        self.valid_timestamps.fetch_add(1, Ordering::Relaxed);
        Ok(orig_ts)
    }

    fn apply_fallback(
        &self,
        event: &mut CanonicalEvent,
        original_ts: i64,
        sys_time_ns: i64,
        reason: &str,
    ) -> Result<i64, String> {
        self.fallback_count.fetch_add(1, Ordering::Relaxed);

        let resolved_ts = match self.fallback_policy {
            FallbackPolicy::UseIngressTimeOrSystem => {
                if event.ingress_timestamp_ns > 0 {
                    event.ingress_timestamp_ns
                } else {
                    sys_time_ns
                }
            }
            FallbackPolicy::UseSystemTime => sys_time_ns,
            FallbackPolicy::StrictIngressTime => {
                if event.ingress_timestamp_ns > 0 {
                    event.ingress_timestamp_ns
                } else {
                    return Err("StrictIngressTime policy failed: ingress timestamp is 0".to_string());
                }
            }
            FallbackPolicy::Reject => {
                return Err(format!(
                    "Timestamp validation rejected: reason={}, original_ts={}, max_skew_ns={}",
                    reason, original_ts, self.max_skew_ns
                ));
            }
        };

        // Annotate event with provenance flags
        event.event_timestamp_ns = resolved_ts;
        event
            .attributes
            .insert("fallback_processing_time".to_string(), ValueVariant::Bool(true));
        event.attributes.insert(
            "fallback_reason".to_string(),
            ValueVariant::String(reason.to_string()),
        );
        event.attributes.insert(
            "original_event_timestamp_ns".to_string(),
            ValueVariant::Int(original_ts),
        );

        Ok(resolved_ts)
    }

    /// Fetches cumulative fallback statistics
    pub fn stats(&self) -> FallbackStats {
        let valid = self.valid_timestamps.load(Ordering::Relaxed);
        let fallback = self.fallback_count.load(Ordering::Relaxed);
        let zero = self.zero_timestamp_count.load(Ordering::Relaxed);
        let skew = self.skew_violation_count.load(Ordering::Relaxed);
        let total = valid + fallback;
        let rate = if total > 0 {
            fallback as f64 / total as f64
        } else {
            0.0
        };

        FallbackStats {
            valid_timestamps: valid,
            fallback_events: fallback,
            zero_timestamps: zero,
            skew_violations: skew,
            fallback_rate: rate,
        }
    }

    #[inline]
    pub fn max_skew_ns(&self) -> i64 {
        self.max_skew_ns
    }
}
