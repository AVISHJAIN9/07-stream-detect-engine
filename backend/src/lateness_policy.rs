use crate::canonical_normalizer::CanonicalEvent;
use crate::metadata_enricher::{IngressContext, IngressProtocol};
use crate::quarantine_dlq::QuarantineManager;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Classification and routing decision for an event relative to pipeline watermark
#[derive(Debug, Clone, PartialEq)]
pub enum LatenessDecision {
    /// Event arrived on-time (t_event >= watermark)
    OnTime(CanonicalEvent),
    /// Event arrived late but within allowed lateness tolerance (watermark - L <= t_event < watermark)
    /// Triggers window state re-evaluation / accumulation delta emission
    LateWithinTolerance {
        event: CanonicalEvent,
        lateness_ns: i64,
    },
    /// Event arrived past allowed lateness tolerance (t_event < watermark - L)
    /// Dropped and quarantined into Dead-Letter Queue
    LateDropped {
        event: CanonicalEvent,
        lateness_ns: i64,
        quarantine_id: Option<u64>,
    },
}

/// Lateness Policy Manager Telemetry
#[derive(Debug, Clone, PartialEq)]
pub struct LatenessStats {
    pub on_time_count: u64,
    pub late_within_tolerance_count: u64,
    pub late_dropped_count: u64,
    pub allowed_lateness_ns: i64,
}

/// Configurable Allowed Lateness & Late-Event Quarantine Policy Engine
///
/// Implements deterministic two-stage late event handling:
///   1. On-Time: (t_event >= W) -> normal streaming path
///   2. Tolerated Lateness: (W - L <= t_event < W) -> re-evaluates active window state
///   3. Dropped Late: (t_event < W - L) -> isolates into Quarantine DLQ to avoid corruption
pub struct LatenessPolicyManager {
    allowed_lateness_ns: i64,
    quarantine_sink: Option<Arc<QuarantineManager>>,
    on_time_count: AtomicU64,
    late_within_tolerance_count: AtomicU64,
    late_dropped_count: AtomicU64,
}

impl LatenessPolicyManager {
    pub fn new(
        allowed_lateness_ns: i64,
        quarantine_sink: Option<Arc<QuarantineManager>>,
    ) -> Self {
        Self {
            allowed_lateness_ns: allowed_lateness_ns.abs(),
            quarantine_sink,
            on_time_count: AtomicU64::new(0),
            late_within_tolerance_count: AtomicU64::new(0),
            late_dropped_count: AtomicU64::new(0),
        }
    }

    /// Evaluates an event against current watermark and routes according to lateness policy
    pub fn evaluate_event(&self, event: CanonicalEvent, watermark_ns: i64) -> LatenessDecision {
        let ts = event.event_timestamp_ns;

        // 1. On-Time Event
        if ts >= watermark_ns {
            self.on_time_count.fetch_add(1, Ordering::Relaxed);
            return LatenessDecision::OnTime(event);
        }

        let lateness_ns = watermark_ns.saturating_sub(ts);

        // 2. Late but within allowed tolerance
        if ts >= watermark_ns - self.allowed_lateness_ns {
            self.late_within_tolerance_count
                .fetch_add(1, Ordering::Relaxed);
            return LatenessDecision::LateWithinTolerance { event, lateness_ns };
        }

        // 3. Late and exceeded allowed lateness -> Divert to Quarantine DLQ
        self.late_dropped_count.fetch_add(1, Ordering::Relaxed);
        let mut quarantine_id = None;

        if let Some(dlq) = &self.quarantine_sink {
            let payload_str = format!(
                r#"{{"event_id":"{}","event_type":"{}","timestamp_ns":{},"watermark_ns":{},"lateness_ns":{}}}"#,
                event.event_id, event.event_type, ts, watermark_ns, lateness_ns
            );
            let ctx = IngressContext {
                client_ip: event.source_ip.clone().or_else(|| Some("127.0.0.1".to_string())),
                gateway_id: format!("lateness_gate_{}", event.source),
                protocol: IngressProtocol::RestHttp,
                client_tls_cipher: None,
            };
            if let Ok(qid) = dlq.quarantine(
                "LateEventExceededAllowedLateness",
                payload_str.as_bytes(),
                &ctx,
            ) {
                quarantine_id = Some(qid);
            }
        }

        LatenessDecision::LateDropped {
            event,
            lateness_ns,
            quarantine_id,
        }
    }

    #[inline]
    pub fn allowed_lateness_ns(&self) -> i64 {
        self.allowed_lateness_ns
    }

    pub fn stats(&self) -> LatenessStats {
        LatenessStats {
            on_time_count: self.on_time_count.load(Ordering::Relaxed),
            late_within_tolerance_count: self.late_within_tolerance_count.load(Ordering::Relaxed),
            late_dropped_count: self.late_dropped_count.load(Ordering::Relaxed),
            allowed_lateness_ns: self.allowed_lateness_ns,
        }
    }
}
