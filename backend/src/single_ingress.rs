use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use crossbeam_channel::{bounded, Receiver, Sender};
use crate::types::{SequenceNumber, TimestampNs, TraceContext};

#[derive(Debug, Clone)]
pub struct IngressRequest {
    pub payload: Vec<u8>,
    pub trace_parent: Option<String>,
    pub client_ip: Option<String>,
}

#[derive(Debug, Clone)]
pub struct QueuedIngressEvent {
    pub sequence_number: SequenceNumber,
    pub arrival_timestamp_ns: TimestampNs,
    pub trace_context: TraceContext,
    pub payload: Vec<u8>,
    pub client_ip: String,
}

#[derive(Debug, Clone)]
pub struct IngressResponse {
    pub sequence_number: SequenceNumber,
    pub arrival_timestamp_ns: TimestampNs,
    pub trace_id: String,
    pub status: IngressStatus,
    pub latency_nanos: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressStatus {
    Accepted,
    RejectedOverloaded,
    MalformedPayload,
}

pub struct SingleEventIngressHandler {
    seq_generator: AtomicU64,
    queue_tx: Sender<QueuedIngressEvent>,
    queue_rx: Receiver<QueuedIngressEvent>,
    total_received: AtomicU64,
    total_accepted: AtomicU64,
    total_rejected: AtomicU64,
}

impl SingleEventIngressHandler {
    pub fn new(capacity: usize) -> Self {
        let (tx, rx) = bounded(capacity);
        Self {
            seq_generator: AtomicU64::new(1),
            queue_tx: tx,
            queue_rx: rx,
            total_received: AtomicU64::new(0),
            total_accepted: AtomicU64::new(0),
            total_rejected: AtomicU64::new(0),
        }
    }

    /// Handles single-event HTTP/gRPC ingress with sub-millisecond nanosecond timestamping & monotonic sequencing
    pub fn handle_ingress(&self, req: IngressRequest) -> IngressResponse {
        let start = Instant::now();
        self.total_received.fetch_add(1, Ordering::Relaxed);

        // Nanosecond arrival timestamp
        let arrival_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);

        // Monotonic sequence number allocation
        let seq = self.seq_generator.fetch_add(1, Ordering::SeqCst);

        // Extract or create W3C trace context
        let trace_ctx = req
            .trace_parent
            .as_deref()
            .and_then(TraceContext::from_traceparent)
            .unwrap_or_else(|| TraceContext {
                trace_id: format!("{:032x}", seq),
                span_id: format!("{:016x}", seq),
                trace_flags: 1,
            });

        let trace_id = trace_ctx.trace_id.clone();
        let client_ip = req.client_ip.unwrap_or_else(|| "127.0.0.1".to_string());

        let queued_event = QueuedIngressEvent {
            sequence_number: seq,
            arrival_timestamp_ns: arrival_ts,
            trace_context: trace_ctx,
            payload: req.payload,
            client_ip,
        };

        let status = match self.queue_tx.try_send(queued_event) {
            Ok(_) => {
                self.total_accepted.fetch_add(1, Ordering::Relaxed);
                IngressStatus::Accepted
            }
            Err(crossbeam_channel::TrySendError::Full(_)) => {
                self.total_rejected.fetch_add(1, Ordering::Relaxed);
                IngressStatus::RejectedOverloaded
            }
            Err(crossbeam_channel::TrySendError::Disconnected(_)) => {
                self.total_rejected.fetch_add(1, Ordering::Relaxed);
                IngressStatus::RejectedOverloaded
            }
        };

        let latency_nanos = start.elapsed().as_nanos() as u64;

        IngressResponse {
            sequence_number: seq,
            arrival_timestamp_ns: arrival_ts,
            trace_id,
            status,
            latency_nanos,
        }
    }

    pub fn receiver(&self) -> Receiver<QueuedIngressEvent> {
        self.queue_rx.clone()
    }

    pub fn stats(&self) -> (u64, u64, u64) {
        (
            self.total_received.load(Ordering::Relaxed),
            self.total_accepted.load(Ordering::Relaxed),
            self.total_rejected.load(Ordering::Relaxed),
        )
    }
}
