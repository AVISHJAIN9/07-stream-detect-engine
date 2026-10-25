use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use crossbeam_queue::SegQueue;
use serde::{Deserialize, Serialize};
use crate::dedup_key_generator::Murmur3Hasher64;
use crate::metadata_enricher::IngressContext;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEnvelope {
    pub id: u64,
    pub failure_reason: String,
    pub source_gateway: String,
    pub protocol: String,
    pub timestamp_ns: i64,
    pub origin_hash: u64,
    pub raw_payload: Vec<u8>,
}

pub struct QuarantineManager {
    queue: Arc<SegQueue<QuarantineEnvelope>>,
    seq_gen: AtomicU64,
    total_quarantined: AtomicU64,
    max_memory_records: usize,
}

impl QuarantineManager {
    pub fn new(max_memory_records: usize) -> Self {
        Self {
            queue: Arc::new(SegQueue::new()),
            seq_gen: AtomicU64::new(1),
            total_quarantined: AtomicU64::new(0),
            max_memory_records,
        }
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.max_memory_records
    }

    /// Isolates a malformed or poisoned event into the Quarantine Dead-Letter Queue
    pub fn quarantine(
        &self,
        failure_reason: &str,
        raw_payload: &[u8],
        ctx: &IngressContext,
    ) -> Result<u64, String> {
        let id = self.seq_gen.fetch_add(1, Ordering::Relaxed);
        let now_ns = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);

        // Compute 64-bit cryptographic origin hash
        let mut hasher = Murmur3Hasher64::new(0x42f7c9e1);
        hasher.write_str(failure_reason);
        hasher.write_str(&ctx.gateway_id);
        hasher.write_str(ctx.protocol.as_str());
        hasher.write_bytes(raw_payload);
        let origin_hash = hasher.finish();

        let env = QuarantineEnvelope {
            id,
            failure_reason: failure_reason.to_string(),
            source_gateway: ctx.gateway_id.clone(),
            protocol: ctx.protocol.as_str().to_string(),
            timestamp_ns: now_ns,
            origin_hash,
            raw_payload: raw_payload.to_vec(),
        };

        self.queue.push(env);
        self.total_quarantined.fetch_add(1, Ordering::Relaxed);

        Ok(id)
    }

    /// Drains up to `max_records` from the in-memory quarantine queue for inspection or spillover
    pub fn drain(&self, max_records: usize) -> Vec<QuarantineEnvelope> {
        let mut drained = Vec::with_capacity(std::cmp::min(max_records, self.queue.len()));
        for _ in 0..max_records {
            if let Some(record) = self.queue.pop() {
                drained.push(record);
            } else {
                break;
            }
        }
        drained
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    pub fn total_quarantined(&self) -> u64 {
        self.total_quarantined.load(Ordering::Relaxed)
    }
}
