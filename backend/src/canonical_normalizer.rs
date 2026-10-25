use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use parking_lot::Mutex;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use crate::types::{EventId, SequenceNumber, TimestampNs, ValueVariant};

#[derive(Debug, Clone, PartialEq)]
pub struct CanonicalEvent {
    pub event_id: EventId,
    pub ingestion_seq: SequenceNumber,
    pub event_timestamp_ns: TimestampNs,
    pub ingress_timestamp_ns: TimestampNs,
    pub event_type: String,
    pub source: String,
    pub entity_id: String,
    pub source_ip: Option<String>,
    pub attributes: HashMap<String, ValueVariant>,
}

impl Default for CanonicalEvent {
    fn default() -> Self {
        Self {
            event_id: Uuid::nil(),
            ingestion_seq: 0,
            event_timestamp_ns: 0,
            ingress_timestamp_ns: 0,
            event_type: String::new(),
            source: String::new(),
            entity_id: String::new(),
            source_ip: None,
            attributes: HashMap::with_capacity(16),
        }
    }
}

impl CanonicalEvent {
    pub fn reset(&mut self) {
        self.event_id = Uuid::nil();
        self.ingestion_seq = 0;
        self.event_timestamp_ns = 0;
        self.ingress_timestamp_ns = 0;
        self.event_type.clear();
        self.source.clear();
        self.entity_id.clear();
        self.source_ip = None;
        self.attributes.clear();
    }
}

/// Thread-safe pre-allocated Object Pool for CanonicalEvent instances
pub struct ObjectPool<T: Default> {
    pool: Mutex<Vec<T>>,
    capacity: usize,
    allocated_count: AtomicU64,
}

impl<T: Default> ObjectPool<T> {
    pub fn new(capacity: usize) -> Self {
        let mut pool = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            pool.push(T::default());
        }
        Self {
            pool: Mutex::new(pool),
            capacity,
            allocated_count: AtomicU64::new(0),
        }
    }

    pub fn acquire(&self) -> T {
        let mut lock = self.pool.lock();
        if let Some(item) = lock.pop() {
            item
        } else {
            self.allocated_count.fetch_add(1, Ordering::Relaxed);
            T::default()
        }
    }

    pub fn release(&self, item: T) {
        let mut lock = self.pool.lock();
        if lock.len() < self.capacity {
            lock.push(item);
        }
    }
}

pub struct CanonicalNormalizer {
    pool: Arc<ObjectPool<CanonicalEvent>>,
    total_normalized: AtomicU64,
}

impl CanonicalNormalizer {
    pub fn new(pool_capacity: usize) -> Self {
        Self {
            pool: Arc::new(ObjectPool::new(pool_capacity)),
            total_normalized: AtomicU64::new(0),
        }
    }

    /// Normalizes raw parsed document attributes into standard CanonicalEvent
    pub fn normalize(
        &self,
        ingestion_seq: SequenceNumber,
        ingress_timestamp_ns: TimestampNs,
        mut raw_fields: HashMap<String, ValueVariant>,
    ) -> Result<CanonicalEvent, String> {
        let mut event = self.pool.acquire();
        event.reset();

        event.ingestion_seq = ingestion_seq;
        event.ingress_timestamp_ns = ingress_timestamp_ns;

        // 1. Extract and normalize event_id (UUID)
        if let Some(id_val) = raw_fields.remove("event_id") {
            match id_val {
                ValueVariant::String(s) => {
                    event.event_id = Uuid::parse_str(s.trim()).unwrap_or_else(|_| Uuid::new_v4());
                }
                _ => {
                    event.event_id = Uuid::new_v4();
                }
            }
        } else {
            event.event_id = Uuid::new_v4();
        }

        // 2. Extract and normalize event_type
        if let Some(et_val) = raw_fields.remove("event_type") {
            if let ValueVariant::String(s) = et_val {
                event.event_type = s.trim().to_lowercase();
            }
        }

        // 3. Extract and normalize source
        if let Some(src_val) = raw_fields.remove("source") {
            if let ValueVariant::String(s) = src_val {
                event.source = s.trim().to_lowercase();
            }
        }

        // 4. Extract and normalize entity_id
        if let Some(ent_val) = raw_fields.remove("entity_id") {
            if let ValueVariant::String(s) = ent_val {
                event.entity_id = s.trim().to_lowercase();
            }
        }

        // 5. Extract and normalize source_ip if present
        if let Some(ip_val) = raw_fields.remove("source_ip").or_else(|| raw_fields.remove("src_ip")) {
            if let ValueVariant::String(s) = ip_val {
                event.source_ip = Some(s.trim().to_lowercase());
            }
        }

        // 6. Flexible Timestamp Normalization into epoch nanoseconds
        if let Some(ts_val) = raw_fields.remove("timestamp").or_else(|| raw_fields.remove("@timestamp")) {
            event.event_timestamp_ns = Self::normalize_timestamp(&ts_val)?;
        } else {
            event.event_timestamp_ns = ingress_timestamp_ns;
        }

        // 7. Store remaining fields in canonical attributes map
        event.attributes = raw_fields;

        self.total_normalized.fetch_add(1, Ordering::Relaxed);
        Ok(event)
    }

    /// Flexible multi-format timestamp parser -> Unix epoch nanoseconds
    pub fn normalize_timestamp(val: &ValueVariant) -> Result<i64, String> {
        match val {
            ValueVariant::Int(num) => {
                let n = *num;
                // Heuristic based on digit magnitude:
                // > 10^17: nanoseconds
                // > 10^14: microseconds
                // > 10^11: milliseconds
                // otherwise: seconds
                if n > 1_000_000_000_000_000_000 {
                    Ok(n) // already nanoseconds
                } else if n > 1_000_000_000_000_000 {
                    Ok(n * 1_000) // microseconds -> nanos
                } else if n > 1_000_000_000_000 {
                    Ok(n * 1_000_000) // milliseconds -> nanos
                } else {
                    Ok(n * 1_000_000_000) // seconds -> nanos
                }
            }
            ValueVariant::Float(f) => {
                let val = *f;
                if val > 1e16 {
                    Ok(val as i64)
                } else if val > 1e13 {
                    Ok((val * 1e3) as i64)
                } else if val > 1e10 {
                    Ok((val * 1e6) as i64)
                } else {
                    Ok((val * 1e9) as i64)
                }
            }
            ValueVariant::String(s) => {
                let s_trimmed = s.trim();
                // 1. Try RFC-3339 / ISO-8601 parsing
                if let Ok(dt) = DateTime::parse_from_rfc3339(s_trimmed) {
                    return Ok(dt.timestamp_nanos_opt().unwrap_or(dt.timestamp() * 1_000_000_000));
                }
                // 2. Try parsing as integer string
                if let Ok(num) = s_trimmed.parse::<i64>() {
                    return Self::normalize_timestamp(&ValueVariant::Int(num));
                }
                // 3. Try parsing as float string
                if let Ok(flt) = s_trimmed.parse::<f64>() {
                    return Self::normalize_timestamp(&ValueVariant::Float(flt));
                }
                // 4. Try standard DateTime<Utc> format
                if let Ok(dt) = s_trimmed.parse::<DateTime<Utc>>() {
                    return Ok(dt.timestamp_nanos_opt().unwrap_or(dt.timestamp() * 1_000_000_000));
                }
                Err(format!("Unparseable timestamp string: '{}'", s_trimmed))
            }
            _ => Err(format!("Invalid timestamp variant type: {:?}", val)),
        }
    }

    pub fn recycle(&self, event: CanonicalEvent) {
        self.pool.release(event);
    }
}
