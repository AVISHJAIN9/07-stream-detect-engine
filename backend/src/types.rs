use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use uuid::Uuid;

/// Monotonic ingestion sequence identifier
pub type SequenceNumber = u64;

/// Epoch timestamp in nanoseconds
pub type TimestampNs = i64;

/// Unique Event UUID
pub type EventId = Uuid;

/// Ingress wire format specification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestFormat {
    /// Newline-delimited JSON
    NdJson,
    /// JSON Array
    JsonArray,
    /// Length-prefixed binary/wire frame
    LengthPrefixed,
    /// Raw single JSON payload
    RawJson,
}

/// W3C Trace Context representation
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TraceContext {
    pub trace_id: String,
    pub span_id: String,
    pub trace_flags: u8,
}

impl TraceContext {
    /// Parse standard W3C `traceparent` header: `00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01`
    pub fn from_traceparent(header: &str) -> Option<Self> {
        let parts: Vec<&str> = header.split('-').collect();
        if parts.len() == 4 && parts[0] == "00" {
            let trace_id = parts[1].to_string();
            let span_id = parts[2].to_string();
            let trace_flags = u8::from_str_radix(parts[3], 16).unwrap_or(0);
            Some(Self {
                trace_id,
                span_id,
                trace_flags,
            })
        } else {
            None
        }
    }

    pub fn to_traceparent(&self) -> String {
        format!("00-{}-{}-{:02x}", self.trace_id, self.span_id, self.trace_flags)
    }
}

/// Dynamic typed value variant for canonical event attributes
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ValueVariant {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
    Bytes(Vec<u8>),
    Array(Vec<ValueVariant>),
    Map(HashMap<String, ValueVariant>),
}

impl fmt::Display for ValueVariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => write!(f, "null"),
            Self::Bool(b) => write!(f, "{}", b),
            Self::Int(i) => write!(f, "{}", i),
            Self::Float(v) => write!(f, "{}", v),
            Self::String(s) => write!(f, "\"{}\"", s),
            Self::Bytes(b) => write!(f, "<bytes:{}b>", b.len()),
            Self::Array(arr) => write!(f, "[{} elements]", arr.len()),
            Self::Map(m) => write!(f, "{{{} keys}}", m.len()),
        }
    }
}

/// Kafka topic and partition identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TopicPartition {
    pub topic: String,
    pub partition: i32,
}

impl TopicPartition {
    pub fn new(topic: impl Into<String>, partition: i32) -> Self {
        Self {
            topic: topic.into(),
            partition,
        }
    }
}

/// Raw message received from Kafka/Redpanda broker
#[derive(Debug, Clone)]
pub struct RawMessage {
    pub topic: String,
    pub partition: i32,
    pub offset: i64,
    pub timestamp_ms: i64,
    pub key: Option<Vec<u8>>,
    pub payload: Vec<u8>,
    pub headers: HashMap<String, Vec<u8>>,
}
