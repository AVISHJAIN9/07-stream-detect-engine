use std::fmt;
use chrono::{DateTime, Utc};
use crate::types::ValueVariant;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimestampErrorKind {
    UnparseableFormat,
    InvalidEpochUnit,
    SkewExceededFuture,
    SkewExceededPast,
    UnsupportedType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimestampError {
    pub kind: TimestampErrorKind,
    pub message: String,
    pub raw_value: String,
}

impl fmt::Display for TimestampError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Timestamp error ({:?}): {} [raw='{}']", self.kind, self.message, self.raw_value)
    }
}

impl std::error::Error for TimestampError {}

pub struct TimestampExtractor {
    max_future_skew_ns: i64,
    max_past_skew_ns: i64,
}

impl TimestampExtractor {
    pub fn new(max_future_skew_secs: i64, max_past_skew_secs: i64) -> Self {
        Self {
            max_future_skew_ns: max_future_skew_secs * 1_000_000_000,
            max_past_skew_ns: max_past_skew_secs * 1_000_000_000,
        }
    }

    pub fn default_extractor() -> Self {
        // Default: max 1 hour future skew, max 7 days past skew
        Self::new(3600, 7 * 86400)
    }

    /// Extracts timestamp and normalizes to Unix epoch nanoseconds
    #[inline(always)]
    pub fn extract_timestamp(&self, field_val: &ValueVariant) -> Result<i64, TimestampError> {
        match field_val {
            ValueVariant::Int(num) => Self::normalize_int_epoch(*num),
            ValueVariant::Float(flt) => Self::normalize_float_epoch(*flt),
            ValueVariant::String(s) => Self::parse_string_timestamp(s.trim()),
            _ => Err(TimestampError {
                kind: TimestampErrorKind::UnsupportedType,
                message: format!("Unsupported timestamp variant: {:?}", field_val),
                raw_value: field_val.to_string(),
            }),
        }
    }

    /// Extracts timestamp and validates clock skew against current system time
    pub fn extract_and_validate_skew(
        &self,
        field_val: &ValueVariant,
        current_sys_ts_ns: i64,
    ) -> Result<i64, TimestampError> {
        let ts_ns = self.extract_timestamp(field_val)?;
        self.validate_skew(ts_ns, current_sys_ts_ns)?;
        Ok(ts_ns)
    }

    pub fn validate_skew(&self, event_ts_ns: i64, current_sys_ts_ns: i64) -> Result<(), TimestampError> {
        let diff = event_ts_ns - current_sys_ts_ns;
        if diff > self.max_future_skew_ns {
            return Err(TimestampError {
                kind: TimestampErrorKind::SkewExceededFuture,
                message: format!(
                    "Event timestamp {} ns is {} ms in the future (max allowed: {} ms)",
                    event_ts_ns,
                    diff / 1_000_000,
                    self.max_future_skew_ns / 1_000_000
                ),
                raw_value: event_ts_ns.to_string(),
            });
        }
        if -diff > self.max_past_skew_ns {
            return Err(TimestampError {
                kind: TimestampErrorKind::SkewExceededPast,
                message: format!(
                    "Event timestamp {} ns is {} ms in the past (max allowed: {} ms)",
                    event_ts_ns,
                    (-diff) / 1_000_000,
                    self.max_past_skew_ns / 1_000_000
                ),
                raw_value: event_ts_ns.to_string(),
            });
        }
        Ok(())
    }

    #[inline(always)]
    fn normalize_int_epoch(n: i64) -> Result<i64, TimestampError> {
        if n < 0 {
            return Err(TimestampError {
                kind: TimestampErrorKind::InvalidEpochUnit,
                message: "Negative epoch timestamps are unsupported".to_string(),
                raw_value: n.to_string(),
            });
        }

        if n >= 1_000_000_000_000_000_000 {
            // Already nanoseconds
            Ok(n)
        } else if n >= 1_000_000_000_000_000 {
            // Microseconds
            Ok(n * 1_000)
        } else if n >= 1_000_000_000_000 {
            // Milliseconds
            Ok(n * 1_000_000)
        } else {
            // Seconds
            Ok(n * 1_000_000_000)
        }
    }

    #[inline(always)]
    fn normalize_float_epoch(f: f64) -> Result<i64, TimestampError> {
        if f < 0.0 {
            return Err(TimestampError {
                kind: TimestampErrorKind::InvalidEpochUnit,
                message: "Negative float epoch timestamps are unsupported".to_string(),
                raw_value: f.to_string(),
            });
        }

        if f >= 1e18 {
            Ok(f as i64)
        } else if f >= 1e15 {
            Ok((f * 1e3) as i64)
        } else if f >= 1e12 {
            Ok((f * 1e6) as i64)
        } else {
            Ok((f * 1e9) as i64)
        }
    }

    /// Zero-allocation fast ISO-8601/RFC-3339 string parser
    pub fn parse_string_timestamp(s: &str) -> Result<i64, TimestampError> {
        let bytes = s.as_bytes();

        // Check if integer string
        if let Ok(num) = s.parse::<i64>() {
            return Self::normalize_int_epoch(num);
        }

        // Fast path for ISO-8601 / RFC-3339 strings (e.g. 2026-10-06T00:20:00.123456789Z or 2026-10-06 00:20:00Z)
        if bytes.len() >= 19 && (bytes[10] == b'T' || bytes[10] == b' ') {
            if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
                return Ok(dt.timestamp_nanos_opt().unwrap_or(dt.timestamp() * 1_000_000_000));
            }
            if let Ok(dt) = s.parse::<DateTime<Utc>>() {
                return Ok(dt.timestamp_nanos_opt().unwrap_or(dt.timestamp() * 1_000_000_000));
            }
        }

        Err(TimestampError {
            kind: TimestampErrorKind::UnparseableFormat,
            message: format!("Failed to parse timestamp string '{}'", s),
            raw_value: s.to_string(),
        })
    }
}
