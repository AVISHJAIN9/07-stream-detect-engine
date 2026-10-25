use crate::canonical_normalizer::CanonicalEvent;
use parking_lot::RwLock;
use std::collections::BTreeMap;

/// Single Tumbling Window Accumulator
#[derive(Debug, Clone, Default)]
pub struct TumblingWindowAccumulator {
    pub window_start_ms: u64,
    pub window_end_ms: u64,
    pub event_count: usize,
    pub event_ids: Vec<String>,
}

/// Materialized Tumbling Window Result
#[derive(Debug, Clone, PartialEq)]
pub struct TumblingWindowResult {
    pub window_start_ms: u64,
    pub window_end_ms: u64,
    pub event_count: usize,
    pub event_ids: Vec<String>,
}

/// Disjoint Epoch-Aligned Tumbling Window State Machine
pub struct TumblingWindow {
    pub window_size_ms: u64,
    windows: RwLock<BTreeMap<u64, TumblingWindowAccumulator>>,
}

impl TumblingWindow {
    pub fn new(window_size_ms: u64) -> Self {
        assert!(window_size_ms > 0, "Window size must be > 0");
        Self {
            window_size_ms,
            windows: RwLock::new(BTreeMap::new()),
        }
    }

    /// Assigns an incoming event to its strictly aligned tumbling interval [T0, T0 + W)
    pub fn assign_event(&self, event_time_ms: u64, event: &CanonicalEvent) {
        let window_start = event_time_ms - (event_time_ms % self.window_size_ms);
        let window_end = window_start + self.window_size_ms;

        let mut windows_guard = self.windows.write();
        let acc = windows_guard.entry(window_start).or_insert_with(|| TumblingWindowAccumulator {
            window_start_ms: window_start,
            window_end_ms: window_end,
            event_count: 0,
            event_ids: Vec::new(),
        });

        acc.event_count += 1;
        acc.event_ids.push(event.event_id.to_string());
    }

    /// Advances watermark and flushes completed tumbling windows
    pub fn advance_watermark<F>(&self, watermark_ms: u64, mut emit_fn: F)
    where
        F: FnMut(TumblingWindowResult),
    {
        let mut windows_guard = self.windows.write();
        let mut ready_keys = Vec::new();

        for (&start_ms, acc) in windows_guard.iter() {
            if acc.window_end_ms <= watermark_ms {
                ready_keys.push(start_ms);
            }
        }

        for start_ms in ready_keys {
            if let Some(acc) = windows_guard.remove(&start_ms) {
                emit_fn(TumblingWindowResult {
                    window_start_ms: acc.window_start_ms,
                    window_end_ms: acc.window_end_ms,
                    event_count: acc.event_count,
                    event_ids: acc.event_ids,
                });
            }
        }
    }
}
