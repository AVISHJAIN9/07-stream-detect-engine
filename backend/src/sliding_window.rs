use crate::canonical_normalizer::CanonicalEvent;
use parking_lot::RwLock;
use std::collections::BTreeMap;

/// Single Disjoint Time Pane Accumulator
#[derive(Debug, Clone, Default)]
pub struct PaneAccumulator {
    pub pane_start_ms: u64,
    pub pane_end_ms: u64,
    pub event_count: usize,
    pub event_ids: Vec<String>,
}

/// Materialized Window Evaluation Result
#[derive(Debug, Clone, PartialEq)]
pub struct SlidingWindowResult {
    pub window_start_ms: u64,
    pub window_end_ms: u64,
    pub event_count: usize,
    pub event_ids: Vec<String>,
}

fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

/// Event-Time Paned Circular Sliding Window State Machine
pub struct SlidingWindow {
    pub window_size_ms: u64,
    pub slide_size_ms: u64,
    pub pane_size_ms: u64,
    panes_per_window: usize,
    panes_per_slide: usize,
    panes: RwLock<BTreeMap<u64, PaneAccumulator>>,
    last_emitted_window_end: RwLock<u64>,
}

impl SlidingWindow {
    pub fn new(window_size_ms: u64, slide_size_ms: u64) -> Self {
        assert!(slide_size_ms <= window_size_ms, "Slide size must be <= window size");
        let pane_size_ms = gcd(window_size_ms, slide_size_ms);
        let panes_per_window = (window_size_ms / pane_size_ms) as usize;
        let panes_per_slide = (slide_size_ms / pane_size_ms) as usize;

        Self {
            window_size_ms,
            slide_size_ms,
            pane_size_ms,
            panes_per_window,
            panes_per_slide,
            panes: RwLock::new(BTreeMap::new()),
            last_emitted_window_end: RwLock::new(0),
        }
    }

    /// Assigns an incoming event to its corresponding time pane slice
    pub fn assign_event(&self, event_time_ms: u64, event: &CanonicalEvent) {
        let pane_start = event_time_ms - (event_time_ms % self.pane_size_ms);
        let pane_end = pane_start + self.pane_size_ms;

        let mut panes_guard = self.panes.write();
        let pane = panes_guard.entry(pane_start).or_insert_with(|| PaneAccumulator {
            pane_start_ms: pane_start,
            pane_end_ms: pane_end,
            event_count: 0,
            event_ids: Vec::new(),
        });

        pane.event_count += 1;
        pane.event_ids.push(event.event_id.to_string());
    }

    /// Advances watermark and triggers completed sliding windows
    pub fn advance_watermark<F>(&self, watermark_ms: u64, mut emit_fn: F)
    where
        F: FnMut(SlidingWindowResult),
    {
        let mut panes_guard = self.panes.write();
        let mut last_end_guard = self.last_emitted_window_end.write();

        // Earliest available pane start
        let earliest_pane_opt = panes_guard.keys().next().copied();
        if earliest_pane_opt.is_none() {
            return;
        }
        let earliest_pane = earliest_pane_opt.unwrap();

        // Determine starting window end
        let mut next_window_end = if *last_end_guard == 0 {
            let first_win_start = earliest_pane - (earliest_pane % self.slide_size_ms);
            first_win_start + self.window_size_ms
        } else {
            *last_end_guard + self.slide_size_ms
        };

        while next_window_end <= watermark_ms {
            let window_start = next_window_end.saturating_sub(self.window_size_ms);

            // Merge all constituent panes within [window_start, next_window_end)
            let mut total_count = 0;
            let mut all_ids = Vec::new();

            for (&pane_start, pane) in panes_guard.range(window_start..next_window_end) {
                total_count += pane.event_count;
                all_ids.extend_from_slice(&pane.event_ids);
            }

            emit_fn(SlidingWindowResult {
                window_start_ms: window_start,
                window_end_ms: next_window_end,
                event_count: total_count,
                event_ids: all_ids,
            });

            *last_end_guard = next_window_end;
            next_window_end += self.slide_size_ms;
        }

        // Clean up expired panes no longer needed by future windows
        if *last_end_guard > self.window_size_ms {
            let expire_cutoff = *last_end_guard - self.window_size_ms;
            let expired_keys: Vec<u64> = panes_guard
                .range(..expire_cutoff)
                .map(|(&k, _)| k)
                .collect();
            for k in expired_keys {
                panes_guard.remove(&k);
            }
        }
    }
}
