use crate::canonical_normalizer::CanonicalEvent;
use crate::sliding_window::{SlidingWindow, SlidingWindowResult};
use crate::tumbling_window::{TumblingWindow, TumblingWindowResult};
use crate::session_window::{SessionWindow, SessionInterval};
use parking_lot::RwLock;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;

/// Materialized Window Output emitted across sliding, tumbling, and session windows
#[derive(Debug, Clone, PartialEq)]
pub enum WindowOutput {
    Sliding(SlidingWindowResult),
    Tumbling(TumblingWindowResult),
    Session(SessionInterval),
}

/// Downstream Window Callback Sink
pub type WindowOutputSink = Arc<dyn Fn(WindowOutput) + Send + Sync>;

/// Event-Time Streaming Pipeline Processor
///
/// Binds window boundaries, aggregations, and rule evaluations strictly to record event
/// timestamps (t_event), decoupling wall-clock execution time from state evaluation.
/// State evaluation and window flushes are driven exclusively through advancing watermarks.
pub struct EventTimeProcessor {
    pipeline_watermark_ns: AtomicI64,
    total_events_processed: AtomicU64,
    watermark_advancements: AtomicU64,
    windows_triggered_count: AtomicU64,

    sliding_windows: RwLock<Vec<Arc<SlidingWindow>>>,
    tumbling_windows: RwLock<Vec<Arc<TumblingWindow>>>,
    session_windows: RwLock<Vec<Arc<SessionWindow>>>,
    output_sink: RwLock<Option<WindowOutputSink>>,
}

impl EventTimeProcessor {
    pub fn new() -> Self {
        Self {
            pipeline_watermark_ns: AtomicI64::new(0),
            total_events_processed: AtomicU64::new(0),
            watermark_advancements: AtomicU64::new(0),
            windows_triggered_count: AtomicU64::new(0),
            sliding_windows: RwLock::new(Vec::new()),
            tumbling_windows: RwLock::new(Vec::new()),
            session_windows: RwLock::new(Vec::new()),
            output_sink: RwLock::new(None),
        }
    }

    /// Sets the window output notification sink
    pub fn set_output_sink(&self, sink: WindowOutputSink) {
        let mut guard = self.output_sink.write();
        *guard = Some(sink);
    }

    /// Registers a sliding window in the event-time processing pipeline
    pub fn register_sliding_window(&self, window: Arc<SlidingWindow>) {
        let mut guard = self.sliding_windows.write();
        guard.push(window);
    }

    /// Registers a tumbling window in the event-time processing pipeline
    pub fn register_tumbling_window(&self, window: Arc<TumblingWindow>) {
        let mut guard = self.tumbling_windows.write();
        guard.push(window);
    }

    /// Registers a session window in the event-time processing pipeline
    pub fn register_session_window(&self, window: Arc<SessionWindow>) {
        let mut guard = self.session_windows.write();
        guard.push(window);
    }

    /// Dispatches an event to all registered windows strictly based on record event timestamp
    pub fn process_event(&self, event: &CanonicalEvent) -> Result<(), String> {
        let event_time_ms = if event.event_timestamp_ns > 0 {
            (event.event_timestamp_ns / 1_000_000) as u64
        } else {
            0
        };

        // 1. Dispatch to sliding windows
        {
            let sliding = self.sliding_windows.read();
            for win in sliding.iter() {
                win.assign_event(event_time_ms, event);
            }
        }

        // 2. Dispatch to tumbling windows
        {
            let tumbling = self.tumbling_windows.read();
            for win in tumbling.iter() {
                win.assign_event(event_time_ms, event);
            }
        }

        // 3. Dispatch to session windows
        {
            let session = self.session_windows.read();
            for win in session.iter() {
                win.add_event(&event.entity_id, event_time_ms, event);
            }
        }

        self.total_events_processed.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Advances the pipeline watermark, triggering all completed windows up to watermark_ns
    pub fn advance_watermark(&self, watermark_ns: i64) -> Vec<WindowOutput> {
        let mut current_wm = self.pipeline_watermark_ns.load(Ordering::Acquire);
        while watermark_ns > current_wm {
            match self.pipeline_watermark_ns.compare_exchange_weak(
                current_wm,
                watermark_ns,
                Ordering::Release,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.watermark_advancements.fetch_add(1, Ordering::Relaxed);
                    break;
                }
                Err(actual) => current_wm = actual,
            }
        }

        let watermark_ms = if watermark_ns > 0 {
            (watermark_ns / 1_000_000) as u64
        } else {
            0
        };

        let mut triggered_outputs = Vec::new();

        // 1. Trigger sliding windows
        {
            let sliding = self.sliding_windows.read();
            for win in sliding.iter() {
                win.advance_watermark(watermark_ms, |res| {
                    triggered_outputs.push(WindowOutput::Sliding(res));
                });
            }
        }

        // 2. Trigger tumbling windows
        {
            let tumbling = self.tumbling_windows.read();
            for win in tumbling.iter() {
                win.advance_watermark(watermark_ms, |res| {
                    triggered_outputs.push(WindowOutput::Tumbling(res));
                });
            }
        }

        // 3. Trigger session windows
        {
            let session = self.session_windows.read();
            for win in session.iter() {
                win.advance_watermark(watermark_ms, |res| {
                    triggered_outputs.push(WindowOutput::Session(res));
                });
            }
        }

        self.windows_triggered_count
            .fetch_add(triggered_outputs.len() as u64, Ordering::Relaxed);

        // Forward to callback sink if configured
        if let Some(sink) = self.output_sink.read().as_ref() {
            for out in triggered_outputs.iter() {
                sink(out.clone());
            }
        }

        triggered_outputs
    }

    #[inline]
    pub fn current_watermark(&self) -> i64 {
        self.pipeline_watermark_ns.load(Ordering::Acquire)
    }

    #[inline]
    pub fn total_events_processed(&self) -> u64 {
        self.total_events_processed.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn watermark_advancements(&self) -> u64 {
        self.watermark_advancements.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn windows_triggered_count(&self) -> u64 {
        self.windows_triggered_count.load(Ordering::Relaxed)
    }
}

impl Default for EventTimeProcessor {
    fn default() -> Self {
        Self::new()
    }
}
