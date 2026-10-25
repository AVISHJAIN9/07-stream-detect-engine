use crate::canonical_normalizer::CanonicalEvent;
use parking_lot::Mutex;
use std::cmp::Ordering as CmpOrdering;
use std::collections::BinaryHeap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

/// Internal min-heap element ordered primarily by event_timestamp_ns, then ingestion sequence
#[derive(Debug, Clone)]
struct ReorderEntry {
    timestamp_ns: i64,
    seq: u64,
    event: CanonicalEvent,
}

impl PartialEq for ReorderEntry {
    fn eq(&self, other: &Self) -> bool {
        self.timestamp_ns == other.timestamp_ns && self.seq == other.seq
    }
}

impl Eq for ReorderEntry {}

impl PartialOrd for ReorderEntry {
    fn partial_cmp(&self, other: &Self) -> Option<CmpOrdering> {
        Some(self.cmp(other))
    }
}

// Inverted comparison for Min-Heap
impl Ord for ReorderEntry {
    fn cmp(&self, other: &Self) -> CmpOrdering {
        // Reverse order so lowest timestamp has highest priority
        other
            .timestamp_ns
            .cmp(&self.timestamp_ns)
            .then_with(|| other.seq.cmp(&self.seq))
    }
}

/// Out-of-Order Buffer & Re-Ordering Engine Telemetry
#[derive(Debug, Clone, PartialEq)]
pub struct ReordererStats {
    pub current_buffered: usize,
    pub max_capacity: usize,
    pub total_buffered: u64,
    pub total_drained: u64,
    pub out_of_order_events_detected: u64,
    pub buffer_overflow_evictions: u64,
    pub last_drained_timestamp_ns: i64,
}

/// Priority Time-Heap Out-of-Order Event Re-Sequencing Engine
///
/// Buffers incoming jittery / out-of-order events within a bounded min-heap priority queue.
/// When watermarks advance, drains events up to W in strictly non-decreasing chronological order.
pub struct EventReorderer {
    max_capacity: usize,
    heap: Mutex<BinaryHeap<ReorderEntry>>,
    seq_gen: AtomicU64,
    total_buffered: AtomicU64,
    total_drained: AtomicU64,
    out_of_order_count: AtomicU64,
    overflow_evictions: AtomicU64,
    last_drained_timestamp: AtomicI64,
    max_timestamp_seen: AtomicI64,
}

impl EventReorderer {
    pub fn new(max_capacity: usize) -> Self {
        assert!(max_capacity > 0, "max_capacity must be > 0");
        Self {
            max_capacity,
            heap: Mutex::new(BinaryHeap::with_capacity(std::cmp::min(
                max_capacity,
                65536,
            ))),
            seq_gen: AtomicU64::new(1),
            total_buffered: AtomicU64::new(0),
            total_drained: AtomicU64::new(0),
            out_of_order_count: AtomicU64::new(0),
            overflow_evictions: AtomicU64::new(0),
            last_drained_timestamp: AtomicI64::new(0),
            max_timestamp_seen: AtomicI64::new(0),
        }
    }

    /// Pushes an event into the reordering priority time-heap
    pub fn push(&self, event: CanonicalEvent) -> Result<(), String> {
        let ts = event.event_timestamp_ns;
        let last_drained = self.last_drained_timestamp.load(Ordering::Acquire);

        // Check if event arrives late relative to already drained watermark
        if last_drained > 0 && ts < last_drained {
            self.out_of_order_count.fetch_add(1, Ordering::Relaxed);
        } else {
            let cur_max = self.max_timestamp_seen.load(Ordering::Acquire);
            if ts < cur_max {
                self.out_of_order_count.fetch_add(1, Ordering::Relaxed);
            }
        }

        // Update max timestamp seen
        let mut cur_max = self.max_timestamp_seen.load(Ordering::Acquire);
        while ts > cur_max {
            match self.max_timestamp_seen.compare_exchange_weak(
                cur_max,
                ts,
                Ordering::Release,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(actual) => cur_max = actual,
            }
        }

        let seq = self.seq_gen.fetch_add(1, Ordering::Relaxed);
        let entry = ReorderEntry {
            timestamp_ns: ts,
            seq,
            event,
        };

        let mut heap_guard = self.heap.lock();
        if heap_guard.len() >= self.max_capacity {
            // Buffer overflow: evict the oldest entry to prevent unbounded memory growth
            if let Some(evicted) = heap_guard.pop() {
                self.overflow_evictions.fetch_add(1, Ordering::Relaxed);
                self.total_drained.fetch_add(1, Ordering::Relaxed);
                self.last_drained_timestamp
                    .store(evicted.timestamp_ns, Ordering::Release);
            }
        }

        heap_guard.push(entry);
        self.total_buffered.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Drains all events with timestamp <= watermark_ns in strictly ascending chronological order
    pub fn drain_up_to(&self, watermark_ns: i64) -> Vec<CanonicalEvent> {
        let mut result = Vec::new();
        let mut heap_guard = self.heap.lock();

        while let Some(top) = heap_guard.peek() {
            if top.timestamp_ns <= watermark_ns {
                let entry = heap_guard.pop().unwrap();
                self.last_drained_timestamp
                    .store(entry.timestamp_ns, Ordering::Release);
                self.total_drained.fetch_add(1, Ordering::Relaxed);
                result.push(entry.event);
            } else {
                break;
            }
        }

        result
    }

    /// Drains all currently buffered events in non-decreasing order regardless of watermark
    pub fn drain_all(&self) -> Vec<CanonicalEvent> {
        let mut result = Vec::new();
        let mut heap_guard = self.heap.lock();

        while let Some(entry) = heap_guard.pop() {
            self.last_drained_timestamp
                .store(entry.timestamp_ns, Ordering::Release);
            self.total_drained.fetch_add(1, Ordering::Relaxed);
            result.push(entry.event);
        }

        result
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.heap.lock().len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.heap.lock().is_empty()
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.max_capacity
    }

    pub fn stats(&self) -> ReordererStats {
        ReordererStats {
            current_buffered: self.heap.lock().len(),
            max_capacity: self.max_capacity,
            total_buffered: self.total_buffered.load(Ordering::Relaxed),
            total_drained: self.total_drained.load(Ordering::Relaxed),
            out_of_order_events_detected: self.out_of_order_count.load(Ordering::Relaxed),
            buffer_overflow_evictions: self.overflow_evictions.load(Ordering::Relaxed),
            last_drained_timestamp_ns: self.last_drained_timestamp.load(Ordering::Relaxed),
        }
    }
}
