use parking_lot::RwLock;
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering};

pub type WindowBucketId = u64;

/// Metadata associated with an active stateful window bucket
#[derive(Debug, Clone, PartialEq)]
pub struct WindowBucketMeta {
    pub bucket_id: WindowBucketId,
    pub window_start_ns: i64,
    pub window_end_ns: i64,
    pub memory_bytes: usize,
    pub event_count: usize,
}

/// Information returned upon successful bucket garbage collection
#[derive(Debug, Clone, PartialEq)]
pub struct PurgedBucket {
    pub bucket_id: WindowBucketId,
    pub window_start_ns: i64,
    pub window_end_ns: i64,
    pub reclaimed_bytes: usize,
    pub event_count: usize,
}

/// Window Garbage Collection Telemetry
#[derive(Debug, Clone, PartialEq)]
pub struct WindowGCStats {
    pub active_windows: usize,
    pub active_memory_bytes: usize,
    pub total_purged_windows: u64,
    pub total_reclaimed_bytes: usize,
    pub last_gc_watermark_ns: i64,
}

/// Watermark-Driven Window State Garbage Collection Engine
///
/// Maintains an epoch-indexed B-Tree of active window state allocations.
/// Upon receiving watermark advancements, evaluates:
///   PurgeThreshold = Watermark - AllowedLateness
/// Discharges all window state buckets where WindowEnd <= PurgeThreshold in sub-microsecond
/// time, recycling memory and eliminating state leaks across long-running streams.
pub struct WindowStateGC {
    // Time-ordered index: window_end_ns -> Vec<WindowBucketId>
    timeline_index: RwLock<BTreeMap<i64, Vec<WindowBucketId>>>,
    // Fast lookup for bucket metadata
    buckets: RwLock<HashMap<WindowBucketId, WindowBucketMeta>>,

    active_memory_bytes: AtomicUsize,
    total_purged_windows: AtomicU64,
    total_reclaimed_bytes: AtomicUsize,
    last_gc_watermark: AtomicI64,
}

impl WindowStateGC {
    pub fn new() -> Self {
        Self {
            timeline_index: RwLock::new(BTreeMap::new()),
            buckets: RwLock::new(HashMap::new()),
            active_memory_bytes: AtomicUsize::new(0),
            total_purged_windows: AtomicU64::new(0),
            total_reclaimed_bytes: AtomicUsize::new(0),
            last_gc_watermark: AtomicI64::new(0),
        }
    }

    /// Registers a newly created window bucket in the GC index
    pub fn register_window(
        &self,
        bucket_id: WindowBucketId,
        window_start_ns: i64,
        window_end_ns: i64,
        memory_bytes: usize,
        event_count: usize,
    ) {
        let meta = WindowBucketMeta {
            bucket_id,
            window_start_ns,
            window_end_ns,
            memory_bytes,
            event_count,
        };

        {
            let mut index_guard = self.timeline_index.write();
            index_guard.entry(window_end_ns).or_default().push(bucket_id);
        }

        {
            let mut buckets_guard = self.buckets.write();
            buckets_guard.insert(bucket_id, meta);
        }

        self.active_memory_bytes
            .fetch_add(memory_bytes, Ordering::Relaxed);
    }

    /// Triggers watermark-driven garbage collection sweep
    pub fn on_watermark_advance(
        &self,
        watermark_ns: i64,
        allowed_lateness_ns: i64,
    ) -> Vec<PurgedBucket> {
        self.last_gc_watermark.store(watermark_ns, Ordering::Release);
        let purge_threshold = watermark_ns.saturating_sub(allowed_lateness_ns);

        let mut expired_bucket_ids = Vec::new();

        // 1. Extract all bucket IDs from the timeline index up to purge_threshold (inclusive)
        {
            let mut index_guard = self.timeline_index.write();
            let mut keys_to_remove = Vec::new();

            for (&end_ts, ids) in index_guard.range(..=purge_threshold) {
                keys_to_remove.push(end_ts);
                expired_bucket_ids.extend_from_slice(ids);
            }

            for k in keys_to_remove {
                index_guard.remove(&k);
            }
        }

        if expired_bucket_ids.is_empty() {
            return Vec::new();
        }

        // 2. Remove metadata and calculate reclaimed metrics
        let mut purged_results = Vec::with_capacity(expired_bucket_ids.len());
        let mut sweep_reclaimed_bytes = 0;

        {
            let mut buckets_guard = self.buckets.write();
            for bucket_id in expired_bucket_ids {
                if let Some(meta) = buckets_guard.remove(&bucket_id) {
                    sweep_reclaimed_bytes += meta.memory_bytes;
                    purged_results.push(PurgedBucket {
                        bucket_id: meta.bucket_id,
                        window_start_ns: meta.window_start_ns,
                        window_end_ns: meta.window_end_ns,
                        reclaimed_bytes: meta.memory_bytes,
                        event_count: meta.event_count,
                    });
                }
            }
        }

        self.active_memory_bytes
            .fetch_sub(sweep_reclaimed_bytes, Ordering::Relaxed);
        self.total_purged_windows
            .fetch_add(purged_results.len() as u64, Ordering::Relaxed);
        self.total_reclaimed_bytes
            .fetch_add(sweep_reclaimed_bytes, Ordering::Relaxed);

        purged_results
    }

    #[inline]
    pub fn active_windows_count(&self) -> usize {
        self.buckets.read().len()
    }

    #[inline]
    pub fn active_memory_bytes(&self) -> usize {
        self.active_memory_bytes.load(Ordering::Relaxed)
    }

    pub fn stats(&self) -> WindowGCStats {
        WindowGCStats {
            active_windows: self.buckets.read().len(),
            active_memory_bytes: self.active_memory_bytes.load(Ordering::Relaxed),
            total_purged_windows: self.total_purged_windows.load(Ordering::Relaxed),
            total_reclaimed_bytes: self.total_reclaimed_bytes.load(Ordering::Relaxed),
            last_gc_watermark_ns: self.last_gc_watermark.load(Ordering::Relaxed),
        }
    }
}

impl Default for WindowStateGC {
    fn default() -> Self {
        Self::new()
    }
}
