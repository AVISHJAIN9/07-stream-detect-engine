use parking_lot::RwLock;
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};

/// Telemetry for Inactivity Idle-Key Scrubber
#[derive(Debug, Clone, PartialEq)]
pub struct IdleEvictionStats {
    pub tracked_keys: usize,
    pub total_touches: u64,
    pub total_idle_evictions: u64,
}

/// Idle-Key Inactivity Monitor with Sliding Access Watermarks
///
/// Tracks access timestamps per state key. Maintains an access-ordered timeline index.
/// When background scrubbers evaluate `CurrentTime - IdleTimeout`, unlinks and reclaims
/// keys that have seen zero read/write traffic within the sliding inactivity window.
pub struct IdleKeyTracker {
    // Map: key -> last_access_ts_ns
    key_timestamps: RwLock<HashMap<Vec<u8>, i64>>,
    // Timeline index: last_access_ts_ns -> Vec<key>
    access_timeline: RwLock<BTreeMap<i64, Vec<Vec<u8>>>>,

    total_touches: AtomicU64,
    total_idle_evictions: AtomicU64,
}

impl IdleKeyTracker {
    pub fn new() -> Self {
        Self {
            key_timestamps: RwLock::new(HashMap::new()),
            access_timeline: RwLock::new(BTreeMap::new()),
            total_touches: AtomicU64::new(0),
            total_idle_evictions: AtomicU64::new(0),
        }
    }

    /// Records access/activity on a key, refreshing its sliding inactivity watermark
    pub fn touch(&self, key: &[u8], current_ts_ns: i64) {
        let mut key_map = self.key_timestamps.write();
        let mut timeline = self.access_timeline.write();

        // 1. If key already exists in timeline, remove old entry
        if let Some(&old_ts) = key_map.get(key) {
            if let Some(keys) = timeline.get_mut(&old_ts) {
                keys.retain(|k| k.as_slice() != key);
                if keys.is_empty() {
                    timeline.remove(&old_ts);
                }
            }
        }

        // 2. Insert new timestamp
        key_map.insert(key.to_vec(), current_ts_ns);
        timeline.entry(current_ts_ns).or_default().push(key.to_vec());

        self.total_touches.fetch_add(1, Ordering::Relaxed);
    }

    /// Evicts stale keys whose last_access_ts <= cutoff_ts_ns
    pub fn evict_stale(&self, cutoff_ts_ns: i64, max_evictions: usize) -> Vec<Vec<u8>> {
        let mut evicted = Vec::new();

        let mut key_map = self.key_timestamps.write();
        let mut timeline = self.access_timeline.write();

        let mut empty_timestamps = Vec::new();

        for (&ts, keys) in timeline.range_mut(..=cutoff_ts_ns) {
            while let Some(k) = keys.pop() {
                // Verify key still has this timestamp
                if let Some(&current_k_ts) = key_map.get(&k) {
                    if current_k_ts == ts {
                        key_map.remove(&k);
                        evicted.push(k);
                        if evicted.len() >= max_evictions {
                            break;
                        }
                    }
                }
            }

            if keys.is_empty() {
                empty_timestamps.push(ts);
            }

            if evicted.len() >= max_evictions {
                break;
            }
        }

        for ts in empty_timestamps {
            timeline.remove(&ts);
        }

        self.total_idle_evictions
            .fetch_add(evicted.len() as u64, Ordering::Relaxed);

        evicted
    }

    /// Explicitly unlinks a key when deleted from state store
    pub fn remove(&self, key: &[u8]) {
        let mut key_map = self.key_timestamps.write();
        if let Some(old_ts) = key_map.remove(key) {
            let mut timeline = self.access_timeline.write();
            if let Some(keys) = timeline.get_mut(&old_ts) {
                keys.retain(|k| k.as_slice() != key);
                if keys.is_empty() {
                    timeline.remove(&old_ts);
                }
            }
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.key_timestamps.read().len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn last_access(&self, key: &[u8]) -> Option<i64> {
        self.key_timestamps.read().get(key).copied()
    }

    pub fn stats(&self) -> IdleEvictionStats {
        IdleEvictionStats {
            tracked_keys: self.key_timestamps.read().len(),
            total_touches: self.total_touches.load(Ordering::Relaxed),
            total_idle_evictions: self.total_idle_evictions.load(Ordering::Relaxed),
        }
    }
}

impl Default for IdleKeyTracker {
    fn default() -> Self {
        Self::new()
    }
}
