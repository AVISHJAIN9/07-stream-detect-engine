use crate::dedup_key_generator::Murmur3Hasher64;
use crate::detection_match::DetectionMatch;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Fingerprint computation
// ---------------------------------------------------------------------------

/// Computes a 64-bit Murmur3-based suppression fingerprint over the canonical
/// alert identity tuple: `(rule_id ‖ entity_id ‖ grouping_keys…)`.
///
/// The hash is order-invariant with respect to the grouping_keys slice because
/// the caller is expected to pass them in a canonical (sorted) order, which
/// `AlertDeduplicator::compute_fingerprint` guarantees internally.
#[inline]
pub fn compute_alert_fingerprint(rule_id: &str, entity_id: &str, grouping_keys: &[&str]) -> u64 {
    let mut h = Murmur3Hasher64::new(0xDEAD_BEEF_CAFE_BABEu64);
    h.write_str(rule_id);
    h.write_str("\x00");
    h.write_str(entity_id);
    h.write_str("\x00");
    // Stable sort of grouping keys ensures order-invariant fingerprints
    let mut sorted: Vec<&str> = grouping_keys.to_vec();
    sorted.sort_unstable();
    for k in &sorted {
        h.write_str(k);
        h.write_str("\x01");
    }
    h.finish()
}

// ---------------------------------------------------------------------------
// Active suppression record
// ---------------------------------------------------------------------------

/// Per-fingerprint suppression window tracked inside the sharded cache.
#[derive(Debug, Clone)]
pub struct ActiveSuppression {
    /// Timestamp (ns) when the first matching alert was received.
    pub first_seen_ns: i64,
    /// Timestamp (ns) of the most recent matching alert trigger.
    pub last_seen_ns: i64,
    /// Running count of additional occurrences suppressed after the first.
    pub occurrence_count: u64,
    /// Absolute expiry timestamp in ms (monotonic wall-clock aligned to the
    /// timing wheel domain).  Updated on every sliding-TTL bump.
    pub expire_ts_ms: u64,
    /// Opaque timer handle ID from the `SlidingDeduplicationWheel`.
    pub timer_handle_id: u64,
}

// ---------------------------------------------------------------------------
// Alert Action – typed discriminated union returned to the caller
// ---------------------------------------------------------------------------

/// The decision returned by `AlertDeduplicator::check_or_suppress`.
#[derive(Debug)]
pub enum AlertAction {
    /// First occurrence – emit the alert downstream.
    Emit(DetectionMatch),
    /// Repeated occurrence within the active window – suppress it.
    Suppress(SuppressionInfo),
}

/// Diagnostic payload carried alongside a suppression decision.
#[derive(Debug, Clone)]
pub struct SuppressionInfo {
    pub fingerprint: u64,
    pub rule_id: String,
    pub entity_id: String,
    pub first_seen_ns: i64,
    pub last_seen_ns: i64,
    pub occurrence_count: u64,
    pub expire_ts_ms: u64,
}

// ---------------------------------------------------------------------------
// TTL configuration
// ---------------------------------------------------------------------------

/// Determines whether the suppression window is fixed or sliding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DedupWindowKind {
    /// The expiry is fixed at `first_seen + ttl_ms`.  Repeated hits do not
    /// extend the window.
    Fixed,
    /// Each hit extends the expiry by `ttl_ms` from the current wall-clock
    /// position: `expire = max(current_expire, now + ttl_ms)`.
    Sliding,
}

/// Complete TTL configuration for a single alert classification.
#[derive(Debug, Clone)]
pub struct TTLConfig {
    pub ttl_ms: u64,
    pub window_kind: DedupWindowKind,
}

impl TTLConfig {
    pub fn fixed(ttl_ms: u64) -> Self {
        Self { ttl_ms, window_kind: DedupWindowKind::Fixed }
    }

    pub fn sliding(ttl_ms: u64) -> Self {
        Self { ttl_ms, window_kind: DedupWindowKind::Sliding }
    }
}

// ---------------------------------------------------------------------------
// Sharded suppression cache shard
// ---------------------------------------------------------------------------

struct SuppressionShard {
    map: RwLock<HashMap<u64, ActiveSuppression>>,
}

impl SuppressionShard {
    fn new() -> Self {
        Self { map: RwLock::new(HashMap::with_capacity(256)) }
    }
}

// ---------------------------------------------------------------------------
// Alert Deduplicator
// ---------------------------------------------------------------------------

const NUM_DEDUP_SHARDS: usize = 64;
const DEDUP_SHARD_MASK: usize = NUM_DEDUP_SHARDS - 1;

/// Sharded, lock-free-read alert deduplication engine.
///
/// # Architecture
/// * 64 independent RwLock-guarded shards distribute contention.
/// * Per-fingerprint `ActiveSuppression` records are stored in-shard.
/// * On a cache miss → `AlertAction::Emit`; on a hit that is still within
///   the TTL window → `AlertAction::Suppress` with bumped counters.
/// * Expired entries are lazily evicted on read (checked at probe time) and
///   eagerly removed when the `SlidingDeduplicationWheel` fires.
pub struct AlertDeduplicator {
    shards: Vec<SuppressionShard>,
    // Telemetry counters
    total_checked: AtomicU64,
    total_emitted: AtomicU64,
    total_suppressed: AtomicU64,
    total_expired_evictions: AtomicU64,
}

impl AlertDeduplicator {
    pub fn new() -> Self {
        let mut shards = Vec::with_capacity(NUM_DEDUP_SHARDS);
        for _ in 0..NUM_DEDUP_SHARDS {
            shards.push(SuppressionShard::new());
        }
        Self {
            shards,
            total_checked: AtomicU64::new(0),
            total_emitted: AtomicU64::new(0),
            total_suppressed: AtomicU64::new(0),
            total_expired_evictions: AtomicU64::new(0),
        }
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    #[inline]
    fn shard_index(fingerprint: u64) -> usize {
        (fingerprint as usize) & DEDUP_SHARD_MASK
    }

    #[inline]
    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    #[inline]
    fn now_ns() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0)
    }

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    /// Compute a canonical 64-bit fingerprint for an alert identity.
    pub fn compute_fingerprint(
        &self,
        rule_id: &str,
        entity_id: &str,
        grouping_keys: &[&str],
    ) -> u64 {
        compute_alert_fingerprint(rule_id, entity_id, grouping_keys)
    }

    /// Core deduplication check.
    ///
    /// Returns `AlertAction::Emit` exactly once per unique suppression window,
    /// and `AlertAction::Suppress` for every subsequent occurrence within the
    /// active window.  After expiry the fingerprint is evicted lazily and the
    /// next occurrence re-opens a fresh emit window.
    pub fn check_or_suppress(
        &self,
        detection: DetectionMatch,
        ttl_config: &TTLConfig,
    ) -> AlertAction {
        self.total_checked.fetch_add(1, Ordering::Relaxed);

        let fp = detection.suppression_fingerprint;
        let shard_idx = Self::shard_index(fp);
        let shard = &self.shards[shard_idx];

        let now_ms = Self::now_ms();
        let now_ns = Self::now_ns();

        // --- Fast read path: check for existing active suppression entry ---
        {
            let guard = shard.map.read();
            if let Some(existing) = guard.get(&fp) {
                if existing.expire_ts_ms > now_ms {
                    // Active window → suppress
                    let info = SuppressionInfo {
                        fingerprint: fp,
                        rule_id: detection.rule_id.clone(),
                        entity_id: detection.entity_id.clone(),
                        first_seen_ns: existing.first_seen_ns,
                        last_seen_ns: now_ns,
                        occurrence_count: existing.occurrence_count + 1,
                        expire_ts_ms: existing.expire_ts_ms,
                    };
                    // Release read lock before acquiring write lock
                    drop(guard);

                    // Update counters under write lock
                    let mut wguard = shard.map.write();
                    if let Some(entry) = wguard.get_mut(&fp) {
                        entry.last_seen_ns = now_ns;
                        entry.occurrence_count += 1;
                        if ttl_config.window_kind == DedupWindowKind::Sliding {
                            let new_expire = now_ms + ttl_config.ttl_ms;
                            if new_expire > entry.expire_ts_ms {
                                entry.expire_ts_ms = new_expire;
                            }
                        }
                    }
                    drop(wguard);

                    self.total_suppressed.fetch_add(1, Ordering::Relaxed);
                    return AlertAction::Suppress(info);
                }
                // Stale entry – will be replaced below (fall through)
            }
        }

        // --- Write path: insert new suppression entry and emit alert ---
        let new_expire_ts_ms = now_ms + ttl_config.ttl_ms;
        let suppression = ActiveSuppression {
            first_seen_ns: now_ns,
            last_seen_ns: now_ns,
            occurrence_count: 0,
            expire_ts_ms: new_expire_ts_ms,
            timer_handle_id: 0, // Set by SlidingDeduplicationWheel after scheduling
        };

        {
            let mut wguard = shard.map.write();
            let old = wguard.insert(fp, suppression);
            if old.map_or(false, |o| o.expire_ts_ms <= now_ms) {
                self.total_expired_evictions.fetch_add(1, Ordering::Relaxed);
            }
        }

        self.total_emitted.fetch_add(1, Ordering::Relaxed);
        AlertAction::Emit(detection)
    }

    /// Directly evict a fingerprint from the suppression cache.
    /// Called by `SlidingDeduplicationWheel` when a TTL timer fires.
    pub fn evict(&self, fingerprint: u64) -> bool {
        let shard_idx = Self::shard_index(fingerprint);
        let shard = &self.shards[shard_idx];
        let mut wguard = shard.map.write();
        if wguard.remove(&fingerprint).is_some() {
            self.total_expired_evictions.fetch_add(1, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Update the timer_handle_id on an existing entry (called by the wheel
    /// after re-scheduling).
    pub fn update_timer_handle(&self, fingerprint: u64, timer_handle_id: u64) {
        let shard_idx = Self::shard_index(fingerprint);
        let shard = &self.shards[shard_idx];
        let mut wguard = shard.map.write();
        if let Some(entry) = wguard.get_mut(&fingerprint) {
            entry.timer_handle_id = timer_handle_id;
        }
    }

    /// Returns the current `ActiveSuppression` record for a fingerprint, or
    /// `None` if absent or expired.
    pub fn get_active(&self, fingerprint: u64) -> Option<ActiveSuppression> {
        let shard_idx = Self::shard_index(fingerprint);
        let shard = &self.shards[shard_idx];
        let guard = shard.map.read();
        guard.get(&fingerprint).filter(|e| {
            let now_ms = Self::now_ms();
            e.expire_ts_ms > now_ms
        }).cloned()
    }

    /// Force-inserts an `ActiveSuppression` record for testing purposes.
    pub fn force_insert(&self, fingerprint: u64, suppression: ActiveSuppression) {
        let shard_idx = Self::shard_index(fingerprint);
        let shard = &self.shards[shard_idx];
        let mut wguard = shard.map.write();
        wguard.insert(fingerprint, suppression);
    }

    /// Telemetry snapshot.
    pub fn stats(&self) -> AlertDedupStats {
        AlertDedupStats {
            total_checked: self.total_checked.load(Ordering::Relaxed),
            total_emitted: self.total_emitted.load(Ordering::Relaxed),
            total_suppressed: self.total_suppressed.load(Ordering::Relaxed),
            total_expired_evictions: self.total_expired_evictions.load(Ordering::Relaxed),
        }
    }

    /// Number of currently active (potentially including stale, lazily-evicted)
    /// suppression entries across all shards.
    pub fn active_count(&self) -> usize {
        self.shards.iter().map(|s| s.map.read().len()).sum()
    }
}

impl Default for AlertDeduplicator {
    fn default() -> Self {
        Self::new()
    }
}

/// Telemetry snapshot for `AlertDeduplicator`.
#[derive(Debug, Clone, PartialEq)]
pub struct AlertDedupStats {
    pub total_checked: u64,
    pub total_emitted: u64,
    pub total_suppressed: u64,
    pub total_expired_evictions: u64,
}
