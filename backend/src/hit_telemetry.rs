use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;

pub type RuleId = u32;
pub type PatternId = u32;

/// Telemetry metrics for a specific rule and its pattern matchers
pub struct RuleHitMetrics {
    pub rule_id: RuleId,
    pub hits: AtomicU64,
    pub fp_suppressed: AtomicU64,
    pub last_hit_timestamp_ns: AtomicI64,
    pub pattern_hits: RwLock<HashMap<PatternId, u64>>,
}

impl RuleHitMetrics {
    pub fn new(rule_id: RuleId) -> Self {
        Self {
            rule_id,
            hits: AtomicU64::new(0),
            fp_suppressed: AtomicU64::new(0),
            last_hit_timestamp_ns: AtomicI64::new(0),
            pattern_hits: RwLock::new(HashMap::new()),
        }
    }

    #[inline]
    pub fn record_hit(&self, pattern_id: PatternId) {
        let now_ns = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
        self.hits.fetch_add(1, Ordering::Relaxed);
        self.last_hit_timestamp_ns.store(now_ns, Ordering::Relaxed);

        let mut guard = self.pattern_hits.write();
        *guard.entry(pattern_id).or_insert(0) += 1;
    }

    #[inline]
    pub fn record_suppression(&self) {
        self.fp_suppressed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> RuleHitSnapshot {
        let hits = self.hits.load(Ordering::Relaxed);
        let suppressed = self.fp_suppressed.load(Ordering::Relaxed);
        let last_hit = self.last_hit_timestamp_ns.load(Ordering::Relaxed);
        let total = hits + suppressed;
        let noise_ratio = if total > 0 {
            (suppressed as f64) / (total as f64)
        } else {
            0.0
        };

        RuleHitSnapshot {
            rule_id: self.rule_id,
            hits,
            fp_suppressed: suppressed,
            last_hit_timestamp_ns: last_hit,
            noise_ratio,
        }
    }
}

/// Point-in-time Rule Hit Telemetry Snapshot
#[derive(Debug, Clone, PartialEq)]
pub struct RuleHitSnapshot {
    pub rule_id: RuleId,
    pub hits: u64,
    pub fp_suppressed: u64,
    pub last_hit_timestamp_ns: i64,
    pub noise_ratio: f64,
}

/// Global Hit Telemetry Tracker
pub struct HitTelemetryTracker {
    rules: RwLock<HashMap<RuleId, Arc<RuleHitMetrics>>>,
}

impl Default for HitTelemetryTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl HitTelemetryTracker {
    pub fn new() -> Self {
        Self {
            rules: RwLock::new(HashMap::new()),
        }
    }

    pub fn get_or_create(&self, rule_id: RuleId) -> Arc<RuleHitMetrics> {
        let mut guard = self.rules.write();
        guard
            .entry(rule_id)
            .or_insert_with(|| Arc::new(RuleHitMetrics::new(rule_id)))
            .clone()
    }

    #[inline]
    pub fn record_hit(&self, rule_id: RuleId, pattern_id: PatternId) {
        let m = self.get_or_create(rule_id);
        m.record_hit(pattern_id);
    }

    #[inline]
    pub fn record_suppression(&self, rule_id: RuleId) {
        let m = self.get_or_create(rule_id);
        m.record_suppression();
    }

    pub fn get_snapshot(&self, rule_id: RuleId) -> Option<RuleHitSnapshot> {
        let guard = self.rules.read();
        guard.get(&rule_id).map(|m| m.snapshot())
    }

    pub fn all_snapshots(&self) -> Vec<RuleHitSnapshot> {
        let guard = self.rules.read();
        guard.values().map(|m| m.snapshot()).collect()
    }
}
