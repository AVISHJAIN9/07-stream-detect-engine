use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Individual Predicate Execution Metrics
pub struct PredicateMetrics {
    pub predicate_id: u32,
    pub name: String,
    pub eval_count: AtomicU64,
    pub total_nanos: AtomicU64,
    pub min_nanos: AtomicU64,
    pub max_nanos: AtomicU64,
    pub short_circuit_skips: AtomicU64,
}

impl PredicateMetrics {
    pub fn new(predicate_id: u32, name: impl Into<String>) -> Self {
        Self {
            predicate_id,
            name: name.into(),
            eval_count: AtomicU64::new(0),
            total_nanos: AtomicU64::new(0),
            min_nanos: AtomicU64::new(u64::MAX),
            max_nanos: AtomicU64::new(0),
            short_circuit_skips: AtomicU64::new(0),
        }
    }

    #[inline]
    pub fn record_eval(&self, duration_ns: u64) {
        self.eval_count.fetch_add(1, Ordering::Relaxed);
        self.total_nanos.fetch_add(duration_ns, Ordering::Relaxed);

        // Update min_nanos atomically
        let mut current_min = self.min_nanos.load(Ordering::Relaxed);
        while duration_ns < current_min {
            match self.min_nanos.compare_exchange_weak(
                current_min,
                duration_ns,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current_min = actual,
            }
        }

        // Update max_nanos atomically
        let mut current_max = self.max_nanos.load(Ordering::Relaxed);
        while duration_ns > current_max {
            match self.max_nanos.compare_exchange_weak(
                current_max,
                duration_ns,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current_max = actual,
            }
        }
    }

    #[inline]
    pub fn record_skip(&self) {
        self.short_circuit_skips.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> PredicateMetricsSnapshot {
        let count = self.eval_count.load(Ordering::Relaxed);
        let total = self.total_nanos.load(Ordering::Relaxed);
        let min = self.min_nanos.load(Ordering::Relaxed);
        let max = self.max_nanos.load(Ordering::Relaxed);
        let skips = self.short_circuit_skips.load(Ordering::Relaxed);

        let min_val = if min == u64::MAX { 0 } else { min };
        let avg = if count > 0 { (total as f64) / (count as f64) } else { 0.0 };

        PredicateMetricsSnapshot {
            predicate_id: self.predicate_id,
            name: self.name.clone(),
            eval_count: count,
            total_nanos: total,
            avg_nanos: avg,
            min_nanos: min_val,
            max_nanos: max,
            short_circuit_skips: skips,
        }
    }
}

/// Point-in-time Snapshot for Predicate Metrics
#[derive(Debug, Clone, PartialEq)]
pub struct PredicateMetricsSnapshot {
    pub predicate_id: u32,
    pub name: String,
    pub eval_count: u64,
    pub total_nanos: u64,
    pub avg_nanos: f64,
    pub min_nanos: u64,
    pub max_nanos: u64,
    pub short_circuit_skips: u64,
}

/// Global Predicate Metrics Registry (< 15 ns tracing overhead)
pub struct PredicateMetricsRegistry {
    metrics: RwLock<HashMap<u32, Arc<PredicateMetrics>>>,
}

impl Default for PredicateMetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PredicateMetricsRegistry {
    pub fn new() -> Self {
        Self {
            metrics: RwLock::new(HashMap::new()),
        }
    }

    pub fn register(&self, predicate_id: u32, name: impl Into<String>) -> Arc<PredicateMetrics> {
        let mut guard = self.metrics.write();
        guard
            .entry(predicate_id)
            .or_insert_with(|| Arc::new(PredicateMetrics::new(predicate_id, name)))
            .clone()
    }

    #[inline]
    pub fn get(&self, predicate_id: u32) -> Option<Arc<PredicateMetrics>> {
        let guard = self.metrics.read();
        guard.get(&predicate_id).cloned()
    }

    #[inline]
    pub fn record_eval(&self, predicate_id: u32, duration_ns: u64) {
        if let Some(m) = self.get(predicate_id) {
            m.record_eval(duration_ns);
        }
    }

    /// Measures an evaluation closure and records nanosecond elapsed duration
    #[inline]
    pub fn time_eval<F, R>(&self, predicate_id: u32, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let start = Instant::now();
        let result = f();
        let elapsed_ns = start.elapsed().as_nanos() as u64;
        self.record_eval(predicate_id, elapsed_ns);
        result
    }

    pub fn snapshots(&self) -> Vec<PredicateMetricsSnapshot> {
        let guard = self.metrics.read();
        guard.values().map(|m| m.snapshot()).collect()
    }
}
