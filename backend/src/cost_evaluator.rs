use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

pub type PredicateFn<T> = Arc<dyn Fn(&T) -> bool + Send + Sync>;

/// Predicate Cost Tier classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CostTier {
    Tier0ExactHash = 1,     // Direct integer, boolean, or hash equality
    Tier1Substring = 10,    // Aho-Corasick / Boyer-Moore substring search
    Tier2GlobWildcard = 50, // Two-way wildcard glob matching
    Tier3RegexDFA = 500,    // Guarded regular expression matching
}

/// Runtime-Instrumented Predicate Node
pub struct InstrumentedPredicate<T> {
    pub id: u32,
    pub name: String,
    pub cost_tier: CostTier,
    pub evaluator: PredicateFn<T>,
    pub eval_count: AtomicU64,
    pub pass_count: AtomicU64,
}

impl<T> InstrumentedPredicate<T> {
    pub fn new(id: u32, name: impl Into<String>, cost_tier: CostTier, evaluator: PredicateFn<T>) -> Self {
        Self {
            id,
            name: name.into(),
            cost_tier,
            evaluator,
            eval_count: AtomicU64::new(1), // Default 1 to avoid div-by-zero
            pass_count: AtomicU64::new(1),
        }
    }

    /// Computes the dynamic execution score: Score = Cost * Selectivity
    #[inline]
    pub fn score(&self) -> f64 {
        let evals = self.eval_count.load(Ordering::Relaxed) as f64;
        let passes = self.pass_count.load(Ordering::Relaxed) as f64;
        let selectivity = (passes / evals).clamp(0.01, 1.0);
        (self.cost_tier as u32 as f64) * selectivity
    }

    #[inline]
    pub fn evaluate(&self, item: &T) -> bool {
        self.eval_count.fetch_add(1, Ordering::Relaxed);
        let result = (self.evaluator)(item);
        if result {
            self.pass_count.fetch_add(1, Ordering::Relaxed);
        }
        result
    }
}

/// Adaptive Cost-Aware Predicate Short-Circuiting Engine
pub struct ShortCircuitEngine<T> {
    predicates: Vec<InstrumentedPredicate<T>>,
}

impl<T> ShortCircuitEngine<T> {
    pub fn new(predicates: Vec<InstrumentedPredicate<T>>) -> Self {
        Self { predicates }
    }

    /// Ranks predicates dynamically by Score = Cost * Selectivity (ascending order)
    pub fn rank_predicates(&mut self) {
        self.predicates.sort_by(|a, b| {
            a.score()
                .partial_cmp(&b.score())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    }

    /// Evaluates an AND group across ranked predicates, short-circuiting on first false
    pub fn evaluate_and(&self, item: &T, eval_order_tracker: &mut Vec<u32>) -> bool {
        for pred in &self.predicates {
            eval_order_tracker.push(pred.id);
            if !pred.evaluate(item) {
                return false; // Early termination
            }
        }
        true
    }

    /// Evaluates an OR group across ranked predicates, short-circuiting on first true
    pub fn evaluate_or(&self, item: &T, eval_order_tracker: &mut Vec<u32>) -> bool {
        for pred in &self.predicates {
            eval_order_tracker.push(pred.id);
            if pred.evaluate(item) {
                return true; // Early termination
            }
        }
        false
    }

    pub fn predicate_count(&self) -> usize {
        self.predicates.len()
    }
}
