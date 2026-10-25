use crate::canonical_normalizer::CanonicalEvent;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

pub type PredicateId = u32;

/// Evaluator closure trait for discrete predicates
pub type PredicateEvaluatorFn = Arc<dyn Fn(&CanonicalEvent) -> bool + Send + Sync>;

/// Shared Predicate Node in the CSE DAG
#[derive(Clone)]
pub struct SharedPredicateNode {
    pub id: PredicateId,
    pub hash: u64,
    pub description: String,
    pub evaluator: PredicateEvaluatorFn,
    pub dependent_rules: Vec<String>,
}

/// Bitset evaluation context allocated per event
pub struct EventEvalContext {
    evaluated_mask: Vec<u64>,
    outcome_mask: Vec<u64>,
}

impl EventEvalContext {
    pub fn new(total_predicates: usize) -> Self {
        let words = (total_predicates + 63) / 64;
        Self {
            evaluated_mask: vec![0; words.max(1)],
            outcome_mask: vec![0; words.max(1)],
        }
    }

    #[inline]
    pub fn is_evaluated(&self, id: PredicateId) -> bool {
        let idx = id as usize;
        let word = idx / 64;
        let bit = idx % 64;
        if word < self.evaluated_mask.len() {
            (self.evaluated_mask[word] & (1u64 << bit)) != 0
        } else {
            false
        }
    }

    #[inline]
    pub fn get_outcome(&self, id: PredicateId) -> bool {
        let idx = id as usize;
        let word = idx / 64;
        let bit = idx % 64;
        if word < self.outcome_mask.len() {
            (self.outcome_mask[word] & (1u64 << bit)) != 0
        } else {
            false
        }
    }

    #[inline]
    pub fn record_outcome(&mut self, id: PredicateId, outcome: bool) {
        let idx = id as usize;
        let word = idx / 64;
        let bit = idx % 64;
        if word < self.evaluated_mask.len() {
            self.evaluated_mask[word] |= 1u64 << bit;
            if outcome {
                self.outcome_mask[word] |= 1u64 << bit;
            } else {
                self.outcome_mask[word] &= !(1u64 << bit);
            }
        }
    }
}

/// Common Subexpression Elimination (CSE) Predicate DAG Engine
pub struct SharedPredicateEngine {
    predicates: RwLock<Vec<SharedPredicateNode>>,
    hash_to_id: RwLock<HashMap<u64, PredicateId>>,
    total_evaluations: AtomicU64,
    cache_hits: AtomicU64,
}

impl Default for SharedPredicateEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedPredicateEngine {
    pub fn new() -> Self {
        Self {
            predicates: RwLock::new(Vec::new()),
            hash_to_id: RwLock::new(HashMap::new()),
            total_evaluations: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
        }
    }

    /// Computes canonical hash for a predicate descriptor
    pub fn calculate_hash(field: &str, operator: &str, value: &str) -> u64 {
        let mut h = 0xcbf29ce484222325u64;
        for s in &[field, operator, value] {
            for b in s.as_bytes() {
                h ^= *b as u64;
                h = h.wrapping_mul(0x100000001b3);
            }
            h ^= 0xFF;
        }
        h
    }

    /// Registers a predicate or links an existing duplicate to a new dependent rule
    pub fn register_predicate(
        &self,
        field: &str,
        operator: &str,
        value: &str,
        rule_id: &str,
        evaluator: PredicateEvaluatorFn,
    ) -> PredicateId {
        let hash = Self::calculate_hash(field, operator, value);
        let mut hash_guard = self.hash_to_id.write();

        if let Some(&existing_id) = hash_guard.get(&hash) {
            let mut pred_guard = self.predicates.write();
            pred_guard[existing_id as usize]
                .dependent_rules
                .push(rule_id.to_string());
            existing_id
        } else {
            let mut pred_guard = self.predicates.write();
            let new_id = pred_guard.len() as PredicateId;
            let node = SharedPredicateNode {
                id: new_id,
                hash,
                description: format!("{} {} {}", field, operator, value),
                evaluator,
                dependent_rules: vec![rule_id.to_string()],
            };
            pred_guard.push(node);
            hash_guard.insert(hash, new_id);
            new_id
        }
    }

    /// Creates a blank per-event evaluation context sized for the registered predicate pool
    pub fn create_event_context(&self) -> EventEvalContext {
        let total = self.predicates.read().len();
        EventEvalContext::new(total)
    }

    /// Evaluates predicate with CSE caching: executes exactly once per event
    #[inline]
    pub fn evaluate_predicate(
        &self,
        pred_id: PredicateId,
        event: &CanonicalEvent,
        ctx: &mut EventEvalContext,
    ) -> bool {
        if ctx.is_evaluated(pred_id) {
            self.cache_hits.fetch_add(1, Ordering::Relaxed);
            return ctx.get_outcome(pred_id);
        }

        let eval_fn = {
            let pred_guard = self.predicates.read();
            Arc::clone(&pred_guard[pred_id as usize].evaluator)
        };

        self.total_evaluations.fetch_add(1, Ordering::Relaxed);
        let outcome = eval_fn(event);
        ctx.record_outcome(pred_id, outcome);
        outcome
    }

    pub fn predicate_count(&self) -> usize {
        self.predicates.read().len()
    }

    pub fn stats(&self) -> (u64, u64) {
        (
            self.total_evaluations.load(Ordering::Relaxed),
            self.cache_hits.load(Ordering::Relaxed),
        )
    }
}
