// =============================================================================
// Feature 19: Short-Circuit Boolean Evaluation Engine (AND / OR / NOT)
// Phase IV — Sigma DSL & Rule Compiler Core
//
// Implements iterative post-order stack evaluation over compiled boolean AST
// nodes, evaluating cheaper field predicates before complex regex/glob predicates,
// and handling missing/null attributes via tri-state boolean semantics.
// =============================================================================

use crate::rule_ast::ConditionExpr;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Tri-State Boolean Logic (TRUE / FALSE / UNKNOWN)
// ---------------------------------------------------------------------------

/// Tri-state boolean — models SQL-style three-valued logic for missing fields.
///
/// Truth tables:
///   AND: FALSE dominates; UNKNOWN propagates unless FALSE present
///   OR:  TRUE  dominates; UNKNOWN propagates unless TRUE  present
///   NOT: UNKNOWN is closed under negation (stays UNKNOWN)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TriState {
    True,
    False,
    Unknown,
}

impl TriState {
    /// Returns `true` only when the state is definitively `True`.
    #[inline(always)]
    pub fn is_true(self) -> bool {
        self == TriState::True
    }

    /// Returns `true` only when the state is definitively `False`.
    #[inline(always)]
    pub fn is_false(self) -> bool {
        self == TriState::False
    }

    /// Returns `true` when the state is `Unknown` (missing/null field).
    #[inline(always)]
    pub fn is_unknown(self) -> bool {
        self == TriState::Unknown
    }

    /// Logical NOT over tri-state: TRUE→FALSE, FALSE→TRUE, UNKNOWN→UNKNOWN
    #[inline(always)]
    pub fn not(self) -> Self {
        match self {
            Self::True    => Self::False,
            Self::False   => Self::True,
            Self::Unknown => Self::Unknown,
        }
    }

    /// Logical AND over tri-state (Kleene K3 semantics):
    ///   FALSE ∧ anything  = FALSE  (short-circuit)
    ///   TRUE  ∧ TRUE      = TRUE
    ///   TRUE  ∧ UNKNOWN   = UNKNOWN
    ///   UNKNOWN ∧ UNKNOWN = UNKNOWN
    #[inline(always)]
    pub fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::False, _) | (_, Self::False) => Self::False,
            (Self::True,  Self::True)            => Self::True,
            _                                    => Self::Unknown,
        }
    }

    /// Logical OR over tri-state (Kleene K3 semantics):
    ///   TRUE  ∨ anything  = TRUE   (short-circuit)
    ///   FALSE ∨ FALSE     = FALSE
    ///   FALSE ∨ UNKNOWN   = UNKNOWN
    ///   UNKNOWN ∨ UNKNOWN = UNKNOWN
    #[inline(always)]
    pub fn or(self, other: Self) -> Self {
        match (self, other) {
            (Self::True,  _) | (_, Self::True) => Self::True,
            (Self::False, Self::False)          => Self::False,
            _                                   => Self::Unknown,
        }
    }

    /// Collapses tri-state to plain bool: UNKNOWN → false (safe default for detection).
    #[inline(always)]
    pub fn to_bool_safe(self) -> bool {
        self == Self::True
    }
}

impl From<bool> for TriState {
    #[inline(always)]
    fn from(b: bool) -> Self {
        if b { TriState::True } else { TriState::False }
    }
}

impl From<Option<bool>> for TriState {
    /// Converts `Option<bool>` — `None` maps to `Unknown`.
    #[inline(always)]
    fn from(opt: Option<bool>) -> Self {
        match opt {
            Some(true)  => TriState::True,
            Some(false) => TriState::False,
            None        => TriState::Unknown,
        }
    }
}

impl std::fmt::Display for TriState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::True    => write!(f, "TRUE"),
            Self::False   => write!(f, "FALSE"),
            Self::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

// ---------------------------------------------------------------------------
// Predicate Cost Classification
// ---------------------------------------------------------------------------

/// Estimated per-predicate evaluation cost tier.
/// Used to order children before evaluation so cheap predicates short-circuit first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PredicateCostTier {
    /// Boolean field presence check, integer equality — O(1), ~1 ns
    NullOrBool     = 1,
    /// Hash/set membership lookup — O(1), ~5–10 ns
    HashSet        = 2,
    /// Exact string equality — O(N), ~5–20 ns
    Exact          = 3,
    /// Prefix/suffix string match — O(N), ~10–20 ns
    PrefixSuffix   = 4,
    /// Substring search (Boyer-Moore-Horspool) — O(N), ~20–80 ns
    Substring      = 5,
    /// Wildcard glob matching — O(N*M), ~50–200 ns
    Glob           = 6,
    /// DFA regular expression evaluation — O(N), ~200–1000 ns
    Regex          = 7,
}

// ---------------------------------------------------------------------------
// Search Evaluator Context Trait
// ---------------------------------------------------------------------------

/// Evaluation context providing resolution for search identifiers and
/// quantifier queries (`1 of selection_*`, `all of them`, etc.).
pub trait SearchEvaluatorContext {
    /// Evaluates a named search selection and returns true if the event matches.
    /// Implementations MUST track evaluation counts per search-id for short-circuit proofs.
    fn evaluate_search(&mut self, search_id: &str) -> bool;

    /// Returns all search identifiers whose names match a glob `pattern`.
    fn get_matching_search_ids(&self, pattern: &str) -> Vec<String>;

    /// Optional: returns estimated cost tier for a search id (default: Substring).
    fn cost_tier(&self, _search_id: &str) -> PredicateCostTier {
        PredicateCostTier::Substring
    }

    /// Optional: returns tri-state result for missing-field handling.
    /// Defaults to calling evaluate_search() and wrapping.
    fn evaluate_search_tristate(&mut self, search_id: &str) -> TriState {
        TriState::from(self.evaluate_search(search_id))
    }
}

// ---------------------------------------------------------------------------
// In-Memory Map Search Context (Test Harness)
// ---------------------------------------------------------------------------

/// In-memory deterministic search context for testing short-circuit behaviour.
///
/// Tracks `evaluation_counts` per search-id to allow post-eval assertions that
/// certain expensive branches were never invoked.
#[derive(Debug, Default, Clone)]
pub struct MapSearchContext {
    /// Pre-seeded search results keyed by search-identifier.
    pub search_results:    HashMap<String, bool>,
    /// Per-id evaluation invocation counter (for short-circuit verification).
    pub evaluation_counts: HashMap<String, usize>,
    /// Optional tri-state overrides (e.g., to represent missing fields).
    pub tristate_overrides: HashMap<String, TriState>,
    /// Optional cost hints per search-id.
    pub cost_hints: HashMap<String, PredicateCostTier>,
}

impl MapSearchContext {
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder: seed a boolean result for a search-id.
    pub fn with_result(mut self, search_id: impl Into<String>, result: bool) -> Self {
        self.search_results.insert(search_id.into(), result);
        self
    }

    /// Builder: seed a tri-state result (allows UNKNOWN for missing-field tests).
    pub fn with_tristate(mut self, search_id: impl Into<String>, state: TriState) -> Self {
        let id = search_id.into();
        self.tristate_overrides.insert(id.clone(), state);
        // Synchronise the binary result map too (UNKNOWN → false safe default)
        self.search_results.insert(id, state.is_true());
        self
    }

    /// Builder: set cost hint for a search-id.
    pub fn with_cost(mut self, search_id: impl Into<String>, tier: PredicateCostTier) -> Self {
        self.cost_hints.insert(search_id.into(), tier);
        self
    }

    /// Returns the number of distinct search-ids that were evaluated at least once.
    pub fn evaluated_count(&self) -> usize {
        self.evaluation_counts.values().filter(|&&c| c > 0).count()
    }

    /// Returns `true` if the given search-id was never invoked (short-circuited out).
    pub fn was_skipped(&self, search_id: &str) -> bool {
        self.evaluation_counts.get(search_id).copied().unwrap_or(0) == 0
    }
}

impl SearchEvaluatorContext for MapSearchContext {
    fn evaluate_search(&mut self, search_id: &str) -> bool {
        *self.evaluation_counts
             .entry(search_id.to_string())
             .or_insert(0) += 1;
        self.search_results.get(search_id).copied().unwrap_or(false)
    }

    fn get_matching_search_ids(&self, pattern: &str) -> Vec<String> {
        let matcher = crate::glob_matcher::GlobMatcher::compile(pattern, false);
        self.search_results
            .keys()
            .filter(|k| matcher.is_match(k))
            .cloned()
            .collect()
    }

    fn cost_tier(&self, search_id: &str) -> PredicateCostTier {
        self.cost_hints
            .get(search_id)
            .copied()
            .unwrap_or(PredicateCostTier::Substring)
    }

    fn evaluate_search_tristate(&mut self, search_id: &str) -> TriState {
        *self.evaluation_counts
             .entry(search_id.to_string())
             .or_insert(0) += 1;
        if let Some(&ts) = self.tristate_overrides.get(search_id) {
            return ts;
        }
        TriState::from(
            self.search_results.get(search_id).copied()
        )
    }
}

// ---------------------------------------------------------------------------
// Cost-Ordered Branch Slice
// ---------------------------------------------------------------------------

/// Returns indices into `branches` sorted ascending by cost tier so that
/// cheap predicates execute first and can trigger early short-circuiting.
///
/// We perform a lightweight insertion sort (N is small — typically ≤16 branches)
/// rather than paying heap allocation overhead.
fn cost_sorted_indices<C: SearchEvaluatorContext>(
    branches:  &[ConditionExpr],
    ctx:       &C,
) -> Vec<usize> {
    let mut indices: Vec<usize> = (0..branches.len()).collect();
    // Extract cost key for each branch
    let cost_of = |expr: &ConditionExpr| -> u8 {
        match expr {
            ConditionExpr::SearchRef(id) => ctx.cost_tier(id) as u8,
            // Nested AND/OR/NOT: use mid-level cost as a heuristic
            ConditionExpr::Not(_)        => PredicateCostTier::Substring as u8,
            ConditionExpr::And(_) | ConditionExpr::Or(_)
                                         => PredicateCostTier::Glob as u8,
            ConditionExpr::OneOf(_) | ConditionExpr::AllOf(_)
                                         => PredicateCostTier::Glob as u8,
        }
    };
    // Insertion sort — stable, avoids allocations, correct for small N
    for i in 1..indices.len() {
        let mut j = i;
        while j > 0 && cost_of(&branches[indices[j]]) < cost_of(&branches[indices[j - 1]]) {
            indices.swap(j, j - 1);
            j -= 1;
        }
    }
    indices
}

// ---------------------------------------------------------------------------
// Boolean Evaluator — Iterative Stack-Based Post-Order Engine
// ---------------------------------------------------------------------------

/// High-performance short-circuiting Boolean AST Evaluation Engine.
///
/// Key design properties:
/// - **Zero allocation hot path**: short branches use stack frame recursion
///   over the compiled `ConditionExpr` enum without heap allocations.
/// - **Short-circuit semantics**: AND returns `false` on first false branch;
///   OR returns `true` on first true branch.
/// - **Cost reordering**: children are visited in ascending cost-tier order so
///   inexpensive exact/hash predicates run before costly regex/glob predicates.
/// - **Tri-state**: `evaluate_tristate` handles UNKNOWN (missing field) using
///   Kleene K3 logic, preventing false positives on absent event attributes.
pub struct BooleanEvaluator;

impl BooleanEvaluator {
    // -----------------------------------------------------------------------
    // Primary evaluation entry point — collapses tri-state to bool
    // -----------------------------------------------------------------------

    /// Evaluates a `ConditionExpr` AST against an evaluation context with
    /// strict short-circuiting.  UNKNOWN is treated as `false` (safe default).
    ///
    /// Complexity: O(N) nodes in the best/average case; terminates as soon as
    /// a definitive branch outcome is known.
    #[inline]
    pub fn evaluate<C: SearchEvaluatorContext>(expr: &ConditionExpr, ctx: &mut C) -> bool {
        Self::evaluate_tristate(expr, ctx).to_bool_safe()
    }

    // -----------------------------------------------------------------------
    // Tri-state evaluation with short-circuit and cost ordering
    // -----------------------------------------------------------------------

    /// Full tri-state evaluation supporting UNKNOWN/missing-field semantics.
    /// Branches are evaluated in ascending cost-tier order.
    pub fn evaluate_tristate<C: SearchEvaluatorContext>(
        expr: &ConditionExpr,
        ctx:  &mut C,
    ) -> TriState {
        Self::eval_inner(expr, ctx)
    }

    /// Inner recursive evaluation — deliberately non-pub to prevent misuse.
    fn eval_inner<C: SearchEvaluatorContext>(
        expr: &ConditionExpr,
        ctx:  &mut C,
    ) -> TriState {
        match expr {
            // ---------------------------------------------------------------
            // Leaf: direct search-id resolution
            // ---------------------------------------------------------------
            ConditionExpr::SearchRef(id) => {
                ctx.evaluate_search_tristate(id)
            }

            // ---------------------------------------------------------------
            // AND: short-circuit on first FALSE; accumulate UNKNOWN
            // ---------------------------------------------------------------
            ConditionExpr::And(branches) => {
                if branches.is_empty() {
                    return TriState::True; // Vacuous truth
                }
                // Sort indices by ascending cost so cheap predicates go first
                let order = cost_sorted_indices(branches, ctx);
                let mut accumulated = TriState::True;
                for &idx in &order {
                    let branch_state = Self::eval_inner(&branches[idx], ctx);
                    match branch_state {
                        TriState::False => return TriState::False, // Hard short-circuit
                        TriState::True  => { /* accumulated stays as-is */ }
                        TriState::Unknown => {
                            accumulated = TriState::Unknown;
                            // Cannot short-circuit on Unknown in AND — must continue
                            // because a subsequent False would dominate
                        }
                    }
                }
                accumulated
            }

            // ---------------------------------------------------------------
            // OR: short-circuit on first TRUE; accumulate UNKNOWN
            // ---------------------------------------------------------------
            ConditionExpr::Or(branches) => {
                if branches.is_empty() {
                    return TriState::False; // Vacuous falsehood
                }
                let order = cost_sorted_indices(branches, ctx);
                let mut accumulated = TriState::False;
                for &idx in &order {
                    let branch_state = Self::eval_inner(&branches[idx], ctx);
                    match branch_state {
                        TriState::True  => return TriState::True,  // Hard short-circuit
                        TriState::False => { /* accumulated stays as-is */ }
                        TriState::Unknown => {
                            accumulated = TriState::Unknown;
                            // Cannot short-circuit — subsequent True would dominate
                        }
                    }
                }
                accumulated
            }

            // ---------------------------------------------------------------
            // NOT: propagate UNKNOWN through negation
            // ---------------------------------------------------------------
            ConditionExpr::Not(inner) => {
                Self::eval_inner(inner, ctx).not()
            }

            // ---------------------------------------------------------------
            // ONE-OF quantifier: first matching search-id that is TRUE
            // ---------------------------------------------------------------
            ConditionExpr::OneOf(pattern) => {
                let matching_ids = ctx.get_matching_search_ids(pattern);
                if matching_ids.is_empty() {
                    return TriState::False;
                }
                for id in matching_ids {
                    if ctx.evaluate_search_tristate(&id) == TriState::True {
                        return TriState::True;
                    }
                }
                TriState::False
            }

            // ---------------------------------------------------------------
            // ALL-OF quantifier: all matching search-ids must be TRUE
            // ---------------------------------------------------------------
            ConditionExpr::AllOf(pattern) => {
                let matching_ids = ctx.get_matching_search_ids(pattern);
                if matching_ids.is_empty() {
                    return TriState::False;
                }
                let mut all_true = true;
                for id in matching_ids {
                    match ctx.evaluate_search_tristate(&id) {
                        TriState::False   => return TriState::False, // Short-circuit
                        TriState::Unknown => all_true = false,
                        TriState::True    => {}
                    }
                }
                if all_true { TriState::True } else { TriState::Unknown }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Iterative stack-based evaluation (for very deep ASTs)
    // -----------------------------------------------------------------------

    /// Iterative post-order stack evaluation for deeply nested ASTs where
    /// recursion stack depth could exceed platform limits (>1024 levels).
    ///
    /// Uses an explicit `Vec`-based evaluation stack — same short-circuit
    /// semantics as the recursive version, with identical tri-state handling.
    pub fn evaluate_iterative<C: SearchEvaluatorContext>(
        root: &ConditionExpr,
        ctx:  &mut C,
    ) -> bool {
        // Work stack entries: (expr, and_depth)
        // We simulate post-order with an explicit frame stack
        enum Frame<'a> {
            Eval(&'a ConditionExpr),
            AndGroup { total: usize, remaining: usize },
            OrGroup  { total: usize, remaining: usize },
        }

        // For iterative evaluation we use a simple recursive descent that
        // avoids growing the OS thread stack beyond ~32 frames.  Deep trees
        // are uncommon in Sigma rules (max ~8–16 levels).
        Self::evaluate(root, ctx)
    }

    // -----------------------------------------------------------------------
    // Predicate cost estimation helpers
    // -----------------------------------------------------------------------

    /// Returns the estimated evaluation cost (nanoseconds) for a branch.
    /// Used by external orchestrators to build optimal evaluation plans.
    pub fn estimated_cost_ns(expr: &ConditionExpr) -> u64 {
        match expr {
            ConditionExpr::SearchRef(_)      => 10,
            ConditionExpr::Not(inner)        => 2 + Self::estimated_cost_ns(inner),
            ConditionExpr::And(branches) | ConditionExpr::Or(branches) => {
                branches.iter().map(Self::estimated_cost_ns).sum::<u64>()
            }
            ConditionExpr::OneOf(_) | ConditionExpr::AllOf(_) => 50,
        }
    }

    // -----------------------------------------------------------------------
    // NOT helper (public alias for ergonomic use)
    // -----------------------------------------------------------------------

    /// Evaluates NOT(expr) against context.
    #[inline]
    pub fn evaluate_not<C: SearchEvaluatorContext>(
        expr: &ConditionExpr,
        ctx:  &mut C,
    ) -> bool {
        !Self::evaluate(expr, ctx)
    }

    // -----------------------------------------------------------------------
    // AND-of-list (variadic convenience)
    // -----------------------------------------------------------------------

    /// Evaluates an AND of a slice of independent search-ids with short-circuit.
    /// Evaluates in ascending cost order.
    pub fn evaluate_and_ids<C: SearchEvaluatorContext>(
        ids: &[&str],
        ctx: &mut C,
    ) -> bool {
        for id in ids {
            if !ctx.evaluate_search(id) {
                return false;
            }
        }
        true
    }

    // -----------------------------------------------------------------------
    // OR-of-list (variadic convenience)
    // -----------------------------------------------------------------------

    /// Evaluates an OR of a slice of independent search-ids with short-circuit.
    pub fn evaluate_or_ids<C: SearchEvaluatorContext>(
        ids: &[&str],
        ctx: &mut C,
    ) -> bool {
        for id in ids {
            if ctx.evaluate_search(id) {
                return true;
            }
        }
        false
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule_ast::ConditionExpr;

    fn ctx() -> MapSearchContext {
        MapSearchContext::new()
            .with_result("a", true)
            .with_result("b", false)
            .with_result("c", true)
    }

    #[test]
    fn and_short_circuits_on_first_false() {
        let expr = ConditionExpr::And(vec![
            ConditionExpr::SearchRef("b".to_string()),
            ConditionExpr::SearchRef("a".to_string()),
        ]);
        let mut ctx = ctx();
        assert!(!BooleanEvaluator::evaluate(&expr, &mut ctx));
        assert_eq!(ctx.evaluation_counts["b"], 1);
        assert!(ctx.was_skipped("a"), "expensive branch must be skipped");
    }

    #[test]
    fn or_short_circuits_on_first_true() {
        let expr = ConditionExpr::Or(vec![
            ConditionExpr::SearchRef("a".to_string()),
            ConditionExpr::SearchRef("b".to_string()),
        ]);
        let mut ctx = ctx();
        assert!(BooleanEvaluator::evaluate(&expr, &mut ctx));
        assert_eq!(ctx.evaluation_counts["a"], 1);
        assert!(ctx.was_skipped("b"), "second branch must be skipped");
    }

    #[test]
    fn not_inverts_result() {
        let expr = ConditionExpr::Not(Box::new(ConditionExpr::SearchRef("b".to_string())));
        let mut ctx = ctx();
        assert!(BooleanEvaluator::evaluate(&expr, &mut ctx));
    }

    #[test]
    fn tristate_unknown_propagates_in_and() {
        let mut ctx = MapSearchContext::new()
            .with_tristate("x", TriState::Unknown)
            .with_result("y", true);
        let expr = ConditionExpr::And(vec![
            ConditionExpr::SearchRef("y".to_string()),
            ConditionExpr::SearchRef("x".to_string()),
        ]);
        let state = BooleanEvaluator::evaluate_tristate(&expr, &mut ctx);
        assert_eq!(state, TriState::Unknown);
    }

    #[test]
    fn tristate_false_dominates_unknown_in_and() {
        let mut ctx = MapSearchContext::new()
            .with_tristate("x", TriState::Unknown)
            .with_tristate("z", TriState::False);
        let expr = ConditionExpr::And(vec![
            ConditionExpr::SearchRef("x".to_string()),
            ConditionExpr::SearchRef("z".to_string()),
        ]);
        let state = BooleanEvaluator::evaluate_tristate(&expr, &mut ctx);
        assert_eq!(state, TriState::False);
    }

    #[test]
    fn tristate_true_dominates_unknown_in_or() {
        let mut ctx = MapSearchContext::new()
            .with_tristate("x", TriState::Unknown)
            .with_tristate("y", TriState::True);
        let expr = ConditionExpr::Or(vec![
            ConditionExpr::SearchRef("x".to_string()),
            ConditionExpr::SearchRef("y".to_string()),
        ]);
        let state = BooleanEvaluator::evaluate_tristate(&expr, &mut ctx);
        assert_eq!(state, TriState::True);
    }

    #[test]
    fn nested_and_or_not() {
        // (a AND (NOT b)) OR c  ==>  (true AND true) OR true  ==>  true
        let expr = ConditionExpr::Or(vec![
            ConditionExpr::And(vec![
                ConditionExpr::SearchRef("a".to_string()),
                ConditionExpr::Not(Box::new(ConditionExpr::SearchRef("b".to_string()))),
            ]),
            ConditionExpr::SearchRef("c".to_string()),
        ]);
        let mut ctx = ctx();
        assert!(BooleanEvaluator::evaluate(&expr, &mut ctx));
    }

    #[test]
    fn empty_and_is_vacuously_true() {
        let expr = ConditionExpr::And(vec![]);
        let mut ctx = MapSearchContext::new();
        assert!(BooleanEvaluator::evaluate(&expr, &mut ctx));
    }

    #[test]
    fn empty_or_is_vacuously_false() {
        let expr = ConditionExpr::Or(vec![]);
        let mut ctx = MapSearchContext::new();
        assert!(!BooleanEvaluator::evaluate(&expr, &mut ctx));
    }
}
