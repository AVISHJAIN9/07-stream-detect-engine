// =============================================================================
// Feature 21: Typed Numeric Comparison Operators
// Phase IV — Sigma DSL & Rule Compiler Core
//
// Implements eq, neq, lt, lte, gt, gte, and closed/half-open range [min,max]
// operators with dynamic coercion from string, integer, float, hex, and boolean
// ValueVariant inputs.  All hot paths are #[inline] for zero-overhead dispatch.
// =============================================================================

use crate::types::ValueVariant;
use std::fmt;

// ---------------------------------------------------------------------------
// NumericOp — the operator enum
// ---------------------------------------------------------------------------

/// Supported numeric comparison operators for Sigma numeric predicates.
///
/// `Between(min, max)` is the closed interval `[min, max]` — both bounds
/// are inclusive, matching YAML range expressions like `gt|lt` compound pairs.
#[derive(Debug, Clone, PartialEq)]
pub enum NumericOp {
    /// `== val` — exact equality within IEEE-754 epsilon for floats
    Equal(f64),
    /// `!= val` — strict inequality
    NotEqual(f64),
    /// `< threshold`
    LessThan(f64),
    /// `<= threshold`
    LessThanOrEqual(f64),
    /// `> threshold`
    GreaterThan(f64),
    /// `>= threshold`
    GreaterThanOrEqual(f64),
    /// Closed interval `[min, max]`  (both bounds inclusive)
    Between(f64, f64),
    /// Half-open interval `[min, max)` (min inclusive, max exclusive)
    BetweenHalfOpen(f64, f64),
}

impl fmt::Display for NumericOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Equal(v)              => write!(f, "== {v}"),
            Self::NotEqual(v)           => write!(f, "!= {v}"),
            Self::LessThan(v)           => write!(f, "< {v}"),
            Self::LessThanOrEqual(v)    => write!(f, "<= {v}"),
            Self::GreaterThan(v)        => write!(f, "> {v}"),
            Self::GreaterThanOrEqual(v) => write!(f, ">= {v}"),
            Self::Between(lo, hi)       => write!(f, "in [{lo}, {hi}]"),
            Self::BetweenHalfOpen(lo, hi) => write!(f, "in [{lo}, {hi})"),
        }
    }
}

// ---------------------------------------------------------------------------
// Coercion helpers
// ---------------------------------------------------------------------------

/// Value Coercion Result — carries both the f64 and i128 interpretations
/// so callers can choose the most precise representation.
#[derive(Debug, Clone, Copy)]
pub struct NumericCoercion {
    /// Floating-point representation (always available on success)
    pub as_f64: f64,
    /// Integer representation — `Some` when the value was an exact integer
    pub as_i64: Option<i64>,
}

impl NumericCoercion {
    #[inline]
    fn from_i64(i: i64) -> Self {
        Self { as_f64: i as f64, as_i64: Some(i) }
    }
    #[inline]
    fn from_f64(f: f64) -> Self {
        // If f is an integer-valued float, expose the i64 path for exact comparison
        let as_i64 = if f.fract() == 0.0 && f >= i64::MIN as f64 && f <= i64::MAX as f64 {
            Some(f as i64)
        } else {
            None
        };
        Self { as_f64: f, as_i64 }
    }
}

// ---------------------------------------------------------------------------
// NumericPredicate
// ---------------------------------------------------------------------------

/// Dynamic Coercion-Safe Scalar Numeric Predicate Evaluator.
///
/// Design decisions:
/// - **Integer fast path**: when both the operator constant and the input value
///   are integer-valued, the comparison is done with exact i64 arithmetic to
///   avoid IEEE-754 rounding errors for large integer values (>2^53).
/// - **String coercion**: supports decimal digits, negative values, hex `0x…`,
///   and scientific notation — all parsed without panicking.
/// - **Boundary precision**: `Between(8000.0, 8443.0)` is inclusive on both
///   bounds; the implementation uses `>=` and `<=` comparisons to guarantee
///   correctness at exact boundary values.
#[derive(Debug, Clone, PartialEq)]
pub struct NumericPredicate {
    pub op: NumericOp,
}

impl NumericPredicate {
    pub fn new(op: NumericOp) -> Self {
        Self { op }
    }

    // -----------------------------------------------------------------------
    // Main evaluate dispatch
    // -----------------------------------------------------------------------

    /// Evaluates the numeric predicate against a dynamically typed `ValueVariant`.
    ///
    /// Returns `false` for non-numeric types (Null, Bytes, Array, Map) rather
    /// than panicking, to model safe "unknown field" semantics.
    #[inline]
    pub fn evaluate(&self, val: &ValueVariant) -> bool {
        let coerced = match Self::coerce(val) {
            Some(c) => c,
            None    => return false,
        };

        // Use i64 fast path when possible (avoids FP rounding for integers)
        if let (Some(iv), Some(op_i)) = (coerced.as_i64, self.op_as_i64()) {
            return self.compare_i64(iv, op_i);
        }

        self.compare_f64(coerced.as_f64)
    }

    // -----------------------------------------------------------------------
    // i64 fast path
    // -----------------------------------------------------------------------

    /// Evaluates the predicate directly against an `i64` value.
    /// Called by internal hot loops when the source type is known to be `i64`.
    #[inline]
    pub fn evaluate_i64(&self, val: i64) -> bool {
        if let Some(op_i) = self.op_as_i64() {
            return self.compare_i64(val, op_i);
        }
        self.compare_f64(val as f64)
    }

    // -----------------------------------------------------------------------
    // f64 comparison
    // -----------------------------------------------------------------------

    #[inline]
    fn compare_f64(&self, v: f64) -> bool {
        match self.op {
            NumericOp::Equal(e)              => Self::f64_eq(v, e),
            NumericOp::NotEqual(e)           => !Self::f64_eq(v, e),
            NumericOp::LessThan(t)           => v < t,
            NumericOp::LessThanOrEqual(t)    => v <= t,
            NumericOp::GreaterThan(t)        => v > t,
            NumericOp::GreaterThanOrEqual(t) => v >= t,
            NumericOp::Between(lo, hi)       => v >= lo && v <= hi,
            NumericOp::BetweenHalfOpen(lo, hi) => v >= lo && v < hi,
        }
    }

    // -----------------------------------------------------------------------
    // i64 comparison
    // -----------------------------------------------------------------------

    #[inline]
    fn compare_i64(&self, v: i64, op_val: i64) -> bool {
        match self.op {
            NumericOp::Equal(_)              => v == op_val,
            NumericOp::NotEqual(_)           => v != op_val,
            NumericOp::LessThan(_)           => v < op_val,
            NumericOp::LessThanOrEqual(_)    => v <= op_val,
            NumericOp::GreaterThan(_)        => v > op_val,
            NumericOp::GreaterThanOrEqual(_) => v >= op_val,
            NumericOp::Between(lo, hi)       => {
                v >= lo as i64 && v <= hi as i64
            }
            NumericOp::BetweenHalfOpen(lo, hi) => {
                v >= lo as i64 && v < hi as i64
            }
        }
    }

    // -----------------------------------------------------------------------
    // Coerce op constant to i64 when it is integer-valued
    // -----------------------------------------------------------------------

    #[inline]
    fn op_as_i64(&self) -> Option<i64> {
        let f = match self.op {
            NumericOp::Equal(v)
            | NumericOp::NotEqual(v)
            | NumericOp::LessThan(v)
            | NumericOp::LessThanOrEqual(v)
            | NumericOp::GreaterThan(v)
            | NumericOp::GreaterThanOrEqual(v) => v,
            // For range ops the fast path comparison is done in compare_i64 using the bounds directly
            NumericOp::Between(_, _)
            | NumericOp::BetweenHalfOpen(_, _) => return Some(0), // sentinel — not actually used
        };
        if f.fract() == 0.0 && f >= i64::MIN as f64 && f <= i64::MAX as f64 {
            Some(f as i64)
        } else {
            None
        }
    }

    // -----------------------------------------------------------------------
    // IEEE-754 equality (epsilon comparison)
    // -----------------------------------------------------------------------

    /// IEEE-754 approximate equality using machine epsilon relative to the
    /// magnitude of the operands (ULP-inspired but simpler for detection use).
    #[inline]
    fn f64_eq(a: f64, b: f64) -> bool {
        if a == b {
            return true; // Handles ±0, identical bits, NaN (NaN≠NaN)
        }
        // Relative epsilon: tolerate rounding in the last ~4 bits
        let scale = a.abs().max(b.abs()).max(1.0);
        (a - b).abs() < scale * 4.0 * f64::EPSILON
    }

    // -----------------------------------------------------------------------
    // Universal coercion from ValueVariant
    // -----------------------------------------------------------------------

    /// Coerces any `ValueVariant` to a `NumericCoercion` struct.
    ///
    /// Supported conversions:
    /// - `Int(i)`      → exact i64 + f64
    /// - `Float(f)`    → f64 (and i64 if integer-valued)
    /// - `Bool(b)`     → 1.0 / 0.0
    /// - `String(s)`   → decimal, negative, hex `0x…`, scientific notation
    /// - `Null`, `Bytes`, `Array`, `Map` → `None`
    #[inline]
    pub fn coerce(val: &ValueVariant) -> Option<NumericCoercion> {
        match val {
            ValueVariant::Int(i)    => Some(NumericCoercion::from_i64(*i)),
            ValueVariant::Float(f)  => Some(NumericCoercion::from_f64(*f)),
            ValueVariant::Bool(b)   => Some(NumericCoercion::from_i64(if *b { 1 } else { 0 })),
            ValueVariant::String(s) => Self::coerce_string(s.trim()),
            _                       => None,
        }
    }

    /// Stable public alias for external callers.
    #[inline]
    pub fn coerce_to_f64(val: &ValueVariant) -> Option<f64> {
        Self::coerce(val).map(|c| c.as_f64)
    }

    /// Parses a string into a `NumericCoercion`, supporting:
    ///   - Decimal integers (positive and negative)
    ///   - Hexadecimal `0x…` / `0X…` prefixed values
    ///   - IEEE-754 floating-point (including `-inf`, `inf`, `nan`)
    ///   - Octal `0o…` / `0O…` prefixed values
    ///   - Binary `0b…` / `0B…` prefixed values
    fn coerce_string(s: &str) -> Option<NumericCoercion> {
        if s.is_empty() {
            return None;
        }

        // Hexadecimal: 0x… / 0X…
        if s.starts_with("0x") || s.starts_with("0X") {
            let hex = &s[2..];
            if let Ok(i) = u64::from_str_radix(hex, 16) {
                return Some(NumericCoercion::from_i64(i as i64));
            }
            return None;
        }

        // Octal: 0o… / 0O…
        if s.starts_with("0o") || s.starts_with("0O") {
            let oct = &s[2..];
            if let Ok(i) = u64::from_str_radix(oct, 8) {
                return Some(NumericCoercion::from_i64(i as i64));
            }
            return None;
        }

        // Binary: 0b… / 0B…
        if s.starts_with("0b") || s.starts_with("0B") {
            let bin = &s[2..];
            if let Ok(i) = u64::from_str_radix(bin, 2) {
                return Some(NumericCoercion::from_i64(i as i64));
            }
            return None;
        }

        // Try exact integer parse first (avoids f64 rounding for large ints)
        if let Ok(i) = s.parse::<i64>() {
            return Some(NumericCoercion::from_i64(i));
        }

        // Fall back to f64 (handles 8080.0, -3.14, 1e9, inf, nan, etc.)
        if let Ok(f) = s.parse::<f64>() {
            return Some(NumericCoercion::from_f64(f));
        }

        None
    }
}

// ---------------------------------------------------------------------------
// NumericPredicateSet — list of numeric predicates evaluated together
// ---------------------------------------------------------------------------

/// Evaluates multiple numeric predicates against a single value.
/// All predicates must match for the result to be `true` (AND semantics).
pub struct NumericPredicateSet {
    pub predicates: Vec<NumericPredicate>,
}

impl NumericPredicateSet {
    pub fn new(predicates: Vec<NumericPredicate>) -> Self {
        Self { predicates }
    }

    /// Returns `true` iff ALL predicates match (short-circuits on first false).
    #[inline]
    pub fn evaluate_all(&self, val: &ValueVariant) -> bool {
        for pred in &self.predicates {
            if !pred.evaluate(val) {
                return false;
            }
        }
        true
    }

    /// Returns `true` iff ANY predicate matches (short-circuits on first true).
    #[inline]
    pub fn evaluate_any(&self, val: &ValueVariant) -> bool {
        for pred in &self.predicates {
            if pred.evaluate(val) {
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
    use crate::types::ValueVariant;

    fn v_int(i: i64) -> ValueVariant   { ValueVariant::Int(i) }
    fn v_str(s: &str) -> ValueVariant  { ValueVariant::String(s.to_string()) }
    fn v_flt(f: f64) -> ValueVariant   { ValueVariant::Float(f) }

    // --- Equal ---
    #[test]
    fn equal_int_hit()   { assert!( NumericPredicate::new(NumericOp::Equal(443.0)).evaluate(&v_int(443))); }
    #[test]
    fn equal_int_miss()  { assert!(!NumericPredicate::new(NumericOp::Equal(443.0)).evaluate(&v_int(80))); }

    // --- String coercion ---
    #[test]
    fn string_port_coercion() {
        let p = NumericPredicate::new(NumericOp::Equal(8080.0));
        assert!( p.evaluate(&v_str("8080")));
        assert!(!p.evaluate(&v_str("9000")));
    }
    #[test]
    fn hex_coercion() {
        let p = NumericPredicate::new(NumericOp::Equal(255.0));
        assert!( p.evaluate(&v_str("0xFF")));
        assert!( p.evaluate(&v_str("0XFF")));
    }
    #[test]
    fn negative_string_coercion() {
        let p = NumericPredicate::new(NumericOp::LessThan(0.0));
        assert!( p.evaluate(&v_str("-42")));
    }

    // --- Between ---
    #[test]
    fn between_inclusive_bounds() {
        let p = NumericPredicate::new(NumericOp::Between(8000.0, 8443.0));
        assert!( p.evaluate(&v_int(8000)));  // lower bound inclusive
        assert!( p.evaluate(&v_int(8080)));
        assert!( p.evaluate(&v_int(8443)));  // upper bound inclusive
        assert!(!p.evaluate(&v_int(7999)));
        assert!(!p.evaluate(&v_int(8444)));
    }
    #[test]
    fn between_string_value() {
        let p = NumericPredicate::new(NumericOp::Between(8000.0, 8443.0));
        assert!( p.evaluate(&v_str("8080")));
        assert!(!p.evaluate(&v_str("443")));
        assert!(!p.evaluate(&v_str("9000")));
    }

    // --- LessThan / GreaterThan ---
    #[test]
    fn lt_and_gt() {
        let lt = NumericPredicate::new(NumericOp::LessThan(100.0));
        let gt = NumericPredicate::new(NumericOp::GreaterThan(100.0));
        assert!( lt.evaluate(&v_int(99)));
        assert!(!lt.evaluate(&v_int(100)));
        assert!(!lt.evaluate(&v_int(101)));
        assert!( gt.evaluate(&v_int(101)));
        assert!(!gt.evaluate(&v_int(100)));
    }

    // --- Float ---
    #[test]
    fn float_value() {
        let p = NumericPredicate::new(NumericOp::GreaterThan(3.14));
        assert!( p.evaluate(&v_flt(3.15)));
        assert!(!p.evaluate(&v_flt(3.14)));
    }

    // --- Null / non-numeric → false ---
    #[test]
    fn null_returns_false() {
        let p = NumericPredicate::new(NumericOp::Equal(0.0));
        assert!(!p.evaluate(&ValueVariant::Null));
    }

    // --- Binary / octal radix ---
    #[test]
    fn binary_radix() {
        let p = NumericPredicate::new(NumericOp::Equal(5.0));
        assert!( p.evaluate(&v_str("0b101")));
    }
    #[test]
    fn octal_radix() {
        let p = NumericPredicate::new(NumericOp::Equal(8.0));
        assert!( p.evaluate(&v_str("0o10")));
    }

    // --- Predicate set ---
    #[test]
    fn predicate_set_all() {
        let set = NumericPredicateSet::new(vec![
            NumericPredicate::new(NumericOp::GreaterThanOrEqual(1024.0)),
            NumericPredicate::new(NumericOp::LessThan(65536.0)),
        ]);
        assert!( set.evaluate_all(&v_int(8080)));
        assert!(!set.evaluate_all(&v_int(80)));
        assert!(!set.evaluate_all(&v_int(65536)));
    }
}
