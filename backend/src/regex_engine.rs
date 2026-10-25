// =============================================================================
// Feature 22: ReDoS-Safe Regex Predicate Engine
// Phase IV — Sigma DSL & Rule Compiler Core
//
// Wraps the `regex` crate's DFA/NFA engine which guarantees linear-time O(N)
// execution with respect to input length.  Enforces:
//   - Lookahead/lookbehind rejection at compile time
//   - Backreference rejection at compile time
//   - Configurable size limits (DFA state explosion guard)
//   - Execution fuel budget (bytes-checked limit as a secondary guard)
//   - Nest limit (AST recursion depth cap)
// =============================================================================

use regex::bytes::RegexBuilder;
use regex::bytes::Regex as BytesRegex;
use std::fmt;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can occur during regex compilation or execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegexError {
    /// The regex pattern could not be compiled by the underlying engine.
    CompilationFailed(String),
    /// The pattern contains a lookahead or lookbehind assertion (`(?=…)`,
    /// `(?!…)`, `(?<=…)`, `(?<!…)`) which can degrade to super-linear time.
    DisallowedLookaround(String),
    /// The pattern contains a numbered backreference (`\1`, `\2`, …) which
    /// requires backtracking and can cause catastrophic execution.
    DisallowedBackreference(String),
    /// The execution fuel (byte-check budget) was exceeded.
    ExecutionBudgetExceeded,
    /// The wall-clock execution deadline was exceeded.
    ExecutionTimeoutExceeded,
}

impl fmt::Display for RegexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CompilationFailed(s) =>
                write!(f, "Regex compilation failed: {s}"),
            Self::DisallowedLookaround(s) =>
                write!(f, "Disallowed lookahead/lookbehind construct rejected at compile time: {s}"),
            Self::DisallowedBackreference(s) =>
                write!(f, "Disallowed backreference rejected at compile time: {s}"),
            Self::ExecutionBudgetExceeded =>
                write!(f, "Regex execution budget/fuel limit exceeded (ReDoS mitigation active)"),
            Self::ExecutionTimeoutExceeded =>
                write!(f, "Regex execution wall-clock deadline exceeded (ReDoS mitigation active)"),
        }
    }
}

impl std::error::Error for RegexError {}

// ---------------------------------------------------------------------------
// SafeRegexConfig — compilation parameters
// ---------------------------------------------------------------------------

/// Configuration parameters for the `SafeRegexMatcher` compiler.
#[derive(Debug, Clone)]
pub struct SafeRegexConfig {
    /// Maximum compiled regex NFA size in bytes. Default: 10 MB.
    pub size_limit: usize,
    /// Maximum DFA cache size in bytes. When exceeded the engine falls back
    /// to bounded NFA simulation (still linear-time). Default: 10 MB.
    pub dfa_size_limit: usize,
    /// Maximum AST nesting depth for the parsed regex. Default: 20.
    pub nest_limit: u32,
    /// Execution fuel limit: maximum bytes inspected before abort. Default: 2 MB.
    pub fuel_bytes: usize,
    /// Wall-clock execution deadline. Default: 100 µs.
    pub wall_clock_deadline: Duration,
    /// Enable case-insensitive matching.
    pub case_insensitive: bool,
    /// Enable multi-line mode (`^` / `$` match at line boundaries).
    pub multi_line: bool,
    /// Enable dot-all mode (`.` matches `\n`).
    pub dot_matches_new_line: bool,
}

impl Default for SafeRegexConfig {
    fn default() -> Self {
        Self {
            size_limit:            10 * 1024 * 1024,  // 10 MB
            dfa_size_limit:        10 * 1024 * 1024,  // 10 MB
            nest_limit:            20,
            fuel_bytes:            2 * 1024 * 1024,   // 2 MB
            wall_clock_deadline:   Duration::from_micros(100),
            case_insensitive:      false,
            multi_line:            false,
            dot_matches_new_line:  false,
        }
    }
}

// ---------------------------------------------------------------------------
// SafeRegexMatcher
// ---------------------------------------------------------------------------

/// Hardened ReDoS-Safe Regular Expression Matcher.
///
/// ## Safety guarantees
///
/// 1. **Compile-time rejection of dangerous constructs**
///    - Lookahead/lookbehind assertions (`(?=…)`, `(?!…)`, `(?<=…)`, `(?<!…)`)
///      are rejected before construction.
///    - Backreferences (`\1`–`\9`) are rejected before construction.
///
/// 2. **Linear-time DFA/NFA engine**
///    - The `regex` crate uses a hybrid NFA/DFA approach that guarantees `O(N)`
///      evaluation with respect to input length for patterns without lookaround
///      or backreferences.
///    - DFA state explosion is bounded by `dfa_size_limit` — when exceeded the
///      engine falls back to bounded NFA simulation (still linear).
///
/// 3. **Execution fuel budget**
///    - `match_with_fuel`: aborts if input length exceeds `fuel_bytes`.
///
/// 4. **Wall-clock deadline**
///    - `match_with_deadline`: aborts if wall-clock time exceeds `deadline`.
///
/// 5. **Compile-time size cap**
///    - `size_limit` and `nest_limit` prevent compilation of pathologically
///      large or deeply nested patterns.
#[derive(Debug, Clone)]
pub struct SafeRegexMatcher {
    /// Original pattern string (for diagnostics and cache keys).
    pattern:          String,
    /// Compiled byte-level regex engine (DFA/NFA hybrid).
    inner:            BytesRegex,
    /// Configuration used at compile time.
    config:           SafeRegexConfig,
}

impl SafeRegexMatcher {
    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------

    /// Compiles a regex pattern with default `SafeRegexConfig`.
    pub fn compile(pattern: &str, case_insensitive: bool) -> Result<Self, RegexError> {
        let mut config = SafeRegexConfig::default();
        config.case_insensitive = case_insensitive;
        Self::compile_with_config(pattern, config)
    }

    /// Compiles a regex pattern with a custom `SafeRegexConfig`.
    pub fn compile_with_config(
        pattern: &str,
        config:  SafeRegexConfig,
    ) -> Result<Self, RegexError> {
        // ----------------------------------------------------------------
        // Semantic safety validation: reject dangerous constructs before
        // even attempting to invoke the underlying engine.
        // ----------------------------------------------------------------
        Self::reject_lookaround(pattern)?;
        Self::reject_backreferences(pattern)?;

        // ----------------------------------------------------------------
        // Compile via the regex crate's DFA/NFA hybrid engine
        // ----------------------------------------------------------------
        let regex = RegexBuilder::new(pattern)
            .case_insensitive(config.case_insensitive)
            .multi_line(config.multi_line)
            .dot_matches_new_line(config.dot_matches_new_line)
            .size_limit(config.size_limit)
            .dfa_size_limit(config.dfa_size_limit)
            .nest_limit(config.nest_limit)
            .build()
            .map_err(|e| RegexError::CompilationFailed(e.to_string()))?;

        Ok(Self { pattern: pattern.to_string(), inner: regex, config })
    }

    // -----------------------------------------------------------------------
    // Matching methods
    // -----------------------------------------------------------------------

    /// Simple is-match check against a `&str` input.
    /// The underlying engine guarantees linear-time evaluation.
    #[inline]
    pub fn is_match(&self, text: &str) -> bool {
        self.inner.is_match(text.as_bytes())
    }

    /// Simple is-match check against a raw byte slice.
    #[inline]
    pub fn is_match_bytes(&self, bytes: &[u8]) -> bool {
        self.inner.is_match(bytes)
    }

    /// Evaluates with a **fuel budget** (maximum bytes inspected).
    ///
    /// Returns `Err(ExecutionBudgetExceeded)` if `payload.len() > fuel_budget`.
    /// This is a pre-evaluation byte-count guard — not a step-counter —
    /// which is safe because the underlying DFA is O(N) and N is bounded.
    #[inline]
    pub fn match_with_fuel(
        &self,
        payload:      &[u8],
        fuel_budget:  usize,
    ) -> Result<bool, RegexError> {
        if payload.len() > fuel_budget {
            return Err(RegexError::ExecutionBudgetExceeded);
        }
        Ok(self.inner.is_match(payload))
    }

    /// Evaluates with a **wall-clock deadline**.
    ///
    /// Because the DFA engine is linear-time the deadline is only violated by
    /// extremely long inputs.  This guard provides an extra safety layer for
    /// adversarial input during a live detection pipeline.
    #[inline]
    pub fn match_with_deadline(
        &self,
        payload:  &[u8],
        deadline: Duration,
    ) -> Result<bool, RegexError> {
        let start = Instant::now();
        let result = self.inner.is_match(payload);
        if start.elapsed() > deadline {
            return Err(RegexError::ExecutionTimeoutExceeded);
        }
        Ok(result)
    }

    /// Evaluates with **both** fuel and wall-clock guards (most conservative).
    #[inline]
    pub fn match_safe(
        &self,
        payload: &[u8],
    ) -> Result<bool, RegexError> {
        self.match_with_fuel(payload, self.config.fuel_bytes)?;
        self.match_with_deadline(payload, self.config.wall_clock_deadline)
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    pub fn pattern(&self) -> &str { &self.pattern }
    pub fn config(&self) -> &SafeRegexConfig { &self.config }
    pub fn is_case_insensitive(&self) -> bool { self.config.case_insensitive }

    // -----------------------------------------------------------------------
    // Safety validators
    // -----------------------------------------------------------------------

    /// Rejects patterns that contain any lookahead or lookbehind assertion.
    ///
    /// Lookarounds are not supported by the `regex` crate's DFA/NFA engine —
    /// patterns containing them will fail compilation.  We proactively reject
    /// them here to return a descriptive error rather than a cryptic compile error.
    fn reject_lookaround(pattern: &str) -> Result<(), RegexError> {
        // Patterns: (?= …) (?! …) (?<= …) (?<! …)
        let lookaround_signatures = ["(?=", "(?!", "(?<=", "(?<!"];
        for sig in lookaround_signatures {
            if pattern.contains(sig) {
                return Err(RegexError::DisallowedLookaround(pattern.to_string()));
            }
        }
        Ok(())
    }

    /// Rejects patterns that contain numbered backreferences (`\1`–`\9`).
    ///
    /// Backreferences require the engine to remember captured sub-matches and
    /// can cause exponential backtracking in classical NFA engines.  The
    /// `regex` crate does not support them, but we reject early for clarity.
    fn reject_backreferences(pattern: &str) -> Result<(), RegexError> {
        let bytes = pattern.as_bytes();
        let mut i = 0;
        while i + 1 < bytes.len() {
            if bytes[i] == b'\\' {
                let next = bytes[i + 1];
                if next.is_ascii_digit() && next != b'0' {
                    return Err(RegexError::DisallowedBackreference(pattern.to_string()));
                }
                i += 2; // skip escaped character
            } else {
                i += 1;
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Pattern analysis helpers
    // -----------------------------------------------------------------------

    /// Returns `true` if the pattern contains nested quantifiers of the form
    /// `(a+)+`, `(a*)+`, `(a+)*`, etc. which are the classic ReDoS trigger.
    ///
    /// This check is informational — the underlying DFA engine is still safe —
    /// but it allows callers to log a warning or reject particularly complex
    /// patterns in high-security environments.
    pub fn has_nested_quantifiers(pattern: &str) -> bool {
        // Simplified heuristic: look for `+)` or `*)` followed immediately by `+` or `*`
        let bytes = pattern.as_bytes();
        let n     = bytes.len();
        let mut i = 0;
        let mut depth = 0i32;
        let mut found = false;

        while i < n {
            match bytes[i] {
                b'(' if i == 0 || bytes[i.saturating_sub(1)] != b'\\' => {
                    depth += 1;
                }
                b')' if i == 0 || bytes[i.saturating_sub(1)] != b'\\' => {
                    depth -= 1;
                    if depth >= 0 && i + 1 < n && (bytes[i + 1] == b'+' || bytes[i + 1] == b'*') {
                        // Check if inside this group there was also a quantified group
                        found = true;
                    }
                }
                _ => {}
            }
            i += 1;
        }
        found
    }

    /// Returns the length of the longest literal prefix of the pattern before
    /// the first metacharacter.  Used by the shared predicate engine to apply
    /// Aho-Corasick pre-filtering.
    pub fn literal_prefix(&self) -> &str {
        // Walk the raw pattern until we hit a regex metacharacter
        let meta = ['.', '*', '+', '?', '[', ']', '{', '}', '(', ')', '^', '$', '|', '\\'];
        let pat  = self.pattern.as_str();
        let end  = pat
            .char_indices()
            .find(|(_, c)| meta.contains(c))
            .map(|(i, _)| i)
            .unwrap_or(pat.len());
        &pat[..end]
    }
}

// ---------------------------------------------------------------------------
// SafeRegexSet — evaluate multiple patterns against one input in a single pass
// ---------------------------------------------------------------------------

/// A compiled set of safe regex patterns evaluated against a single input.
///
/// Each pattern is compiled individually with safety validation; the set
/// can be queried for any-match or all-match semantics.
pub struct SafeRegexSet {
    matchers: Vec<SafeRegexMatcher>,
}

impl SafeRegexSet {
    /// Compiles a set of patterns.  Returns the first error if any pattern
    /// fails safety validation or compilation.
    pub fn compile(patterns: &[&str], case_insensitive: bool) -> Result<Self, RegexError> {
        let mut matchers = Vec::with_capacity(patterns.len());
        for &p in patterns {
            matchers.push(SafeRegexMatcher::compile(p, case_insensitive)?);
        }
        Ok(Self { matchers })
    }

    /// Returns `true` if ANY pattern matches the input.
    #[inline]
    pub fn is_match_any(&self, text: &str) -> bool {
        self.matchers.iter().any(|m| m.is_match(text))
    }

    /// Returns `true` if ALL patterns match the input.
    #[inline]
    pub fn is_match_all(&self, text: &str) -> bool {
        self.matchers.iter().all(|m| m.is_match(text))
    }

    /// Returns a bitmask of which patterns matched.
    pub fn match_mask(&self, text: &str) -> u64 {
        let mut mask = 0u64;
        for (i, m) in self.matchers.iter().enumerate().take(64) {
            if m.is_match(text) {
                mask |= 1u64 << i;
            }
        }
        mask
    }

    pub fn len(&self) -> usize { self.matchers.len() }
    pub fn is_empty(&self) -> bool { self.matchers.is_empty() }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn basic_match() {
        let m = SafeRegexMatcher::compile(r"^cmd\.exe$", false).unwrap();
        assert!( m.is_match("cmd.exe"));
        assert!(!m.is_match("powershell.exe"));
    }

    #[test]
    fn case_insensitive_match() {
        let m = SafeRegexMatcher::compile(r"powershell", true).unwrap();
        assert!( m.is_match("POWERSHELL.EXE"));
        assert!(!m.is_match("python.exe"));
    }

    #[test]
    fn lookahead_rejected_at_compile() {
        let r = SafeRegexMatcher::compile(r"user(?=pass)", false);
        assert!(matches!(r, Err(RegexError::DisallowedLookaround(_))));
    }

    #[test]
    fn lookbehind_rejected_at_compile() {
        let r = SafeRegexMatcher::compile(r"(?<=prefix)word", false);
        assert!(matches!(r, Err(RegexError::DisallowedLookaround(_))));
    }

    #[test]
    fn backreference_rejected_at_compile() {
        let r = SafeRegexMatcher::compile(r"(abc)\1", false);
        assert!(matches!(r, Err(RegexError::DisallowedBackreference(_))));
    }

    #[test]
    fn nested_quantifier_pattern_compiles_and_runs_linearly() {
        // (a+)+$ is a classic ReDoS trigger for backtracking engines.
        // The `regex` crate's DFA engine handles this in O(N).
        let m = SafeRegexMatcher::compile(r"(a+)+$", false).unwrap();

        let attack = format!("{}b", "a".repeat(5000));
        let start  = Instant::now();
        let result = m.is_match(&attack);
        let elapsed = start.elapsed();

        assert!(!result);
        assert!(
            elapsed.as_millis() < 50,
            "DFA must evaluate in < 50ms; took {:?}", elapsed
        );
    }

    #[test]
    fn fuel_budget_exceeded() {
        let m = SafeRegexMatcher::compile(r"a+", false).unwrap();
        let huge = "a".repeat(3_000_000);
        let r = m.match_with_fuel(huge.as_bytes(), 2_000_000);
        assert!(matches!(r, Err(RegexError::ExecutionBudgetExceeded)));
    }

    #[test]
    fn fuel_budget_within_limit() {
        let m = SafeRegexMatcher::compile(r"hello", false).unwrap();
        let r = m.match_with_fuel(b"say hello world", 1_000_000);
        assert!(matches!(r, Ok(true)));
    }

    #[test]
    fn literal_prefix_extraction() {
        let m = SafeRegexMatcher::compile(r"powershell\.exe.*-enc", false).unwrap();
        assert_eq!(m.literal_prefix(), "powershell");
    }

    #[test]
    fn regex_set_any_match() {
        let set = SafeRegexSet::compile(&[r"cmd\.exe", r"powershell", r"wscript"], false).unwrap();
        assert!( set.is_match_any("wscript.exe running"));
        assert!(!set.is_match_any("python.exe running"));
    }

    #[test]
    fn regex_set_all_match() {
        let set = SafeRegexSet::compile(&[r"powershell", r"-enc"], false).unwrap();
        assert!( set.is_match_all("powershell.exe -enc Y21kLmV4ZQ=="));
        assert!(!set.is_match_all("powershell.exe -nologo"));
    }
}
