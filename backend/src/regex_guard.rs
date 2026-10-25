use regex::bytes::Regex as BytesRegex;
use regex::bytes::RegexBuilder;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegexGuardError {
    CompilationError(String),
    FuelExhausted { attempted_bytes: usize, fuel_budget: usize },
    TimeoutExpired,
}

impl fmt::Display for RegexGuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CompilationError(e) => write!(f, "Regex compilation error: {}", e),
            Self::FuelExhausted { attempted_bytes, fuel_budget } => {
                write!(
                    f,
                    "Regex execution aborted: fuel exhausted (attempted {} bytes, budget {})",
                    attempted_bytes, fuel_budget
                )
            }
            Self::TimeoutExpired => write!(f, "Regex execution aborted: timeout expired"),
        }
    }
}

impl std::error::Error for RegexGuardError {}

/// Resource-Bounded Sandboxed Regular Expression Matcher
pub struct GuardedRegexMatcher {
    pattern: String,
    inner: BytesRegex,
    default_fuel_budget: usize,
    throttled_count: AtomicU64,
}

impl GuardedRegexMatcher {
    pub fn compile(pattern: &str, case_insensitive: bool, default_fuel_budget: usize) -> Result<Self, RegexGuardError> {
        let regex = RegexBuilder::new(pattern)
            .case_insensitive(case_insensitive)
            .size_limit(10 * 1024 * 1024)
            .dfa_size_limit(10 * 1024 * 1024)
            .nest_limit(20)
            .build()
            .map_err(|e| RegexGuardError::CompilationError(e.to_string()))?;

        Ok(Self {
            pattern: pattern.to_string(),
            inner: regex,
            default_fuel_budget,
            throttled_count: AtomicU64::new(0),
        })
    }

    /// Evaluates regex matching against a payload with strict fuel limiting
    #[inline]
    pub fn match_with_fuel(&self, payload: &[u8], fuel_budget: usize) -> Result<bool, RegexGuardError> {
        if payload.len() > fuel_budget {
            self.throttled_count.fetch_add(1, Ordering::Relaxed);
            return Err(RegexGuardError::FuelExhausted {
                attempted_bytes: payload.len(),
                fuel_budget,
            });
        }

        Ok(self.inner.is_match(payload))
    }

    /// Evaluates using the default configured fuel budget
    #[inline]
    pub fn is_match(&self, payload: &[u8]) -> Result<bool, RegexGuardError> {
        self.match_with_fuel(payload, self.default_fuel_budget)
    }

    pub fn throttled_count(&self) -> u64 {
        self.throttled_count.load(Ordering::Relaxed)
    }

    pub fn pattern(&self) -> &str {
        &self.pattern
    }
}
