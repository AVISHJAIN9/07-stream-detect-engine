use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};

pub type RuleId = u32;

/// Lexical Boundary Token Extractor
pub struct TokenExtractor;

impl TokenExtractor {
    /// Extracts unique normalized alphanumeric tokens (length >= 3) from text payloads
    pub fn extract_tokens(text: &str) -> Vec<String> {
        let mut tokens = Vec::with_capacity(16);
        let mut current = String::with_capacity(32);

        for ch in text.chars() {
            if ch.is_alphanumeric() {
                current.push(ch.to_ascii_lowercase());
            } else {
                if current.len() >= 3 {
                    tokens.push(current.clone());
                }
                current.clear();
            }
        }

        if current.len() >= 3 {
            tokens.push(current);
        }

        tokens
    }

    /// Computes 64-bit token hash
    #[inline]
    pub fn hash_token(token: &str) -> u64 {
        let mut h = 0xcbf29ce484222325u64;
        for b in token.as_bytes() {
            h ^= *b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        h
    }
}

/// Dynamic Bitset for Candidate Rule IDs
#[derive(Debug, Clone, Default)]
pub struct RuleBitSet {
    words: Vec<u64>,
}

impl RuleBitSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(max_rules: usize) -> Self {
        let words = (max_rules + 63) / 64;
        Self {
            words: vec![0; words],
        }
    }

    #[inline]
    pub fn insert(&mut self, id: RuleId) {
        let idx = id as usize;
        let word = idx / 64;
        let bit = idx % 64;
        if word >= self.words.len() {
            self.words.resize(word + 1, 0);
        }
        self.words[word] |= 1u64 << bit;
    }

    #[inline]
    pub fn contains(&self, id: RuleId) -> bool {
        let idx = id as usize;
        let word = idx / 64;
        let bit = idx % 64;
        if word < self.words.len() {
            (self.words[word] & (1u64 << bit)) != 0
        } else {
            false
        }
    }

    pub fn union_with(&mut self, other: &RuleBitSet) {
        if other.words.len() > self.words.len() {
            self.words.resize(other.words.len(), 0);
        }
        for (i, word) in other.words.iter().enumerate() {
            self.words[i] |= *word;
        }
    }

    pub fn count(&self) -> usize {
        self.words.iter().map(|w| w.count_ones() as usize).sum()
    }

    pub fn to_vec(&self) -> Vec<RuleId> {
        let mut result = Vec::new();
        for (word_idx, &word) in self.words.iter().enumerate() {
            if word != 0 {
                for bit in 0..64 {
                    if (word & (1u64 << bit)) != 0 {
                        result.push((word_idx * 64 + bit) as RuleId);
                    }
                }
            }
        }
        result
    }
}

/// Inverted Candidate Rule Index using Token Hashes
pub struct InvertedRuleIndex {
    index: RwLock<HashMap<u64, Vec<RuleId>>>,
    total_rules: RwLock<usize>,
}

impl Default for InvertedRuleIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl InvertedRuleIndex {
    pub fn new() -> Self {
        Self {
            index: RwLock::new(HashMap::new()),
            total_rules: RwLock::new(0),
        }
    }

    /// Registers a rule and its required candidate token keywords
    pub fn register_rule(&self, rule_id: RuleId, tokens: &[&str]) {
        let mut idx_guard = self.index.write();
        let mut seen = HashSet::new();

        for &t in tokens {
            let normalized = t.to_ascii_lowercase();
            let hash = TokenExtractor::hash_token(&normalized);
            if seen.insert(hash) {
                idx_guard.entry(hash).or_default().push(rule_id);
            }
        }

        let mut count_guard = self.total_rules.write();
        if (rule_id as usize + 1) > *count_guard {
            *count_guard = rule_id as usize + 1;
        }
    }

    /// Queries the candidate rule bitset matching any extracted event token (Pre-Filter)
    pub fn query_candidates(&self, event_text: &str) -> RuleBitSet {
        let tokens = TokenExtractor::extract_tokens(event_text);
        let mut candidates = RuleBitSet::new();

        let idx_guard = self.index.read();
        for token in tokens {
            let hash = TokenExtractor::hash_token(&token);
            if let Some(rule_list) = idx_guard.get(&hash) {
                for &rule_id in rule_list {
                    candidates.insert(rule_id);
                }
            }
        }

        candidates
    }

    pub fn total_rules(&self) -> usize {
        *self.total_rules.read()
    }
}
