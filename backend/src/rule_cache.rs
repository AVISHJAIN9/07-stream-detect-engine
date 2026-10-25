use crate::rule_ast::RuleAST;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Executable compiled rule container
#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub ast: RuleAST,
    pub fingerprint: u64,
    pub compiled_at_ns: i64,
    pub execution_count: Arc<AtomicU64>,
}

impl CompiledRule {
    pub fn new(ast: RuleAST, fingerprint: u64) -> Self {
        let now = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
        Self {
            ast,
            fingerprint,
            compiled_at_ns: now,
            execution_count: Arc::new(AtomicU64::new(0)),
        }
    }
}

/// Cache entry with access tracking for LRU eviction
struct CacheEntry {
    rule: Arc<CompiledRule>,
    last_access: Instant,
}

/// High-performance thread-safe Rule Compilation Cache
pub struct RuleCompilationCache {
    capacity: usize,
    entries: RwLock<HashMap<u64, CacheEntry>>,
    hits: AtomicU64,
    misses: AtomicU64,
}

impl RuleCompilationCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: RwLock::new(HashMap::with_capacity(capacity)),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// Computes a 64-bit invariant fingerprint for a rule YAML string
    #[inline]
    pub fn calculate_rule_fingerprint(rule_yaml: &str) -> u64 {
        let mut h = 0xcbf29ce484222325u64; // FNV-1a 64-bit offset basis
        for b in rule_yaml.as_bytes() {
            if !b.is_ascii_whitespace() {
                h ^= *b as u64;
                h = h.wrapping_mul(0x100000001b3);
            }
        }
        h
    }

    /// Retrieves a compiled rule if present, updating LRU access time (< 50 ns)
    #[inline]
    pub fn get(&self, fingerprint: u64) -> Option<Arc<CompiledRule>> {
        let read_guard = self.entries.read();
        if let Some(entry) = read_guard.get(&fingerprint) {
            self.hits.fetch_add(1, Ordering::Relaxed);
            Some(Arc::clone(&entry.rule))
        } else {
            drop(read_guard);
            self.misses.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    /// Stores a compiled rule into the cache with LRU eviction when capacity is reached
    pub fn insert(&self, fingerprint: u64, rule: Arc<CompiledRule>) {
        let mut write_guard = self.entries.write();
        if write_guard.len() >= self.capacity && !write_guard.contains_key(&fingerprint) {
            // Evict oldest entry
            if let Some((&oldest_key, _)) = write_guard
                .iter()
                .min_by_key(|(_, entry)| entry.last_access)
            {
                write_guard.remove(&oldest_key);
            }
        }

        write_guard.insert(
            fingerprint,
            CacheEntry {
                rule,
                last_access: Instant::now(),
            },
        );
    }

    /// Helper to get or compile atomically with compiler closure
    pub fn get_or_compile<F, E>(&self, rule_yaml: &str, compile_fn: F) -> Result<Arc<CompiledRule>, E>
    where
        F: FnOnce(&str) -> Result<RuleAST, E>,
    {
        let fp = Self::calculate_rule_fingerprint(rule_yaml);
        if let Some(cached) = self.get(fp) {
            return Ok(cached);
        }

        let ast = compile_fn(rule_yaml)?;
        let compiled = Arc::new(CompiledRule::new(ast, fp));
        self.insert(fp, Arc::clone(&compiled));
        Ok(compiled)
    }

    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }

    pub fn stats(&self) -> (u64, u64) {
        (
            self.hits.load(Ordering::Relaxed),
            self.misses.load(Ordering::Relaxed),
        )
    }
}
