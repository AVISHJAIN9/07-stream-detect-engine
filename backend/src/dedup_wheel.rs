use crate::alert_dedup::AlertDeduplicator;
use crate::timing_wheel::{TimerHandle, TimingWheel};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// Wheel entry – tracks a fingerprint's active timer slot
// ---------------------------------------------------------------------------

/// A single deduplication entry managed by the sliding wheel.
#[derive(Debug, Clone)]
struct WheelEntry {
    /// The 64-bit alert fingerprint.
    fingerprint: u64,
    /// Current timer handle inside the `TimingWheel`; replaced on each slide.
    timer_handle: TimerHandle,
    /// Whether this entry uses sliding (true) or fixed (false) TTL semantics.
    sliding: bool,
    /// Extension applied on each sliding bump (milliseconds).
    extension_ms: u64,
}

// ---------------------------------------------------------------------------
// Sliding Deduplication TTL Wheel
// ---------------------------------------------------------------------------

/// Integrates alert suppression fingerprints into the hierarchical timing wheel
/// from Phase X.  Supports both **fixed** (one-shot) and **sliding** (extended
/// on each hit) TTL windows.
///
/// # Fixed TTL
/// The expiry is set once when the alert first fires.  Subsequent hits within
/// the window do not reschedule the timer.
///
/// # Sliding TTL
/// Every call to `update_ttl` with `sliding = true` cancels the previous timer
/// and re-registers a fresh one at `now + extension_ms`, pushing the eviction
/// deadline forward in `O(1)` time inside the hierarchical wheel.
///
/// # Expiry integration
/// When the wheel fires, `tick_expired` must be called.  It feeds all expired
/// fingerprint keys back to the `AlertDeduplicator` to evict their suppression
/// entries, ensuring zero zombie records.
pub struct SlidingDeduplicationWheel {
    /// Underlying hierarchical timing wheel (shared with the broader engine).
    wheel: TimingWheel,
    /// Active entries keyed by fingerprint.
    entries: RwLock<HashMap<u64, WheelEntry>>,
    /// Monotonic counter used to detect racing re-schedules.
    generation: AtomicU64,
    // Telemetry
    total_scheduled: AtomicU64,
    total_slides: AtomicU64,
    total_expirations: AtomicU64,
    total_cancels: AtomicU64,
}

impl SlidingDeduplicationWheel {
    /// Constructs the wheel anchored at `start_time_ms` (epoch milliseconds).
    pub fn new(start_time_ms: u64) -> Self {
        Self {
            wheel: TimingWheel::new(start_time_ms),
            entries: RwLock::new(HashMap::with_capacity(1024)),
            generation: AtomicU64::new(0),
            total_scheduled: AtomicU64::new(0),
            total_slides: AtomicU64::new(0),
            total_expirations: AtomicU64::new(0),
            total_cancels: AtomicU64::new(0),
        }
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    /// Encodes `fingerprint` into a stable byte key for the timing wheel.
    #[inline]
    fn fp_to_key(fingerprint: u64) -> Vec<u8> {
        fingerprint.to_le_bytes().to_vec()
    }

    #[inline]
    fn key_to_fp(key: &[u8]) -> u64 {
        if key.len() == 8 {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(key);
            u64::from_le_bytes(arr)
        } else {
            0
        }
    }

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    /// Registers a new fingerprint for TTL-based eviction.
    ///
    /// If the fingerprint is already tracked and `sliding` is `true`, the
    /// existing timer is cancelled and a fresh one is installed; for `sliding =
    /// false` (fixed), subsequent calls are no-ops unless the old timer has
    /// already fired.
    ///
    /// Returns the new `timer_handle_id` that should be stored in the
    /// `AlertDeduplicator` entry via `update_timer_handle`.
    pub fn register_or_update(
        &self,
        fingerprint: u64,
        sliding: bool,
        extension_ms: u64,
    ) -> u64 {
        let key = Self::fp_to_key(fingerprint);
        let mut entries_guard = self.entries.write();

        // If an entry already exists and window is FIXED → do nothing.
        if let Some(existing) = entries_guard.get(&fingerprint) {
            if !sliding {
                // Fixed window: first expiry stands.
                return existing.timer_handle.id;
            }
            // Sliding: cancel old timer, re-register below.
            self.wheel.cancel(existing.timer_handle);
            self.total_cancels.fetch_add(1, Ordering::Relaxed);
            self.total_slides.fetch_add(1, Ordering::Relaxed);
        }

        // Schedule new timer
        let handle = self.wheel.schedule(key, extension_ms);
        let entry = WheelEntry {
            fingerprint,
            timer_handle: handle,
            sliding,
            extension_ms,
        };
        entries_guard.insert(fingerprint, entry);
        self.total_scheduled.fetch_add(1, Ordering::Relaxed);
        handle.id
    }

    /// Cancels an active TTL entry for `fingerprint` without waiting for
    /// natural expiry.  Called when an alert is resolved externally.
    pub fn cancel(&self, fingerprint: u64) -> bool {
        let mut entries_guard = self.entries.write();
        if let Some(entry) = entries_guard.remove(&fingerprint) {
            let cancelled = self.wheel.cancel(entry.timer_handle);
            if cancelled {
                self.total_cancels.fetch_add(1, Ordering::Relaxed);
            }
            cancelled
        } else {
            false
        }
    }

    /// Advances the internal clock to `now_ms` and returns all fingerprints
    /// whose TTL has expired.
    ///
    /// The caller (engine event loop) must call `AlertDeduplicator::evict` for
    /// each returned fingerprint to guarantee zero zombie suppression records.
    pub fn tick_expired(&self, now_ms: u64) -> Vec<u64> {
        let expired_keys = self.wheel.advance(now_ms);
        let mut expired_fingerprints = Vec::with_capacity(expired_keys.len());

        let mut entries_guard = self.entries.write();
        for key in &expired_keys {
            let fp = Self::key_to_fp(key);
            entries_guard.remove(&fp);
            expired_fingerprints.push(fp);
            self.total_expirations.fetch_add(1, Ordering::Relaxed);
        }
        expired_fingerprints
    }

    /// Convenience method that advances the clock, fires expired entries, and
    /// evicts them from the supplied `AlertDeduplicator` in one call.
    pub fn tick_and_evict(&self, now_ms: u64, dedup: &AlertDeduplicator) -> usize {
        let fps = self.tick_expired(now_ms);
        let count = fps.len();
        for fp in fps {
            dedup.evict(fp);
        }
        count
    }

    /// Returns the current wheel time in milliseconds.
    pub fn current_time_ms(&self) -> u64 {
        self.wheel.current_time_ms()
    }

    /// Number of fingerprints currently tracked in the wheel.
    pub fn active_count(&self) -> usize {
        self.entries.read().len()
    }

    /// Telemetry snapshot.
    pub fn stats(&self) -> DedupWheelStats {
        DedupWheelStats {
            total_scheduled: self.total_scheduled.load(Ordering::Relaxed),
            total_slides: self.total_slides.load(Ordering::Relaxed),
            total_expirations: self.total_expirations.load(Ordering::Relaxed),
            total_cancels: self.total_cancels.load(Ordering::Relaxed),
            active_entries: self.entries.read().len(),
        }
    }
}

/// Telemetry snapshot for `SlidingDeduplicationWheel`.
#[derive(Debug, Clone, PartialEq)]
pub struct DedupWheelStats {
    pub total_scheduled: u64,
    pub total_slides: u64,
    pub total_expirations: u64,
    pub total_cancels: u64,
    pub active_entries: usize,
}
