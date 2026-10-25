/// Feature 74 – Tamper-Evident Alert Lifecycle History Journal
///
/// Maintains an append-only, cryptographically-chained SHA-256 audit journal
/// for every alert state transition, analyst comment, and automated system
/// action.
///
/// Hash chaining formula:
///   H_n = SHA256(H_{n-1} ‖ Seq ‖ Timestamp ‖ FromState ‖ ToState ‖ Actor ‖ Payload)
///
/// The genesis entry (seq=0) uses a 32-byte zero vector as the predecessor hash.
///
/// KPI: Append overhead ≤ 50 ns.

use crate::alert_state_machine::AlertState;
use sha2::{Sha256, Digest};

// ---------------------------------------------------------------------------
// Journal Entry
// ---------------------------------------------------------------------------

/// A single immutable entry in the lifecycle audit journal.
#[derive(Debug, Clone)]
pub struct JournalEntry {
    /// Monotonically increasing sequence number within this journal.
    pub seq: u64,
    /// Nanosecond-precision timestamp of the event.
    pub timestamp_ns: i64,
    /// Alert state before this event.
    pub from_state: AlertState,
    /// Alert state after this event.
    pub to_state: AlertState,
    /// Identifier of the actor who caused this event (analyst ID or `system`).
    pub actor: String,
    /// Optional free-text annotation or comment.
    pub payload: String,
    /// SHA-256 hash of the previous entry (32 zero bytes for seq=0).
    pub prev_hash: [u8; 32],
    /// SHA-256 hash of this entry's content including `prev_hash`.
    pub entry_hash: [u8; 32],
}

impl JournalEntry {
    /// Computes the SHA-256 hash for this entry.
    ///
    /// Hash input (big-endian byte concatenation):
    ///   prev_hash(32) ‖ seq(8) ‖ timestamp_ns(8) ‖ from_state_str ‖ NUL
    ///   ‖ to_state_str ‖ NUL ‖ actor ‖ NUL ‖ payload
    fn compute_hash(
        prev_hash: &[u8; 32],
        seq: u64,
        timestamp_ns: i64,
        from_state: AlertState,
        to_state: AlertState,
        actor: &str,
        payload: &str,
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(prev_hash);
        hasher.update(seq.to_be_bytes());
        hasher.update(timestamp_ns.to_be_bytes());
        hasher.update(from_state.as_str().as_bytes());
        hasher.update(b"\x00");
        hasher.update(to_state.as_str().as_bytes());
        hasher.update(b"\x00");
        hasher.update(actor.as_bytes());
        hasher.update(b"\x00");
        hasher.update(payload.as_bytes());
        hasher.finalize().into()
    }

    /// Recomputes and verifies that `entry_hash` is consistent with the stored
    /// fields and `prev_hash`.
    pub fn verify(&self) -> bool {
        let expected = Self::compute_hash(
            &self.prev_hash,
            self.seq,
            self.timestamp_ns,
            self.from_state,
            self.to_state,
            &self.actor,
            &self.payload,
        );
        expected == self.entry_hash
    }
}

// ---------------------------------------------------------------------------
// Lifecycle Journal
// ---------------------------------------------------------------------------

/// Append-only, SHA-256 Merkle-chained lifecycle history journal.
///
/// Each `LifecycleJournal` is bound to a single alert and records every
/// significant lifecycle event in order.  The cryptographic chain ensures
/// that any retroactive mutation of historical entries is detectable by
/// `verify_integrity()`.
pub struct LifecycleJournal {
    /// Bound alert UUID (for display / logging).
    pub alert_id: uuid::Uuid,
    /// Ordered append-only entry list.
    entries: Vec<JournalEntry>,
}

impl LifecycleJournal {
    /// Creates an empty journal for the given alert.
    pub fn new(alert_id: uuid::Uuid) -> Self {
        Self { alert_id, entries: Vec::with_capacity(16) }
    }

    /// Appends a new lifecycle event to the journal, computing the SHA-256
    /// chain link.
    ///
    /// # Arguments
    /// * `from_state` – State before the event.
    /// * `to_state` – State after the event.
    /// * `actor` – Actor identifier.
    /// * `payload` – Optional comment or metadata string.
    /// * `timestamp_ns` – Event timestamp in nanoseconds.
    ///
    /// # Returns
    /// The newly appended `JournalEntry`.
    pub fn append_entry(
        &mut self,
        from_state: AlertState,
        to_state: AlertState,
        actor: &str,
        payload: &str,
        timestamp_ns: i64,
    ) -> &JournalEntry {
        let seq = self.entries.len() as u64;

        let prev_hash: [u8; 32] = self
            .entries
            .last()
            .map(|e| e.entry_hash)
            .unwrap_or([0u8; 32]);

        let entry_hash = JournalEntry::compute_hash(
            &prev_hash,
            seq,
            timestamp_ns,
            from_state,
            to_state,
            actor,
            payload,
        );

        self.entries.push(JournalEntry {
            seq,
            timestamp_ns,
            from_state,
            to_state,
            actor: actor.to_string(),
            payload: payload.to_string(),
            prev_hash,
            entry_hash,
        });

        self.entries.last().unwrap()
    }

    /// Traverses the full chain from genesis to the last entry, verifying that:
    ///   1. Each entry's `entry_hash` is consistent with its stored fields.
    ///   2. Each entry's `prev_hash` matches the previous entry's `entry_hash`.
    ///
    /// Returns `true` when the chain is intact; `false` on any mismatch.
    pub fn verify_integrity(&self) -> bool {
        let mut expected_prev: [u8; 32] = [0u8; 32];

        for entry in &self.entries {
            // Verify prev_hash matches the accumulated chain.
            if entry.prev_hash != expected_prev {
                return false;
            }
            // Verify the entry's own hash.
            if !entry.verify() {
                return false;
            }
            expected_prev = entry.entry_hash;
        }
        true
    }

    /// Returns the number of entries in the journal.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true when the journal is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns an immutable slice of all journal entries.
    pub fn entries(&self) -> &[JournalEntry] {
        &self.entries
    }

    /// Returns a mutable reference to the entries vector.
    ///
    /// # Safety
    /// Intended **only** for test-harness tampering scenarios.  Direct mutation
    /// of historical entries will cause `verify_integrity()` to return `false`.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn entries_mut_for_test(&mut self) -> &mut Vec<JournalEntry> {
        &mut self.entries
    }
}
