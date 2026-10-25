/// Feature 73 – Alert Acknowledgment State Machine (FSM)
///
/// Implements a strict finite-state machine for alert lifecycle management.
///
/// Valid state graph:
///   New → Acknowledged → InTriage → Resolved
///                                 → Dismissed
///   Any state → ExpiredArchived (via Alert Reaper, Feature 75)
///   Resolved / Dismissed → New (re-open path, explicit only)
///
/// KPI: Transition latency ≤ 15 ns.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

/// Lifecycle state of an alert in the incident management workflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlertState {
    /// Alert has been generated but no analyst has acknowledged it.
    New,
    /// An analyst has claimed the alert and acknowledged its existence.
    Acknowledged,
    /// Alert is actively being investigated by an analyst.
    InTriage,
    /// Alert has been confirmed as a true positive and resolved.
    Resolved,
    /// Alert has been dismissed (false positive, benign, or expected).
    Dismissed,
    /// Alert has been auto-archived by the Alert Reaper (SLA expiry, Feature 75).
    ExpiredArchived,
}

impl AlertState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::New             => "new",
            Self::Acknowledged    => "acknowledged",
            Self::InTriage        => "in_triage",
            Self::Resolved        => "resolved",
            Self::Dismissed       => "dismissed",
            Self::ExpiredArchived => "expired_archived",
        }
    }

    /// Returns true if this is a terminal state.
    /// Terminal states cannot transition further except via explicit re-open.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Resolved | Self::Dismissed | Self::ExpiredArchived)
    }
}

impl fmt::Display for AlertState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// State Transition Error
// ---------------------------------------------------------------------------

/// Error returned when an illegal FSM state transition is attempted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateTransitionError {
    pub from: AlertState,
    pub to: AlertState,
    pub reason: String,
}

impl fmt::Display for StateTransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Illegal state transition: {} -> {} ({})",
            self.from, self.to, self.reason
        )
    }
}

impl std::error::Error for StateTransitionError {}

// ---------------------------------------------------------------------------
// Valid Transition Matrix
// ---------------------------------------------------------------------------

/// Returns true when transitioning from `from` to `to` is a valid FSM edge.
///
/// Valid transitions:
///   New           → Acknowledged, ExpiredArchived
///   Acknowledged  → InTriage, ExpiredArchived, New (escalation reset)
///   InTriage      → Resolved, Dismissed
///   Resolved      → New (re-open)
///   Dismissed     → New (re-open)
///   ExpiredArchived → (terminal – no further transitions)
#[inline]
pub fn is_valid_transition(from: AlertState, to: AlertState) -> bool {
    use AlertState::*;
    matches!(
        (from, to),
        (New, Acknowledged)
        | (New, ExpiredArchived)
        | (Acknowledged, InTriage)
        | (Acknowledged, ExpiredArchived)
        | (Acknowledged, New)          // De-acknowledge / reset
        | (InTriage, Resolved)
        | (InTriage, Dismissed)
        | (InTriage, Acknowledged)     // Step back to re-evaluate
        | (Resolved, New)              // Re-open
        | (Dismissed, New)             // Re-open
    )
}

// ---------------------------------------------------------------------------
// Transition Record
// ---------------------------------------------------------------------------

/// An immutable record of a single FSM transition.
#[derive(Debug, Clone)]
pub struct TransitionRecord {
    /// State before the transition.
    pub from: AlertState,
    /// State after the transition.
    pub to: AlertState,
    /// Actor who initiated the transition (analyst ID or system).
    pub actor: String,
    /// Optional free-text reason or comment.
    pub reason: String,
    /// Nanosecond-precision timestamp of the transition.
    pub timestamp_ns: i64,
}

// ---------------------------------------------------------------------------
// Alert State Machine
// ---------------------------------------------------------------------------

/// Validates and records FSM state transitions for a single alert.
///
/// Each `AlertStateMachine` is bound to exactly one alert (identified by
/// `alert_id`) and maintains a complete ordered history of all transitions.
pub struct AlertStateMachine {
    /// Bound alert identifier.
    pub alert_id: uuid::Uuid,
    /// Current FSM state.
    pub current_state: AlertState,
    /// Ordered transition history.
    pub history: Vec<TransitionRecord>,
    /// Telemetry: total transitions applied.
    total_transitions: AtomicU64,
    /// Telemetry: total illegal attempts rejected.
    total_rejections: AtomicU64,
}

impl AlertStateMachine {
    /// Creates a new FSM in the `New` state.
    pub fn new(alert_id: uuid::Uuid) -> Self {
        Self {
            alert_id,
            current_state: AlertState::New,
            history: Vec::with_capacity(8),
            total_transitions: AtomicU64::new(0),
            total_rejections: AtomicU64::new(0),
        }
    }

    /// Attempts to transition from `current_state` to `target`.
    ///
    /// # Returns
    /// * `Ok(new_state)` on success; `current_state` is updated.
    /// * `Err(StateTransitionError)` on illegal transition; state is unchanged.
    pub fn transition(
        &mut self,
        target: AlertState,
        actor: &str,
        reason: &str,
        now_ns: i64,
    ) -> Result<AlertState, StateTransitionError> {
        if !is_valid_transition(self.current_state, target) {
            self.total_rejections.fetch_add(1, Ordering::Relaxed);
            return Err(StateTransitionError {
                from: self.current_state,
                to: target,
                reason: format!(
                    "transition '{}' -> '{}' is not permitted by the FSM",
                    self.current_state, target
                ),
            });
        }

        let record = TransitionRecord {
            from: self.current_state,
            to: target,
            actor: actor.to_string(),
            reason: reason.to_string(),
            timestamp_ns: now_ns,
        };
        self.history.push(record);
        self.current_state = target;
        self.total_transitions.fetch_add(1, Ordering::Relaxed);
        Ok(target)
    }

    /// Returns (total_transitions, total_rejections) counters.
    pub fn stats(&self) -> (u64, u64) {
        (
            self.total_transitions.load(Ordering::Relaxed),
            self.total_rejections.load(Ordering::Relaxed),
        )
    }
}

// ---------------------------------------------------------------------------
// Global FSM Registry
// ---------------------------------------------------------------------------

/// Thread-safe registry of `AlertStateMachine` instances keyed by alert UUID.
pub struct AlertFsmRegistry {
    machines: parking_lot::RwLock<std::collections::HashMap<uuid::Uuid, AlertStateMachine>>,
}

impl AlertFsmRegistry {
    pub fn new() -> Self {
        Self { machines: parking_lot::RwLock::new(std::collections::HashMap::new()) }
    }

    /// Registers a new alert (creates FSM in `New` state).
    pub fn register(&self, alert_id: uuid::Uuid) {
        self.machines.write().insert(alert_id, AlertStateMachine::new(alert_id));
    }

    /// Applies a transition to the alert's FSM.
    pub fn transition(
        &self,
        alert_id: uuid::Uuid,
        target: AlertState,
        actor: &str,
        reason: &str,
        now_ns: i64,
    ) -> Result<AlertState, StateTransitionError> {
        let mut machines = self.machines.write();
        if let Some(fsm) = machines.get_mut(&alert_id) {
            fsm.transition(target, actor, reason, now_ns)
        } else {
            Err(StateTransitionError {
                from: AlertState::New,
                to: target,
                reason: format!("Alert {} not registered in FSM registry", alert_id),
            })
        }
    }

    /// Returns the current state of an alert.
    pub fn state(&self, alert_id: uuid::Uuid) -> Option<AlertState> {
        self.machines.read().get(&alert_id).map(|fsm| fsm.current_state)
    }
}

impl Default for AlertFsmRegistry {
    fn default() -> Self {
        Self::new()
    }
}
