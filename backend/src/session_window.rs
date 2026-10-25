use crate::canonical_normalizer::CanonicalEvent;
use parking_lot::RwLock;
use std::collections::HashMap;

/// Materialized or In-Flight Session Interval
#[derive(Debug, Clone, PartialEq)]
pub struct SessionInterval {
    pub entity_key: String,
    pub start_ms: u64,
    pub end_ms: u64,
    pub event_count: usize,
    pub event_ids: Vec<String>,
}

/// Dynamic Activity-Gap Session Window State Machine with Interval Merging
pub struct SessionWindow {
    pub gap_threshold_ms: u64,
    sessions_by_entity: RwLock<HashMap<String, Vec<SessionInterval>>>,
}

impl SessionWindow {
    pub fn new(gap_threshold_ms: u64) -> Self {
        assert!(gap_threshold_ms > 0, "Gap threshold must be > 0");
        Self {
            gap_threshold_ms,
            sessions_by_entity: RwLock::new(HashMap::new()),
        }
    }

    /// Adds an event for an entity, merging with any adjacent or overlapping session windows
    pub fn add_event(&self, entity_key: &str, event_time_ms: u64, event: &CanonicalEvent) {
        let mut guard = self.sessions_by_entity.write();
        let entity_sessions = guard.entry(entity_key.to_string()).or_default();

        let mut new_session = SessionInterval {
            entity_key: entity_key.to_string(),
            start_ms: event_time_ms,
            end_ms: event_time_ms,
            event_count: 1,
            event_ids: vec![event.event_id.to_string()],
        };

        let mut merged = Vec::with_capacity(entity_sessions.len() + 1);

        for existing in entity_sessions.drain(..) {
            // Check if existing session overlaps or bridges with new_session within gap_threshold_ms
            let overlaps = !(existing.end_ms + self.gap_threshold_ms < new_session.start_ms
                || new_session.end_ms + self.gap_threshold_ms < existing.start_ms);

            if overlaps {
                // Merge intervals
                new_session.start_ms = new_session.start_ms.min(existing.start_ms);
                new_session.end_ms = new_session.end_ms.max(existing.end_ms);
                new_session.event_count += existing.event_count;
                new_session.event_ids.extend(existing.event_ids);
            } else {
                merged.push(existing);
            }
        }

        merged.push(new_session);
        // Keep sorted by start time
        merged.sort_by_key(|s| s.start_ms);
        *entity_sessions = merged;
    }

    /// Advances watermark and closes completed sessions where watermark >= end_ms + gap_threshold_ms
    pub fn advance_watermark<F>(&self, watermark_ms: u64, mut emit_fn: F)
    where
        F: FnMut(SessionInterval),
    {
        let mut guard = self.sessions_by_entity.write();
        let mut empty_entities = Vec::new();

        for (entity, sessions) in guard.iter_mut() {
            let mut active = Vec::with_capacity(sessions.len());
            for session in sessions.drain(..) {
                if watermark_ms >= session.end_ms + self.gap_threshold_ms {
                    emit_fn(session);
                } else {
                    active.push(session);
                }
            }
            *sessions = active;
            if sessions.is_empty() {
                empty_entities.push(entity.clone());
            }
        }

        for e in empty_entities {
            guard.remove(&e);
        }
    }
}
