use rand::Rng;
use std::sync::Arc;
use uuid::Uuid;

use stream_detect_engine::canonical_normalizer::CanonicalEvent;
use stream_detect_engine::event_reorderer::EventReorderer;
use stream_detect_engine::event_time_driver::{EventTimeProcessor, WindowOutput};
use stream_detect_engine::lateness_policy::{LatenessDecision, LatenessPolicyManager};
use stream_detect_engine::partition_watermark_tracker::PartitionWatermarkTracker;
use stream_detect_engine::processing_time_fallback::{FallbackPolicy, FallbackTimeGate};
use stream_detect_engine::quarantine_dlq::QuarantineManager;
use stream_detect_engine::sliding_window::SlidingWindow;
use stream_detect_engine::tumbling_window::TumblingWindow;
use stream_detect_engine::types::ValueVariant;
use stream_detect_engine::watermark_generator::BoundedOutOfOrderWatermarkGenerator;

fn make_event(entity_id: &str, timestamp_ns: i64) -> CanonicalEvent {
    let mut evt = CanonicalEvent::default();
    evt.event_id = Uuid::new_v4();
    evt.entity_id = entity_id.to_string();
    evt.event_type = "auth_event".to_string();
    evt.source = "audit_stream".to_string();
    evt.event_timestamp_ns = timestamp_ns;
    evt.ingress_timestamp_ns = timestamp_ns;
    evt
}

#[test]
fn test_feature_43_event_time_vs_processing_time_pipeline_isolation() {
    let processor = EventTimeProcessor::new();

    // 60s Tumbling Window (60,000ms = 60,000,000,000ns)
    let tumbling = Arc::new(TumblingWindow::new(60_000));
    // 60s Sliding Window with 10s slide
    let sliding = Arc::new(SlidingWindow::new(60_000, 10_000));

    processor.register_tumbling_window(Arc::clone(&tumbling));
    processor.register_sliding_window(Arc::clone(&sliding));

    // Epoch-aligned synthetic timestamps from "yesterday" (e.g. 120,000,000 ms is exactly 2000 * 60s)
    let base_ms: u64 = 120_000_000;
    let base_ns: i64 = (base_ms as i64) * 1_000_000;

    // Send 3 events in window [100_000_000, 100_060_000)
    let e1 = make_event("u1", base_ns + 10_000 * 1_000_000); // 10s in
    let e2 = make_event("u2", base_ns + 30_000 * 1_000_000); // 30s in
    let e3 = make_event("u3", base_ns + 50_000 * 1_000_000); // 50s in

    assert!(processor.process_event(&e1).is_ok());
    assert!(processor.process_event(&e2).is_ok());
    assert!(processor.process_event(&e3).is_ok());

    assert_eq!(processor.total_events_processed(), 3);

    // Advancing watermark below window end emits nothing
    let pre_outputs = processor.advance_watermark(base_ns + 59_000 * 1_000_000);
    assert!(pre_outputs.is_empty());

    // Advance watermark past 60s (to base_ns + 65_000ms)
    let outputs = processor.advance_watermark(base_ns + 65_000 * 1_000_000);
    assert!(!outputs.is_empty(), "Tumbling and sliding windows must trigger based on event timestamp watermark");

    let mut found_tumbling = false;
    for out in outputs {
        if let WindowOutput::Tumbling(t) = out {
            assert_eq!(t.event_count, 3);
            assert_eq!(t.window_start_ms, (base_ms / 60_000) * 60_000);
            found_tumbling = true;
        }
    }
    assert!(found_tumbling, "Tumbling window output must be emitted");
}

#[test]
fn test_feature_44_dynamic_processing_time_fallback_trigger() {
    // Max skew: 1 hour (3,600,000,000,000 ns)
    let max_skew_ns = 3_600 * 1_000_000_000;
    let gate = FallbackTimeGate::new(max_skew_ns, FallbackPolicy::UseIngressTimeOrSystem);

    let sys_now_ns = 1_700_000_000_000_000_000; // Reference current wall clock

    // Case 1: Valid timestamp within skew
    let mut valid_evt = make_event("u1", sys_now_ns + 500_000_000); // +0.5s skew
    let resolved = gate.resolve_timestamp(&mut valid_evt, sys_now_ns).unwrap();
    assert_eq!(resolved, sys_now_ns + 500_000_000);
    assert!(!valid_evt.attributes.contains_key("fallback_processing_time"));

    // Case 2: Zero / Missing timestamp
    let mut zero_evt = make_event("u2", 0);
    zero_evt.ingress_timestamp_ns = sys_now_ns + 100;
    let resolved_zero = gate.resolve_timestamp(&mut zero_evt, sys_now_ns).unwrap();
    assert_eq!(resolved_zero, sys_now_ns + 100);
    assert_eq!(
        zero_evt.attributes.get("fallback_processing_time"),
        Some(&ValueVariant::Bool(true))
    );
    assert_eq!(
        zero_evt.attributes.get("fallback_reason"),
        Some(&ValueVariant::String("ZeroOrMissingTimestamp".to_string()))
    );

    // Case 3: Extreme future skew (> 24 hours skew > 1 hour limit)
    let future_ts = sys_now_ns + (24 * 3600 * 1_000_000_000);
    let mut skewed_evt = make_event("u3", future_ts);
    skewed_evt.ingress_timestamp_ns = 0; // Test fallback to sys_now_ns
    let resolved_skewed = gate.resolve_timestamp(&mut skewed_evt, sys_now_ns).unwrap();
    assert_eq!(resolved_skewed, sys_now_ns);
    assert_eq!(
        skewed_evt.attributes.get("fallback_processing_time"),
        Some(&ValueVariant::Bool(true))
    );
    assert_eq!(
        skewed_evt.attributes.get("fallback_reason"),
        Some(&ValueVariant::String("ClockSkewExceeded".to_string()))
    );

    let stats = gate.stats();
    assert_eq!(stats.valid_timestamps, 1);
    assert_eq!(stats.fallback_events, 2);
    assert_eq!(stats.zero_timestamps, 1);
    assert_eq!(stats.skew_violations, 1);
    assert!((stats.fallback_rate - (2.0 / 3.0)).abs() < 0.001);
}

#[test]
fn test_feature_45_monotonic_bounded_out_of_order_watermark_progression() {
    // Delta out-of-orderness: 20ns
    let generator = BoundedOutOfOrderWatermarkGenerator::new(20, 1_000);

    let input_timestamps = [100, 90, 110, 80, 150];
    let mut emitted_watermarks = Vec::new();

    let mut sys_time = 1000;
    for &ts in &input_timestamps {
        sys_time += 10;
        if let Some(wm) = generator.on_event(ts, sys_time) {
            emitted_watermarks.push(wm.timestamp_ns);
        }
    }

    // Progression:
    // ts=100 -> Tmax=100, W = 100 - 20 = 80 -> Emits 80
    // ts=90  -> Tmax=100, W = 80 (not > 80) -> None
    // ts=110 -> Tmax=110, W = 110 - 20 = 90 -> Emits 90
    // ts=80  -> Tmax=110, W = 90 (not > 90) -> None
    // ts=150 -> Tmax=150, W = 150 - 20 = 130 -> Emits 130
    assert_eq!(emitted_watermarks, vec![80, 90, 130]);

    // Check monotonic invariant
    for i in 1..emitted_watermarks.len() {
        assert!(
            emitted_watermarks[i] >= emitted_watermarks[i - 1],
            "Watermarks must be strictly non-decreasing"
        );
    }

    assert_eq!(generator.current_watermark(), 130);
    assert_eq!(generator.max_timestamp_seen(), 150);
}

#[test]
fn test_feature_46_partition_aware_min_watermark_aggregation() {
    // 3 Partitions with 5000ns idle timeout
    let tracker = PartitionWatermarkTracker::new(3, 5000);
    let sys_now = 10_000;

    // Initial state: Partition 0 at T=100, Partition 1 at T=80, Partition 2 at T=90
    tracker.update_partition_watermark(0, 100, sys_now);
    tracker.update_partition_watermark(1, 80, sys_now);
    let global_wm = tracker.update_partition_watermark(2, 90, sys_now);

    // Global watermark must be min(100, 80, 90) = 80
    assert_eq!(global_wm, 80);
    assert_eq!(tracker.global_watermark(), 80);
    assert_eq!(tracker.active_partition_count(), 3);

    // Advance Partition 0 to 120 and Partition 2 to 110 (Partition 1 remains at 80)
    tracker.update_partition_watermark(0, 120, sys_now + 100);
    tracker.update_partition_watermark(2, 110, sys_now + 100);
    assert_eq!(tracker.global_watermark(), 80, "Lagging partition 1 must hold global watermark at 80");

    // Partition 1 goes idle (mark idle or simulate timeout)
    let advanced_wm = tracker.mark_partition_idle(1);
    // Global watermark must advance to min(Partition 0 (120), Partition 2 (110)) = 110
    assert_eq!(advanced_wm, 110);
    assert_eq!(tracker.global_watermark(), 110);
    assert_eq!(tracker.active_partition_count(), 2);

    // When Partition 1 resumes traffic with new watermark 130
    let resumed_wm = tracker.update_partition_watermark(1, 130, sys_now + 200);
    // Global watermark is min(120, 130, 110) = 110 (already 110, monotonic)
    assert_eq!(resumed_wm, 110);
    assert_eq!(tracker.active_partition_count(), 3);
}

#[test]
fn test_feature_47_time_heap_reorderer_chronological_output() {
    let reorderer = EventReorderer::new(2048);
    let mut rng = rand::thread_rng();

    let base_ts = 1_000_000;
    let event_count = 1_000;

    // Generate 1000 events with random jitter +/- 50ms (+/- 50,000,000ns)
    let mut input_events = Vec::with_capacity(event_count);
    for i in 0..event_count {
        let logical_ts = base_ts + (i as i64 * 1_000_000); // 1ms intervals
        let jitter: i64 = rng.gen_range(-50_000_000..50_000_000);
        let noisy_ts = (logical_ts + jitter).max(1);
        input_events.push(make_event(&format!("user_{}", i), noisy_ts));
    }

    // Ingest events into reorderer
    for evt in input_events {
        assert!(reorderer.push(evt).is_ok());
    }

    assert_eq!(reorderer.len(), event_count);

    // Drain all events
    let drained = reorderer.drain_all();
    assert_eq!(drained.len(), event_count);
    assert!(reorderer.is_empty());

    // Verify output stream is strictly sorted in non-decreasing timestamp order
    for i in 1..drained.len() {
        assert!(
            drained[i].event_timestamp_ns >= drained[i - 1].event_timestamp_ns,
            "Reordered events must have non-decreasing timestamps (idx {}: {} < idx {}: {})",
            i,
            drained[i].event_timestamp_ns,
            i - 1,
            drained[i - 1].event_timestamp_ns
        );
    }
}

#[test]
fn test_feature_48_allowed_lateness_retriggering_vs_dlq_drop() {
    let dlq = Arc::new(QuarantineManager::new(100));
    // Allowed lateness: 10s (10,000,000,000ns)
    let allowed_lateness_ns = 10 * 1_000_000_000;
    let manager = LatenessPolicyManager::new(allowed_lateness_ns, Some(Arc::clone(&dlq)));

    // Watermark at T=100s (100,000,000,000ns)
    let watermark_ns: i64 = 100 * 1_000_000_000;

    // 1. On-Time Event at T=105s (>= 100s)
    let e_ontime = make_event("u1", 105 * 1_000_000_000);
    match manager.evaluate_event(e_ontime, watermark_ns) {
        LatenessDecision::OnTime(e) => {
            assert_eq!(e.entity_id, "u1");
        }
        other => panic!("Expected OnTime decision, got {:?}", other),
    }

    // 2. Late within tolerance at T=95s (95s >= 100s - 10s = 90s)
    let e_late_ok = make_event("u2", 95 * 1_000_000_000);
    match manager.evaluate_event(e_late_ok, watermark_ns) {
        LatenessDecision::LateWithinTolerance { event, lateness_ns } => {
            assert_eq!(event.entity_id, "u2");
            assert_eq!(lateness_ns, 5 * 1_000_000_000); // 5s late
        }
        other => panic!("Expected LateWithinTolerance decision, got {:?}", other),
    }

    // 3. Late beyond tolerance at T=85s (< 90s cutoff) -> Dropped to DLQ
    let e_late_drop = make_event("u3", 85 * 1_000_000_000);
    match manager.evaluate_event(e_late_drop, watermark_ns) {
        LatenessDecision::LateDropped {
            event,
            lateness_ns,
            quarantine_id,
        } => {
            assert_eq!(event.entity_id, "u3");
            assert_eq!(lateness_ns, 15 * 1_000_000_000); // 15s late
            assert!(quarantine_id.is_some(), "Must have a generated DLQ quarantine ID");
        }
        other => panic!("Expected LateDropped decision, got {:?}", other),
    }

    // Assert DLQ received the quarantined record
    assert_eq!(dlq.len(), 1);
    let quarantined_records = dlq.drain(10);
    assert_eq!(quarantined_records.len(), 1);
    assert_eq!(
        quarantined_records[0].failure_reason,
        "LateEventExceededAllowedLateness"
    );

    let stats = manager.stats();
    assert_eq!(stats.on_time_count, 1);
    assert_eq!(stats.late_within_tolerance_count, 1);
    assert_eq!(stats.late_dropped_count, 1);
}
