use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;
use uuid::Uuid;
use stream_detect_engine::canonical_normalizer::CanonicalEvent;
use stream_detect_engine::hit_telemetry::HitTelemetryTracker;
use stream_detect_engine::matcher_benchmark::BenchmarkRunner;
use stream_detect_engine::predicate_telemetry::PredicateMetricsRegistry;
use stream_detect_engine::session_window::SessionWindow;
use stream_detect_engine::sliding_window::SlidingWindow;
use stream_detect_engine::tumbling_window::TumblingWindow;

fn make_event(id: &str) -> CanonicalEvent {
    let mut evt = CanonicalEvent::default();
    evt.event_id = Uuid::new_v4();
    evt.entity_id = id.to_string();
    evt
}

#[test]
fn test_feature_37_predicate_cost_telemetry_accuracy() {
    let registry = PredicateMetricsRegistry::new();
    let metrics = registry.register(101, "PortRangeCheck");

    let start = Instant::now();
    let iterations = 10_000;
    for i in 0..iterations {
        let val = (i % 65535) as i64;
        registry.time_eval(101, || val > 1024 && val < 60000);
    }
    let elapsed = start.elapsed();
    let amortized_ns = (elapsed.as_nanos() as f64) / (iterations as f64);

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.eval_count, 10000);
    assert!(snapshot.total_nanos > 0);
    assert!(snapshot.avg_nanos > 0.0);
    assert!(snapshot.max_nanos >= snapshot.min_nanos);
    assert!(
        amortized_ns < 1000.0,
        "Telemetry evaluation overhead must be low (actual: {:.2} ns/eval)",
        amortized_ns
    );
}

#[test]
fn test_feature_38_pattern_hit_and_false_positive_attribution() {
    let tracker = HitTelemetryTracker::new();
    let rule_id = 42;

    for _ in 0..500 {
        tracker.record_hit(rule_id, 1);
    }
    for _ in 0..50 {
        tracker.record_suppression(rule_id);
    }

    let snap = tracker.get_snapshot(rule_id).expect("Rule snapshot exists");
    assert_eq!(snap.hits, 500);
    assert_eq!(snap.fp_suppressed, 50);
    assert!(snap.last_hit_timestamp_ns > 0);
    assert!((snap.noise_ratio - (50.0 / 550.0)).abs() < 0.001);
}

#[test]
fn test_feature_39_matcher_benchmark_suite() {
    let stats = BenchmarkRunner::run_benchmark("SubstringScan", 1000, 1024, || {
        let sample = "The quick brown fox jumps over the lazy dog";
        assert!(sample.contains("brown"));
    });

    assert_eq!(stats.iterations, 1000);
    assert!(stats.ops_per_sec > 0.0);
    assert!(stats.mean_ns > 0.0);
    assert!(stats.p50_ns > 0.0);
    assert!(stats.p99_ns >= stats.p50_ns);
    assert!(stats.throughput_mb_per_sec > 0.0);
}

#[test]
fn test_feature_40_sliding_window_pane_aggregation() {
    // Window: 60s (60,000ms), Slide: 10s (10,000ms), Pane: 10s
    let window = SlidingWindow::new(60_000, 10_000);

    // Feed events: 1 event every 10s from T=0 to T=120s
    for t_sec in 0..=12 {
        let t_ms = t_sec * 10_000;
        let evt = make_event(&format!("evt-{}", t_sec));
        window.assign_event(t_ms, &evt);
    }

    let mut emitted_windows = Vec::new();
    // Advance watermark to T=120s (120,000ms)
    window.advance_watermark(120_000, |res| {
        emitted_windows.push(res);
    });

    // Windows expected to trigger: [0, 60), [10, 70), [20, 80), [30, 90), [40, 100), [50, 110), [60, 120)
    assert_eq!(emitted_windows.len(), 7);
    assert_eq!(emitted_windows[0].window_start_ms, 0);
    assert_eq!(emitted_windows[0].window_end_ms, 60_000);
    assert_eq!(emitted_windows[0].event_count, 6); // events at 0, 10, 20, 30, 40, 50

    assert_eq!(emitted_windows[6].window_start_ms, 60_000);
    assert_eq!(emitted_windows[6].window_end_ms, 120_000);
    assert_eq!(emitted_windows[6].event_count, 6); // events at 60, 70, 80, 90, 100, 110
}

#[test]
fn test_feature_41_tumbling_window_boundary_flush() {
    // 60s Tumbling Window
    let tumbling = TumblingWindow::new(60_000);

    // Send events at T=10s, 40s (Window 1: [0, 60)), T=70s, 90s (Window 2: [60, 120))
    tumbling.assign_event(10_000, &make_event("e1"));
    tumbling.assign_event(40_000, &make_event("e2"));
    tumbling.assign_event(70_000, &make_event("e3"));
    tumbling.assign_event(90_000, &make_event("e4"));

    let mut emitted = Vec::new();
    tumbling.advance_watermark(130_000, |res| {
        emitted.push(res);
    });

    assert_eq!(emitted.len(), 2);
    assert_eq!(emitted[0].window_start_ms, 0);
    assert_eq!(emitted[0].window_end_ms, 60_000);
    assert_eq!(emitted[0].event_count, 2);

    assert_eq!(emitted[1].window_start_ms, 60_000);
    assert_eq!(emitted[1].window_end_ms, 120_000);
    assert_eq!(emitted[1].event_count, 2);

    // Subsequent watermark advance flushes nothing (state already reclaimed)
    let mut empty_flushed = Vec::new();
    tumbling.advance_watermark(150_000, |res| {
        empty_flushed.push(res);
    });
    assert!(empty_flushed.is_empty());
}

#[test]
fn test_feature_42_dynamic_session_window_interval_merging() {
    // Gap threshold: 15s (15,000ms)
    let session_win = SessionWindow::new(15_000);
    let entity = "user_admin";

    // 1. Event at T=0s
    session_win.add_event(entity, 0, &make_event("e1"));

    // 2. Event at T=20s (Gap = 20s > 15s, separate session [20, 20])
    session_win.add_event(entity, 20_000, &make_event("e2"));

    // 3. Late arriving event at T=10s (Bridges gap: 0..10 <= 15 and 10..20 <= 15)
    // Merges both into a single session [0, 20_000]
    session_win.add_event(entity, 10_000, &make_event("e3_late"));

    let mut closed_sessions = Vec::new();
    // Watermark at 40s (40,000ms >= 20_000 + 15_000)
    session_win.advance_watermark(40_000, |s| {
        closed_sessions.push(s);
    });

    assert_eq!(closed_sessions.len(), 1, "Disjoint sessions must merge into 1 unified session");
    assert_eq!(closed_sessions[0].start_ms, 0);
    assert_eq!(closed_sessions[0].end_ms, 20_000);
    assert_eq!(closed_sessions[0].event_count, 3);
}
