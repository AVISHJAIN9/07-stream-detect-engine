use rand::Rng;
use std::sync::Arc;
use std::thread;
use uuid::Uuid;

use stream_detect_engine::canonical_normalizer::CanonicalEvent;
use stream_detect_engine::composite_key::CompositeKeyEncoder;
use stream_detect_engine::keyed_state_store::{KeyedStateStore, StateValue};
use stream_detect_engine::late_event_policy::{LateEventPolicyEngine, LatePolicy};
use stream_detect_engine::sliding_window::SlidingWindow;
use stream_detect_engine::types::ValueVariant;
use stream_detect_engine::window_gc::WindowStateGC;
use stream_detect_engine::window_memory_tracker::{MemoryStatus, WindowMemoryManager};
use stream_detect_engine::window_oracle::WindowOracle;

fn make_event(entity_id: &str, timestamp_ns: i64) -> CanonicalEvent {
    let mut evt = CanonicalEvent::default();
    evt.event_id = Uuid::new_v4();
    evt.entity_id = entity_id.to_string();
    evt.event_type = "network_flow".to_string();
    evt.source = "firewall_core".to_string();
    evt.event_timestamp_ns = timestamp_ns;
    evt.ingress_timestamp_ns = timestamp_ns;
    evt
}

#[test]
fn test_feature_49_late_event_side_output_routing() {
    let side_tag = "quarantine_late_dead_letter";
    let engine = LateEventPolicyEngine::new(LatePolicy::SideOutput(side_tag.to_string()));

    let watermark_ns: i64 = 200 * 1_000_000_000;
    let allowed_lateness_ns: i64 = 20 * 1_000_000_000;
    let event_ts: i64 = 150 * 1_000_000_000; // 50s late > 20s allowed

    let lateness_ns = watermark_ns - event_ts;
    assert!(lateness_ns > allowed_lateness_ns);

    let evt = make_event("user_late_01", event_ts);
    let rule_id = Some(4242);

    let result = engine
        .handle_late_event(evt.clone(), watermark_ns, lateness_ns, rule_id)
        .expect("Handling late event must succeed");

    assert!(result.is_some());
    let record = result.unwrap();
    assert_eq!(record.tag, side_tag);
    assert_eq!(record.watermark_ns, watermark_ns);
    assert_eq!(record.lateness_ns, 50 * 1_000_000_000);
    assert_eq!(record.target_rule_id, Some(4242));
    assert_eq!(record.event.entity_id, "user_late_01");

    assert_eq!(engine.side_output_len(), 1);
    let drained = engine.drain_side_outputs(10);
    assert_eq!(drained.len(), 1);
    assert_eq!(engine.side_output_len(), 0);

    let stats = engine.stats();
    assert_eq!(stats.total_evaluated, 1);
    assert_eq!(stats.emitted_side_outputs, 1);
    assert_eq!(stats.dropped_silently, 0);
}

#[test]
fn test_feature_50_watermark_state_reclamation_gc() {
    let gc = WindowStateGC::new();

    // Create 50 window buckets from T=0 to T=5000s in 100s steps
    let bucket_size_ns = 100 * 1_000_000_000;
    let bytes_per_bucket = 2048;

    for i in 0..50 {
        let win_start = (i as i64) * bucket_size_ns;
        let win_end = win_start + bucket_size_ns;
        let bucket_id = (i + 1) as u64;
        gc.register_window(bucket_id, win_start, win_end, bytes_per_bucket, 10);
    }

    assert_eq!(gc.active_windows_count(), 50);
    assert_eq!(gc.active_memory_bytes(), 50 * bytes_per_bucket);

    // Advance watermark to T=4000s with allowed lateness 0
    let watermark_ns = 4000 * 1_000_000_000;
    let allowed_lateness_ns = 0;

    let purged = gc.on_watermark_advance(watermark_ns, allowed_lateness_ns);

    // Windows with end <= 4000s:
    // Window 0: [0, 100], end=100
    // ...
    // Window 39: [3900, 4000], end=4000 -> purged! (40 windows)
    // Window 40: [4000, 4100], end=4100 -> stays active! (10 windows remain)
    assert_eq!(purged.len(), 40);
    assert_eq!(gc.active_windows_count(), 10);
    assert_eq!(gc.active_memory_bytes(), 10 * bytes_per_bucket);

    let stats = gc.stats();
    assert_eq!(stats.total_purged_windows, 40);
    assert_eq!(stats.total_reclaimed_bytes, 40 * bytes_per_bucket);
    assert_eq!(stats.last_gc_watermark_ns, watermark_ns);
}

#[test]
fn test_feature_51_memory_limit_enforcement_and_spill_trigger() {
    // 10 MB total limit (10,485,760 bytes)
    // High watermark (85%): 8,912,896 bytes
    // Critical watermark (95%): 9,961,472 bytes
    let total_limit = 10 * 1024 * 1024;
    let manager = WindowMemoryManager::new(total_limit);

    // 1. Initial allocations below high watermark -> Ok
    let s1 = manager.track_alloc(5 * 1024 * 1024); // 5 MB
    assert_eq!(s1, MemoryStatus::Ok);
    assert_eq!(manager.current_allocated_bytes(), 5 * 1024 * 1024);

    // 2. Cross High Watermark (85%) -> SpillRequired
    let s2 = manager.track_alloc(4 * 1024 * 1024); // 5 + 4 = 9 MB >= 8.5 MB
    assert_eq!(s2, MemoryStatus::SpillRequired);

    // 3. Cross Critical Watermark (95%) -> Throttle
    let s3 = manager.track_alloc(1 * 1024 * 1024); // 9 + 1 = 10 MB >= 9.5 MB
    assert_eq!(s3, MemoryStatus::Throttle);

    // 4. Free memory and assert recovery back to Ok
    manager.track_free(6 * 1024 * 1024); // 10 - 6 = 4 MB
    assert_eq!(manager.current_allocated_bytes(), 4 * 1024 * 1024);

    let stats = manager.stats();
    assert_eq!(stats.allocated_bytes, 4 * 1024 * 1024);
    assert_eq!(stats.spill_triggers, 1);
    assert_eq!(stats.throttle_triggers, 1);
}

#[test]
fn test_feature_52_window_correctness_property_test() {
    let mut rng = rand::thread_rng();

    let window_size_ms: u64 = 60_000;
    let slide_size_ms: u64 = 10_000;
    let max_watermark_ms: u64 = 300_000;

    let event_count = 10_000;
    let mut events = Vec::with_capacity(event_count);

    // Generate 10,000 randomized events across [0, 300_000ms] with jitter
    for i in 0..event_count {
        let ts_ms = rng.gen_range(0..max_watermark_ms);
        let evt = make_event(&format!("user_{}", i % 50), (ts_ms as i64) * 1_000_000);
        events.push(evt);
    }

    // 1. Online Sliding Window state machine
    let online_window = SlidingWindow::new(window_size_ms, slide_size_ms);
    for evt in &events {
        let t_ms = (evt.event_timestamp_ns / 1_000_000) as u64;
        online_window.assign_event(t_ms, evt);
    }

    let mut online_results = Vec::new();
    online_window.advance_watermark(max_watermark_ms, |res| {
        online_results.push(res);
    });

    // 2. Offline Reference Oracle computation
    let reference_results = WindowOracle::compute_reference_sliding_windows(
        &events,
        window_size_ms,
        slide_size_ms,
        max_watermark_ms,
    );

    // 3. Assert bitwise mathematical parity
    assert!(
        WindowOracle::verify_sliding_windows(&online_results, &reference_results).is_ok(),
        "Online sliding window results must match offline reference oracle 100%"
    );
}

#[test]
fn test_feature_53_sharded_keyed_state_concurrent_access() {
    let store = Arc::new(KeyedStateStore::new());
    let thread_count = 16;
    let updates_per_thread = 10_000;
    let num_unique_keys = 500;

    let mut handles = Vec::with_capacity(thread_count);

    for t_id in 0..thread_count {
        let store_clone = Arc::clone(&store);
        let handle = thread::spawn(move || {
            for i in 0..updates_per_thread {
                let key_id = (t_id + i) % num_unique_keys;
                let key = format!("entity_counter_{:04}", key_id).into_bytes();

                store_clone.update_state(&key, StateValue::Counter(1), |val| {
                    if let StateValue::Counter(ref mut c) = val {
                        *c += 1;
                    }
                });
            }
        });
        handles.push(handle);
    }

    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(store.len(), num_unique_keys);

    // Calculate total aggregated count across all keys
    let mut total_counter_sum = 0;
    for k_id in 0..num_unique_keys {
        let key = format!("entity_counter_{:04}", k_id).into_bytes();
        let val = store.get_state(&key).expect("Key must exist");
        if let StateValue::Counter(c) = val {
            total_counter_sum += c;
        }
    }

    let expected_sum = (thread_count * updates_per_thread) as u64;
    assert_eq!(
        total_counter_sum, expected_sum,
        "Concurrent updates across shards must equal total operations exactly"
    );
}

#[test]
fn test_feature_54_canonical_composite_key_determinism() {
    let tenant_id: u32 = 101;

    let user_name = ValueVariant::String("alice_secops".to_string());
    let src_ip = ValueVariant::String("192.168.1.50".to_string());
    let event_type = ValueVariant::String("privilege_escalation".to_string());
    let severity = ValueVariant::Int(4);

    // Order 1: user.name, source_ip, event_type, severity
    let fields_order1 = vec![
        ("user.name", &user_name),
        ("source_ip", &src_ip),
        ("event_type", &event_type),
        ("severity", &severity),
    ];

    // Order 2: Reverse / Shuffled order
    let fields_order2 = vec![
        ("severity", &severity),
        ("event_type", &event_type),
        ("source_ip", &src_ip),
        ("user.name", &user_name),
    ];

    let encoded1 = CompositeKeyEncoder::encode_to_vec(tenant_id, &fields_order1);
    let encoded2 = CompositeKeyEncoder::encode_to_vec(tenant_id, &fields_order2);

    assert_eq!(
        encoded1, encoded2,
        "Composite key encoding must be strictly identical regardless of field parameter ordering"
    );
    assert!(!encoded1.is_empty());

    // Test Stack Buffer fast path
    let (stack_buf, len) =
        CompositeKeyEncoder::encode_to_stack_buffer::<256>(tenant_id, &fields_order1).unwrap();
    assert_eq!(&stack_buf[..len], encoded1.as_slice());
}
