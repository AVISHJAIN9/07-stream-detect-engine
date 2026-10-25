use std::fs;
use uuid::Uuid;

use stream_detect_engine::dedup_engine::DedupEngine;
use stream_detect_engine::idle_eviction::IdleKeyTracker;
use stream_detect_engine::keyed_state_store::{KeyedStateStore, StateValue};
use stream_detect_engine::state_limiter::StateSizeLimiter;
use stream_detect_engine::state_restore::StateRestoreEngine;
use stream_detect_engine::state_snapshot::SnapshotManager;
use stream_detect_engine::timing_wheel::TimingWheel;

#[test]
fn test_feature_55_hierarchical_timing_wheel_precision() {
    let start_time_ms = 1_000_000;
    let wheel = TimingWheel::new(start_time_ms);

    // Schedule 1,000 keys with diverse TTLs:
    // 250 keys @ 20ms (Level 0)
    // 250 keys @ 50ms (Level 0)
    // 250 keys @ 5,000ms (Level 1)
    // 250 keys @ 20,000ms (Level 1)
    for i in 0..250 {
        wheel.schedule(format!("k_20ms_{}", i).into_bytes(), 20);
        wheel.schedule(format!("k_50ms_{}", i).into_bytes(), 50);
        wheel.schedule(format!("k_5s_{}", i).into_bytes(), 5_000);
        wheel.schedule(format!("k_20s_{}", i).into_bytes(), 20_000);
    }

    assert_eq!(wheel.active_timers_count(), 1000);

    // 1. Advance by 19ms -> 0 keys expired
    let exp0 = wheel.advance(start_time_ms + 19);
    assert_eq!(exp0.len(), 0);

    // 2. Advance by 1ms (to +20ms) -> exactly 250 keys expired
    let exp20 = wheel.advance(start_time_ms + 20);
    assert_eq!(exp20.len(), 250);
    assert_eq!(wheel.active_timers_count(), 750);

    // 3. Advance to +50ms -> exactly 250 keys expired
    let exp50 = wheel.advance(start_time_ms + 50);
    assert_eq!(exp50.len(), 250);
    assert_eq!(wheel.active_timers_count(), 500);

    // 4. Advance to +5,000ms -> Level 1 cascade & 250 keys expired
    let exp5s = wheel.advance(start_time_ms + 5_000);
    assert_eq!(exp5s.len(), 250);
    assert_eq!(wheel.active_timers_count(), 250);

    // 5. Advance to +20,000ms -> remaining 250 keys expired
    let exp20s = wheel.advance(start_time_ms + 20_000);
    assert_eq!(exp20s.len(), 250);
    assert_eq!(wheel.active_timers_count(), 0);
}

#[test]
fn test_feature_56_idle_key_inactivity_eviction() {
    let tracker = IdleKeyTracker::new();
    let key_a = b"user_active_session";
    let key_b = b"user_idle_session";

    let t0 = 1_000_000_000; // 1.0s
    tracker.touch(key_a, t0);
    tracker.touch(key_b, t0);

    assert_eq!(tracker.len(), 2);

    // Key A is accessed at T=2.0s, T=3.0s, T=4.0s
    tracker.touch(key_a, 2_000_000_000);
    tracker.touch(key_a, 3_000_000_000);
    tracker.touch(key_a, 4_000_000_000);

    // Scrubber runs at T=4.5s with an Inactivity Timeout of 2.0s (Cutoff = 4.5s - 2.0s = 2.5s)
    let cutoff = 2_500_000_000;
    let evicted = tracker.evict_stale(cutoff, 10);

    // Key B (last accessed at 1.0s <= 2.5s) must be evicted
    // Key A (last accessed at 4.0s > 2.5s) must remain active
    assert_eq!(evicted.len(), 1);
    assert_eq!(evicted[0], key_b);
    assert_eq!(tracker.len(), 1);
    assert_eq!(tracker.last_access(key_a), Some(4_000_000_000));
    assert_eq!(tracker.last_access(key_b), None);
}

#[test]
fn test_feature_57_memory_budget_shedding_under_pressure() {
    // 10 MB total budget (10,000,000 bytes)
    // Soft Limit (80%): 8,000,000 bytes
    // Hard Limit (95%): 9,500,000 bytes
    let total_budget = 10_000_000;
    let limiter = StateSizeLimiter::new(total_budget);

    // Allocate 9.2 MB (92% capacity -> above soft limit, below hard limit)
    let initial_alloc = 9_200_000;
    assert!(limiter.track_alloc(initial_alloc).is_ok());
    assert_eq!(limiter.current_bytes(), 9_200_000);

    // Attempting to allocate 500 KB (9.2MB + 0.5MB = 9.7MB > 9.5MB hard limit) must be rejected
    assert!(!limiter.can_allocate(500_000));
    assert!(limiter.track_alloc(500_000).is_err());

    // Trigger proactive limit enforcement with LRU eviction callback
    let mut evicted_records_count = 0;
    let bytes_freed = limiter.enforce_limits(|needed_to_free| {
        // Each mock entry is 100 KB
        let entries_to_evict = (needed_to_free + 102_399) / 102_400;
        evicted_records_count = entries_to_evict;
        entries_to_evict * 102_400
    });

    assert!(bytes_freed >= 1_200_000); // 9.2MB - 8.0MB = 1.2MB needed
    assert!(limiter.current_bytes() <= limiter.soft_limit_bytes());
    assert!(limiter.can_allocate(500_000), "Allocation should succeed once memory pressure is relieved");
}

#[test]
fn test_feature_58_consistent_point_in_time_snapshot() {
    let tmp_path = std::env::temp_dir().join(format!("stream_detect_snap58_{}", Uuid::new_v4()));
    let checkpoint_path = tmp_path.to_str().unwrap();

    let store = KeyedStateStore::new();
    let num_keys = 50_000;

    for i in 0..num_keys {
        let key = format!("state_metric_key_{:06}", i).into_bytes();
        let val = StateValue::Counter(i as u64);
        store.put_state(&key, val);
    }

    assert_eq!(store.len(), num_keys);

    let snapshot_id = 1001;
    let meta = SnapshotManager::create_snapshot(checkpoint_path, snapshot_id, &store)
        .expect("Snapshot creation must succeed");

    assert_eq!(meta.snapshot_id, snapshot_id);
    assert_eq!(meta.total_keys, num_keys);
    assert_eq!(meta.shard_count, store.num_shards());
    assert_eq!(meta.shard_checksums.len(), store.num_shards());

    let _ = fs::remove_dir_all(&tmp_path);
}

#[test]
fn test_feature_59_state_restore_and_checksum_verification() {
    let tmp_path = std::env::temp_dir().join(format!("stream_detect_snap59_{}", Uuid::new_v4()));
    let checkpoint_path = tmp_path.to_str().unwrap();

    let original_store = KeyedStateStore::new();
    let num_keys = 50_000;

    for i in 0..num_keys {
        let key = format!("state_metric_key_{:06}", i).into_bytes();
        let val = StateValue::Counter(i as u64);
        original_store.put_state(&key, val);
    }

    let snapshot_id = 2002;
    let meta = SnapshotManager::create_snapshot(checkpoint_path, snapshot_id, &original_store)
        .expect("Snapshot creation must succeed");
    assert_eq!(meta.total_keys, num_keys);

    // Mount restored state into clean store
    let restored_store = KeyedStateStore::new();
    assert_eq!(restored_store.len(), 0);

    let restored_meta = StateRestoreEngine::restore_from_snapshot(
        checkpoint_path,
        snapshot_id,
        &restored_store,
    )
    .expect("State restore must succeed");

    assert_eq!(restored_meta.total_keys, num_keys);
    assert_eq!(restored_store.len(), num_keys);

    for i in (0..num_keys).step_by(500) {
        let key = format!("state_metric_key_{:06}", i).into_bytes();
        let val = restored_store.get_state(&key).expect("Key must exist in restored store");
        assert_eq!(val, StateValue::Counter(i as u64));
    }

    let _ = fs::remove_dir_all(&tmp_path);
}

#[test]
fn test_feature_60_high_throughput_event_deduplication() {
    // 256K bit Bloom Filter, 64K entry Exact LRU
    let dedup = DedupEngine::new(262_144, 65_536);

    let unique_count = 100_000;
    let duplicate_count = 20_000;

    let now_ns = 1_700_000_000_000_000_000;

    // 1. Ingest 100,000 unique event fingerprints (IDs 0..100,000)
    for i in 0..unique_count {
        let fp = (i as u64) ^ 0xA5A5_5A5A_0F0F_F0F0;
        let is_dup = dedup.is_duplicate(fp, now_ns + i as i64);
        assert!(!is_dup, "First encounter of fingerprint must not be duplicate (id: {})", i);
    }

    // 2. Re-ingest 20,000 duplicate fingerprints from the recent window
    let mut detected_duplicates = 0;
    for i in (unique_count - duplicate_count)..unique_count {
        let fp = (i as u64) ^ 0xA5A5_5A5A_0F0F_F0F0;
        let is_dup = dedup.is_duplicate(fp, now_ns + (i + 100_000) as i64);
        if is_dup {
            detected_duplicates += 1;
        }
    }

    assert_eq!(
        detected_duplicates, duplicate_count,
        "100% of duplicate event fingerprints must be trapped and rejected"
    );

    let stats = dedup.stats();
    assert_eq!(stats.total_checked, (unique_count + duplicate_count) as u64);
    assert_eq!(stats.unique_count, unique_count as u64);
    assert_eq!(stats.duplicate_count, duplicate_count as u64);
}
