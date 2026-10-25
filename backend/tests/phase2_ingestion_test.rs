use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use stream_detect_engine::types::*;
use stream_detect_engine::canonical_normalizer::*;
use stream_detect_engine::zero_copy_buffer::*;
use stream_detect_engine::timestamp_extractor::*;
use stream_detect_engine::dedup_key_generator::*;
use stream_detect_engine::metadata_enricher::*;
use stream_detect_engine::affinity_router::*;
use stream_detect_engine::ingress_metrics::*;

#[test]
fn test_feature_7_zero_copy_buffer_lifecycle() {
    let arena = Arc::new(MemoryArena::new(4, DEFAULT_PAGE_SIZE));
    assert_eq!(arena.available_pages(), 4);

    let raw_payload = b"ZERO_COPY_NETWORK_INGESTION_PAYLOAD_CHUNK_001_DATA_SECTION_FOR_TESTING";
    let root_slice = arena.acquire_slice(raw_payload).expect("Acquire slice must succeed");

    assert_eq!(arena.available_pages(), 3);
    assert_eq!(root_slice.ref_count(), 1);

    let mut slices = Vec::new();
    for i in 0..20 {
        let sub = root_slice.slice(i, 10).expect("Sub-slice must succeed");
        slices.push(sub);
    }
    assert_eq!(root_slice.ref_count(), 21);

    drop(root_slice);
    assert_eq!(arena.available_pages(), 3);

    let mut chunks = vec![Vec::new(), Vec::new(), Vec::new(), Vec::new()];
    for (i, slice) in slices.into_iter().enumerate() {
        chunks[i % 4].push(slice);
    }

    let mut handles = Vec::new();
    for worker_chunk in chunks {
        let handle = thread::spawn(move || {
            for slice in worker_chunk {
                assert!(!slice.as_slice().is_empty());
            }
        });
        handles.push(handle);
    }

    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(arena.available_pages(), 4, "Arena page must be 100% recycled back to pool");
}

#[test]
fn test_feature_8_timestamp_extraction_and_skew_rejection() {
    let extractor = TimestampExtractor::new(3600, 86400 * 7);
    let now_ns = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);

    for i in 0..10000 {
        let mode = i % 4;
        let val = match mode {
            0 => ValueVariant::String("2026-10-06T00:00:00.000000000Z".to_string()),
            1 => ValueVariant::Int(1791244800000),
            2 => ValueVariant::Float(1791244800000.0),
            _ => ValueVariant::Int(1791244800000000000),
        };
        let ts = extractor.extract_timestamp(&val).expect("Extraction must succeed");
        assert_eq!(ts, 1791244800000000000);
    }

    let future_skewed_ts = now_ns + (3 * 3600 * 1_000_000_000);
    assert!(extractor.validate_skew(future_skewed_ts, now_ns).is_err());

    let past_skewed_ts = now_ns - (10 * 86400 * 1_000_000_000);
    assert!(extractor.validate_skew(past_skewed_ts, now_ns).is_err());
}

#[test]
fn test_feature_9_deterministic_dedup_fingerprinting() {
    let uuid_gen = UUIDv7Generator::new();
    let mut uuids = Vec::with_capacity(1000);
    for _ in 0..1000 {
        uuids.push(uuid_gen.generate());
    }
    for i in 1..1000 {
        assert!(uuids[i] > uuids[i - 1]);
    }

    let attrs_order_a = vec![
        ("src_ip".to_string(), ValueVariant::String("192.168.1.50".to_string())),
        ("dst_port".to_string(), ValueVariant::Int(443)),
        ("protocol".to_string(), ValueVariant::String("TLS_1_3".to_string())),
        ("bytes_transferred".to_string(), ValueVariant::Int(84920)),
    ];

    let attrs_order_b = vec![
        ("bytes_transferred".to_string(), ValueVariant::Int(84920)),
        ("protocol".to_string(), ValueVariant::String("TLS_1_3".to_string())),
        ("dst_port".to_string(), ValueVariant::Int(443)),
        ("src_ip".to_string(), ValueVariant::String("192.168.1.50".to_string())),
    ];

    let fp_a = DedupKeyGenerator::compute_fingerprint(
        "tenant_sec_corp",
        "srv_db_master",
        "network_connection",
        1791244800000000000,
        &attrs_order_a,
    );

    let fp_b = DedupKeyGenerator::compute_fingerprint(
        "tenant_sec_corp",
        "srv_db_master",
        "network_connection",
        1791244800000000000,
        &attrs_order_b,
    );

    assert_eq!(fp_a, fp_b);
}

#[test]
fn test_feature_10_ambient_metadata_enrichment() {
    let enricher = MetadataEnricher::new(SourceProvenance {
        gateway_id: "edge-gw-us-east-1a".to_string(),
        protocol: IngressProtocol::Grpc,
        cluster_region: "us-east-1".to_string(),
        network_cidr: Some("10.0.0.0/16".to_string()),
        k8s_pod: Some("stream-detect-ingress-pod-99x".to_string()),
        k8s_namespace: Some("prod-detection".to_string()),
        cloud_provider: "aws".to_string(),
    });

    let mut event = CanonicalEvent {
        event_id: uuid::Uuid::new_v4(),
        ingestion_seq: 1001,
        event_timestamp_ns: 1791244800000000000,
        ingress_timestamp_ns: 1791244800000000000,
        event_type: "ssh_login".to_string(),
        source: "bastion_01".to_string(),
        entity_id: "admin_user".to_string(),
        source_ip: Some("10.1.50.22".to_string()),
        attributes: HashMap::new(),
    };

    let ctx = IngressContext {
        gateway_id: "edge-gw-us-east-1a".to_string(),
        protocol: IngressProtocol::Grpc,
        client_ip: Some("10.1.50.22".to_string()),
        client_tls_cipher: Some("TLS_AES_256_GCM_SHA384".to_string()),
    };

    enricher.enrich(&mut event, &ctx);

    assert_eq!(event.attributes.get("_meta.gateway_id"), Some(&ValueVariant::String("edge-gw-us-east-1a".to_string())));
    assert_eq!(event.attributes.get("_meta.ingress_protocol"), Some(&ValueVariant::String("GRPC".to_string())));
    assert_eq!(event.attributes.get("_meta.cluster_region"), Some(&ValueVariant::String("eu-west-1".to_string())));
    assert_eq!(event.attributes.get("_meta.vpc_id"), Some(&ValueVariant::String("vpc-prod-eu".to_string())));
    assert_eq!(event.attributes.get("_meta.cloud_provider"), Some(&ValueVariant::String("aws".to_string())));
}

#[test]
fn test_feature_11_entity_affinity_partitioning() {
    let num_workers = 8;
    let events_per_partition = Arc::new(vec![
        AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0),
        AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0),
    ]);

    let counters_clone = Arc::clone(&events_per_partition);
    let worker_consumer = Arc::new(move |partition_id: usize, _evt: CanonicalEvent| {
        counters_clone[partition_id].fetch_add(1, Ordering::Relaxed);
    });

    let router = PartitionRouter::new(num_workers, 16384, worker_consumer);
    let mut entity_assigned_partition: HashMap<String, usize> = HashMap::new();

    let total_events = 50000;
    for i in 0..total_events {
        let entity_id = format!("entity_device_{:04}", i % 100);
        let expected_partition = router.get_target_partition(&entity_id);

        if let Some(&prev_p) = entity_assigned_partition.get(&entity_id) {
            assert_eq!(prev_p, expected_partition);
        } else {
            entity_assigned_partition.insert(entity_id.clone(), expected_partition);
        }

        let evt = CanonicalEvent {
            event_id: uuid::Uuid::new_v4(),
            ingestion_seq: i as u64,
            event_timestamp_ns: 1791244800000000000,
            ingress_timestamp_ns: 1791244800000000000,
            event_type: "metric_tick".to_string(),
            source: "agent".to_string(),
            entity_id,
            source_ip: None,
            attributes: HashMap::new(),
        };

        let routed_p = router.route(evt).expect("Route must succeed");
        assert_eq!(routed_p, expected_partition);
    }

    let deadline = Instant::now() + std::time::Duration::from_secs(3);
    while router.total_routed() < 50000 && Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(5));
    }

    router.shutdown();
}

#[test]
fn test_feature_12_ingress_telemetry_registry() {
    let registry = Arc::new(IngressMetricsRegistry::new());
    let total_events = 500000;
    let num_threads = 8;
    let events_per_thread = total_events / num_threads;

    let mut handles = Vec::new();
    for _ in 0..num_threads {
        let reg = Arc::clone(&registry);
        let h = thread::spawn(move || {
            for i in 0..events_per_thread {
                let simulated_latency_ns = 250 + (i % 500) as u64;
                reg.record_event(512, simulated_latency_ns);
            }
        });
        handles.push(h);
    }

    for h in handles {
        h.join().unwrap();
    }

    let report = registry.snapshot_report();
    assert_eq!(report.total_events, total_events as u64);
    assert_eq!(report.total_bytes, (total_events * 512) as u64);
    assert!(report.events_per_sec > 500_000.0);
}
