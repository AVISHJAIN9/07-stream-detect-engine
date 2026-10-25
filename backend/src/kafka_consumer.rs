use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use parking_lot::RwLock;
use crate::types::{RawMessage, TopicPartition};

#[derive(Debug, Clone)]
pub struct ConsumerConfig {
    pub brokers: Vec<String>,
    pub group_id: String,
    pub topics: Vec<String>,
    pub max_poll_records: usize,
    pub enable_auto_commit: bool,
    pub auto_offset_reset: String,
    pub session_timeout_ms: u64,
    pub heartbeat_interval_ms: u64,
}

impl Default for ConsumerConfig {
    fn default() -> Self {
        Self {
            brokers: vec!["localhost:9092".to_string()],
            group_id: "stream-detection-workers".to_string(),
            topics: vec!["telemetry-events".to_string()],
            max_poll_records: 5000,
            enable_auto_commit: false,
            auto_offset_reset: "earliest".to_string(),
            session_timeout_ms: 30000,
            heartbeat_interval_ms: 3000,
        }
    }
}

pub trait RebalanceListener: Send + Sync {
    fn on_partitions_assigned(&self, partitions: &[TopicPartition]);
    fn on_partitions_revoked(&self, partitions: &[TopicPartition]);
}

pub struct DefaultRebalanceListener;
impl RebalanceListener for DefaultRebalanceListener {
    fn on_partitions_assigned(&self, partitions: &[TopicPartition]) {
        tracing::info!("Consumer assigned partitions: {:?}", partitions);
    }
    fn on_partitions_revoked(&self, partitions: &[TopicPartition]) {
        tracing::info!("Consumer revoked partitions: {:?}", partitions);
    }
}

/// In-memory Redpanda/Kafka partition stream simulator for deterministic testing & local broker dispatch
#[derive(Debug, Default)]
pub struct MockKafkaBroker {
    topic_data: RwLock<HashMap<TopicPartition, Vec<RawMessage>>>,
    committed_offsets: RwLock<HashMap<String, HashMap<TopicPartition, i64>>>,
}

impl MockKafkaBroker {
    pub fn new() -> Self {
        Self {
            topic_data: RwLock::new(HashMap::new()),
            committed_offsets: RwLock::new(HashMap::new()),
        }
    }

    pub fn produce(&self, topic: &str, partition: i32, key: Option<Vec<u8>>, payload: Vec<u8>) -> i64 {
        let tp = TopicPartition::new(topic, partition);
        let mut map = self.topic_data.write();
        let queue = map.entry(tp).or_default();
        let offset = queue.len() as i64;
        queue.push(RawMessage {
            topic: topic.to_string(),
            partition,
            offset,
            timestamp_ms: chrono::Utc::now().timestamp_millis(),
            key,
            payload,
            headers: HashMap::new(),
        });
        offset
    }

    pub fn produce_batch(&self, topic: &str, partition: i32, records: Vec<Vec<u8>>) -> usize {
        let tp = TopicPartition::new(topic, partition);
        let mut map = self.topic_data.write();
        let queue = map.entry(tp).or_default();
        let count = records.len();
        for payload in records {
            let offset = queue.len() as i64;
            queue.push(RawMessage {
                topic: topic.to_string(),
                partition,
                offset,
                timestamp_ms: chrono::Utc::now().timestamp_millis(),
                key: None,
                payload,
                headers: HashMap::new(),
            });
        }
        count
    }

    pub fn get_committed_offset(&self, group_id: &str, tp: &TopicPartition) -> Option<i64> {
        let lock = self.committed_offsets.read();
        lock.get(group_id).and_then(|m| m.get(tp).copied())
    }
}

/// Thread-safe Stream Consumer for Redpanda and Apache Kafka
pub struct KafkaStreamConsumer {
    config: ConsumerConfig,
    broker: Arc<MockKafkaBroker>,
    assigned_partitions: RwLock<HashSet<TopicPartition>>,
    paused_partitions: RwLock<HashSet<TopicPartition>>,
    current_offsets: RwLock<HashMap<TopicPartition, i64>>,
    rebalance_listener: Arc<dyn RebalanceListener>,
    is_running: AtomicBool,
    last_heartbeat_ms: AtomicI64,
}

impl KafkaStreamConsumer {
    pub fn new(
        config: ConsumerConfig,
        broker: Arc<MockKafkaBroker>,
        rebalance_listener: Option<Arc<dyn RebalanceListener>>,
    ) -> Self {
        let listener = rebalance_listener.unwrap_or_else(|| Arc::new(DefaultRebalanceListener));
        Self {
            config,
            broker,
            assigned_partitions: RwLock::new(HashSet::new()),
            paused_partitions: RwLock::new(HashSet::new()),
            current_offsets: RwLock::new(HashMap::new()),
            rebalance_listener: listener,
            is_running: AtomicBool::new(true),
            last_heartbeat_ms: AtomicI64::new(chrono::Utc::now().timestamp_millis()),
        }
    }

    pub fn subscribe(&self, topics: &[String]) {
        let mut assigned = self.assigned_partitions.write();
        let mut offsets = self.current_offsets.write();
        assigned.clear();
        offsets.clear();

        for topic in topics {
            // Assume 4 partitions per topic in standard setup
            for p in 0..4 {
                let tp = TopicPartition::new(topic.clone(), p);
                let committed = self
                    .broker
                    .get_committed_offset(&self.config.group_id, &tp)
                    .unwrap_or(0);
                offsets.insert(tp.clone(), committed);
                assigned.insert(tp);
            }
        }

        let assigned_vec: Vec<TopicPartition> = assigned.iter().cloned().collect();
        self.rebalance_listener.on_partitions_assigned(&assigned_vec);
    }

    pub fn assign_partitions(&self, partitions: Vec<TopicPartition>) {
        let mut assigned = self.assigned_partitions.write();
        let mut offsets = self.current_offsets.write();
        assigned.clear();
        offsets.clear();

        for tp in &partitions {
            let committed = self
                .broker
                .get_committed_offset(&self.config.group_id, tp)
                .unwrap_or(0);
            offsets.insert(tp.clone(), committed);
            assigned.insert(tp.clone());
        }

        self.rebalance_listener.on_partitions_assigned(&partitions);
    }

    pub fn pause_partition(&self, tp: &TopicPartition) {
        self.paused_partitions.write().insert(tp.clone());
    }

    pub fn resume_partition(&self, tp: &TopicPartition) {
        self.paused_partitions.write().remove(tp);
    }

    pub fn is_paused(&self, tp: &TopicPartition) -> bool {
        self.paused_partitions.read().contains(tp)
    }

    pub fn poll_batch(&self, _timeout: Duration) -> Vec<RawMessage> {
        if !self.is_running.load(Ordering::Acquire) {
            return Vec::new();
        }

        self.last_heartbeat_ms
            .store(chrono::Utc::now().timestamp_millis(), Ordering::Release);

        let assigned = self.assigned_partitions.read().clone();
        let paused = self.paused_partitions.read().clone();
        let mut offsets = self.current_offsets.write();
        let broker_data = self.broker.topic_data.read();

        let mut batch = Vec::new();
        let max_per_partition = self.config.max_poll_records / std::cmp::max(1, assigned.len());

        for tp in assigned {
            if paused.contains(&tp) {
                continue;
            }

            if let Some(queue) = broker_data.get(&tp) {
                let current_off = offsets.entry(tp.clone()).or_insert(0);
                let start_idx = *current_off as usize;

                if start_idx < queue.len() {
                    let end_idx = std::cmp::min(queue.len(), start_idx + max_per_partition);
                    for item in &queue[start_idx..end_idx] {
                        batch.push(item.clone());
                    }
                    *current_off = end_idx as i64;
                }
            }
        }

        batch
    }

    pub fn commit_offsets(&self, offsets_to_commit: &HashMap<TopicPartition, i64>) -> Result<(), String> {
        let mut committed = self.broker.committed_offsets.write();
        let group_map = committed.entry(self.config.group_id.clone()).or_default();
        for (tp, offset) in offsets_to_commit {
            group_map.insert(tp.clone(), *offset);
        }
        Ok(())
    }

    pub fn commit_sync(&self) -> Result<(), String> {
        let current = self.current_offsets.read().clone();
        self.commit_offsets(&current)
    }

    pub fn trigger_rebalance(&self, new_partitions: Vec<TopicPartition>) {
        let old_assigned: Vec<TopicPartition> = self.assigned_partitions.read().iter().cloned().collect();
        self.rebalance_listener.on_partitions_revoked(&old_assigned);
        self.assign_partitions(new_partitions);
    }

    pub fn close(&self) {
        self.is_running.store(false, Ordering::Release);
        let _ = self.commit_sync();
    }
}
