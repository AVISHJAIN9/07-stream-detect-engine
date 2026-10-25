use parking_lot::RwLock;
use std::sync::atomic::{AtomicI64, Ordering};

/// State tracking for a single ingress partition / worker channel
#[derive(Debug, Clone, PartialEq)]
pub struct PartitionState {
    pub partition_id: usize,
    pub watermark_ns: i64,
    pub last_updated_sys_ns: i64,
    pub is_idle: bool,
    pub event_count: u64,
}

/// Partition-Aware Multi-Channel Watermark Tracker
///
/// For P Kafka partitions or worker ingress queues, tracks individual partition watermarks
/// and computes the global aligned engine watermark as:
///   GlobalWatermark = min_{p \in ActivePartitions} W_p
/// Automatically excludes partitions marked as IDLE due to inactivity timeouts,
/// preventing global streaming progress freezes while strictly maintaining monotonic progression.
pub struct PartitionWatermarkTracker {
    num_partitions: usize,
    idle_timeout_ns: i64,
    partitions: RwLock<Vec<PartitionState>>,
    global_watermark: AtomicI64,
}

impl PartitionWatermarkTracker {
    pub fn new(num_partitions: usize, idle_timeout_ns: i64) -> Self {
        assert!(num_partitions > 0, "num_partitions must be > 0");

        let mut partitions = Vec::with_capacity(num_partitions);
        for id in 0..num_partitions {
            partitions.push(PartitionState {
                partition_id: id,
                watermark_ns: 0,
                last_updated_sys_ns: 0,
                is_idle: false,
                event_count: 0,
            });
        }

        Self {
            num_partitions,
            idle_timeout_ns: idle_timeout_ns.abs(),
            partitions: RwLock::new(partitions),
            global_watermark: AtomicI64::new(0),
        }
    }

    /// Updates the watermark for a specific partition and recomputes the global watermark
    pub fn update_partition_watermark(
        &self,
        partition_id: usize,
        watermark_ns: i64,
        sys_time_ns: i64,
    ) -> i64 {
        let mut parts = self.partitions.write();
        if partition_id < parts.len() {
            let p = &mut parts[partition_id];
            p.watermark_ns = watermark_ns;
            p.last_updated_sys_ns = sys_time_ns;
            p.is_idle = false;
            p.event_count += 1;
        }

        self.recalculate_global_watermark(&parts)
    }

    /// Explicitly marks a partition as idle
    pub fn mark_partition_idle(&self, partition_id: usize) -> i64 {
        let mut parts = self.partitions.write();
        if partition_id < parts.len() {
            parts[partition_id].is_idle = true;
        }
        self.recalculate_global_watermark(&parts)
    }

    /// Scans for partitions that have timed out and marks them as idle, advancing global watermark
    pub fn check_idle_partitions(&self, current_sys_time_ns: i64) -> i64 {
        let mut parts = self.partitions.write();
        let mut changed = false;

        for p in parts.iter_mut() {
            if !p.is_idle && p.last_updated_sys_ns > 0 {
                let elapsed = current_sys_time_ns.saturating_sub(p.last_updated_sys_ns);
                if elapsed >= self.idle_timeout_ns {
                    p.is_idle = true;
                    changed = true;
                }
            }
        }

        if changed {
            self.recalculate_global_watermark(&parts)
        } else {
            self.global_watermark.load(Ordering::Acquire)
        }
    }

    /// Recomputes global watermark as min of all non-idle partitions
    fn recalculate_global_watermark(&self, parts: &[PartitionState]) -> i64 {
        let active_parts: Vec<&PartitionState> = parts.iter().filter(|p| !p.is_idle).collect();

        let candidate_global = if active_parts.is_empty() {
            // If all partitions are idle, use maximum watermark among all partitions
            parts.iter().map(|p| p.watermark_ns).max().unwrap_or(0)
        } else {
            active_parts.iter().map(|p| p.watermark_ns).min().unwrap_or(0)
        };

        // Ensure global watermark never regresses
        let mut cur_global = self.global_watermark.load(Ordering::Acquire);
        while candidate_global > cur_global {
            match self.global_watermark.compare_exchange_weak(
                cur_global,
                candidate_global,
                Ordering::Release,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return candidate_global;
                }
                Err(actual) => cur_global = actual,
            }
        }

        cur_global
    }

    #[inline]
    pub fn global_watermark(&self) -> i64 {
        self.global_watermark.load(Ordering::Acquire)
    }

    #[inline]
    pub fn num_partitions(&self) -> usize {
        self.num_partitions
    }

    pub fn active_partition_count(&self) -> usize {
        let parts = self.partitions.read();
        parts.iter().filter(|p| !p.is_idle).count()
    }

    pub fn partition_state(&self, partition_id: usize) -> Option<PartitionState> {
        let parts = self.partitions.read();
        parts.get(partition_id).cloned()
    }

    pub fn all_partition_states(&self) -> Vec<PartitionState> {
        let parts = self.partitions.read();
        parts.clone()
    }
}
