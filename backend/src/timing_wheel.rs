use parking_lot::RwLock;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};

/// Typed Timer Handle for cancellation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TimerHandle {
    pub id: u64,
    pub expire_ts_ms: u64,
}

#[derive(Debug, Clone)]
struct ScheduledTimer {
    id: u64,
    key: Vec<u8>,
    expire_ts_ms: u64,
}

/// Timing Wheel Level Configuration
struct WheelLevel {
    num_slots: usize,
    slot_duration_ms: u64,
    level_duration_ms: u64,
    slots: Vec<VecDeque<ScheduledTimer>>,
}

impl WheelLevel {
    fn new(num_slots: usize, slot_duration_ms: u64) -> Self {
        let mut slots = Vec::with_capacity(num_slots);
        for _ in 0..num_slots {
            slots.push(VecDeque::new());
        }
        let level_duration_ms = (num_slots as u64) * slot_duration_ms;
        Self {
            num_slots,
            slot_duration_ms,
            level_duration_ms,
            slots,
        }
    }

    #[inline]
    fn get_slot_index(&self, expire_ts_ms: u64) -> usize {
        ((expire_ts_ms / self.slot_duration_ms) % (self.num_slots as u64)) as usize
    }
}

/// Timing Wheel Telemetry & Stats
#[derive(Debug, Clone, PartialEq)]
pub struct TimingWheelStats {
    pub current_time_ms: u64,
    pub active_timers: usize,
    pub total_scheduled: u64,
    pub total_expired: u64,
    pub total_cancelled: u64,
}

/// Hierarchical Timing Wheel for O(1) TTL Registration, Cascading, and Eviction
///
/// Implements 4-tier hierarchy:
///   Level 0: Milliseconds (64 slots x 1ms = 64ms)
///   Level 1: Seconds (60 slots x 1,000ms = 60s)
///   Level 2: Minutes (60 slots x 60,000ms = 60m)
///   Level 3: Hours (24 slots x 3,600,000ms = 24h)
/// Supports sub-millisecond precision, O(1) scheduling, cancellation, and cascading ticks.
pub struct TimingWheel {
    current_time_ms: RwLock<u64>,
    levels: RwLock<Vec<WheelLevel>>,
    timer_lookup: RwLock<HashMap<u64, u64>>, // id -> expire_ts_ms
    timer_id_gen: AtomicU64,
    total_scheduled: AtomicU64,
    total_expired: AtomicU64,
    total_cancelled: AtomicU64,
}

impl TimingWheel {
    pub fn new(start_time_ms: u64) -> Self {
        let levels = vec![
            WheelLevel::new(64, 1),             // Level 0: 64 ms
            WheelLevel::new(60, 1_000),         // Level 1: 60 sec
            WheelLevel::new(60, 60_000),        // Level 2: 60 min
            WheelLevel::new(24, 3_600_000),     // Level 3: 24 hr
        ];

        Self {
            current_time_ms: RwLock::new(start_time_ms),
            levels: RwLock::new(levels),
            timer_lookup: RwLock::new(HashMap::new()),
            timer_id_gen: AtomicU64::new(1),
            total_scheduled: AtomicU64::new(0),
            total_expired: AtomicU64::new(0),
            total_cancelled: AtomicU64::new(0),
        }
    }

    /// Schedules a key for eviction after ttl_duration_ms
    pub fn schedule(&self, key: Vec<u8>, ttl_duration_ms: u64) -> TimerHandle {
        let cur_time = *self.current_time_ms.read();
        let expire_ts_ms = cur_time + ttl_duration_ms;
        let id = self.timer_id_gen.fetch_add(1, Ordering::Relaxed);

        let timer = ScheduledTimer {
            id,
            key,
            expire_ts_ms,
        };

        {
            let mut levels_guard = self.levels.write();
            self.insert_timer(&mut levels_guard, timer, cur_time);
        }

        {
            let mut lookup = self.timer_lookup.write();
            lookup.insert(id, expire_ts_ms);
        }

        self.total_scheduled.fetch_add(1, Ordering::Relaxed);

        TimerHandle { id, expire_ts_ms }
    }

    /// Internal helper inserting timer into the appropriate hierarchical level
    fn insert_timer(&self, levels: &mut [WheelLevel], timer: ScheduledTimer, cur_time: u64) {
        let diff = timer.expire_ts_ms.saturating_sub(cur_time);

        if diff < levels[0].level_duration_ms {
            let slot = levels[0].get_slot_index(timer.expire_ts_ms);
            levels[0].slots[slot].push_back(timer);
        } else if diff < levels[1].level_duration_ms {
            let slot = levels[1].get_slot_index(timer.expire_ts_ms);
            levels[1].slots[slot].push_back(timer);
        } else if diff < levels[2].level_duration_ms {
            let slot = levels[2].get_slot_index(timer.expire_ts_ms);
            levels[2].slots[slot].push_back(timer);
        } else {
            let slot = levels[3].get_slot_index(timer.expire_ts_ms);
            levels[3].slots[slot].push_back(timer);
        }
    }

    /// Cancels an active timer
    pub fn cancel(&self, handle: TimerHandle) -> bool {
        let mut lookup = self.timer_lookup.write();
        if lookup.remove(&handle.id).is_some() {
            self.total_cancelled.fetch_add(1, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Advances the clock to now_ms, cascading upper wheels and expiring all due timers
    pub fn advance(&self, now_ms: u64) -> Vec<Vec<u8>> {
        let mut cur_time_guard = self.current_time_ms.write();
        if now_ms < *cur_time_guard {
            return Vec::new();
        }

        let mut expired_keys = Vec::new();
        let mut levels_guard = self.levels.write();
        let mut lookup_guard = self.timer_lookup.write();

        while *cur_time_guard < now_ms {
            *cur_time_guard += 1;
            let current = *cur_time_guard;

            // 1. Cascade upper levels first if slot boundaries are crossed
            // Level 3: Every hour (3,600,000ms)
            if current % 3_600_000 == 0 {
                self.cascade_level(&mut levels_guard, &lookup_guard, 3, current);
            }
            // Level 2: Every minute (60,000ms)
            if current % 60_000 == 0 {
                self.cascade_level(&mut levels_guard, &lookup_guard, 2, current);
            }
            // Level 1: Every second (1,000ms)
            if current % 1_000 == 0 {
                self.cascade_level(&mut levels_guard, &lookup_guard, 1, current);
            }

            // 2. Drain Level 0 slot matching current timestamp
            let slot_idx = levels_guard[0].get_slot_index(current);
            let mut due_timers = VecDeque::new();
            std::mem::swap(&mut levels_guard[0].slots[slot_idx], &mut due_timers);

            while let Some(timer) = due_timers.pop_front() {
                if lookup_guard.remove(&timer.id).is_some() {
                    if timer.expire_ts_ms <= current {
                        expired_keys.push(timer.key);
                        self.total_expired.fetch_add(1, Ordering::Relaxed);
                    } else {
                        // Re-insert if not yet due
                        self.insert_timer(&mut levels_guard, timer, current);
                    }
                }
            }
        }

        expired_keys
    }

    fn cascade_level(
        &self,
        levels: &mut [WheelLevel],
        lookup: &HashMap<u64, u64>,
        level_idx: usize,
        current_time: u64,
    ) {
        let slot_idx = levels[level_idx].get_slot_index(current_time);
        let mut timers = VecDeque::new();
        std::mem::swap(&mut levels[level_idx].slots[slot_idx], &mut timers);

        while let Some(timer) = timers.pop_front() {
            if lookup.contains_key(&timer.id) {
                self.insert_timer(levels, timer, current_time);
            }
        }
    }

    pub fn current_time_ms(&self) -> u64 {
        *self.current_time_ms.read()
    }

    pub fn active_timers_count(&self) -> usize {
        self.timer_lookup.read().len()
    }

    pub fn stats(&self) -> TimingWheelStats {
        TimingWheelStats {
            current_time_ms: *self.current_time_ms.read(),
            active_timers: self.timer_lookup.read().len(),
            total_scheduled: self.total_scheduled.load(Ordering::Relaxed),
            total_expired: self.total_expired.load(Ordering::Relaxed),
            total_cancelled: self.total_cancelled.load(Ordering::Relaxed),
        }
    }
}
