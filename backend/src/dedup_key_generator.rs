use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use rand::Rng;
use uuid::Uuid;
use crate::types::ValueVariant;

pub struct UUIDv7Generator {
    last_millis: AtomicU64,
    counter: AtomicU64,
}

impl Default for UUIDv7Generator {
    fn default() -> Self {
        Self::new()
    }
}

impl UUIDv7Generator {
    pub fn new() -> Self {
        Self {
            last_millis: AtomicU64::new(0),
            counter: AtomicU64::new(0),
        }
    }

    /// Generates time-ordered UUIDv7 (128-bit)
    pub fn generate(&self) -> Uuid {
        let now_millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let mut last = self.last_millis.load(Ordering::Acquire);
        let (ts, seq) = loop {
            let cur_ts = std::cmp::max(now_millis, last);
            if cur_ts > last {
                if self.last_millis.compare_exchange_weak(last, cur_ts, Ordering::SeqCst, Ordering::Acquire).is_ok() {
                    let _seq = self.counter.swap(1, Ordering::SeqCst);
                    break (cur_ts, 0u64);
                } else {
                    last = self.last_millis.load(Ordering::Acquire);
                }
            } else {
                let seq = self.counter.fetch_add(1, Ordering::SeqCst);
                break (cur_ts, seq);
            }
        };

        let mut bytes = [0u8; 16];
        // 48-bit timestamp
        bytes[0] = (ts >> 40) as u8;
        bytes[1] = (ts >> 32) as u8;
        bytes[2] = (ts >> 24) as u8;
        bytes[3] = (ts >> 16) as u8;
        bytes[4] = (ts >> 8) as u8;
        bytes[5] = ts as u8;

        // 12-bit sequence in rand_a
        let rand_a = (seq & 0x0FFF) as u16;
        bytes[6] = 0x70 | ((rand_a >> 8) as u8 & 0x0F); // Version 7
        bytes[7] = (rand_a & 0xFF) as u8;

        // Variant 2 (RFC 4122 / 9562)
        let seq_hi = ((seq >> 12) & 0x3FFF) as u16;
        bytes[8] = 0x80 | ((seq_hi >> 8) as u8 & 0x3F);
        bytes[9] = (seq_hi & 0xFF) as u8;

        let mut rng = rand::thread_rng();
        let rand_tail: [u8; 6] = rng.gen();
        bytes[10..16].copy_from_slice(&rand_tail);

        Uuid::from_bytes(bytes)
    }
}


pub struct DedupKeyGenerator;

impl DedupKeyGenerator {
    /// Computes deterministic 64-bit Murmur3-like fingerprint over canonical fields
    /// Guaranteed invariant under attribute key-value reordering
    pub fn compute_fingerprint(
        tenant_id: &str,
        entity_id: &str,
        event_type: &str,
        timestamp_ns: i64,
        attributes: &[(String, ValueVariant)],
    ) -> u64 {
        let mut hasher = Murmur3Hasher64::new(0x9747b28c);

        // Hash core canonical fields
        hasher.write_str(tenant_id);
        hasher.write_str(entity_id);
        hasher.write_str(event_type);
        hasher.write_i64(timestamp_ns);

        // Sort attributes into canonical BTreeMap to guarantee invariant hashing regardless of insertion order
        let mut sorted_attrs = BTreeMap::new();
        for (k, v) in attributes {
            sorted_attrs.insert(k.as_str(), v);
        }

        for (k, v) in sorted_attrs {
            hasher.write_str(k);
            Self::hash_variant(&mut hasher, v);
        }

        hasher.finish()
    }

    fn hash_variant(hasher: &mut Murmur3Hasher64, v: &ValueVariant) {
        match v {
            ValueVariant::Null => hasher.write_u8(0),
            ValueVariant::Bool(b) => {
                hasher.write_u8(1);
                hasher.write_u8(if *b { 1 } else { 0 });
            }
            ValueVariant::Int(i) => {
                hasher.write_u8(2);
                hasher.write_i64(*i);
            }
            ValueVariant::Float(f) => {
                hasher.write_u8(3);
                hasher.write_u64(f.to_bits());
            }
            ValueVariant::String(s) => {
                hasher.write_u8(4);
                hasher.write_str(s);
            }
            ValueVariant::Bytes(b) => {
                hasher.write_u8(5);
                hasher.write_bytes(b);
            }
            ValueVariant::Array(arr) => {
                hasher.write_u8(6);
                hasher.write_u64(arr.len() as u64);
                for item in arr {
                    Self::hash_variant(hasher, item);
                }
            }
            ValueVariant::Map(map) => {
                hasher.write_u8(7);
                let mut sorted = BTreeMap::new();
                for (mk, mv) in map {
                    sorted.insert(mk.as_str(), mv);
                }
                hasher.write_u64(sorted.len() as u64);
                for (mk, mv) in sorted {
                    hasher.write_str(mk);
                    Self::hash_variant(hasher, mv);
                }
            }
        }
    }
}

/// Fast, bitwise 64-bit MurmurHash3 implementation
pub struct Murmur3Hasher64 {
    h: u64,
}

impl Murmur3Hasher64 {
    pub fn new(seed: u64) -> Self {
        Self { h: seed }
    }

    pub fn write_bytes(&mut self, bytes: &[u8]) {
        let mut cursor = 0;
        while cursor + 8 <= bytes.len() {
            let mut k = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap());
            k = k.wrapping_mul(0xc6a4a7935bd1e995);
            k ^= k >> 47;
            k = k.wrapping_mul(0xc6a4a7935bd1e995);

            self.h ^= k;
            self.h = self.h.wrapping_mul(0xc6a4a7935bd1e995);
            cursor += 8;
        }

        let rem = bytes.len() - cursor;
        if rem > 0 {
            let mut tail = 0u64;
            for i in 0..rem {
                tail |= (bytes[cursor + i] as u64) << (i * 8);
            }
            self.h ^= tail;
            self.h = self.h.wrapping_mul(0xc6a4a7935bd1e995);
        }
    }

    pub fn write_str(&mut self, s: &str) {
        self.write_bytes(s.as_bytes());
    }

    pub fn write_u8(&mut self, val: u8) {
        self.write_bytes(&[val]);
    }

    pub fn write_i64(&mut self, val: i64) {
        self.write_bytes(&val.to_le_bytes());
    }

    pub fn write_u64(&mut self, val: u64) {
        self.write_bytes(&val.to_le_bytes());
    }

    pub fn finish(mut self) -> u64 {
        self.h ^= self.h >> 47;
        self.h = self.h.wrapping_mul(0xc6a4a7935bd1e995);
        self.h ^= self.h >> 47;
        self.h
    }
}
