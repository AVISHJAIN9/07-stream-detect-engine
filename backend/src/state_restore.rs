use crate::keyed_state_store::{KeyedStateStore, StateValue};
use crate::state_snapshot::{crc32c, SnapshotMeta};
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

/// Helper function decoding a varint u64 from a byte slice with offset advancement
pub fn decode_varint_u64(data: &[u8], offset: &mut usize) -> Result<u64, String> {
    let mut result: u64 = 0;
    let mut shift: usize = 0;

    while *offset < data.len() {
        let byte = data[*offset];
        *offset += 1;
        result |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
        if shift >= 64 {
            return Err("Varint overflow".to_string());
        }
    }

    Err("Unexpected EOF while decoding varint".to_string())
}

/// Checkpoint State Restore & Replay Engine
///
/// Restores `KeyedStateStore` partitions from on-disk binary checkpoints.
/// Validates CRC32C checksums before mounting recovered state to prevent data corruption.
pub struct StateRestoreEngine;

impl StateRestoreEngine {
    /// Deserializes a binary shard payload into key-value pairs
    pub fn deserialize_shard_entries(data: &[u8]) -> Result<Vec<(Vec<u8>, StateValue)>, String> {
        let mut offset = 0;
        let count = decode_varint_u64(data, &mut offset)? as usize;
        let mut entries = Vec::with_capacity(count);

        for _ in 0..count {
            // Read key
            let key_len = decode_varint_u64(data, &mut offset)? as usize;
            if offset + key_len > data.len() {
                return Err("Corrupted payload: unexpected EOF reading key".to_string());
            }
            let key = data[offset..offset + key_len].to_vec();
            offset += key_len;

            // Read value tag
            if offset >= data.len() {
                return Err("Corrupted payload: unexpected EOF reading value tag".to_string());
            }
            let tag = data[offset];
            offset += 1;

            let val = match tag {
                0x01 => {
                    // Int: 8 bytes
                    if offset + 8 > data.len() {
                        return Err("Corrupted payload: unexpected EOF reading Int".to_string());
                    }
                    let mut bytes = [0u8; 8];
                    bytes.copy_from_slice(&data[offset..offset + 8]);
                    offset += 8;
                    StateValue::Int(i64::from_be_bytes(bytes))
                }
                0x02 => {
                    // Float: 8 bytes
                    if offset + 8 > data.len() {
                        return Err("Corrupted payload: unexpected EOF reading Float".to_string());
                    }
                    let mut bytes = [0u8; 8];
                    bytes.copy_from_slice(&data[offset..offset + 8]);
                    offset += 8;
                    StateValue::Float(f64::from_bits(u64::from_be_bytes(bytes)))
                }
                0x03 => {
                    // Counter: 8 bytes
                    if offset + 8 > data.len() {
                        return Err("Corrupted payload: unexpected EOF reading Counter".to_string());
                    }
                    let mut bytes = [0u8; 8];
                    bytes.copy_from_slice(&data[offset..offset + 8]);
                    offset += 8;
                    StateValue::Counter(u64::from_be_bytes(bytes))
                }
                0x04 => {
                    // String: varint len + bytes
                    let str_len = decode_varint_u64(data, &mut offset)? as usize;
                    if offset + str_len > data.len() {
                        return Err("Corrupted payload: unexpected EOF reading String".to_string());
                    }
                    let s = String::from_utf8(data[offset..offset + str_len].to_vec())
                        .map_err(|e| format!("Invalid UTF-8 string in state: {}", e))?;
                    offset += str_len;
                    StateValue::String(s)
                }
                0x05 => {
                    // Bytes: varint len + bytes
                    let byte_len = decode_varint_u64(data, &mut offset)? as usize;
                    if offset + byte_len > data.len() {
                        return Err("Corrupted payload: unexpected EOF reading Bytes".to_string());
                    }
                    let b = data[offset..offset + byte_len].to_vec();
                    offset += byte_len;
                    StateValue::Bytes(b)
                }
                unknown => {
                    return Err(format!("Unknown StateValue type tag 0x{:02X}", unknown));
                }
            };

            entries.push((key, val));
        }

        Ok(entries)
    }

    /// Restores a snapshot into target KeyedStateStore
    pub fn restore_from_snapshot(
        checkpoint_dir: &str,
        snapshot_id: u64,
        state_store: &KeyedStateStore,
    ) -> Result<SnapshotMeta, String> {
        let snap_dir = Path::new(checkpoint_dir).join(format!("snapshot_{:08}", snapshot_id));
        let meta_path = snap_dir.join("META.json");

        let meta_data = fs::read_to_string(&meta_path)
            .map_err(|e| format!("Failed to read META.json from {:?}: {}", meta_path, e))?;
        let meta: SnapshotMeta = serde_json::from_str(&meta_data)
            .map_err(|e| format!("Failed to parse META.json: {}", e))?;

        // Validate each shard file
        for idx in 0..meta.shard_count {
            let shard_path = snap_dir.join(format!("shard_{:04}.bin", idx));
            let mut file = File::open(&shard_path)
                .map_err(|e| format!("Failed to open shard file {:?}: {}", shard_path, e))?;
            let mut data = Vec::new();
            file.read_to_end(&mut data)
                .map_err(|e| format!("Failed to read shard file {:?}: {}", shard_path, e))?;

            // 1. Validate CRC32C
            let computed_crc = crc32c(&data);
            if computed_crc != meta.shard_checksums[idx] {
                return Err(format!(
                    "CRC32C mismatch for shard {}: expected 0x{:08X}, computed 0x{:08X}",
                    idx, meta.shard_checksums[idx], computed_crc
                ));
            }

            // 2. Deserialize entries
            let entries = Self::deserialize_shard_entries(&data)?;

            // 3. Populate state store
            for (k, v) in entries {
                state_store.put_state(&k, v);
            }
        }

        Ok(meta)
    }
}
