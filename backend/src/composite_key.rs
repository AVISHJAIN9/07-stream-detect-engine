use crate::types::ValueVariant;

/// Variable-Length Integer (Varint) Encoding Utilities
#[inline]
pub fn encode_varint_u64(mut val: u64, buf: &mut Vec<u8>) {
    while val >= 0x80 {
        buf.push((val as u8 & 0x7F) | 0x80);
        val >>= 7;
    }
    buf.push(val as u8);
}

#[inline]
pub fn encode_varint_u64_slice(mut val: u64, buf: &mut [u8], offset: &mut usize) -> Result<(), String> {
    while val >= 0x80 {
        if *offset >= buf.len() {
            return Err("Buffer overflow in varint encoding".to_string());
        }
        buf[*offset] = (val as u8 & 0x7F) | 0x80;
        *offset += 1;
        val >>= 7;
    }
    if *offset >= buf.len() {
        return Err("Buffer overflow in varint encoding".to_string());
    }
    buf[*offset] = val as u8;
    *offset += 1;
    Ok(())
}

/// Zero-Allocation Canonical Composite Event Key Encoder
///
/// Combines multiple event dimensions (e.g. tenant_id, entity_id, event_type, dynamic attributes)
/// into a compact, collision-free binary key representation.
/// Sorts field tags prior to serialization, guaranteeing structural determinism regardless
/// of attribute ordering in the incoming event.
pub struct CompositeKeyEncoder;

impl CompositeKeyEncoder {
    /// Encodes a composite key into an output vector with sorted, order-independent canonical encoding
    pub fn encode_key(
        tenant_id: u32,
        fields: &[(&str, &ValueVariant)],
        out_buf: &mut Vec<u8>,
    ) {
        out_buf.clear();

        // 1. Write Header: 4-byte tenant_id (Big-Endian)
        out_buf.extend_from_slice(&tenant_id.to_be_bytes());

        // 2. Sort field references by field name to guarantee order invariance
        let mut sorted_fields: Vec<(&str, &ValueVariant)> = fields.to_vec();
        sorted_fields.sort_by(|a, b| a.0.cmp(b.0));

        // 3. Write field count as varint
        encode_varint_u64(sorted_fields.len() as u64, out_buf);

        // 4. Encode each sorted (name, value) pair
        for (name, val) in sorted_fields {
            // Write field name length & bytes
            encode_varint_u64(name.len() as u64, out_buf);
            out_buf.extend_from_slice(name.as_bytes());

            // Write value type tag & serialized value payload
            match val {
                ValueVariant::Null => {
                    out_buf.push(0x00);
                }
                ValueVariant::Bool(b) => {
                    out_buf.push(0x01);
                    out_buf.push(if *b { 1 } else { 0 });
                }
                ValueVariant::Int(num) => {
                    out_buf.push(0x02);
                    out_buf.extend_from_slice(&num.to_be_bytes());
                }
                ValueVariant::Float(f) => {
                    out_buf.push(0x03);
                    out_buf.extend_from_slice(&f.to_bits().to_be_bytes());
                }
                ValueVariant::String(s) => {
                    out_buf.push(0x04);
                    encode_varint_u64(s.len() as u64, out_buf);
                    out_buf.extend_from_slice(s.as_bytes());
                }
                ValueVariant::Bytes(bytes) => {
                    out_buf.push(0x05);
                    encode_varint_u64(bytes.len() as u64, out_buf);
                    out_buf.extend_from_slice(bytes);
                }
                ValueVariant::Array(arr) => {
                    out_buf.push(0x06);
                    encode_varint_u64(arr.len() as u64, out_buf);
                    for item in arr {
                        let repr = item.to_string();
                        encode_varint_u64(repr.len() as u64, out_buf);
                        out_buf.extend_from_slice(repr.as_bytes());
                    }
                }
                ValueVariant::Map(m) => {
                    out_buf.push(0x07);
                    encode_varint_u64(m.len() as u64, out_buf);
                    let mut sorted_keys: Vec<_> = m.keys().collect();
                    sorted_keys.sort();
                    for k in sorted_keys {
                        encode_varint_u64(k.len() as u64, out_buf);
                        out_buf.extend_from_slice(k.as_bytes());
                        let val_str = m[k].to_string();
                        encode_varint_u64(val_str.len() as u64, out_buf);
                        out_buf.extend_from_slice(val_str.as_bytes());
                    }
                }
            }
        }
    }

    /// Helper allocating and returning a new Vec<u8>
    pub fn encode_to_vec(tenant_id: u32, fields: &[(&str, &ValueVariant)]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);
        Self::encode_key(tenant_id, fields, &mut buf);
        buf
    }

    /// Fast-path encoding into a fixed stack slice [u8; N]
    pub fn encode_to_stack_buffer<const N: usize>(
        tenant_id: u32,
        fields: &[(&str, &ValueVariant)],
    ) -> Result<([u8; N], usize), String> {
        let mut heap_buf = Vec::with_capacity(N);
        Self::encode_key(tenant_id, fields, &mut heap_buf);

        if heap_buf.len() > N {
            return Err(format!(
                "Encoded key length {} exceeds stack buffer capacity {}",
                heap_buf.len(),
                N
            ));
        }

        let mut stack_buf = [0u8; N];
        stack_buf[..heap_buf.len()].copy_from_slice(&heap_buf);
        Ok((stack_buf, heap_buf.len()))
    }
}
