use std::collections::HashMap;
use std::fmt;
use crate::types::ValueVariant;

#[derive(Debug, Clone)]
pub struct DecodeError {
    pub position: usize,
    pub message: String,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "JSON decode error at position {}: {}", self.position, self.message)
    }
}

impl std::error::Error for DecodeError {}

/// Zero-copy fast parsed value view referencing original byte buffer
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FastValue<'a> {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(&'a str),
}

/// Zero-copy parsed document holding up to 32 key-value pairs without heap allocations
#[derive(Debug, Clone)]
pub struct FastParsedDocument<'a> {
    pub pairs: [(&'a str, FastValue<'a>); 32],
    pub len: usize,
}

impl<'a> Default for FastParsedDocument<'a> {
    #[inline(always)]
    fn default() -> Self {
        Self {
            pairs: [("", FastValue::Null); 32],
            len: 0,
        }
    }
}

impl<'a> FastParsedDocument<'a> {
    #[inline(always)]
    pub fn new() -> Self {
        Self {
            pairs: [("", FastValue::Null); 32],
            len: 0,
        }
    }

    #[inline(always)]
    pub fn get(&self, key: &str) -> Option<FastValue<'a>> {
        for i in 0..self.len {
            if self.pairs[i].0 == key {
                return Some(self.pairs[i].1);
            }
        }
        None
    }

    #[inline(always)]
    pub fn get_str(&self, key: &str) -> Option<&'a str> {
        match self.get(key) {
            Some(FastValue::Str(s)) => Some(s),
            _ => None,
        }
    }

    #[inline(always)]
    pub fn get_int(&self, key: &str) -> Option<i64> {
        match self.get(key) {
            Some(FastValue::Int(i)) => Some(i),
            _ => None,
        }
    }

    #[inline(always)]
    pub fn get_bool(&self, key: &str) -> Option<bool> {
        match self.get(key) {
            Some(FastValue::Bool(b)) => Some(b),
            _ => None,
        }
    }

    pub fn to_parsed_document(&self) -> ParsedDocument {
        let mut fields = HashMap::with_capacity(self.len);
        for i in 0..self.len {
            let (k, v) = self.pairs[i];
            let val = match v {
                FastValue::Null => ValueVariant::Null,
                FastValue::Bool(b) => ValueVariant::Bool(b),
                FastValue::Int(i) => ValueVariant::Int(i),
                FastValue::Float(f) => ValueVariant::Float(f),
                FastValue::Str(s) => ValueVariant::String(s.to_string()),
            };
            fields.insert(k.to_string(), val);
        }
        ParsedDocument { fields }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ParsedDocument {
    pub fields: HashMap<String, ValueVariant>,
}

impl ParsedDocument {
    pub fn get_string(&self, key: &str) -> Option<&str> {
        match self.fields.get(key) {
            Some(ValueVariant::String(s)) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn get_int(&self, key: &str) -> Option<i64> {
        match self.fields.get(key) {
            Some(ValueVariant::Int(i)) => Some(*i),
            _ => None,
        }
    }

    pub fn get_float(&self, key: &str) -> Option<f64> {
        match self.fields.get(key) {
            Some(ValueVariant::Float(f)) => Some(*f),
            Some(ValueVariant::Int(i)) => Some(*i as f64),
            _ => None,
        }
    }

    pub fn get_bool(&self, key: &str) -> Option<bool> {
        match self.fields.get(key) {
            Some(ValueVariant::Bool(b)) => Some(*b),
            _ => None,
        }
    }
}

/// High-Performance SIMD-accelerated zero-copy JSON scanner and decoder
pub struct SIMDJsonDecoder;

impl SIMDJsonDecoder {
    /// Zero-copy fast decode referencing input buffer with zero heap allocations
    #[inline(always)]
    pub fn decode_fast<'a>(bytes: &'a [u8]) -> Result<FastParsedDocument<'a>, DecodeError> {
        let mut doc = FastParsedDocument::new();
        let mut cursor = 0;
        cursor = Self::skip_whitespace(bytes, cursor);

        if cursor >= bytes.len() || bytes[cursor] != b'{' {
            return Err(DecodeError {
                position: cursor,
                message: "Expected '{' at start of JSON object".to_string(),
            });
        }
        cursor += 1;

        while cursor < bytes.len() {
            cursor = Self::skip_whitespace(bytes, cursor);
            if cursor >= bytes.len() || bytes[cursor] == b'}' {
                break;
            }

            if bytes[cursor] != b'"' {
                return Err(DecodeError {
                    position: cursor,
                    message: "Expected '\"' for key".to_string(),
                });
            }

            // Zero-copy parse key
            let (key, next_cursor) = Self::parse_string_zero_copy(bytes, cursor)?;
            cursor = if next_cursor < bytes.len() && bytes[next_cursor] > 32 {
                next_cursor
            } else {
                Self::skip_whitespace(bytes, next_cursor)
            };

            if cursor >= bytes.len() || bytes[cursor] != b':' {
                return Err(DecodeError {
                    position: cursor,
                    message: "Expected ':' after key".to_string(),
                });
            }
            cursor += 1; // skip ':'
            cursor = if cursor < bytes.len() && bytes[cursor] == b' ' {
                cursor + 1
            } else {
                Self::skip_whitespace(bytes, cursor)
            };

            // Zero-copy parse value
            let (val, next_cursor) = Self::parse_fast_value(bytes, cursor)?;
            if doc.len < 32 {
                doc.pairs[doc.len] = (key, val);
                doc.len += 1;
            }
            cursor = if next_cursor < bytes.len() && bytes[next_cursor] > 32 {
                next_cursor
            } else {
                Self::skip_whitespace(bytes, next_cursor)
            };

            if cursor < bytes.len() && bytes[cursor] == b',' {
                cursor += 1;
            } else if cursor < bytes.len() && bytes[cursor] == b'}' {
                break;
            } else {
                return Err(DecodeError {
                    position: cursor,
                    message: "Expected ',' or '}'".to_string(),
                });
            }
        }

        Ok(doc)
    }

    pub fn decode(bytes: &[u8]) -> Result<ParsedDocument, DecodeError> {
        let fast_doc = Self::decode_fast(bytes)?;
        Ok(fast_doc.to_parsed_document())
    }

    #[inline(always)]
    fn skip_whitespace(bytes: &[u8], mut pos: usize) -> usize {
        while pos < bytes.len() {
            if bytes[pos] > 32 {
                return pos;
            }
            pos += 1;
        }
        pos
    }

    #[inline(always)]
    fn parse_string_zero_copy<'a>(bytes: &'a [u8], start: usize) -> Result<(&'a str, usize), DecodeError> {
        let str_start = start + 1;
        if let Some(offset) = memchr::memchr(b'"', &bytes[str_start..]) {
            let quote_idx = str_start + offset;
            if quote_idx > str_start && bytes[quote_idx - 1] != b'\\' {
                let slice = &bytes[str_start..quote_idx];
                let s = unsafe { std::str::from_utf8_unchecked(slice) };
                return Ok((s, quote_idx + 1));
            }

            // Fallback for strings containing backslash escapes
            let mut pos = str_start;
            while pos < bytes.len() {
                if let Some(off) = memchr::memchr2(b'"', b'\\', &bytes[pos..]) {
                    let idx = pos + off;
                    if bytes[idx] == b'\\' {
                        pos = idx + 2;
                    } else {
                        let slice = &bytes[str_start..idx];
                        let s = unsafe { std::str::from_utf8_unchecked(slice) };
                        return Ok((s, idx + 1));
                    }
                } else {
                    break;
                }
            }
        }

        Err(DecodeError {
            position: start,
            message: "Unclosed string literal".to_string(),
        })
    }

    #[inline(always)]
    fn parse_fast_value<'a>(bytes: &'a [u8], pos: usize) -> Result<(FastValue<'a>, usize), DecodeError> {
        if pos >= bytes.len() {
            return Err(DecodeError {
                position: pos,
                message: "Unexpected EOF in value".to_string(),
            });
        }

        match bytes[pos] {
            b'"' => {
                let (s, next) = Self::parse_string_zero_copy(bytes, pos)?;
                Ok((FastValue::Str(s), next))
            }
            b't' => {
                if pos + 4 <= bytes.len() && &bytes[pos..pos + 4] == b"true" {
                    Ok((FastValue::Bool(true), pos + 4))
                } else {
                    Err(DecodeError { position: pos, message: "Invalid bool".to_string() })
                }
            }
            b'f' => {
                if pos + 5 <= bytes.len() && &bytes[pos..pos + 5] == b"false" {
                    Ok((FastValue::Bool(false), pos + 5))
                } else {
                    Err(DecodeError { position: pos, message: "Invalid bool".to_string() })
                }
            }
            b'n' => {
                if pos + 4 <= bytes.len() && &bytes[pos..pos + 4] == b"null" {
                    Ok((FastValue::Null, pos + 4))
                } else {
                    Err(DecodeError { position: pos, message: "Invalid null".to_string() })
                }
            }
            b'-' | b'0'..=b'9' => {
                Self::parse_fast_number(bytes, pos)
            }
            _ => {
                // Skip non-primitive values (objects / arrays) by scanning matching bracket
                let mut depth = 0;
                let mut end = pos;
                while end < bytes.len() {
                    let b = bytes[end];
                    if b == b'{' || b == b'[' {
                        depth += 1;
                    } else if b == b'}' || b == b']' {
                        depth -= 1;
                        if depth == 0 {
                            end += 1;
                            break;
                        }
                    } else if depth == 0 && (b == b',' || b == b' ' || b == b'\n') {
                        break;
                    }
                    end += 1;
                }
                let raw_str = std::str::from_utf8(&bytes[pos..end]).unwrap_or("");
                Ok((FastValue::Str(raw_str), end))
            }
        }
    }

    #[inline(always)]
    fn parse_fast_number<'a>(bytes: &'a [u8], start: usize) -> Result<(FastValue<'a>, usize), DecodeError> {
        let mut pos = start;
        let mut is_float = false;
        let mut num: i64 = 0;
        let mut neg = false;

        if pos < bytes.len() && bytes[pos] == b'-' {
            neg = true;
            pos += 1;
        }

        while pos < bytes.len() {
            let b = bytes[pos];
            if b >= b'0' && b <= b'9' {
                num = num * 10 + ((b - b'0') as i64);
                pos += 1;
            } else if b == b'.' || b == b'e' || b == b'E' {
                is_float = true;
                pos += 1;
                while pos < bytes.len() && ((bytes[pos] >= b'0' && bytes[pos] <= b'9') || bytes[pos] == b'+' || bytes[pos] == b'-') {
                    pos += 1;
                }
                break;
            } else {
                break;
            }
        }

        if is_float {
            let s = unsafe { std::str::from_utf8_unchecked(&bytes[start..pos]) };
            let f = s.parse::<f64>().unwrap_or(0.0);
            Ok((FastValue::Float(f), pos))
        } else {
            if neg {
                num = -num;
            }
            Ok((FastValue::Int(num), pos))
        }
    }
}
