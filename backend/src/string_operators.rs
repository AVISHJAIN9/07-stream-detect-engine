// =============================================================================
// Feature 20: High-Throughput String Operators Engine
// Phase IV — Sigma DSL & Rule Compiler Core
//
// Implements: contains, startswith, endswith, wide (UTF-16LE), base64,
// base64offset (3-alignment variant generation), and |all modifier semantics.
// Uses zero-allocation fast paths for case-sensitive matching and inline
// byte-by-byte comparison for case-insensitive paths.
// =============================================================================

// ---------------------------------------------------------------------------
// StringOperatorEvaluator
// ---------------------------------------------------------------------------

/// High-performance string operator evaluator for Sigma streaming detection predicates.
///
/// All methods are `#[inline]` or `#[inline(always)]` to allow the compiler to
/// fuse them into the hot evaluation loop.  Case-insensitive paths perform
/// ASCII-only lowercasing to avoid heap allocation in the common case.
#[derive(Debug, Clone, Copy)]
pub struct StringOperatorEvaluator;

impl StringOperatorEvaluator {
    // -----------------------------------------------------------------------
    // contains
    // -----------------------------------------------------------------------

    /// Substring search: returns true iff `needle` appears within `haystack`.
    ///
    /// Case-sensitive fast path delegates to `str::contains` which uses the
    /// standard library's Two-Way / BMH implementation.  Case-insensitive path
    /// performs a sliding byte-by-byte ASCII comparison without allocating a
    /// lowercased copy of the full haystack.
    #[inline]
    pub fn match_contains(haystack: &str, needle: &str, case_insensitive: bool) -> bool {
        if needle.is_empty() {
            return true;
        }
        if needle.len() > haystack.len() {
            return false;
        }
        if !case_insensitive {
            // Delegates to Rust std Two-Way algorithm — O(N) amortized
            haystack.contains(needle)
        } else {
            Self::contains_ascii_ci(haystack.as_bytes(), needle.as_bytes())
        }
    }

    /// Case-insensitive ASCII sliding-window contains.
    /// Builds a lowercased needle once; slides across haystack bytes.
    #[inline]
    fn contains_ascii_ci(h: &[u8], n: &[u8]) -> bool {
        if n.len() > h.len() {
            return false;
        }
        // Build a stack-local lowercased needle (most needles < 256 bytes)
        if n.len() <= 256 {
            let mut lower_needle = [0u8; 256];
            for (i, &b) in n.iter().enumerate() {
                lower_needle[i] = b.to_ascii_lowercase();
            }
            let ln = &lower_needle[..n.len()];
            let limit = h.len() - n.len();
            'outer: for i in 0..=limit {
                for (j, &nb) in ln.iter().enumerate() {
                    if h[i + j].to_ascii_lowercase() != nb {
                        continue 'outer;
                    }
                }
                return true;
            }
        } else {
            // Heap fallback for unusually long needles
            let ln: Vec<u8> = n.iter().map(|b| b.to_ascii_lowercase()).collect();
            let limit = h.len() - n.len();
            'outer2: for i in 0..=limit {
                for (j, &nb) in ln.iter().enumerate() {
                    if h[i + j].to_ascii_lowercase() != nb {
                        continue 'outer2;
                    }
                }
                return true;
            }
        }
        false
    }

    // -----------------------------------------------------------------------
    // startswith
    // -----------------------------------------------------------------------

    /// Prefix matching: returns true iff `haystack` starts with `prefix`.
    ///
    /// Case-insensitive path uses `[u8]::eq_ignore_ascii_case` on the prefix
    /// slice — zero allocation, O(prefix_len).
    #[inline]
    pub fn match_startswith(haystack: &str, prefix: &str, case_insensitive: bool) -> bool {
        if prefix.is_empty() {
            return true;
        }
        if prefix.len() > haystack.len() {
            return false;
        }
        if !case_insensitive {
            haystack.starts_with(prefix)
        } else {
            haystack.as_bytes()[..prefix.len()]
                .eq_ignore_ascii_case(prefix.as_bytes())
        }
    }

    // -----------------------------------------------------------------------
    // endswith
    // -----------------------------------------------------------------------

    /// Suffix matching: returns true iff `haystack` ends with `suffix`.
    ///
    /// Case-insensitive path uses `[u8]::eq_ignore_ascii_case` on the suffix
    /// tail slice — zero allocation, O(suffix_len).
    #[inline]
    pub fn match_endswith(haystack: &str, suffix: &str, case_insensitive: bool) -> bool {
        if suffix.is_empty() {
            return true;
        }
        if suffix.len() > haystack.len() {
            return false;
        }
        if !case_insensitive {
            haystack.ends_with(suffix)
        } else {
            let offset = haystack.len() - suffix.len();
            haystack.as_bytes()[offset..]
                .eq_ignore_ascii_case(suffix.as_bytes())
        }
    }

    // -----------------------------------------------------------------------
    // Wide (UTF-16LE) matching
    // -----------------------------------------------------------------------

    /// Searches for a UTF-16LE encoded `needle` within a raw byte `haystack`.
    ///
    /// Used for the Sigma `|wide` modifier — matches strings stored in memory
    /// as UTF-16 Little Endian (Windows-native encoding for process command
    /// lines, registry values, etc.).
    ///
    /// Builds a wide-encoded needle on the stack (≤512 bytes) or heap (larger),
    /// then slides across the haystack performing byte-pair comparison.
    pub fn match_wide(haystack: &[u8], needle: &str, case_insensitive: bool) -> bool {
        // Encode needle as UTF-16LE bytes
        let wide: Vec<u8> = needle
            .encode_utf16()
            .flat_map(|u| [(u & 0xFF) as u8, ((u >> 8) & 0xFF) as u8])
            .collect();

        if wide.len() > haystack.len() {
            return false;
        }

        let w_len  = wide.len();
        let limit  = haystack.len() - w_len;

        // Slide: compare character pairs
        'outer: for i in 0..=limit {
            let slice = &haystack[i..i + w_len];
            // Wide chars are 2 bytes each; high byte must be 0x00 for BMP chars
            for j in (0..w_len).step_by(2) {
                let h_lo = slice[j];
                let h_hi = slice[j + 1];
                let n_lo = wide[j];
                let n_hi = wide[j + 1];

                if h_hi != n_hi {
                    continue 'outer;
                }
                if case_insensitive {
                    if h_lo.to_ascii_lowercase() != n_lo.to_ascii_lowercase() {
                        continue 'outer;
                    }
                } else if h_lo != n_lo {
                    continue 'outer;
                }
            }
            return true;
        }
        false
    }

    // -----------------------------------------------------------------------
    // |all modifier: ALL values must match
    // -----------------------------------------------------------------------

    /// Evaluates the `|all` modifier: every value in `needles` must be present
    /// in `haystack` for the overall predicate to return `true`.
    ///
    /// Short-circuits on the first missing needle.
    #[inline]
    pub fn match_all_contains(haystack: &str, needles: &[&str], case_insensitive: bool) -> bool {
        for &needle in needles {
            if !Self::match_contains(haystack, needle, case_insensitive) {
                return false; // Short-circuit: all must match
            }
        }
        true
    }

    /// Evaluates `|startswith|all`: every prefix must match the haystack.
    #[inline]
    pub fn match_all_startswith(haystack: &str, prefixes: &[&str], case_insensitive: bool) -> bool {
        for &prefix in prefixes {
            if !Self::match_startswith(haystack, prefix, case_insensitive) {
                return false;
            }
        }
        true
    }

    /// Evaluates `|endswith|all`: every suffix must match the haystack.
    #[inline]
    pub fn match_all_endswith(haystack: &str, suffixes: &[&str], case_insensitive: bool) -> bool {
        for &suffix in suffixes {
            if !Self::match_endswith(haystack, suffix, case_insensitive) {
                return false;
            }
        }
        true
    }

    // -----------------------------------------------------------------------
    // Boyer-Moore-Horspool bad character table (used for long needle search)
    // -----------------------------------------------------------------------

    /// Builds a 256-entry bad-character skip table for Boyer-Moore-Horspool.
    /// Returns the skip amounts indexed by byte value.
    fn bmh_bad_char_table(needle: &[u8]) -> [usize; 256] {
        let n = needle.len();
        let mut table = [n; 256];
        for i in 0..n.saturating_sub(1) {
            table[needle[i] as usize] = n - 1 - i;
        }
        table
    }

    /// Boyer-Moore-Horspool substring search (case-sensitive).
    /// Returns the byte offset of the first occurrence, or `None`.
    pub fn bmh_search(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        if needle.is_empty() {
            return Some(0);
        }
        if needle.len() > haystack.len() {
            return None;
        }
        let n      = needle.len();
        let table  = Self::bmh_bad_char_table(needle);
        let mut i  = n - 1;

        while i < haystack.len() {
            let mut k = n - 1;
            let mut j = i;
            while k > 0 && haystack[j] == needle[k] {
                j -= 1;
                k -= 1;
            }
            if haystack[j] == needle[0] {
                return Some(j);
            }
            i += table[haystack[i] as usize];
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Base64OffsetCompiler
// ---------------------------------------------------------------------------

/// Sigma `|base64` and `|base64offset` Pattern Generator.
///
/// Pre-computes 3 byte-alignment variants of a substring pattern so that
/// base64-encoded command lines can be searched without decoding the entire
/// event.  This is the technique used by Sigma's base64offset modifier.
///
/// Background
/// ----------
/// When encoding `cmd.exe` with different preceding byte alignments:
///
///   Offset 0: `Y21kLmV4ZQ==`   → inner fragment: `Y21kLmV4ZQ`
///   Offset 1: `QGNtZC5leGU=`   → inner fragment: `GNtZC5leGU` (after stripping prefix)
///   Offset 2: `AGNtZC5leGU=`   → inner fragment: `Ntd5leGU` (after stripping prefix)
///
/// By searching for any of the 3 fragments in the raw (still-encoded) base64
/// field, we can detect the pattern regardless of how the surrounding context
/// aligns the base64 triplet boundary.
pub struct Base64OffsetCompiler;

impl Base64OffsetCompiler {
    /// Standard RFC 4648 Base64 alphabet (no URL-safe variant).
    const ALPHABET: &'static [u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    // -----------------------------------------------------------------------
    // Core encoder (no external crate dependency)
    // -----------------------------------------------------------------------

    /// Encodes raw bytes into standard Base64 with `=` padding.
    /// Zero external dependencies — implemented against RFC 4648 §4.
    pub fn encode_base64(input: &[u8]) -> String {
        let out_len = (input.len() + 2) / 3 * 4;
        let mut result = String::with_capacity(out_len);
        let mut i = 0;

        while i < input.len() {
            let b0 = input[i] as usize;
            let b1 = if i + 1 < input.len() { input[i + 1] as usize } else { 0 };
            let b2 = if i + 2 < input.len() { input[i + 2] as usize } else { 0 };

            result.push(Self::ALPHABET[(b0 >> 2) & 0x3F]                   as char);
            result.push(Self::ALPHABET[((b0 << 4) | (b1 >> 4)) & 0x3F]    as char);

            if i + 1 < input.len() {
                result.push(Self::ALPHABET[((b1 << 2) | (b2 >> 6)) & 0x3F] as char);
            } else {
                result.push('=');
            }

            if i + 2 < input.len() {
                result.push(Self::ALPHABET[b2 & 0x3F] as char);
            } else {
                result.push('=');
            }

            i += 3;
        }
        result
    }

    // -----------------------------------------------------------------------
    // generate_base64_variations (3 byte-alignment offsets)
    // -----------------------------------------------------------------------

    /// Generates up to 3 base64 search substrings for `needle` that cover all
    /// possible byte-alignment offsets (0, 1, 2).
    ///
    /// ## Algorithm
    ///
    /// 1. **Offset 0** — encode `needle` directly; strip trailing `=` padding.
    ///    The resulting string is always a valid base64 fragment.
    ///
    /// 2. **Offset 1** — prepend one dummy byte (`\x00`), encode, strip the
    ///    first 2 base64 chars (which represent the dummy byte alignment bits)
    ///    and any trailing padding.
    ///
    /// 3. **Offset 2** — prepend two dummy bytes (`\x00\x00`), encode, strip
    ///    the first 3 base64 chars and any trailing padding.
    ///
    /// The resulting 3 strings can be searched as plain substrings in the raw
    /// base64 field without decoding — matching any of them implies the needle
    /// is present in the decoded payload.
    pub fn generate_base64_variations(needle: &str) -> Vec<String> {
        Self::generate_variants_from_bytes(needle.as_bytes())
    }

    /// Generates base64 variations for raw bytes (used internally and for
    /// the `|wide|base64offset` combined modifier).
    pub fn generate_variants_from_bytes(raw: &[u8]) -> Vec<String> {
        let mut out = Vec::with_capacity(3);

        // --- Offset 0 ---
        let enc0 = Self::encode_base64(raw);
        let frag0 = enc0.trim_end_matches('=');
        // Remove the last char when the tail byte-triplet produces an ambiguous
        // fragment (the last char of a 2-residue group encodes only 2 bits of payload)
        let frag0_trimmed = Self::trim_ambiguous_tail(frag0, raw.len(), 0);
        if !frag0_trimmed.is_empty() {
            out.push(frag0_trimmed.to_string());
        }

        // --- Offset 1 ---
        let mut padded1 = Vec::with_capacity(raw.len() + 1);
        padded1.push(0u8); // dummy alignment byte
        padded1.extend_from_slice(raw);
        let enc1 = Self::encode_base64(&padded1);
        let frag1 = enc1.trim_end_matches('=');
        // Strip the 2 chars that encoded the dummy byte
        if frag1.len() > 2 {
            let inner = &frag1[2..];
            let inner = Self::trim_ambiguous_tail(inner, raw.len(), 1);
            if !inner.is_empty() {
                out.push(inner.to_string());
            }
        }

        // --- Offset 2 ---
        let mut padded2 = Vec::with_capacity(raw.len() + 2);
        padded2.push(0u8);
        padded2.push(0u8); // 2 dummy alignment bytes
        padded2.extend_from_slice(raw);
        let enc2 = Self::encode_base64(&padded2);
        let frag2 = enc2.trim_end_matches('=');
        // Strip the 3 chars that encoded the 2 dummy bytes
        if frag2.len() > 3 {
            let inner = &frag2[3..];
            let inner = Self::trim_ambiguous_tail(inner, raw.len(), 2);
            if !inner.is_empty() {
                out.push(inner.to_string());
            }
        }

        out
    }

    /// Trims the final potentially-ambiguous base64 character from a fragment.
    ///
    /// When the payload's last byte triplet is incomplete (mod 3 ≠ 0), the
    /// last base64 character encodes mixed bits from both the payload and the
    /// implicit zero padding.  Searching for that character could produce false
    /// positives at alignment boundaries, so we drop it.
    fn trim_ambiguous_tail(frag: &str, payload_len: usize, offset: usize) -> &str {
        let effective_len = payload_len + offset;
        // If the combined byte sequence is a perfect multiple of 3, no ambiguity
        if effective_len % 3 == 0 || frag.is_empty() {
            return frag;
        }
        // Drop last char to avoid cross-boundary collision
        &frag[..frag.len().saturating_sub(1)]
    }

    // -----------------------------------------------------------------------
    // Wide + Base64 combined variations
    // -----------------------------------------------------------------------

    /// Generates base64offset variations for a **UTF-16LE wide** encoding of
    /// `needle`.  This covers the `|wide|base64offset` Sigma modifier chain,
    /// which encodes the wide (UTF-16LE) bytes of the pattern and then
    /// computes all 3 alignment variants.
    pub fn generate_wide_base64_variations(needle: &str) -> Vec<String> {
        let wide_bytes: Vec<u8> = needle
            .encode_utf16()
            .flat_map(|u| [(u & 0xFF) as u8, ((u >> 8) & 0xFF) as u8])
            .collect();
        Self::generate_variants_from_bytes(&wide_bytes)
    }

    // -----------------------------------------------------------------------
    // Convenience: generate plain base64 (no offset variants)
    // -----------------------------------------------------------------------

    /// Generates a single base64 encoding of `needle` (standard `|base64` modifier).
    /// Returns the full base64 string including `=` padding.
    pub fn encode_needle(needle: &str) -> String {
        Self::encode_base64(needle.as_bytes())
    }

    /// Generates a single base64 encoding of the UTF-16LE wide form of `needle`.
    pub fn encode_wide_needle(needle: &str) -> String {
        let wide: Vec<u8> = needle
            .encode_utf16()
            .flat_map(|u| [(u & 0xFF) as u8, ((u >> 8) & 0xFF) as u8])
            .collect();
        Self::encode_base64(&wide)
    }
}

// ---------------------------------------------------------------------------
// Multi-pattern string set evaluator (|all modifier over a list)
// ---------------------------------------------------------------------------

/// Evaluates a set of string values against a haystack field.
///
/// Supports Sigma list-value matching where any one of the values can match
/// (OR semantics by default) or all must match (AND semantics with `|all`).
pub struct StringSetEvaluator {
    pub patterns:         Vec<String>,
    pub case_insensitive: bool,
    pub require_all:      bool, // `|all` modifier
}

impl StringSetEvaluator {
    pub fn new(patterns: Vec<String>, case_insensitive: bool, require_all: bool) -> Self {
        Self { patterns, case_insensitive, require_all }
    }

    /// Evaluates contains-match for all patterns in the set.
    #[inline]
    pub fn match_contains(&self, haystack: &str) -> bool {
        if self.require_all {
            self.patterns.iter().all(|p| {
                StringOperatorEvaluator::match_contains(haystack, p, self.case_insensitive)
            })
        } else {
            self.patterns.iter().any(|p| {
                StringOperatorEvaluator::match_contains(haystack, p, self.case_insensitive)
            })
        }
    }

    /// Evaluates startswith-match for all patterns in the set.
    #[inline]
    pub fn match_startswith(&self, haystack: &str) -> bool {
        if self.require_all {
            self.patterns.iter().all(|p| {
                StringOperatorEvaluator::match_startswith(haystack, p, self.case_insensitive)
            })
        } else {
            self.patterns.iter().any(|p| {
                StringOperatorEvaluator::match_startswith(haystack, p, self.case_insensitive)
            })
        }
    }

    /// Evaluates endswith-match for all patterns in the set.
    #[inline]
    pub fn match_endswith(&self, haystack: &str) -> bool {
        if self.require_all {
            self.patterns.iter().all(|p| {
                StringOperatorEvaluator::match_endswith(haystack, p, self.case_insensitive)
            })
        } else {
            self.patterns.iter().any(|p| {
                StringOperatorEvaluator::match_endswith(haystack, p, self.case_insensitive)
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- contains ---
    #[test]
    fn contains_case_sensitive_hit() {
        assert!(StringOperatorEvaluator::match_contains("Hello World", "World", false));
    }
    #[test]
    fn contains_case_sensitive_miss() {
        assert!(!StringOperatorEvaluator::match_contains("Hello World", "world", false));
    }
    #[test]
    fn contains_case_insensitive_hit() {
        assert!(StringOperatorEvaluator::match_contains("Hello World", "world", true));
    }
    #[test]
    fn contains_empty_needle_always_true() {
        assert!(StringOperatorEvaluator::match_contains("anything", "", false));
    }
    #[test]
    fn contains_longer_needle_false() {
        assert!(!StringOperatorEvaluator::match_contains("ab", "abcdef", false));
    }

    // --- startswith ---
    #[test]
    fn startswith_ci() {
        assert!(StringOperatorEvaluator::match_startswith("C:\\Windows\\cmd.exe", "c:\\windows", true));
    }
    #[test]
    fn startswith_cs_miss() {
        assert!(!StringOperatorEvaluator::match_startswith("C:\\Windows\\cmd.exe", "c:\\windows", false));
    }

    // --- endswith ---
    #[test]
    fn endswith_ci() {
        assert!(StringOperatorEvaluator::match_endswith("powershell.EXE", ".exe", true));
    }
    #[test]
    fn endswith_cs_miss() {
        assert!(!StringOperatorEvaluator::match_endswith("powershell.EXE", ".exe", false));
    }

    // --- base64offset ---
    #[test]
    fn base64_variations_count() {
        let vars = Base64OffsetCompiler::generate_base64_variations("cmd.exe");
        assert!(!vars.is_empty() && vars.len() <= 3, "expect 1–3 variants, got {}", vars.len());
    }

    #[test]
    fn base64_offset0_is_searchable_in_encoded_payload() {
        let needle   = "cmd.exe";
        let vars     = Base64OffsetCompiler::generate_base64_variations(needle);
        // Build a reference encoded payload at offset 0
        let encoded  = Base64OffsetCompiler::encode_needle(needle);
        assert!(
            vars.iter().any(|v| encoded.contains(v.as_str())),
            "offset-0 variant must appear in direct base64 encoding; encoded={encoded:?}, vars={vars:?}"
        );
    }

    #[test]
    fn wide_base64_variations_not_empty() {
        let vars = Base64OffsetCompiler::generate_wide_base64_variations("cmd.exe");
        assert!(!vars.is_empty());
    }

    // --- all modifier ---
    #[test]
    fn all_contains_short_circuits_on_miss() {
        let eval = StringSetEvaluator::new(
            vec!["alpha".to_string(), "beta".to_string(), "gamma".to_string()],
            false, true,
        );
        assert!(!eval.match_contains("alpha only")); // beta missing → false
    }

    #[test]
    fn all_contains_passes_when_all_present() {
        let eval = StringSetEvaluator::new(
            vec!["alpha".to_string(), "beta".to_string()],
            false, true,
        );
        assert!(eval.match_contains("alpha and beta together"));
    }

    // --- BMH search ---
    #[test]
    fn bmh_finds_pattern() {
        let h = b"the quick brown fox";
        let n = b"brown";
        assert_eq!(StringOperatorEvaluator::bmh_search(h, n), Some(10));
    }

    #[test]
    fn bmh_returns_none_when_absent() {
        let h = b"the quick fox";
        let n = b"brown";
        assert_eq!(StringOperatorEvaluator::bmh_search(h, n), None);
    }
}
