//! The offline receipt verifier, built for a web browser.
//!
//! The same code as `abb verify`: the container is read with `abb_receipt::read_container`, the
//! receipt checked with `abb_receipt::verify_with`, and the report written with
//! `abb_receipt::report_json`, which the CLI also uses. So `verify_json` returns, byte for byte,
//! what `abb verify <file> --keys <keys> --json` prints for the same inputs and profile.
//!
//! Nothing is sent anywhere: the page hands the bytes in and gets the JSON back.

use abb_verify::Profile;

/// Verify a receipt container and return the verifier's JSON report.
///
/// `keys_json` is the key manifest (`*.keys.json`), or empty when the person has none; then
/// signatures are reported `UNKNOWN`, never passed. A file this build will not read gives
/// `{"overall":"UNREADABLE","message":...}`, which is not the same as `INVALID`, just as the CLI
/// exits 65 rather than 1 for it.
#[must_use]
pub fn verify_json(receipt: &[u8], keys_json: &[u8], profile: &str) -> String {
    let profile = match Profile::parse(profile) {
        Some(profile) => profile,
        None => return refusal("UNREADABLE", &format!("unknown profile {profile}")),
    };
    let file = match abb_receipt::read_container(receipt) {
        Ok(file) => file,
        Err(error) => return refusal("UNREADABLE", &error.to_string()),
    };
    let parsed = match abb_receipt::Receipt::parse(&file.receipt_json) {
        Ok(parsed) => parsed,
        Err(abb_receipt::ReceiptError::Unsupported(why)) => return refusal("UNSUPPORTED", &why),
        Err(other) => return refusal("UNREADABLE", &other.to_string()),
    };
    let keys = if keys_json.is_empty() {
        None
    } else {
        let value = match abb_jcs::parse_bytes(keys_json, &abb_jcs::Limits::relaxed()) {
            Ok(value) => value,
            Err(error) => return refusal("UNREADABLE", &format!("key manifest: {error}")),
        };
        match abb_checkpoint::KeyManifest::from_value(&value) {
            Ok(keys) => Some(keys),
            Err(error) => return refusal("UNREADABLE", &format!("key manifest: {error}")),
        }
    };
    let report = abb_receipt::verify_with(&parsed, keys.as_ref(), profile, &file.artifacts);
    abb_receipt::report_json(&report, &parsed)
}

fn refusal(overall: &str, message: &str) -> String {
    let value = abb_jcs::Value::Object(vec![
        (
            "message".to_owned(),
            abb_jcs::Value::Str(message.to_owned()),
        ),
        (
            "overall".to_owned(),
            abb_jcs::Value::Str(overall.to_owned()),
        ),
    ]);
    abb_jcs::to_canonical_with(&value, &abb_jcs::Limits::relaxed())
        .unwrap_or_else(|_| "{\"overall\":\"INTERNAL\"}".to_owned())
}

#[cfg(target_arch = "wasm32")]
mod abi {
    //! The WebAssembly boundary: the page writes bytes into memory this module allocated, calls
    //! `abb_verify`, and reads the JSON back. Reason for `unsafe` (AGENTS.md 7): WebAssembly
    //! exports can only exchange numbers, so the bytes travel as (pointer, length) pairs and must
    //! be turned back into slices. Every pointer comes from `abb_alloc` in this module, with the
    //! length it was allocated with; nothing else here is unsafe.
    #![allow(unsafe_code)]

    use std::alloc::{alloc, dealloc, Layout};

    /// Allocate `len` bytes for the page to write into. Returns 0 for a zero length.
    #[no_mangle]
    pub extern "C" fn abb_alloc(len: usize) -> *mut u8 {
        if len == 0 {
            return core::ptr::null_mut();
        }
        let Ok(layout) = Layout::from_size_align(len, 1) else {
            return core::ptr::null_mut();
        };
        // SAFETY: the layout has a non-zero size.
        unsafe { alloc(layout) }
    }

    /// Free bytes from `abb_alloc` (or a result from `abb_verify`).
    #[no_mangle]
    pub extern "C" fn abb_free(ptr: *mut u8, len: usize) {
        if ptr.is_null() || len == 0 {
            return;
        }
        if let Ok(layout) = Layout::from_size_align(len, 1) {
            // SAFETY: `ptr` came from `abb_alloc(len)` (or `abb_verify`, which allocates the same
            // way) and is freed once, with the same length.
            unsafe { dealloc(ptr, layout) }
        }
    }

    /// Verify. Inputs are (pointer, length) pairs from `abb_alloc`; profile 0 = LOCAL_ONLY,
    /// 1 = CONNECTED_EVIDENCE. Returns `(pointer << 32) | length` of the JSON report, which the
    /// page frees with `abb_free` after reading it.
    #[no_mangle]
    pub extern "C" fn abb_verify(
        receipt_ptr: *const u8,
        receipt_len: usize,
        keys_ptr: *const u8,
        keys_len: usize,
        profile: u32,
    ) -> u64 {
        let receipt = slice(receipt_ptr, receipt_len);
        let keys = slice(keys_ptr, keys_len);
        let profile = if profile == 1 {
            "CONNECTED_EVIDENCE"
        } else {
            "LOCAL_ONLY"
        };
        let json = super::verify_json(receipt, keys, profile).into_bytes();
        let out = abb_alloc(json.len());
        if out.is_null() {
            return 0;
        }
        // SAFETY: `out` was just allocated with exactly `json.len()` bytes.
        unsafe { core::ptr::copy_nonoverlapping(json.as_ptr(), out, json.len()) };
        ((out as u64) << 32) | json.len() as u64
    }

    fn slice<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
        if ptr.is_null() || len == 0 {
            return &[];
        }
        // SAFETY: the page passes a pointer from `abb_alloc(len)` that it filled with `len`
        // bytes and does not free until this call returns.
        unsafe { core::slice::from_raw_parts(ptr, len) }
    }
}

#[cfg(test)]
mod tests {
    use super::verify_json;

    #[test]
    fn junk_is_unreadable_not_invalid() {
        let json = verify_json(b"this is not a zip", b"", "LOCAL_ONLY");
        assert!(json.contains("\"overall\":\"UNREADABLE\""), "{json}");
    }

    #[test]
    fn an_unknown_profile_is_refused() {
        let json = verify_json(b"", b"", "NOPE");
        assert!(json.contains("unknown profile"), "{json}");
    }

    #[test]
    fn a_bad_key_manifest_is_unreadable() {
        // A real (empty) zip is still not a receipt; the key manifest is checked only after.
        let json = verify_json(
            b"PK\x05\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            b"{nope",
            "LOCAL_ONLY",
        );
        assert!(json.contains("UNREADABLE"), "{json}");
    }
}
