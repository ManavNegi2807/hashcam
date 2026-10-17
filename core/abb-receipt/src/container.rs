//! The `*.abbreceipt` container: a ZIP holding `receipt.json` (`D-04`).
//!
//! A receipt arrives from somewhere else, so reading one is attack surface.
//! `PROTOCOL.md` 15 requires a verifier to bound decompressed size, reject path
//! traversal and reject nested archives; tamper case TS-16 tests exactly that,
//! and the CLI answers with exit code 65 rather than a result.
//!
//! The limits are deliberately small. A receipt is events and proofs, not a
//! disk image.

use std::io::{Cursor, Read, Write};

/// Largest `receipt.json` this build will read.
pub const MAX_RECEIPT_JSON: u64 = 32 * 1024 * 1024;
/// Largest total decompressed size across all entries.
pub const MAX_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
/// Largest number of entries.
pub const MAX_ENTRIES: usize = 10_000;
/// Refuse anything whose compression ratio is beyond this: a zip bomb.
pub const MAX_RATIO: u64 = 200;

/// Why a container was refused, before any verification ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainerError {
    /// The file could not be opened or is not a ZIP.
    Unreadable(String),
    /// `receipt.json` is missing.
    NoReceipt,
    /// An entry name escapes the archive, or is absolute.
    PathTraversal(String),
    /// An entry is itself an archive.
    NestedArchive(String),
    /// Over a size, count or ratio limit.
    TooLarge(String),
}

impl std::fmt::Display for ContainerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable(why) => write!(f, "not a readable receipt container: {why}"),
            Self::NoReceipt => f.write_str("the container has no receipt.json"),
            Self::PathTraversal(name) => {
                write!(f, "entry {name:?} would be written outside the archive")
            }
            Self::NestedArchive(name) => write!(f, "entry {name:?} is itself an archive"),
            Self::TooLarge(why) => write!(f, "over a container limit: {why}"),
        }
    }
}

impl std::error::Error for ContainerError {}

/// What a container holds.
#[derive(Debug, Clone)]
pub struct ReceiptFile {
    /// The canonical `receipt.json` bytes.
    pub receipt_json: Vec<u8>,
    /// `artifacts/<digest>` entries, by digest.
    pub artifacts: Vec<(String, Vec<u8>)>,
}

fn safe_name(name: &str) -> Result<(), ContainerError> {
    if name.starts_with('/')
        || name.starts_with('\\')
        || name.contains("..")
        || name.contains(':')
        || name.contains('\0')
    {
        return Err(ContainerError::PathTraversal(name.to_owned()));
    }
    Ok(())
}

fn not_nested(name: &str, bytes: &[u8]) -> Result<(), ContainerError> {
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".zip")
        || lower.ends_with(".abbreceipt")
        || lower.ends_with(".gz")
        || lower.ends_with(".tar")
    {
        return Err(ContainerError::NestedArchive(name.to_owned()));
    }
    // A ZIP or gzip magic number inside an entry is refused regardless of name.
    if bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(&[0x1f, 0x8b]) {
        return Err(ContainerError::NestedArchive(name.to_owned()));
    }
    Ok(())
}

/// Read a receipt container, applying every limit before returning anything.
pub fn read_container(bytes: &[u8]) -> Result<ReceiptFile, ContainerError> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))
        .map_err(|e| ContainerError::Unreadable(e.to_string()))?;

    if archive.len() > MAX_ENTRIES {
        return Err(ContainerError::TooLarge(format!(
            "{} entries",
            archive.len()
        )));
    }

    // Declared sizes first: refuse a bomb before decompressing a byte of it.
    let mut declared_total: u64 = 0;
    for index in 0..archive.len() {
        let entry = archive
            .by_index_raw(index)
            .map_err(|e| ContainerError::Unreadable(e.to_string()))?;
        let name = entry
            .name()
            .map_err(|e| ContainerError::Unreadable(format!("entry name: {e}")))?
            .to_string();
        safe_name(&name)?;
        declared_total = declared_total.saturating_add(entry.size());
        let compressed = entry.compressed_size().max(1);
        if entry.size() / compressed > MAX_RATIO {
            return Err(ContainerError::TooLarge(format!(
                "{name} expands {}x, which looks like a zip bomb",
                entry.size() / compressed
            )));
        }
    }
    if declared_total > MAX_TOTAL_BYTES {
        return Err(ContainerError::TooLarge(format!(
            "{declared_total} bytes declared"
        )));
    }

    let mut receipt_json: Option<Vec<u8>> = None;
    let mut artifacts = Vec::new();
    let mut read_total: u64 = 0;

    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|e| ContainerError::Unreadable(e.to_string()))?;
        let name = entry
            .name()
            .map_err(|e| ContainerError::Unreadable(format!("entry name: {e}")))?
            .to_string();
        if entry.is_dir() {
            continue;
        }
        safe_name(&name)?;

        let limit = if name == "receipt.json" {
            MAX_RECEIPT_JSON
        } else {
            MAX_TOTAL_BYTES
        };
        let mut buffer = Vec::new();
        // Read with a hard cap, so a lying header cannot make us allocate.
        entry
            .by_ref()
            .take(limit + 1)
            .read_to_end(&mut buffer)
            .map_err(|e| ContainerError::Unreadable(e.to_string()))?;
        if buffer.len() as u64 > limit {
            return Err(ContainerError::TooLarge(format!(
                "{name} is over its limit"
            )));
        }
        read_total = read_total.saturating_add(buffer.len() as u64);
        if read_total > MAX_TOTAL_BYTES {
            return Err(ContainerError::TooLarge(
                "total decompressed size".to_owned(),
            ));
        }
        not_nested(&name, &buffer)?;

        if name == "receipt.json" {
            receipt_json = Some(buffer);
        } else if let Some(digest) = name.strip_prefix("artifacts/") {
            artifacts.push((digest.to_owned(), buffer));
        }
        // Anything else is ignored rather than refused: a future version may
        // add files that an old verifier should not choke on.
    }

    receipt_json
        .map(|receipt_json| ReceiptFile {
            receipt_json,
            artifacts,
        })
        .ok_or(ContainerError::NoReceipt)
}

/// Write a receipt container. Entries are stored uncompressed: a receipt is
/// small, and a producer that cannot inflate anything cannot ship a bomb.
pub fn write_container(file: &ReceiptFile) -> Result<Vec<u8>, ContainerError> {
    let mut out = Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut out);
        let options: zip::write::FileOptions<'_, '_, ()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
        writer
            .start_file("receipt.json", options)
            .map_err(|e| ContainerError::Unreadable(e.to_string()))?;
        writer
            .write_all(&file.receipt_json)
            .map_err(|e| ContainerError::Unreadable(e.to_string()))?;
        for (digest, bytes) in &file.artifacts {
            safe_name(digest)?;
            writer
                .start_file(format!("artifacts/{digest}"), options)
                .map_err(|e| ContainerError::Unreadable(e.to_string()))?;
            writer
                .write_all(bytes)
                .map_err(|e| ContainerError::Unreadable(e.to_string()))?;
        }
        writer
            .finish()
            .map_err(|e| ContainerError::Unreadable(e.to_string()))?;
    }
    Ok(out.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn container_with(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut out);
            let options: zip::write::FileOptions<'_, '_, ()> = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            for (name, bytes) in entries {
                writer.start_file(*name, options).expect("entry");
                writer.write_all(bytes).expect("write");
            }
            writer.finish().expect("finish");
        }
        out.into_inner()
    }

    #[test]
    fn a_receipt_round_trips() {
        let file = ReceiptFile {
            receipt_json: b"{\"a\":1}".to_vec(),
            artifacts: vec![("ab".repeat(32), b"shot".to_vec())],
        };
        let bytes = write_container(&file).expect("writes");
        let read = read_container(&bytes).expect("reads");
        assert_eq!(read.receipt_json, file.receipt_json);
        assert_eq!(read.artifacts, file.artifacts);
    }

    #[test]
    fn a_container_without_a_receipt_is_refused() {
        let bytes = container_with(&[("notes.txt", b"hello")]);
        assert_eq!(
            read_container(&bytes).unwrap_err(),
            ContainerError::NoReceipt
        );
    }

    #[test]
    fn path_traversal_is_refused() {
        for name in ["../escape.json", "/etc/passwd", "a/../../b"] {
            let bytes = container_with(&[("receipt.json", b"{}"), (name, b"x")]);
            match read_container(&bytes) {
                Err(ContainerError::PathTraversal(_)) => {}
                other => panic!("{name} was not refused: {other:?}"),
            }
        }
    }

    #[test]
    fn a_nested_archive_is_refused_by_name_and_by_content() {
        let inner = container_with(&[("receipt.json", b"{}")]);
        let bytes = container_with(&[("receipt.json", b"{}"), ("artifacts/inner.zip", &inner)]);
        assert!(matches!(
            read_container(&bytes),
            Err(ContainerError::NestedArchive(_))
        ));

        // Same bytes, innocent name: still refused.
        let bytes = container_with(&[("receipt.json", b"{}"), ("artifacts/innocent", &inner)]);
        assert!(matches!(
            read_container(&bytes),
            Err(ContainerError::NestedArchive(_))
        ));
    }

    #[test]
    fn a_zip_bomb_is_refused_before_it_is_decompressed() {
        // Highly compressible content, written with deflate so the ratio is high.
        let mut out = Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut out);
            let options: zip::write::FileOptions<'_, '_, ()> = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            writer.start_file("receipt.json", options).expect("entry");
            writer
                .write_all(&vec![0u8; 8 * 1024 * 1024])
                .expect("write");
            writer.finish().expect("finish");
        }
        let bytes = out.into_inner();
        assert!(matches!(
            read_container(&bytes),
            Err(ContainerError::TooLarge(_))
        ));
    }

    #[test]
    fn rubbish_is_a_result_not_a_panic() {
        for bad in [b"".as_slice(), b"PK", b"not a zip at all", &[0xffu8; 64]] {
            assert!(read_container(bad).is_err());
        }
    }
}
