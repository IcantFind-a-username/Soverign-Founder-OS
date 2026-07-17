//! Audited, host-mediated external effects — the first real thing the runtime
//! *does* rather than prepares.
//!
//! This crate provides a single reference effect: writing an approved
//! document into an owner-controlled local **outbox** directory. It is the
//! Phase D "one local reference tool with opaque grants" from RFC 0002,
//! deliberately the safest possible external effect: entirely local, fully
//! auditable, and revocable by deleting a file.
//!
//! The effect is performed by the trusted host, never by guest code, and only
//! after the full authorization chain (deterministic policy → signed approval
//! evidence → Capability V2 → durable authority consumption → verified
//! sandbox step) has already succeeded. This crate does not re-authorize; it
//! enforces the *effect-local* safety properties:
//!
//! - the write target is a virtual grant rooted at the host-controlled outbox;
//!   the caller supplies an opaque key, never a path;
//! - filenames are host-derived single components — traversal (`..`, `/`) and
//!   control characters are structurally impossible and re-checked;
//! - writes are atomic (exclusive temp → flush → rename → directory flush), so
//!   a crash never leaves a partial file, and a symlinked or non-regular
//!   target is refused rather than followed;
//! - Red-classified data can never enter the outbox (privacy model);
//! - content size is bounded and the receipt carries the content digest.
//!
//! ## Honest limits
//!
//! This is a **local filesystem** effect only. No network, DNS, or egress
//! broker exists; those require their own adversarial review (RFC 0002) and
//! are rejected until then. "Writing to the outbox" is not "delivering to the
//! customer": it produces a real local artifact the founder can inspect, sign,
//! and send themselves. Atomic rename is the durability primitive — the file
//! is either fully present or absent, so this local effect has no
//! indeterminate state.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::Serialize;
use sha2::{Digest, Sha256};

pub const MAX_OUTBOX_BYTES: usize = 1024 * 1024;

/// Data sensitivity of the content being written. Mirrors the runtime's
/// classification; Red never reaches a host effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectDataClass {
    Green,
    Amber,
    Red,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EffectError {
    #[error("red-classified data may never leave through a host effect")]
    RedDataForbidden,
    #[error("outbox key is not a safe single-component name")]
    UnsafeName,
    #[error("content exceeds the outbox size ceiling")]
    ContentTooLarge,
    #[error("outbox target already exists and is not a regular file")]
    UnsafeExistingTarget,
    #[error("outbox effect I/O failed: {0}")]
    Io(String),
}

/// Non-repudiable record of one completed outbox write.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct OutboxReceipt {
    /// Path relative to the outbox root — never an absolute host path.
    pub relative_path: String,
    pub content_sha256_hex: String,
    pub bytes: usize,
}

/// Owner-controlled local outbox. The root is created and owned by the host;
/// callers can only address files inside it by opaque key.
#[derive(Debug)]
pub struct OutboxBroker {
    root: PathBuf,
}

impl OutboxBroker {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, EffectError> {
        let root = root.as_ref().to_path_buf();
        create_dir_private(&root)?;
        Ok(Self { root })
    }

    /// Write `contents` to `<outbox>/<key>.txt` atomically. The key is a
    /// host-supplied opaque identifier (e.g. a document id); it is validated
    /// as a single safe component and given the `.txt` extension by the host.
    pub fn write_document(
        &self,
        key: &str,
        data_class: EffectDataClass,
        contents: &[u8],
    ) -> Result<OutboxReceipt, EffectError> {
        if data_class == EffectDataClass::Red {
            return Err(EffectError::RedDataForbidden);
        }
        if contents.len() > MAX_OUTBOX_BYTES {
            return Err(EffectError::ContentTooLarge);
        }
        let file_name = safe_file_name(key)?;
        let final_path = self.root.join(&file_name);

        // Refuse to write through an existing symlink or non-regular file.
        if let Ok(metadata) = std::fs::symlink_metadata(&final_path) {
            if !metadata.file_type().is_file() {
                return Err(EffectError::UnsafeExistingTarget);
            }
        }

        write_exclusive_atomic(&self.root, &file_name, contents)?;

        Ok(OutboxReceipt {
            relative_path: file_name,
            content_sha256_hex: hex::encode(Sha256::digest(contents)),
            bytes: contents.len(),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

/// Derive a safe `.txt` filename from an opaque key. Only ASCII alphanumerics,
/// `-`, and `_` survive; anything else is rejected. The result is guaranteed
/// to be a single path component.
fn safe_file_name(key: &str) -> Result<String, EffectError> {
    if key.is_empty() || key.len() > 128 {
        return Err(EffectError::UnsafeName);
    }
    if !key
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(EffectError::UnsafeName);
    }
    let name = format!("{key}.txt");
    // Defense in depth: the derived name must still be exactly one normal
    // component, matching the vault's traversal guard.
    let mut components = Path::new(&name).components();
    let single_normal = matches!(components.next(), Some(std::path::Component::Normal(_)))
        && components.next().is_none();
    if !single_normal || name.contains(['/', '\\']) {
        return Err(EffectError::UnsafeName);
    }
    Ok(name)
}

fn write_exclusive_atomic(dir: &Path, final_name: &str, bytes: &[u8]) -> Result<(), EffectError> {
    let temp_path = dir.join(format!(".{final_name}.tmp"));
    // Remove any stale temp from a previous crash before exclusive create.
    let _ = std::fs::remove_file(&temp_path);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options.open(&temp_path).map_err(io)?;
        file.write_all(bytes).map_err(io)?;
        file.sync_all().map_err(io)?;
        drop(file);
        std::fs::rename(&temp_path, dir.join(final_name)).map_err(io)?;
        sync_dir(dir);
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }
    result
}

fn create_dir_private(dir: &Path) -> Result<(), EffectError> {
    std::fs::create_dir_all(dir).map_err(io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

#[cfg(unix)]
fn sync_dir(dir: &Path) {
    if let Ok(handle) = std::fs::File::open(dir) {
        let _ = handle.sync_all();
    }
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) {}

fn io(error: std::io::Error) -> EffectError {
    EffectError::Io(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn writes_document_and_returns_receipt() {
        let dir = tempdir().unwrap();
        let broker = OutboxBroker::open(dir.path().join("outbox")).unwrap();
        let receipt = broker
            .write_document("invoice-2026-001", EffectDataClass::Amber, b"INVOICE DRAFT")
            .unwrap();
        assert_eq!(receipt.relative_path, "invoice-2026-001.txt");
        assert_eq!(receipt.bytes, 13);
        assert_eq!(
            receipt.content_sha256_hex,
            hex::encode(Sha256::digest(b"INVOICE DRAFT"))
        );

        let written =
            std::fs::read(dir.path().join("outbox").join("invoice-2026-001.txt")).unwrap();
        assert_eq!(written, b"INVOICE DRAFT");
    }

    #[test]
    fn red_data_is_refused() {
        let dir = tempdir().unwrap();
        let broker = OutboxBroker::open(dir.path().join("outbox")).unwrap();
        assert_eq!(
            broker.write_document("secret", EffectDataClass::Red, b"pii"),
            Err(EffectError::RedDataForbidden)
        );
        assert!(!dir.path().join("outbox").join("secret.txt").exists());
    }

    #[test]
    fn traversal_and_control_names_are_refused() {
        let dir = tempdir().unwrap();
        let broker = OutboxBroker::open(dir.path().join("outbox")).unwrap();
        for bad in [
            "../escape",
            "a/b",
            "a\\b",
            "",
            "with space",
            "dot.dot",
            "tab\tname",
        ] {
            assert_eq!(
                broker.write_document(bad, EffectDataClass::Green, b"x"),
                Err(EffectError::UnsafeName),
                "key {bad:?} must be refused"
            );
        }
        // Nothing escaped the outbox root.
        assert!(!dir.path().join("escape.txt").exists());
    }

    #[test]
    fn oversize_content_is_refused() {
        let dir = tempdir().unwrap();
        let broker = OutboxBroker::open(dir.path().join("outbox")).unwrap();
        let big = vec![b'x'; MAX_OUTBOX_BYTES + 1];
        assert_eq!(
            broker.write_document("big", EffectDataClass::Green, &big),
            Err(EffectError::ContentTooLarge)
        );
    }

    #[cfg(unix)]
    #[test]
    fn existing_symlink_target_is_refused_not_followed() {
        let dir = tempdir().unwrap();
        let outbox = dir.path().join("outbox");
        let broker = OutboxBroker::open(&outbox).unwrap();
        let outside = dir.path().join("outside.txt");
        std::fs::write(&outside, b"original").unwrap();
        std::os::unix::fs::symlink(&outside, outbox.join("evil.txt")).unwrap();

        assert_eq!(
            broker.write_document("evil", EffectDataClass::Green, b"attacker"),
            Err(EffectError::UnsafeExistingTarget)
        );
        // The symlink target outside the outbox was not modified.
        assert_eq!(std::fs::read(&outside).unwrap(), b"original");
    }

    #[test]
    fn rewrite_replaces_atomically() {
        let dir = tempdir().unwrap();
        let broker = OutboxBroker::open(dir.path().join("outbox")).unwrap();
        broker
            .write_document("doc", EffectDataClass::Green, b"first")
            .unwrap();
        let receipt = broker
            .write_document("doc", EffectDataClass::Green, b"second")
            .unwrap();
        assert_eq!(receipt.bytes, 6);
        let written = std::fs::read(dir.path().join("outbox").join("doc.txt")).unwrap();
        assert_eq!(written, b"second");
    }
}
