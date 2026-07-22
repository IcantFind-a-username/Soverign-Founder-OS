//! Trusted, signed on-disk cache of compiled artifacts.
//!
//! The compile worker (see `compile_worker`) isolates compilation but throws
//! its result away every run. Persisting a compiled module is dangerous:
//! `Module::deserialize` trusts its input and will run whatever machine code
//! it is handed, so a poisoned cache file is arbitrary code execution. RFC
//! 0002: *"Before any unsafe engine deserialization, the worker verifies the
//! cache-record COSE envelope, role, engine/configuration identity, target
//! identity, and compiled bytes. A missing, mutable, unsigned, mismatched,
//! symlinked, or poisoned cache entry is rejected and quarantined."*
//!
//! Each entry is the serialized module plus a COSE record signed under the
//! `compiled-cache` role binding the engine identity, the source component
//! digest, and the compiled-blob digest. On lookup the record is verified
//! against the owner's cache trust store, every field is checked, and the
//! blob is rehashed — only then is it deserialized. Any failure quarantines
//! the entry and reports a miss, so the caller recompiles from source. This
//! never trusts a file merely because it sits under a digest-shaped name.

use std::path::{Path, PathBuf};

use serde_json::Value;
use wasmtime::{Engine, Module};

use sovereign_artifact::Digest;
use sovereign_identity::{CompiledCacheRole, RoleTrustStore, TypedSigner};

use crate::SandboxError;

/// Compilation-identity tag bound into every record. A blob is only a
/// candidate for an engine that declares the same identity; wasmtime's own
/// deserialize compatibility check is the ultimate gate, so a version skew
/// that slips past this tag still fails closed at deserialize (quarantined,
/// then recompiled). Bump on any change to the shared engine configuration.
pub const COMPILED_CACHE_ENGINE_IDENTITY: &str = "sovereign-corewasm-v2";

const RECORD_TYPE: &str = "sovereign.compiled-cache-record";
const RECORD_VERSION: u64 = 1;
const MAX_RECORD_BYTES: u64 = 16 * 1024;
const MAX_BLOB_BYTES: u64 = 64 * 1024 * 1024;

/// An owner-controlled cache of compiled artifacts. Holds both the signer
/// (to fill the cache) and the trust store (to verify on read); for the
/// single-owner local runtime these anchor to the same key.
pub struct CompiledCache {
    dir: PathBuf,
    quarantine: PathBuf,
    signer: TypedSigner<CompiledCacheRole>,
    trust: RoleTrustStore<CompiledCacheRole>,
    issuer: String,
    now_unix: i64,
}

impl std::fmt::Debug for CompiledCache {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CompiledCache")
            .field("dir", &self.dir)
            .field("issuer", &self.issuer)
            .finish_non_exhaustive()
    }
}

impl CompiledCache {
    /// Open (creating) a cache directory. `issuer` is the expected
    /// compiled-cache issuer that `trust` anchors; `now_unix` is the trusted
    /// validation time for record signatures.
    pub fn open(
        dir: impl Into<PathBuf>,
        signer: TypedSigner<CompiledCacheRole>,
        trust: RoleTrustStore<CompiledCacheRole>,
        issuer: impl Into<String>,
        now_unix: i64,
    ) -> Result<Self, SandboxError> {
        let dir = dir.into();
        let quarantine = dir.join("quarantine");
        std::fs::create_dir_all(&quarantine)
            .map_err(|error| SandboxError::CompiledCacheUnavailable(error.to_string()))?;
        Ok(Self {
            dir,
            quarantine,
            signer,
            trust,
            issuer: issuer.into(),
            now_unix,
        })
    }

    /// Return a verified compiled module for `component_digest`, or `None` on a
    /// miss or any integrity failure. A failing entry is quarantined so the
    /// caller recompiles and never sees it again.
    pub(crate) fn lookup(&self, engine: &Engine, component_digest: Digest) -> Option<Module> {
        let key = self.entry_key(component_digest);
        let blob_path = self.dir.join(format!("{key}.blob"));
        let record_path = self.dir.join(format!("{key}.cose"));

        // A plain miss (either file absent) is not a failure and is not
        // quarantined.
        if !is_present(&blob_path) || !is_present(&record_path) {
            return None;
        }

        match self.verify_entry(engine, component_digest, &blob_path, &record_path) {
            Ok(module) => Some(module),
            Err(_) => {
                // Poisoned/mismatched/mutable entry: move it aside and miss.
                self.quarantine_entry(&key, &blob_path, &record_path);
                None
            }
        }
    }

    /// Store a compiled blob for `component_digest` under a freshly signed
    /// record. Best-effort: a storage failure is not fatal to the caller (it
    /// already holds the module), only future lookups miss.
    pub(crate) fn store(
        &self,
        component_digest: Digest,
        serialized: &[u8],
    ) -> Result<(), SandboxError> {
        if serialized.len() as u64 > MAX_BLOB_BYTES {
            return Err(SandboxError::CompiledCacheUnavailable(
                "blob too large".into(),
            ));
        }
        let record = serde_json::json!({
            "typ": RECORD_TYPE,
            "version": RECORD_VERSION,
            "engine_identity": COMPILED_CACHE_ENGINE_IDENTITY,
            "component_digest": component_digest.as_hex(),
            "compiled_blob_digest": Digest::of_bytes(serialized).as_hex(),
        });
        let canonical = serde_json_canonicalizer::to_vec(&record)
            .map_err(|error| SandboxError::CompiledCacheUnavailable(error.to_string()))?;
        let signed = self
            .signer
            .sign_cose(&canonical)
            .map_err(|error| SandboxError::CompiledCacheUnavailable(error.to_string()))?;

        let key = self.entry_key(component_digest);
        // Write the blob first, then the record: a lookup requires both, and
        // an interrupted store that left only a blob is an ignorable miss.
        write_atomic(&self.dir.join(format!("{key}.blob")), serialized)
            .map_err(|error| SandboxError::CompiledCacheUnavailable(error.to_string()))?;
        write_atomic(&self.dir.join(format!("{key}.cose")), &signed)
            .map_err(|error| SandboxError::CompiledCacheUnavailable(error.to_string()))?;
        Ok(())
    }

    fn verify_entry(
        &self,
        engine: &Engine,
        component_digest: Digest,
        blob_path: &Path,
        record_path: &Path,
    ) -> Result<Module, SandboxError> {
        let signed = read_regular_bounded(record_path, MAX_RECORD_BYTES)?;
        let blob = read_regular_bounded(blob_path, MAX_BLOB_BYTES)?;

        let verified = self
            .trust
            .verify(&signed, &self.issuer, self.now_unix)
            .map_err(|error| SandboxError::CompiledCachePoisoned(error.to_string()))?;
        let value: Value = serde_json::from_slice(verified.payload())
            .map_err(|error| SandboxError::CompiledCachePoisoned(error.to_string()))?;
        let canonical = serde_json_canonicalizer::to_vec(&value)
            .map_err(|error| SandboxError::CompiledCachePoisoned(error.to_string()))?;
        if canonical != verified.payload() {
            return Err(SandboxError::CompiledCachePoisoned(
                "non-canonical record".into(),
            ));
        }

        let field = |name: &str| -> Result<String, SandboxError> {
            value
                .get(name)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| SandboxError::CompiledCachePoisoned(format!("missing {name}")))
        };
        if value.get("typ").and_then(Value::as_str) != Some(RECORD_TYPE)
            || value.get("version").and_then(Value::as_u64) != Some(RECORD_VERSION)
        {
            return Err(SandboxError::CompiledCachePoisoned("type/version".into()));
        }
        if field("engine_identity")? != COMPILED_CACHE_ENGINE_IDENTITY {
            return Err(SandboxError::CompiledCachePoisoned(
                "engine identity".into(),
            ));
        }
        if field("component_digest")? != component_digest.as_hex() {
            return Err(SandboxError::CompiledCachePoisoned(
                "component digest".into(),
            ));
        }
        if field("compiled_blob_digest")? != Digest::of_bytes(&blob).as_hex() {
            return Err(SandboxError::CompiledCachePoisoned("blob digest".into()));
        }

        // Every field checked and the blob rehashed against the signed digest:
        // only now is deserialization of the machine code allowed.
        // SAFETY: the blob's digest was just re-verified against a record
        // signed under the trusted compiled-cache role; wasmtime's own
        // compatibility check is the final gate.
        unsafe { Module::deserialize(engine, &blob) }
            .map_err(|error| SandboxError::CompiledCachePoisoned(error.to_string()))
    }

    fn entry_key(&self, component_digest: Digest) -> String {
        let mut keyed = COMPILED_CACHE_ENGINE_IDENTITY.as_bytes().to_vec();
        keyed.push(0);
        keyed.extend_from_slice(component_digest.as_bytes());
        Digest::of_bytes(&keyed).as_hex()
    }

    fn quarantine_entry(&self, key: &str, blob_path: &Path, record_path: &Path) {
        // Best-effort: move both files aside so the poisoned entry cannot be
        // reused, and a lookup after this simply recompiles.
        let _ = std::fs::rename(blob_path, self.quarantine.join(format!("{key}.blob")));
        let _ = std::fs::rename(record_path, self.quarantine.join(format!("{key}.cose")));
    }
}

/// A path that exists and is a regular file (not a symlink, directory, or
/// device). Anything else is treated as absent — the cache never follows a
/// symlink into or out of its directory.
fn is_present(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_file())
        .unwrap_or(false)
}

fn read_regular_bounded(path: &Path, max: u64) -> Result<Vec<u8>, SandboxError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| SandboxError::CompiledCachePoisoned(error.to_string()))?;
    if !metadata.file_type().is_file() {
        return Err(SandboxError::CompiledCachePoisoned(
            "not a regular file".into(),
        ));
    }
    if metadata.len() > max {
        return Err(SandboxError::CompiledCachePoisoned(
            "entry too large".into(),
        ));
    }
    std::fs::read(path).map_err(|error| SandboxError::CompiledCachePoisoned(error.to_string()))
}

/// Crash-safe replacement write: temp + fsync + rename (+ dir flush on Unix).
fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let temp_path = path.with_extension("tmp");
    let result = (|| {
        let mut file = std::fs::File::create(&temp_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temp_path, path)?;
        #[cfg(unix)]
        if let Some(directory) = path.parent() {
            std::fs::File::open(directory)?.sync_all()?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wasm::compile_engine_config;
    use sovereign_identity::KeyValidity;

    const NOW: i64 = 1_800_000_000;

    fn engine() -> Engine {
        Engine::new(&compile_engine_config()).unwrap()
    }

    fn serialized_module(engine: &Engine, ret: i32) -> Vec<u8> {
        let wasm = wat::parse_str(format!(
            "(module (func (export \"sovereign_run\") (result i32) i32.const {ret}))"
        ))
        .unwrap();
        Module::from_binary(engine, &wasm)
            .unwrap()
            .serialize()
            .unwrap()
    }

    fn signer(issuer: &str, secret: u8) -> TypedSigner<CompiledCacheRole> {
        TypedSigner::from_secret_bytes(issuer, [secret; 32]).unwrap()
    }

    fn cache(dir: &Path, issuer: &str, secret: u8, trust_secret: u8) -> CompiledCache {
        let mut trust = RoleTrustStore::new();
        trust
            .trust_signer(
                &signer(issuer, trust_secret),
                KeyValidity::new(NOW - 60, NOW + 3_600).unwrap(),
            )
            .unwrap();
        CompiledCache::open(
            dir.to_path_buf(),
            signer(issuer, secret),
            trust,
            issuer,
            NOW,
        )
        .unwrap()
    }

    fn find(dir: &Path, ext: &str) -> Option<PathBuf> {
        std::fs::read_dir(dir)
            .ok()?
            .flatten()
            .map(|e| e.path())
            .find(|p| p.is_file() && p.extension().is_some_and(|x| x == ext))
    }

    fn quarantined_count(dir: &Path) -> usize {
        std::fs::read_dir(dir.join("quarantine"))
            .map(|it| it.flatten().count())
            .unwrap_or(0)
    }

    #[test]
    fn store_then_lookup_returns_a_verified_module() {
        let dir = tempfile::tempdir().unwrap();
        let engine = engine();
        let cache = cache(dir.path(), "cache.local", 0x55, 0x55);
        let digest = Digest::of_bytes(b"component-A");
        cache.store(digest, &serialized_module(&engine, 7)).unwrap();
        assert!(cache.lookup(&engine, digest).is_some());
        assert_eq!(quarantined_count(dir.path()), 0);
    }

    #[test]
    fn a_tampered_blob_is_rejected_and_quarantined() {
        let dir = tempfile::tempdir().unwrap();
        let engine = engine();
        let cache = cache(dir.path(), "cache.local", 0x55, 0x55);
        let digest = Digest::of_bytes(b"component-A");
        cache.store(digest, &serialized_module(&engine, 7)).unwrap();

        // Flip the compiled bytes: the record's blob digest no longer matches.
        let blob = find(dir.path(), "blob").unwrap();
        let mut bytes = std::fs::read(&blob).unwrap();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xff;
        std::fs::write(&blob, &bytes).unwrap();

        assert!(cache.lookup(&engine, digest).is_none());
        assert!(
            find(dir.path(), "blob").is_none(),
            "poisoned entry left in place"
        );
        assert_eq!(
            quarantined_count(dir.path()),
            2,
            "blob + record quarantined"
        );
    }

    #[test]
    fn an_entry_signed_by_an_untrusted_key_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let engine = engine();
        // Stored under key 0xAA, but the reader trusts only key 0xBB.
        let writer = cache(dir.path(), "cache.local", 0xAA, 0xAA);
        let digest = Digest::of_bytes(b"component-A");
        writer
            .store(digest, &serialized_module(&engine, 7))
            .unwrap();

        let reader = cache(dir.path(), "cache.local", 0xBB, 0xBB);
        assert!(reader.lookup(&engine, digest).is_none());
        assert_eq!(quarantined_count(dir.path()), 2);
    }

    #[test]
    fn a_record_bound_to_a_different_component_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let engine = engine();
        let cache = cache(dir.path(), "cache.local", 0x55, 0x55);
        let real = Digest::of_bytes(b"component-A");
        cache.store(real, &serialized_module(&engine, 7)).unwrap();

        // Rename A's files under B's key: the record still says component A.
        let other = Digest::of_bytes(b"component-B");
        let a_key = cache.entry_key(real);
        let b_key = cache.entry_key(other);
        std::fs::rename(
            dir.path().join(format!("{a_key}.blob")),
            dir.path().join(format!("{b_key}.blob")),
        )
        .unwrap();
        std::fs::rename(
            dir.path().join(format!("{a_key}.cose")),
            dir.path().join(format!("{b_key}.cose")),
        )
        .unwrap();

        assert!(cache.lookup(&engine, other).is_none());
        assert_eq!(quarantined_count(dir.path()), 2);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_entry_is_treated_as_absent() {
        let dir = tempfile::tempdir().unwrap();
        let engine = engine();
        let cache = cache(dir.path(), "cache.local", 0x55, 0x55);
        let digest = Digest::of_bytes(b"component-A");
        cache.store(digest, &serialized_module(&engine, 7)).unwrap();

        let blob = find(dir.path(), "blob").unwrap();
        let elsewhere = dir.path().join("elsewhere.blob");
        std::fs::rename(&blob, &elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &blob).unwrap();

        assert!(cache.lookup(&engine, digest).is_none());
    }
}
