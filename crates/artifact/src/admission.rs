//! Local artifact admission: RFC 0002 admission transaction steps 6–8.
//!
//! Publisher verification (steps 1–5, [`crate::ArtifactVerifier`]) proves
//! provenance; it does not install anything. Admission is the separate local
//! trust decision: the owner's artifact-admission key signs a record binding
//! the exact component digest, manifest digest, risk class, backend, ABI,
//! effective host capabilities, and installation state, and the verified bytes
//! are persisted in an owner-controlled content-addressed store.
//!
//! Trust on the load path comes from the admission record signature and from
//! recomputed digests of the stored bytes — never from a filename. A store
//! entry whose bytes do not hash to its admitted digest is corruption, not a
//! cache miss, and fails closed.
//!
//! Limits of this stage, stated explicitly: the [`AdmittedArtifact`] handle is
//! not yet required by the verified executor (a subsequent slice), there is no
//! durable revocation of admission records beyond revoking the admission key
//! in the caller-persisted trust store, and concurrent `admit` calls against
//! the same store directory from multiple processes are not serialized.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sovereign_identity::{AdmissionRole, IdentityError, RoleTrustStore, TypedSigner};
use uuid::Uuid;

use crate::manifest::{canonicalize, TrustedClock, MANIFEST_DIGEST_DOMAIN};
use crate::schema::{parse_strict_json, StrictJsonError};
use crate::{
    ArtifactError, Digest, PluginManifest, VerifiedArtifact, CANONICALIZATION_PROFILE,
    HARD_MAX_COMPONENT_BYTES, HARD_MAX_MANIFEST_PAYLOAD_BYTES,
};

pub const ADMISSION_RECORD_TYPE: &str = "sovereign.artifact-admission";
pub const ADMISSION_RECORD_VERSION: u16 = 1;
pub const HARD_MAX_SIGNED_ADMISSION_BYTES: usize = 64 * 1024;
const MAX_ADMISSION_PAYLOAD_BYTES: usize = 32 * 1024;

const OBJECTS_DIR: &str = "objects";
const MANIFESTS_DIR: &str = "manifests";
const ADMISSIONS_DIR: &str = "admissions";

/// Installation state recorded inside the signed admission record. Only
/// `admitted` is loadable; every other value fails closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallationState {
    Admitted,
    Revoked,
    #[serde(other)]
    Unsupported,
}

/// Strict canonical payload of the artifact-admission COSE_Sign1 record.
/// Public fields support inspection after validation; the store never accepts
/// caller-constructed claims for loading.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionRecordClaimsV1 {
    pub typ: String,
    pub version: u16,
    pub admission_id: Uuid,
    pub admitting_issuer: String,
    pub admitting_key_id: Digest,
    pub component_digest: Digest,
    pub manifest_digest: Digest,
    pub backend: crate::ArtifactBackend,
    pub risk_class: crate::RiskClass,
    pub abi: crate::ArtifactAbi,
    pub effective_host_capabilities: Vec<String>,
    pub installation_state: InstallationState,
    pub canonicalization_profile: String,
    pub admitted_at_unix: i64,
}

/// A locally admitted artifact: verified bytes plus the validated admission
/// record that authorized their installation. Only the store can create one.
#[derive(Debug, Clone)]
pub struct AdmittedArtifact {
    artifact: VerifiedArtifact,
    record: AdmissionRecordClaimsV1,
}

impl AdmittedArtifact {
    pub fn artifact(&self) -> &VerifiedArtifact {
        &self.artifact
    }

    pub fn record(&self) -> &AdmissionRecordClaimsV1 {
        &self.record
    }

    pub fn admission_id(&self) -> Uuid {
        self.record.admission_id
    }
}

/// Owner-controlled content-addressed artifact store.
///
/// Layout under `root`:
/// - `objects/<component-digest-hex>` — exact component bytes;
/// - `manifests/<manifest-digest-hex>` — canonical JCS manifest payload;
/// - `admissions/<manifest-digest-hex>` — tagged COSE_Sign1 admission record.
#[derive(Debug)]
pub struct ArtifactStore {
    objects: PathBuf,
    manifests: PathBuf,
    admissions: PathBuf,
}

impl ArtifactStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, ArtifactError> {
        let root = root.as_ref();
        let objects = root.join(OBJECTS_DIR);
        let manifests = root.join(MANIFESTS_DIR);
        let admissions = root.join(ADMISSIONS_DIR);
        for directory in [&objects, &manifests, &admissions] {
            std::fs::create_dir_all(directory).map_err(store_io)?;
        }
        Ok(Self {
            objects,
            manifests,
            admissions,
        })
    }

    /// Persist a publisher-verified artifact and publish a locally signed
    /// admission record for it. Fails closed without publishing a record if
    /// any store entry cannot be written or an existing content-addressed
    /// entry does not rehash to its digest.
    pub fn admit<C: TrustedClock>(
        &self,
        artifact: &VerifiedArtifact,
        signer: &TypedSigner<AdmissionRole>,
        clock: &C,
    ) -> Result<AdmittedArtifact, ArtifactError> {
        let component_digest = artifact.component_digest();
        let manifest_digest = artifact.manifest_digest();

        // Re-derive both digests from the exact bytes being persisted so the
        // stored entries can never disagree with the record that admits them.
        let actual_component = Digest::of_bytes(artifact.bytes());
        if actual_component != component_digest {
            return Err(ArtifactError::StoredComponentCorrupted {
                expected: component_digest,
                actual: actual_component,
            });
        }
        let actual_manifest =
            Digest::domain_separated(MANIFEST_DIGEST_DOMAIN, artifact.canonical_manifest());
        if actual_manifest != manifest_digest {
            return Err(ArtifactError::StoredManifestCorrupted);
        }

        let admission_path = self.admissions.join(manifest_digest.as_hex());
        if admission_path.exists() {
            return Err(ArtifactError::AdmissionRecordExists);
        }

        self.store_content_addressed(
            &self.objects,
            component_digest,
            artifact.bytes(),
            |actual| ArtifactError::StoredComponentCorrupted {
                expected: component_digest,
                actual,
            },
        )?;
        self.store_manifest_payload(manifest_digest, artifact.canonical_manifest())?;

        let record = AdmissionRecordClaimsV1 {
            typ: ADMISSION_RECORD_TYPE.to_owned(),
            version: ADMISSION_RECORD_VERSION,
            admission_id: Uuid::new_v4(),
            admitting_issuer: signer.issuer().to_owned(),
            admitting_key_id: Digest::from_bytes(*signer.key_id()),
            component_digest,
            manifest_digest,
            backend: artifact.manifest().backend(),
            risk_class: artifact.manifest().risk_class(),
            abi: artifact.manifest().abi(),
            effective_host_capabilities: Vec::new(),
            installation_state: InstallationState::Admitted,
            canonicalization_profile: CANONICALIZATION_PROFILE.to_owned(),
            admitted_at_unix: clock.now_unix(),
        };
        let canonical_record =
            canonicalize(&record).map_err(|_| ArtifactError::AdmissionSigningFailed)?;
        if canonical_record.len() > MAX_ADMISSION_PAYLOAD_BYTES {
            return Err(ArtifactError::AdmissionRecordTooLarge);
        }
        let signed_record = signer
            .sign_cose(&canonical_record)
            .map_err(|_| ArtifactError::AdmissionSigningFailed)?;
        if signed_record.len() > HARD_MAX_SIGNED_ADMISSION_BYTES {
            return Err(ArtifactError::AdmissionRecordTooLarge);
        }
        write_exclusive_atomic(&self.admissions, &manifest_digest.as_hex(), &signed_record)?;

        Ok(AdmittedArtifact {
            artifact: artifact.clone(),
            record,
        })
    }

    /// Load a previously admitted artifact. Trust comes from the admission
    /// record signature verified against the caller's admission trust store
    /// and from recomputing every digest over the stored bytes.
    pub fn load<C: TrustedClock>(
        &self,
        component_digest: Digest,
        manifest_digest: Digest,
        admissions: &RoleTrustStore<AdmissionRole>,
        expected_issuer: &str,
        clock: &C,
    ) -> Result<AdmittedArtifact, ArtifactError> {
        let now_unix = clock.now_unix();
        let admission_path = self.admissions.join(manifest_digest.as_hex());
        if std::fs::symlink_metadata(&admission_path).is_err() {
            return Err(ArtifactError::AdmissionRecordNotFound);
        }
        let signed_record = read_bounded(&admission_path, HARD_MAX_SIGNED_ADMISSION_BYTES)?;

        let verified = admissions
            .verify(&signed_record, expected_issuer, now_unix)
            .map_err(map_admission_identity_error)?;
        if verified.payload().len() > MAX_ADMISSION_PAYLOAD_BYTES {
            return Err(ArtifactError::AdmissionRecordTooLarge);
        }
        let value = parse_strict_json(verified.payload()).map_err(|error| match error {
            StrictJsonError::DuplicateKey(key) => {
                ArtifactError::InvalidAdmissionRecord(format!("duplicate JSON key `{key}`"))
            }
            StrictJsonError::Invalid(message) => ArtifactError::InvalidAdmissionRecord(message),
        })?;
        let canonical = canonicalize(&value).map_err(|_| ArtifactError::AdmissionSigningFailed)?;
        if canonical != verified.payload() {
            return Err(ArtifactError::NonCanonicalAdmissionRecord);
        }
        let record: AdmissionRecordClaimsV1 = serde_json::from_value(value)
            .map_err(|error| ArtifactError::InvalidAdmissionRecord(error.to_string()))?;

        if record.typ != ADMISSION_RECORD_TYPE {
            return Err(ArtifactError::AdmissionRecordMismatch("typ"));
        }
        if record.version != ADMISSION_RECORD_VERSION {
            return Err(ArtifactError::AdmissionRecordMismatch("version"));
        }
        if record.admitting_issuer != verified.issuer() {
            return Err(ArtifactError::AdmissionRecordMismatch("admitting_issuer"));
        }
        if record.admitting_key_id.as_bytes() != verified.key_id() {
            return Err(ArtifactError::AdmissionRecordMismatch("admitting_key_id"));
        }
        if record.component_digest != component_digest {
            return Err(ArtifactError::AdmissionRecordMismatch("component_digest"));
        }
        if record.manifest_digest != manifest_digest {
            return Err(ArtifactError::AdmissionRecordMismatch("manifest_digest"));
        }
        if record.installation_state != InstallationState::Admitted {
            return Err(ArtifactError::AdmissionRecordMismatch("installation_state"));
        }
        if !record.effective_host_capabilities.is_empty() {
            return Err(ArtifactError::AdmissionRecordMismatch(
                "effective_host_capabilities",
            ));
        }
        if record.canonicalization_profile != CANONICALIZATION_PROFILE {
            return Err(ArtifactError::AdmissionRecordMismatch(
                "canonicalization_profile",
            ));
        }
        if record.admitted_at_unix > now_unix {
            return Err(ArtifactError::AdmissionRecordMismatch("admitted_at_unix"));
        }

        let manifest_path = self.manifests.join(manifest_digest.as_hex());
        let canonical_manifest = read_bounded(&manifest_path, HARD_MAX_MANIFEST_PAYLOAD_BYTES)?;
        if Digest::domain_separated(MANIFEST_DIGEST_DOMAIN, &canonical_manifest) != manifest_digest
        {
            return Err(ArtifactError::StoredManifestCorrupted);
        }
        let manifest_value =
            parse_strict_json(&canonical_manifest).map_err(|error| match error {
                StrictJsonError::DuplicateKey(key) => {
                    ArtifactError::InvalidManifest(format!("duplicate JSON key `{key}`"))
                }
                StrictJsonError::Invalid(message) => ArtifactError::InvalidManifest(message),
            })?;
        let manifest: PluginManifest = serde_json::from_value(manifest_value)
            .map_err(|error| ArtifactError::InvalidManifest(error.to_string()))?;
        manifest.validate_structural()?;
        if manifest.component_digest() != component_digest {
            return Err(ArtifactError::ComponentDigestMismatch {
                expected: manifest.component_digest(),
                actual: component_digest,
            });
        }
        if manifest.backend() != record.backend
            || manifest.risk_class() != record.risk_class
            || manifest.abi() != record.abi
        {
            return Err(ArtifactError::AdmissionRecordMismatch("runtime_profile"));
        }

        let object_path = self.objects.join(component_digest.as_hex());
        let bytes = read_bounded(&object_path, HARD_MAX_COMPONENT_BYTES)?;
        let actual_component = Digest::of_bytes(&bytes);
        if actual_component != component_digest {
            return Err(ArtifactError::StoredComponentCorrupted {
                expected: component_digest,
                actual: actual_component,
            });
        }

        let artifact = VerifiedArtifact::from_admitted_parts(
            manifest_digest,
            component_digest,
            Arc::new(manifest),
            Arc::from(bytes),
            Arc::from(canonical_manifest),
        );
        Ok(AdmittedArtifact { artifact, record })
    }

    fn store_content_addressed(
        &self,
        directory: &Path,
        digest: Digest,
        bytes: &[u8],
        corruption: impl FnOnce(Digest) -> ArtifactError,
    ) -> Result<(), ArtifactError> {
        let final_path = directory.join(digest.as_hex());
        if final_path.exists() {
            // Reuse rule: an existing entry is trusted only after its bytes
            // rehash to the requested digest. The filename is never evidence.
            let existing = read_bounded(&final_path, HARD_MAX_COMPONENT_BYTES)?;
            let actual = Digest::of_bytes(&existing);
            if actual != digest {
                return Err(corruption(actual));
            }
            return Ok(());
        }
        write_exclusive_atomic(directory, &digest.as_hex(), bytes)
    }

    fn store_manifest_payload(
        &self,
        manifest_digest: Digest,
        canonical_manifest: &[u8],
    ) -> Result<(), ArtifactError> {
        let final_path = self.manifests.join(manifest_digest.as_hex());
        if final_path.exists() {
            let existing = read_bounded(&final_path, HARD_MAX_MANIFEST_PAYLOAD_BYTES)?;
            if Digest::domain_separated(MANIFEST_DIGEST_DOMAIN, &existing) != manifest_digest {
                return Err(ArtifactError::StoredManifestCorrupted);
            }
            return Ok(());
        }
        write_exclusive_atomic(
            &self.manifests,
            &manifest_digest.as_hex(),
            canonical_manifest,
        )
    }
}

/// Exclusive-create temporary file, flush, atomic rename, directory flush.
/// A crash leaves an orphan `*.tmp-*` file that no load path ever reads.
fn write_exclusive_atomic(
    directory: &Path,
    final_name: &str,
    bytes: &[u8],
) -> Result<(), ArtifactError> {
    let temp_path = directory.join(format!("{final_name}.tmp-{}", Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options.open(&temp_path).map_err(store_io)?;
        file.write_all(bytes).map_err(store_io)?;
        file.sync_all().map_err(store_io)?;
        drop(file);
        std::fs::rename(&temp_path, directory.join(final_name)).map_err(store_io)?;
        sync_directory(directory)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }
    result
}

#[cfg(unix)]
fn sync_directory(directory: &Path) -> Result<(), ArtifactError> {
    std::fs::File::open(directory)
        .and_then(|handle| handle.sync_all())
        .map_err(store_io)
}

#[cfg(not(unix))]
fn sync_directory(_directory: &Path) -> Result<(), ArtifactError> {
    // Windows directory handles cannot be flushed through std; the rename
    // itself is atomic and the content remains digest-verified on load.
    Ok(())
}

/// Bounded read that refuses symlinks and non-regular files. The recomputed
/// digest after reading — not this metadata check — is the integrity
/// guarantee; the check exists to fail early and bound memory use.
fn read_bounded(path: &Path, max_bytes: usize) -> Result<Vec<u8>, ArtifactError> {
    let metadata = std::fs::symlink_metadata(path).map_err(store_io)?;
    if !metadata.file_type().is_file() {
        return Err(ArtifactError::StoredEntryNotRegularFile);
    }
    if metadata.len() > max_bytes as u64 {
        return Err(ArtifactError::AdmissionStoreIo(
            "stored entry exceeds its protocol size ceiling".into(),
        ));
    }
    let bytes = std::fs::read(path).map_err(store_io)?;
    if bytes.len() > max_bytes {
        return Err(ArtifactError::AdmissionStoreIo(
            "stored entry exceeds its protocol size ceiling".into(),
        ));
    }
    Ok(bytes)
}

fn store_io(error: std::io::Error) -> ArtifactError {
    ArtifactError::AdmissionStoreIo(format!("{:?}: {error}", error.kind()))
}

fn map_admission_identity_error(error: IdentityError) -> ArtifactError {
    match error {
        IdentityError::UnknownKeyId => ArtifactError::UnknownAdmissionKey,
        IdentityError::IssuerMismatch | IdentityError::InvalidIssuer => {
            ArtifactError::AdmissionIssuerMismatch
        }
        IdentityError::KeyRevoked => ArtifactError::AdmissionKeyRevoked,
        IdentityError::KeyNotYetValid => ArtifactError::AdmissionKeyNotYetValid,
        IdentityError::KeyExpired => ArtifactError::AdmissionKeyExpired,
        IdentityError::VerificationFailed => ArtifactError::InvalidAdmissionSignature,
        IdentityError::InvalidProtectedHeaders
        | IdentityError::UnprotectedHeadersForbidden
        | IdentityError::MissingPayload
        | IdentityError::NonCanonicalCose
        | IdentityError::Cose(_) => ArtifactError::InvalidAdmissionEnvelope,
        _ => ArtifactError::AdmissionVerificationFailed,
    }
}
