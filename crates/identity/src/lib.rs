use std::collections::HashMap;
use std::fmt;
use std::io::{Read, Write};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::ffi::{CStr, CString};
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;

use base64::{engine::general_purpose::STANDARD, Engine};
use coset::{iana, CoseSign1, CoseSign1Builder, Header, HeaderBuilder, TaggedCborSerializable};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const IDENTITY_FORMAT_VERSION: u16 = 1;
const MAX_IDENTITY_FILE_BYTES: u64 = 16 * 1024;
const KEY_ID_PREFIX: &[u8] = b"sovereign-founder-os\0key-id\0v1\0";

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("invalid key material: {0}")]
    InvalidKey(String),
    #[error("stored {0} does not match the secret key")]
    KeyMaterialMismatch(&'static str),
    #[error("unsupported identity format version {0}")]
    UnsupportedIdentityVersion(u16),
    #[error("signature verification failed")]
    VerificationFailed,
    #[error("unsafe identity path: {0}")]
    UnsafePath(String),
    #[error("identity file exceeds {MAX_IDENTITY_FILE_BYTES} bytes")]
    IdentityFileTooLarge,
    #[error("invalid issuer")]
    InvalidIssuer,
    #[error("invalid key validity interval")]
    InvalidValidity,
    #[error("duplicate trusted key id")]
    DuplicateKeyId,
    #[error("unknown trusted key id")]
    UnknownKeyId,
    #[error("trusted key issuer mismatch")]
    IssuerMismatch,
    #[error("trusted key is revoked")]
    KeyRevoked,
    #[error("trusted key is not yet valid")]
    KeyNotYetValid,
    #[error("trusted key has expired")]
    KeyExpired,
    #[error("invalid COSE protected headers")]
    InvalidProtectedHeaders,
    #[error("COSE unprotected headers are forbidden")]
    UnprotectedHeadersForbidden,
    #[error("COSE payload is missing")]
    MissingPayload,
    #[error("COSE encoding is not canonical")]
    NonCanonicalCose,
    #[error("COSE error: {0}")]
    Cose(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Stable device identity derived from an Ed25519 signing key.
///
/// The public key and display identifier are private cached derivations. They
/// are checked against the secret key whenever an identity is loaded.
pub struct DeviceIdentity {
    device_id: String,
    public_key_b64: String,
    signing_key: SigningKey,
}

impl fmt::Debug for DeviceIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceIdentity")
            .field("device_id", &self.device_id)
            .field("public_key_b64", &self.public_key_b64)
            .finish_non_exhaustive()
    }
}

impl DeviceIdentity {
    pub fn generate() -> Self {
        Self::from_signing_key(SigningKey::generate(&mut OsRng))
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub fn public_key_b64(&self) -> &str {
        &self.public_key_b64
    }

    /// Raw V1 signing is retained only while existing capability and audit
    /// callers migrate to role-typed COSE signatures.
    pub fn sign_legacy_v1(&self, message: &[u8]) -> String {
        let signature = self.signing_key.sign(message);
        STANDARD.encode(signature.to_bytes())
    }

    /// Verify a raw V1 signature with strict Ed25519 checks.
    pub fn verify_legacy_v1(
        public_key_b64: &str,
        message: &[u8],
        signature_b64: &str,
    ) -> Result<(), IdentityError> {
        let verifying_key = decode_verifying_key(public_key_b64)?;
        let signature = decode_legacy_signature(signature_b64)?;
        verifying_key
            .verify_strict(message, &signature)
            .map_err(|_| IdentityError::VerificationFailed)
    }

    pub fn save(&self, path: &Path) -> Result<(), IdentityError> {
        let stored = StoredIdentity {
            format_version: IDENTITY_FORMAT_VERSION,
            device_id: self.device_id.clone(),
            public_key_b64: self.public_key_b64.clone(),
            secret_key_b64: STANDARD.encode(self.signing_key.to_bytes()),
        };
        let json = serde_json::to_vec_pretty(&stored)?;
        atomic_write_private(path, &json)
    }

    pub fn load(path: &Path) -> Result<Self, IdentityError> {
        let bytes = read_regular_file(path)?;
        let stored: StoredIdentity = serde_json::from_slice(&bytes)?;
        if stored.format_version != IDENTITY_FORMAT_VERSION {
            return Err(IdentityError::UnsupportedIdentityVersion(
                stored.format_version,
            ));
        }

        let secret_bytes = STANDARD
            .decode(&stored.secret_key_b64)
            .map_err(|error| IdentityError::InvalidKey(error.to_string()))?;
        let secret_array: [u8; 32] = secret_bytes
            .try_into()
            .map_err(|_| IdentityError::InvalidKey("expected 32-byte secret key".into()))?;
        if STANDARD.encode(secret_array) != stored.secret_key_b64 {
            return Err(IdentityError::InvalidKey(
                "secret key must use canonical padded Base64".into(),
            ));
        }

        let identity = Self::from_signing_key(SigningKey::from_bytes(&secret_array));
        if stored.public_key_b64 != identity.public_key_b64 {
            return Err(IdentityError::KeyMaterialMismatch("public key"));
        }
        if stored.device_id != identity.device_id {
            return Err(IdentityError::KeyMaterialMismatch("device id"));
        }
        Ok(identity)
    }

    pub fn into_audit_signer(
        self,
        issuer: impl Into<String>,
    ) -> Result<TypedSigner<AuditRole>, IdentityError> {
        TypedSigner::from_signing_key(self.signing_key, issuer.into())
    }

    fn from_signing_key(signing_key: SigningKey) -> Self {
        let public_key_bytes = signing_key.verifying_key().to_bytes();
        Self {
            device_id: device_fingerprint(&public_key_bytes),
            public_key_b64: STANDARD.encode(public_key_bytes),
            signing_key,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredIdentity {
    #[serde(default = "identity_format_version")]
    format_version: u16,
    device_id: String,
    public_key_b64: String,
    secret_key_b64: String,
}

fn identity_format_version() -> u16 {
    IDENTITY_FORMAT_VERSION
}

fn device_fingerprint(public_key: &[u8; 32]) -> String {
    let digest = Sha256::digest(public_key);
    format!("dev_{}", hex::encode(&digest[..12]))
}

fn decode_verifying_key(public_key_b64: &str) -> Result<VerifyingKey, IdentityError> {
    let public_bytes = STANDARD
        .decode(public_key_b64)
        .map_err(|error| IdentityError::InvalidKey(error.to_string()))?;
    let key_bytes: [u8; 32] = public_bytes
        .try_into()
        .map_err(|_| IdentityError::InvalidKey("expected 32-byte public key".into()))?;
    if STANDARD.encode(key_bytes) != public_key_b64 {
        return Err(IdentityError::InvalidKey(
            "public key must use canonical padded Base64".into(),
        ));
    }
    VerifyingKey::from_bytes(&key_bytes)
        .map_err(|error| IdentityError::InvalidKey(error.to_string()))
}

fn decode_legacy_signature(signature_b64: &str) -> Result<Signature, IdentityError> {
    let signature_bytes = STANDARD
        .decode(signature_b64)
        .map_err(|error| IdentityError::InvalidKey(error.to_string()))?;
    let signature_array: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| IdentityError::InvalidKey("expected 64-byte signature".into()))?;
    if STANDARD.encode(signature_array) != signature_b64 {
        return Err(IdentityError::InvalidKey(
            "signature must use canonical padded Base64".into(),
        ));
    }
    Ok(Signature::from_bytes(&signature_array))
}

#[cfg(not(unix))]
fn validate_regular_destination(path: &Path) -> Result<(), IdentityError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(IdentityError::UnsafePath(
            format!("{} is a symbolic link", path.display()),
        )),
        Ok(metadata) if !metadata.file_type().is_file() => Err(IdentityError::UnsafePath(format!(
            "{} is not a regular file",
            path.display()
        ))),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(not(unix))]
fn checked_parent(path: &Path) -> Result<&Path, IdentityError> {
    let parent = path
        .parent()
        .filter(|candidate| !candidate.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let metadata = std::fs::symlink_metadata(parent)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(IdentityError::UnsafePath(format!(
            "{} is not a direct regular directory",
            parent.display()
        )));
    }
    Ok(parent)
}

#[cfg(unix)]
struct OpenedParent {
    fd: OwnedFd,
    path: PathBuf,
}

#[cfg(unix)]
fn open_parent_and_name(path: &Path) -> Result<(OpenedParent, CString), IdentityError> {
    let parent_path = path
        .parent()
        .filter(|candidate| !candidate.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| IdentityError::UnsafePath(format!("{} has no file name", path.display())))?;
    let file_name = CString::new(file_name.as_bytes()).map_err(|_| {
        IdentityError::UnsafePath(format!("{} contains a NUL byte", path.display()))
    })?;
    let parent_c = CString::new(parent_path.as_os_str().as_bytes()).map_err(|_| {
        IdentityError::UnsafePath(format!("{} contains a NUL byte", parent_path.display()))
    })?;

    let raw_fd = unsafe {
        libc::open(
            parent_c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw_fd < 0 {
        return Err(path_syscall_error(
            std::io::Error::last_os_error(),
            parent_path,
        ));
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    let parent = OpenedParent {
        fd,
        path: parent_path.to_path_buf(),
    };
    let metadata = stat_fd(parent.fd.as_raw_fd())?;
    validate_parent_stat(&metadata, &parent.path)?;
    Ok((parent, file_name))
}

#[cfg(unix)]
fn stat_fd(fd: libc::c_int) -> Result<libc::stat, IdentityError> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd, metadata.as_mut_ptr()) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { metadata.assume_init() })
}

#[cfg(unix)]
fn stat_at(parent: &OpenedParent, name: &CStr) -> Result<Option<libc::stat>, IdentityError> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    let result = unsafe {
        libc::fstatat(
            parent.fd.as_raw_fd(),
            name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        return Ok(Some(unsafe { metadata.assume_init() }));
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ENOENT) {
        return Ok(None);
    }
    Err(path_syscall_error(error, &parent.path))
}

#[cfg(unix)]
fn validate_parent_stat(metadata: &libc::stat, parent: &Path) -> Result<(), IdentityError> {
    if metadata.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Err(IdentityError::UnsafePath(format!(
            "{} is not a directory",
            parent.display()
        )));
    }
    if metadata.st_uid != unsafe { libc::geteuid() } {
        return Err(IdentityError::UnsafePath(format!(
            "{} is not owned by the effective user",
            parent.display()
        )));
    }
    if metadata.st_mode & 0o022 != 0 {
        return Err(IdentityError::UnsafePath(format!(
            "{} is group- or other-writable",
            parent.display()
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_identity_stat(metadata: &libc::stat, path: &Path) -> Result<(), IdentityError> {
    if metadata.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(IdentityError::UnsafePath(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    if metadata.st_uid != unsafe { libc::geteuid() } {
        return Err(IdentityError::UnsafePath(format!(
            "{} is not owned by the effective user",
            path.display()
        )));
    }
    if metadata.st_mode & 0o077 != 0 {
        return Err(IdentityError::UnsafePath(format!(
            "{} grants group or other permissions",
            path.display()
        )));
    }
    if metadata.st_nlink != 1 {
        return Err(IdentityError::UnsafePath(format!(
            "{} must have exactly one hard link",
            path.display()
        )));
    }
    if metadata.st_size < 0 || metadata.st_size as u64 > MAX_IDENTITY_FILE_BYTES {
        return Err(IdentityError::IdentityFileTooLarge);
    }
    Ok(())
}

#[cfg(unix)]
fn validate_existing_identity(
    parent: &OpenedParent,
    name: &CStr,
    path: &Path,
) -> Result<(), IdentityError> {
    if let Some(metadata) = stat_at(parent, name)? {
        validate_identity_stat(&metadata, path)?;
    }
    Ok(())
}

#[cfg(unix)]
fn create_temporary_file(parent: &OpenedParent) -> Result<(CString, std::fs::File), IdentityError> {
    for _ in 0..8 {
        let mut nonce = [0_u8; 16];
        OsRng.fill_bytes(&mut nonce);
        let name = CString::new(format!(".sovereign-identity.{}.tmp", hex::encode(nonce)))
            .expect("temporary name contains only ASCII");
        let raw_fd = unsafe {
            libc::openat(
                parent.fd.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if raw_fd >= 0 {
            let file = unsafe { std::fs::File::from_raw_fd(raw_fd) };
            if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } < 0 {
                let error = std::io::Error::last_os_error();
                drop(file);
                let _ = unlink_at(parent, &name);
                return Err(error.into());
            }
            return Ok((name, file));
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(path_syscall_error(error, &parent.path));
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not allocate a unique identity temporary file",
    )
    .into())
}

#[cfg(unix)]
fn unlink_at(parent: &OpenedParent, name: &CStr) -> Result<(), IdentityError> {
    if unsafe { libc::unlinkat(parent.fd.as_raw_fd(), name.as_ptr(), 0) } < 0 {
        return Err(path_syscall_error(
            std::io::Error::last_os_error(),
            &parent.path,
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn rename_at(
    parent: &OpenedParent,
    source: &CStr,
    destination: &CStr,
) -> Result<(), IdentityError> {
    if unsafe {
        libc::renameat(
            parent.fd.as_raw_fd(),
            source.as_ptr(),
            parent.fd.as_raw_fd(),
            destination.as_ptr(),
        )
    } < 0
    {
        return Err(path_syscall_error(
            std::io::Error::last_os_error(),
            &parent.path,
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn sync_parent(parent: &OpenedParent) -> Result<(), IdentityError> {
    if unsafe { libc::fsync(parent.fd.as_raw_fd()) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(unix)]
fn path_syscall_error(error: std::io::Error, path: &Path) -> IdentityError {
    if matches!(error.raw_os_error(), Some(libc::ELOOP | libc::ENOTDIR)) {
        IdentityError::UnsafePath(format!(
            "{} contains a symbolic link or non-directory component",
            path.display()
        ))
    } else {
        IdentityError::Io(error)
    }
}

#[cfg(unix)]
fn atomic_write_private(path: &Path, bytes: &[u8]) -> Result<(), IdentityError> {
    if bytes.len() as u64 > MAX_IDENTITY_FILE_BYTES {
        return Err(IdentityError::IdentityFileTooLarge);
    }
    let (parent, name) = open_parent_and_name(path)?;
    atomic_write_private_at(&parent, &name, path, bytes)
}

#[cfg(unix)]
fn atomic_write_private_at(
    parent: &OpenedParent,
    name: &CStr,
    path: &Path,
    bytes: &[u8],
) -> Result<(), IdentityError> {
    if bytes.len() as u64 > MAX_IDENTITY_FILE_BYTES {
        return Err(IdentityError::IdentityFileTooLarge);
    }
    validate_existing_identity(parent, name, path)?;
    let (temporary_name, mut file) = create_temporary_file(parent)?;
    let mut renamed = false;
    let result = (|| -> Result<(), IdentityError> {
        file.write_all(bytes)?;
        file.sync_all()?;
        let temporary_stat = stat_fd(file.as_raw_fd())?;
        validate_identity_stat(&temporary_stat, path)?;
        if temporary_stat.st_mode & 0o777 != 0o600 {
            return Err(IdentityError::UnsafePath(
                "temporary identity file does not have mode 0600".into(),
            ));
        }
        drop(file);

        // The parent directory is a stable descriptor owned by the effective
        // user and is not writable by other users. Re-check the destination
        // entry immediately before replacing it within that same directory.
        validate_existing_identity(parent, name, path)?;
        rename_at(parent, &temporary_name, name)?;
        renamed = true;
        let installed = stat_at(parent, name)?.ok_or_else(|| {
            IdentityError::UnsafePath(format!("{} disappeared after rename", path.display()))
        })?;
        validate_identity_stat(&installed, path)?;
        if installed.st_mode & 0o777 != 0o600 {
            return Err(IdentityError::UnsafePath(format!(
                "{} was not installed with mode 0600",
                path.display()
            )));
        }
        sync_parent(parent)
    })();
    if result.is_err() && !renamed {
        let _ = unlink_at(parent, &temporary_name);
    }
    result
}

#[cfg(not(unix))]
fn atomic_write_private(path: &Path, bytes: &[u8]) -> Result<(), IdentityError> {
    // Non-Unix platforms do not provide the dirfd and ownership guarantees of
    // the Unix implementation. Callers must protect the parent directory.
    validate_regular_destination(path)?;
    let _ = checked_parent(path)?;
    std::fs::write(path, bytes)?;
    Ok(())
}

#[cfg(unix)]
fn read_regular_file(path: &Path) -> Result<Vec<u8>, IdentityError> {
    let (parent, name) = open_parent_and_name(path)?;
    let pre_open = stat_at(&parent, &name)?.ok_or_else(|| {
        IdentityError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("{} does not exist", path.display()),
        ))
    })?;
    validate_identity_stat(&pre_open, path)?;

    let raw_fd = unsafe {
        libc::openat(
            parent.fd.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        )
    };
    if raw_fd < 0 {
        return Err(path_syscall_error(std::io::Error::last_os_error(), path));
    }
    let mut file = unsafe { std::fs::File::from_raw_fd(raw_fd) };
    let metadata = stat_fd(file.as_raw_fd())?;
    validate_identity_stat(&metadata, path)?;
    let mut bytes = Vec::with_capacity(metadata.st_size as usize);
    Read::by_ref(&mut file)
        .take(MAX_IDENTITY_FILE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_IDENTITY_FILE_BYTES {
        return Err(IdentityError::IdentityFileTooLarge);
    }
    Ok(bytes)
}

#[cfg(not(unix))]
fn read_regular_file(path: &Path) -> Result<Vec<u8>, IdentityError> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(IdentityError::UnsafePath(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    if metadata.len() > MAX_IDENTITY_FILE_BYTES {
        return Err(IdentityError::IdentityFileTooLarge);
    }
    Ok(std::fs::read(path)?)
}

mod role_sealed {
    pub trait Sealed {}
}

/// A closed set of signing roles. External crates can use these roles but
/// cannot introduce a role that accidentally reuses a security domain.
pub trait SigningRole: role_sealed::Sealed + Send + Sync + 'static {
    const NAME: &'static str;
    const CONTENT_TYPE: &'static str;
    const EXTERNAL_AAD: &'static [u8];
}

#[derive(Debug)]
pub enum PublisherRole {}

#[derive(Debug)]
pub enum AuthorityRole {}

#[derive(Debug)]
pub enum AuditRole {}

#[derive(Debug)]
pub enum AdmissionRole {}

#[derive(Debug)]
pub enum ApprovalRole {}

impl role_sealed::Sealed for PublisherRole {}
impl role_sealed::Sealed for AuthorityRole {}
impl role_sealed::Sealed for AuditRole {}
impl role_sealed::Sealed for AdmissionRole {}
impl role_sealed::Sealed for ApprovalRole {}

impl SigningRole for PublisherRole {
    const NAME: &'static str = "publisher";
    const CONTENT_TYPE: &'static str = "application/sovereign.plugin-manifest+json;v=1";
    const EXTERNAL_AAD: &'static [u8] = b"sovereign:plugin-manifest:v1";
}

impl SigningRole for AuthorityRole {
    const NAME: &'static str = "authority";
    const CONTENT_TYPE: &'static str = "application/sovereign.capability+json;v=2";
    const EXTERNAL_AAD: &'static [u8] = b"sovereign:capability:v2";
}

impl SigningRole for AuditRole {
    const NAME: &'static str = "audit";
    const CONTENT_TYPE: &'static str = "application/sovereign.audit-event+json;v=1";
    const EXTERNAL_AAD: &'static [u8] = b"sovereign:audit-event:v1";
}

impl SigningRole for AdmissionRole {
    const NAME: &'static str = "artifact-admission";
    const CONTENT_TYPE: &'static str = "application/sovereign.artifact-admission+json;v=1";
    const EXTERNAL_AAD: &'static [u8] = b"sovereign:artifact-admission:v1";
}

impl SigningRole for ApprovalRole {
    const NAME: &'static str = "approval";
    const CONTENT_TYPE: &'static str = "application/sovereign.approval+json;v=1";
    const EXTERNAL_AAD: &'static [u8] = b"sovereign:approval:v1";
}

/// Ed25519 signer whose role is enforced by the type system and COSE domain.
pub struct TypedSigner<R: SigningRole> {
    issuer: String,
    signing_key: SigningKey,
    key_id: [u8; 32],
    role: PhantomData<R>,
}

impl<R: SigningRole> fmt::Debug for TypedSigner<R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TypedSigner")
            .field("role", &R::NAME)
            .field("issuer", &self.issuer)
            .field("key_id", &hex::encode(self.key_id))
            .finish_non_exhaustive()
    }
}

impl<R: SigningRole> TypedSigner<R> {
    pub fn generate(issuer: impl Into<String>) -> Result<Self, IdentityError> {
        Self::from_signing_key(SigningKey::generate(&mut OsRng), issuer.into())
    }

    pub fn from_secret_bytes(
        issuer: impl Into<String>,
        secret_key: [u8; 32],
    ) -> Result<Self, IdentityError> {
        Self::from_signing_key(SigningKey::from_bytes(&secret_key), issuer.into())
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn key_id(&self) -> &[u8; 32] {
        &self.key_id
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    pub fn public_key_b64(&self) -> String {
        STANDARD.encode(self.public_key_bytes())
    }

    /// Sign caller-supplied canonical application payload bytes as a tagged
    /// COSE_Sign1 object. COSE canonicality does not canonicalize the payload.
    pub fn sign_cose(&self, canonical_payload: &[u8]) -> Result<Vec<u8>, IdentityError> {
        let protected = expected_protected_header::<R>(&self.key_id);
        let sign1 = CoseSign1Builder::new()
            .protected(protected)
            .payload(canonical_payload.to_vec())
            .create_signature(R::EXTERNAL_AAD, |to_be_signed| {
                self.signing_key.sign(to_be_signed).to_bytes().to_vec()
            })
            .build();
        sign1
            .to_tagged_vec()
            .map_err(|error| IdentityError::Cose(error.to_string()))
    }

    fn from_signing_key(signing_key: SigningKey, issuer: String) -> Result<Self, IdentityError> {
        validate_issuer(&issuer)?;
        let public_key = signing_key.verifying_key().to_bytes();
        Ok(Self {
            issuer,
            signing_key,
            key_id: role_key_id::<R>(&public_key),
            role: PhantomData,
        })
    }
}

fn validate_issuer(issuer: &str) -> Result<(), IdentityError> {
    if issuer.is_empty() || issuer.trim() != issuer || issuer.len() > 256 {
        return Err(IdentityError::InvalidIssuer);
    }
    Ok(())
}

fn role_key_id<R: SigningRole>(public_key: &[u8; 32]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(KEY_ID_PREFIX);
    digest.update((R::NAME.len() as u16).to_be_bytes());
    digest.update(R::NAME.as_bytes());
    digest.update(b"\0ed25519\0");
    digest.update(public_key);
    digest.finalize().into()
}

fn expected_protected_header<R: SigningRole>(key_id: &[u8; 32]) -> Header {
    HeaderBuilder::new()
        .algorithm(iana::Algorithm::EdDSA)
        .key_id(key_id.to_vec())
        .content_type(R::CONTENT_TYPE.to_owned())
        .build()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustStatus {
    Active,
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyValidity {
    not_before_unix: i64,
    not_after_unix: i64,
}

impl KeyValidity {
    pub fn new(not_before_unix: i64, not_after_unix: i64) -> Result<Self, IdentityError> {
        if not_after_unix <= not_before_unix {
            return Err(IdentityError::InvalidValidity);
        }
        Ok(Self {
            not_before_unix,
            not_after_unix,
        })
    }

    pub fn not_before_unix(&self) -> i64 {
        self.not_before_unix
    }

    pub fn not_after_unix(&self) -> i64 {
        self.not_after_unix
    }
}

#[derive(Debug)]
struct TrustedKey {
    issuer: String,
    status: TrustStatus,
    validity: KeyValidity,
    verifying_key: VerifyingKey,
}

/// Role-specific trust store. COSE `kid` selects a locally registered key;
/// no public key supplied by the signed object is ever trusted.
#[derive(Debug)]
pub struct RoleTrustStore<R: SigningRole> {
    keys: HashMap<[u8; 32], TrustedKey>,
    role: PhantomData<R>,
}

impl<R: SigningRole> Default for RoleTrustStore<R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R: SigningRole> RoleTrustStore<R> {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            role: PhantomData,
        }
    }

    pub fn add_key(
        &mut self,
        issuer: impl Into<String>,
        public_key: [u8; 32],
        validity: KeyValidity,
    ) -> Result<[u8; 32], IdentityError> {
        let issuer = issuer.into();
        validate_issuer(&issuer)?;
        let verifying_key = VerifyingKey::from_bytes(&public_key)
            .map_err(|error| IdentityError::InvalidKey(error.to_string()))?;
        let key_id = role_key_id::<R>(&public_key);
        if self.keys.contains_key(&key_id) {
            return Err(IdentityError::DuplicateKeyId);
        }
        self.keys.insert(
            key_id,
            TrustedKey {
                issuer,
                status: TrustStatus::Active,
                validity,
                verifying_key,
            },
        );
        Ok(key_id)
    }

    pub fn trust_signer(
        &mut self,
        signer: &TypedSigner<R>,
        validity: KeyValidity,
    ) -> Result<[u8; 32], IdentityError> {
        self.add_key(signer.issuer(), signer.public_key_bytes(), validity)
    }

    pub fn set_status(
        &mut self,
        key_id: &[u8; 32],
        status: TrustStatus,
    ) -> Result<(), IdentityError> {
        let trusted = self
            .keys
            .get_mut(key_id)
            .ok_or(IdentityError::UnknownKeyId)?;
        trusted.status = status;
        Ok(())
    }

    pub fn revoke(&mut self, key_id: &[u8; 32]) -> Result<(), IdentityError> {
        self.set_status(key_id, TrustStatus::Revoked)
    }

    pub fn verify(
        &self,
        encoded: &[u8],
        expected_issuer: &str,
        now_unix: i64,
    ) -> Result<VerifiedCosePayload, IdentityError> {
        validate_issuer(expected_issuer)?;
        let sign1 = CoseSign1::from_tagged_slice(encoded)
            .map_err(|error| IdentityError::Cose(error.to_string()))?;
        ensure_canonical_cose(encoded, &sign1)?;
        if !sign1.unprotected.is_empty() {
            return Err(IdentityError::UnprotectedHeadersForbidden);
        }

        let key_id: [u8; 32] = sign1
            .protected
            .header
            .key_id
            .as_slice()
            .try_into()
            .map_err(|_| IdentityError::InvalidProtectedHeaders)?;
        let trusted = self.keys.get(&key_id).ok_or(IdentityError::UnknownKeyId)?;
        if trusted.issuer != expected_issuer {
            return Err(IdentityError::IssuerMismatch);
        }
        if trusted.status == TrustStatus::Revoked {
            return Err(IdentityError::KeyRevoked);
        }
        if now_unix < trusted.validity.not_before_unix {
            return Err(IdentityError::KeyNotYetValid);
        }
        if now_unix >= trusted.validity.not_after_unix {
            return Err(IdentityError::KeyExpired);
        }
        if sign1.protected.header != expected_protected_header::<R>(&key_id) {
            return Err(IdentityError::InvalidProtectedHeaders);
        }

        sign1.verify_signature(R::EXTERNAL_AAD, |signature_bytes, to_be_signed| {
            let signature_array: [u8; 64] = signature_bytes
                .try_into()
                .map_err(|_| IdentityError::VerificationFailed)?;
            let signature = Signature::from_bytes(&signature_array);
            trusted
                .verifying_key
                .verify_strict(to_be_signed, &signature)
                .map_err(|_| IdentityError::VerificationFailed)
        })?;

        let payload = sign1.payload.ok_or(IdentityError::MissingPayload)?;
        Ok(VerifiedCosePayload {
            issuer: trusted.issuer.clone(),
            key_id,
            payload,
        })
    }
}

fn ensure_canonical_cose(encoded: &[u8], sign1: &CoseSign1) -> Result<(), IdentityError> {
    let mut canonical = sign1.clone();
    canonical.protected.original_data = None;
    let canonical_bytes = canonical
        .to_tagged_vec()
        .map_err(|error| IdentityError::Cose(error.to_string()))?;
    if canonical_bytes != encoded {
        return Err(IdentityError::NonCanonicalCose);
    }
    Ok(())
}

#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedCosePayload {
    issuer: String,
    key_id: [u8; 32],
    payload: Vec<u8>,
}

impl fmt::Debug for VerifiedCosePayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedCosePayload")
            .field("issuer", &self.issuer)
            .field("key_id", &hex::encode(self.key_id))
            .field("payload_len", &self.payload.len())
            .finish_non_exhaustive()
    }
}

impl VerifiedCosePayload {
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn key_id(&self) -> &[u8; 32] {
        &self.key_id
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_directory(label: &str) -> PathBuf {
        let mut nonce = [0_u8; 8];
        OsRng.fill_bytes(&mut nonce);
        let path = std::env::temp_dir().join(format!(
            "sovereign-identity-{label}-{}-{}",
            std::process::id(),
            hex::encode(nonce)
        ));
        std::fs::create_dir_all(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        path
    }

    fn validity() -> KeyValidity {
        KeyValidity::new(100, 200).unwrap()
    }

    fn sign_custom_cose<R: SigningRole>(
        signer: &TypedSigner<R>,
        protected: Header,
        unprotected: Header,
        payload: &[u8],
        external_aad: &[u8],
    ) -> Vec<u8> {
        CoseSign1Builder::new()
            .protected(protected)
            .unprotected(unprotected)
            .payload(payload.to_vec())
            .create_signature(external_aad, |to_be_signed| {
                signer.signing_key.sign(to_be_signed).to_bytes().to_vec()
            })
            .build()
            .to_tagged_vec()
            .unwrap()
    }

    #[test]
    fn legacy_v1_sign_and_strict_verify_roundtrip() {
        let identity = DeviceIdentity::generate();
        let message = b"sovereign audit event";
        let signature = identity.sign_legacy_v1(message);
        DeviceIdentity::verify_legacy_v1(identity.public_key_b64(), message, &signature).unwrap();
    }

    #[test]
    fn persist_identity_and_reject_key_mismatch() {
        let directory = test_directory("mismatch");
        let path = directory.join("device.json");
        let identity = DeviceIdentity::generate();
        identity.save(&path).unwrap();
        let loaded = DeviceIdentity::load(&path).unwrap();
        assert_eq!(identity.device_id(), loaded.device_id());
        assert_eq!(identity.public_key_b64(), loaded.public_key_b64());

        let mut stored: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        stored["public_key_b64"] = serde_json::Value::String(
            STANDARD.encode(
                DeviceIdentity::generate()
                    .signing_key
                    .verifying_key()
                    .to_bytes(),
            ),
        );
        std::fs::write(&path, serde_json::to_vec_pretty(&stored).unwrap()).unwrap();
        assert!(matches!(
            DeviceIdentity::load(&path),
            Err(IdentityError::KeyMaterialMismatch("public key"))
        ));

        identity.save(&path).unwrap();
        let mut stored: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        stored["device_id"] = serde_json::Value::String("dev_attacker".into());
        std::fs::write(&path, serde_json::to_vec_pretty(&stored).unwrap()).unwrap();
        assert!(matches!(
            DeviceIdentity::load(&path),
            Err(IdentityError::KeyMaterialMismatch("device id"))
        ));
        std::fs::remove_dir_all(directory).ok();
    }

    #[cfg(unix)]
    #[test]
    fn save_and_load_enforce_private_owned_single_link_files() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let directory = test_directory("permissions");
        let path = directory.join("device.json");
        let identity = DeviceIdentity::generate();
        identity.save(&path).unwrap();
        let metadata = std::fs::metadata(&path).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
        assert_eq!(metadata.nlink(), 1);

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            DeviceIdentity::load(&path),
            Err(IdentityError::UnsafePath(_))
        ));
        assert!(matches!(
            identity.save(&path),
            Err(IdentityError::UnsafePath(_))
        ));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let hard_link = directory.join("device-hard-link.json");
        std::fs::hard_link(&path, &hard_link).unwrap();
        assert!(matches!(
            DeviceIdentity::load(&path),
            Err(IdentityError::UnsafePath(_))
        ));
        assert!(matches!(
            identity.save(&path),
            Err(IdentityError::UnsafePath(_))
        ));
        std::fs::remove_file(hard_link).unwrap();
        DeviceIdentity::load(&path).unwrap();

        std::fs::remove_dir_all(directory).ok();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_nonregular_and_unsafe_parent_destinations() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let directory = test_directory("unsafe-paths");
        let identity = DeviceIdentity::generate();

        let target = directory.join("target.json");
        std::fs::write(&target, b"target").unwrap();
        let link = directory.join("link.json");
        symlink(&target, &link).unwrap();
        assert!(matches!(
            identity.save(&link),
            Err(IdentityError::UnsafePath(_))
        ));
        assert!(matches!(
            DeviceIdentity::load(&link),
            Err(IdentityError::Io(_)) | Err(IdentityError::UnsafePath(_))
        ));

        let non_regular = directory.join("directory.json");
        std::fs::create_dir(&non_regular).unwrap();
        assert!(matches!(
            identity.save(&non_regular),
            Err(IdentityError::UnsafePath(_))
        ));

        let writable_parent = directory.join("writable-parent");
        std::fs::create_dir(&writable_parent).unwrap();
        std::fs::set_permissions(&writable_parent, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(matches!(
            identity.save(&writable_parent.join("device.json")),
            Err(IdentityError::UnsafePath(_))
        ));
        std::fs::set_permissions(&writable_parent, std::fs::Permissions::from_mode(0o700)).unwrap();

        let real_parent = directory.join("real-parent");
        std::fs::create_dir(&real_parent).unwrap();
        std::fs::set_permissions(&real_parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        let linked_parent = directory.join("linked-parent");
        symlink(&real_parent, &linked_parent).unwrap();
        assert!(matches!(
            identity.save(&linked_parent.join("device.json")),
            Err(IdentityError::UnsafePath(_))
        ));
        std::fs::remove_dir_all(directory).ok();
    }

    #[cfg(unix)]
    #[test]
    fn opened_parent_descriptor_survives_path_replacement() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let directory = test_directory("parent-replacement");
        let original_parent = directory.join("original");
        std::fs::create_dir(&original_parent).unwrap();
        std::fs::set_permissions(&original_parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = original_parent.join("device.bin");
        let (opened_parent, name) = open_parent_and_name(&path).unwrap();

        let moved_parent = directory.join("moved");
        std::fs::rename(&original_parent, &moved_parent).unwrap();
        let replacement_parent = directory.join("replacement");
        std::fs::create_dir(&replacement_parent).unwrap();
        std::fs::set_permissions(&replacement_parent, std::fs::Permissions::from_mode(0o700))
            .unwrap();
        symlink(&replacement_parent, &original_parent).unwrap();

        atomic_write_private_at(&opened_parent, &name, &path, b"stable-parent").unwrap();
        assert_eq!(
            std::fs::read(moved_parent.join("device.bin")).unwrap(),
            b"stable-parent"
        );
        assert!(!replacement_parent.join("device.bin").exists());
        drop(opened_parent);
        std::fs::remove_dir_all(directory).ok();
    }

    #[test]
    fn typed_cose_roundtrip_has_expected_protected_headers() {
        let signer = TypedSigner::<AuthorityRole>::generate("authority.example").unwrap();
        let encoded = signer.sign_cose(br#"{"operation":"draft"}"#).unwrap();
        let parsed = CoseSign1::from_tagged_slice(&encoded).unwrap();
        assert_eq!(
            parsed.protected.header,
            expected_protected_header::<AuthorityRole>(signer.key_id())
        );
        assert!(parsed.unprotected.is_empty());

        let mut store = RoleTrustStore::<AuthorityRole>::new();
        store.trust_signer(&signer, validity()).unwrap();
        let verified = store.verify(&encoded, "authority.example", 150).unwrap();
        assert_eq!(verified.payload(), br#"{"operation":"draft"}"#);
        assert_eq!(verified.issuer(), "authority.example");
        assert_eq!(verified.key_id(), signer.key_id());
    }

    #[test]
    fn role_key_ids_prevent_cross_role_use() {
        let secret = [7_u8; 32];
        let authority =
            TypedSigner::<AuthorityRole>::from_secret_bytes("same-issuer", secret).unwrap();
        let audit = TypedSigner::<AuditRole>::from_secret_bytes("same-issuer", secret).unwrap();
        assert_ne!(authority.key_id(), audit.key_id());

        let encoded = authority.sign_cose(b"same payload").unwrap();
        let mut audit_store = RoleTrustStore::<AuditRole>::new();
        audit_store.trust_signer(&audit, validity()).unwrap();
        assert!(matches!(
            audit_store.verify(&encoded, "same-issuer", 150),
            Err(IdentityError::UnknownKeyId)
        ));
    }

    #[test]
    fn external_aad_is_verified_after_header_and_key_match() {
        let signer = TypedSigner::<AuthorityRole>::generate("authority.example").unwrap();
        let encoded = sign_custom_cose(
            &signer,
            expected_protected_header::<AuthorityRole>(signer.key_id()),
            HeaderBuilder::new().build(),
            b"capability",
            b"wrong-external-aad",
        );
        let mut store = RoleTrustStore::<AuthorityRole>::new();
        store.trust_signer(&signer, validity()).unwrap();

        assert!(matches!(
            store.verify(&encoded, "authority.example", 150),
            Err(IdentityError::VerificationFailed)
        ));
    }

    #[test]
    fn rejects_protected_header_and_unprotected_downgrades() {
        let signer = TypedSigner::<AuthorityRole>::generate("authority.example").unwrap();
        let mut store = RoleTrustStore::<AuthorityRole>::new();
        store.trust_signer(&signer, validity()).unwrap();
        let empty = || HeaderBuilder::new().build();

        let wrong_algorithm = HeaderBuilder::new()
            .algorithm(iana::Algorithm::ES256)
            .key_id(signer.key_id().to_vec())
            .content_type(AuthorityRole::CONTENT_TYPE.to_owned())
            .build();
        let encoded = sign_custom_cose(
            &signer,
            wrong_algorithm,
            empty(),
            b"capability",
            AuthorityRole::EXTERNAL_AAD,
        );
        assert!(matches!(
            store.verify(&encoded, "authority.example", 150),
            Err(IdentityError::InvalidProtectedHeaders)
        ));

        let wrong_content_type = HeaderBuilder::new()
            .algorithm(iana::Algorithm::EdDSA)
            .key_id(signer.key_id().to_vec())
            .content_type("application/sovereign.audit-event+json;v=1".to_owned())
            .build();
        let encoded = sign_custom_cose(
            &signer,
            wrong_content_type,
            empty(),
            b"capability",
            AuthorityRole::EXTERNAL_AAD,
        );
        assert!(matches!(
            store.verify(&encoded, "authority.example", 150),
            Err(IdentityError::InvalidProtectedHeaders)
        ));

        let encoded = sign_custom_cose(
            &signer,
            expected_protected_header::<AuthorityRole>(signer.key_id()),
            HeaderBuilder::new()
                .key_id(signer.key_id().to_vec())
                .build(),
            b"capability",
            AuthorityRole::EXTERNAL_AAD,
        );
        assert!(matches!(
            store.verify(&encoded, "authority.example", 150),
            Err(IdentityError::UnprotectedHeadersForbidden)
        ));
    }

    #[test]
    fn rejects_noncanonical_cose_and_payload_tampering() {
        let signer = TypedSigner::<PublisherRole>::generate("publisher.example").unwrap();
        let encoded = signer.sign_cose(b"manifest-v1").unwrap();
        let mut store = RoleTrustStore::<PublisherRole>::new();
        store.trust_signer(&signer, validity()).unwrap();

        assert_eq!(encoded[0], 0xd2, "expected canonical CBOR tag 18");
        let mut noncanonical = vec![0xd8, 0x12];
        noncanonical.extend_from_slice(&encoded[1..]);
        assert!(matches!(
            store.verify(&noncanonical, "publisher.example", 150),
            Err(IdentityError::NonCanonicalCose)
        ));

        let mut parsed = CoseSign1::from_tagged_slice(&encoded).unwrap();
        parsed.payload = Some(b"substituted-manifest".to_vec());
        let tampered = parsed.to_tagged_vec().unwrap();
        assert!(matches!(
            store.verify(&tampered, "publisher.example", 150),
            Err(IdentityError::VerificationFailed)
        ));
    }

    #[test]
    fn trust_store_enforces_issuer_revocation_and_validity() {
        let signer = TypedSigner::<AuditRole>::generate("device.example").unwrap();
        let encoded = signer.sign_cose(b"audit-event").unwrap();
        let mut store = RoleTrustStore::<AuditRole>::new();
        let key_id = store.trust_signer(&signer, validity()).unwrap();

        assert!(matches!(
            store.verify(&encoded, "other.example", 150),
            Err(IdentityError::IssuerMismatch)
        ));
        assert!(matches!(
            store.verify(&encoded, "device.example", 99),
            Err(IdentityError::KeyNotYetValid)
        ));
        assert!(matches!(
            store.verify(&encoded, "device.example", 200),
            Err(IdentityError::KeyExpired)
        ));
        store.revoke(&key_id).unwrap();
        assert!(matches!(
            store.verify(&encoded, "device.example", 150),
            Err(IdentityError::KeyRevoked)
        ));
    }

    #[test]
    fn debug_output_redacts_secrets_and_verified_payloads() {
        let secret = [0xa5_u8; 32];
        let identity = DeviceIdentity::from_signing_key(SigningKey::from_bytes(&secret));
        let identity_debug = format!("{identity:?}");
        assert!(!identity_debug.contains(&STANDARD.encode(secret)));
        assert!(!identity_debug.contains("signing_key"));

        let signer = TypedSigner::<AuditRole>::from_secret_bytes("device.example", secret).unwrap();
        let signer_debug = format!("{signer:?}");
        assert!(!signer_debug.contains(&STANDARD.encode(secret)));
        assert!(!signer_debug.contains("signing_key"));

        let verified = VerifiedCosePayload {
            issuer: "device.example".into(),
            key_id: *signer.key_id(),
            payload: b"secret audit payload".to_vec(),
        };
        let verified_debug = format!("{verified:?}");
        assert!(!verified_debug.contains("secret audit payload"));
        assert!(verified_debug.contains("payload_len"));
    }
}
