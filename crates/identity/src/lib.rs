//! Device identity, role-typed COSE signing, and role trust stores.

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

mod device;
mod fs;
mod roles;
mod signer;
mod trust;

#[cfg(test)]
mod tests;

pub use device::*;
pub use roles::*;
pub use signer::*;
pub use trust::*;
