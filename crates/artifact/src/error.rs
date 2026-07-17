use thiserror::Error;

use crate::{Digest, SelectorError};

/// Stable verification and invocation failure classes. Text carried by the
/// diagnostic variants is not part of the protocol contract.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ArtifactError {
    #[error("artifact verification limits are invalid")]
    InvalidVerificationLimits,
    #[error("artifact verification intent is invalid")]
    InvalidVerificationIntent,
    #[error("signed manifest exceeds the verification ceiling")]
    ManifestTooLarge,
    #[error("component exceeds the verification ceiling")]
    ComponentTooLarge,
    #[error("signed envelope digest mismatch: expected {expected}, got {actual}")]
    SignedEnvelopeDigestMismatch { expected: Digest, actual: Digest },
    #[error("publisher signing key is not trusted")]
    UnknownPublisherKey,
    #[error("publisher issuer does not match the trusted installation intent")]
    PublisherIssuerMismatch,
    #[error("publisher signing key is revoked")]
    PublisherKeyRevoked,
    #[error("publisher signing key is not yet valid")]
    PublisherKeyNotYetValid,
    #[error("publisher signing key is expired")]
    PublisherKeyExpired,
    #[error("publisher signature is invalid")]
    InvalidPublisherSignature,
    #[error("publisher signature envelope is malformed or non-canonical")]
    InvalidPublisherEnvelope,
    #[error("publisher verification failed")]
    PublisherVerificationFailed,
    #[error("manifest payload is not canonical RFC 8785 JSON")]
    NonCanonicalManifest,
    #[error("manifest JSON is invalid: {0}")]
    InvalidManifest(String),
    #[error("unsupported manifest protocol version {0}")]
    UnsupportedProtocolVersion(u32),
    #[error("manifest publisher key id does not match the verified COSE key")]
    PublisherKeyIdMismatch,
    #[error("only the pure_compute risk class is supported in this phase")]
    UnsupportedRiskClass,
    #[error("only the core_wasm backend is supported in this phase")]
    UnsupportedBackend,
    #[error("only the sovereign_core_wasm_v1 ABI is supported in this phase")]
    UnsupportedAbi,
    #[error("host capabilities are forbidden for pure-compute artifacts")]
    HostCapabilitiesForbidden,
    #[error("manifest declares no operations")]
    MissingOperations,
    #[error("manifest declares a duplicate operation selector")]
    DuplicateOperation,
    #[error("operation selector is invalid: {0}")]
    InvalidOperationSelector(#[from] SelectorError),
    #[error("component digest mismatch: expected {expected}, got {actual}")]
    ComponentDigestMismatch { expected: Digest, actual: Digest },
    #[error("manifest digest does not match the authorized claim")]
    ManifestDigestMismatch,
    #[error("input schema is invalid: {0}")]
    InvalidInputSchema(String),
    #[error("resource binding rule is invalid: {0}")]
    InvalidResourceBinding(String),
    #[error("operation is not declared by the verified manifest")]
    OperationNotDeclared,
    #[error("input exceeds the operation byte ceiling")]
    InputTooLarge,
    #[error("input exceeds the operation depth ceiling")]
    InputTooDeep,
    #[error("input JSON is invalid: {0}")]
    InvalidInputJson(String),
    #[error("input JSON contains duplicate key `{0}`")]
    DuplicateInputKey(String),
    #[error("input does not satisfy the strict schema at {path}: {reason}")]
    InputSchemaMismatch { path: String, reason: String },
    #[error("RFC 8785 input canonicalization failed")]
    InputCanonicalizationFailed,
    #[error("resource binding `{0}` could not be resolved")]
    ResourceBindingNotFound(String),
    #[error("resource binding `{0}` must resolve to a UTF-8 JSON string")]
    ResourceBindingNotString(String),
    #[error("resource binding normalization is unsupported")]
    UnsupportedResourceNormalization,
    #[error("resource grant `{0}` is missing")]
    MissingResourceGrant(String),
    #[error("resource grant `{0}` was supplied more than once")]
    DuplicateResourceGrant(String),
    #[error("resource grant `{0}` was not declared by the manifest")]
    UnexpectedResourceGrant(String),
    #[error("resource grant `{0}` does not match the manifest-derived target")]
    ResourceGrantMismatch(String),
    #[error("canonical input digest does not match the authorized claim")]
    InputDigestMismatch,
    #[error("resource bindings digest does not match the authorized claim")]
    ResourceBindingsDigestMismatch,
    #[error("artifact store I/O failed: {0}")]
    AdmissionStoreIo(String),
    #[error("artifact store entry is not a regular file")]
    StoredEntryNotRegularFile,
    #[error("stored component bytes do not match the admitted digest: expected {expected}, got {actual}")]
    StoredComponentCorrupted { expected: Digest, actual: Digest },
    #[error("stored manifest bytes do not match the admitted digest")]
    StoredManifestCorrupted,
    #[error("an admission record already exists for this manifest")]
    AdmissionRecordExists,
    #[error("no admission record exists for this manifest")]
    AdmissionRecordNotFound,
    #[error("signed admission record exceeds the protocol size limit")]
    AdmissionRecordTooLarge,
    #[error("failed to canonicalize or sign the admission record")]
    AdmissionSigningFailed,
    #[error("admission record JSON is invalid: {0}")]
    InvalidAdmissionRecord(String),
    #[error("admission record payload is not canonical RFC 8785 JSON")]
    NonCanonicalAdmissionRecord,
    #[error("admission record does not match the requested artifact: {0}")]
    AdmissionRecordMismatch(&'static str),
    #[error("admission signing key is not trusted")]
    UnknownAdmissionKey,
    #[error("admission issuer does not match the trusted local authority")]
    AdmissionIssuerMismatch,
    #[error("admission signing key is revoked")]
    AdmissionKeyRevoked,
    #[error("admission signing key is not yet valid")]
    AdmissionKeyNotYetValid,
    #[error("admission signing key is expired")]
    AdmissionKeyExpired,
    #[error("admission record signature is invalid")]
    InvalidAdmissionSignature,
    #[error("admission record envelope is malformed or non-canonical")]
    InvalidAdmissionEnvelope,
    #[error("admission record verification failed")]
    AdmissionVerificationFailed,
}
