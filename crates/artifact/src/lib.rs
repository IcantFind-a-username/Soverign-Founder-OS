//! Phase B foundation for verifying publisher artifacts and preparing exact
//! invocations.
//!
//! The crate deliberately exposes no path-based or raw-module execution
//! handle. A [`VerifiedArtifact`] owns the exact bytes that were hashed and
//! publisher-verified; a [`PreparedInvocation`] owns canonical RFC 8785 input
//! and only exposes resource commitments required by capability validation.
//!
//! The [`ArtifactStore`] adds the next trust transition: a locally signed
//! admission record and a content-addressed store that promote a
//! publisher-verified artifact to an [`AdmittedArtifact`]. The verified
//! executor does not yet require the admitted handle; that wiring is a
//! separate slice.

mod admission;
mod digest;
mod error;
mod invocation;
mod manifest;
mod schema;
mod selector;

pub use admission::{
    AdmissionRecordClaimsV1, AdmittedArtifact, ArtifactStore, InstallationState,
    ADMISSION_RECORD_TYPE, ADMISSION_RECORD_VERSION, HARD_MAX_SIGNED_ADMISSION_BYTES,
};
pub use digest::{Digest, DigestError};
pub use error::ArtifactError;
pub use invocation::{PreparedInvocation, RawResourceGrant};
pub use manifest::{
    AdmissionLimits, ArtifactAbi, ArtifactBackend, ArtifactVerificationIntent, ArtifactVerifier,
    OperationDefinition, PluginManifest, ResourceBindingRule, ResourceNormalization, RiskClass,
    SystemClock, TrustedClock, VerifiedArtifact, CANONICALIZATION_PROFILE, CORE_WASM_ENTRYPOINT,
    HARD_MAX_COMPONENT_BYTES, HARD_MAX_MANIFEST_PAYLOAD_BYTES, HARD_MAX_SIGNED_MANIFEST_BYTES,
    MANIFEST_PROTOCOL_VERSION,
};
pub use schema::{
    InputLimits, InputSchema, IJSON_SAFE_INTEGER_MAX, IJSON_SAFE_INTEGER_MIN,
    MAX_DECLARED_INPUT_BYTES, MAX_DECLARED_INPUT_DEPTH,
};
pub use selector::{OperationSelector, SelectorError};
