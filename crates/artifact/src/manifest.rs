use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sovereign_identity::{IdentityError, PublisherRole, RoleTrustStore};

use crate::schema::{parse_strict_json, StrictJsonError};
use crate::{ArtifactError, Digest, InputLimits, InputSchema, OperationSelector};

pub const MANIFEST_PROTOCOL_VERSION: u32 = 1;
pub const CORE_WASM_ENTRYPOINT: &str = "sovereign_run";
pub const CANONICALIZATION_PROFILE: &str = "rfc8785-jcs+sovereign-digest-v1";
pub const HARD_MAX_SIGNED_MANIFEST_BYTES: usize = 256 * 1024;
pub const HARD_MAX_MANIFEST_PAYLOAD_BYTES: usize = 192 * 1024;
pub const HARD_MAX_COMPONENT_BYTES: usize = 2 * 1024 * 1024;
const MANIFEST_DIGEST_DOMAIN: &[u8] = b"sovereign.plugin-manifest.jcs.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactBackend {
    CoreWasm,
    ComponentWasm,
    Native,
    #[serde(other)]
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskClass {
    PureCompute,
    LowRiskEffectful,
    HighRiskNative,
    #[serde(other)]
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactAbi {
    SovereignCoreWasmV1,
    SovereignComponentV1,
    #[serde(other)]
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ResourceNormalization(String);

impl ResourceNormalization {
    pub const EXACT_UTF8_V1: &'static str = "exact_utf8_v1";

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn is_supported(&self) -> bool {
        self.0 == Self::EXACT_UTF8_V1
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceBindingRule {
    binding_id: String,
    json_pointer: String,
    normalization: ResourceNormalization,
    primary: bool,
}

impl ResourceBindingRule {
    pub fn binding_id(&self) -> &str {
        &self.binding_id
    }

    pub fn json_pointer(&self) -> &str {
        &self.json_pointer
    }

    pub fn normalization(&self) -> &ResourceNormalization {
        &self.normalization
    }

    pub fn is_primary(&self) -> bool {
        self.primary
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationDefinition {
    selector: OperationSelector,
    input_limits: InputLimits,
    input_schema: InputSchema,
    resource_bindings: Vec<ResourceBindingRule>,
}

impl OperationDefinition {
    pub fn selector(&self) -> &OperationSelector {
        &self.selector
    }

    pub fn input_limits(&self) -> &InputLimits {
        &self.input_limits
    }

    pub fn input_schema(&self) -> &InputSchema {
        &self.input_schema
    }

    pub fn resource_bindings(&self) -> &[ResourceBindingRule] {
        &self.resource_bindings
    }

    fn validate(&self) -> Result<(), ArtifactError> {
        self.selector.validate()?;
        self.input_schema.validate_declaration(&self.input_limits)?;

        let mut binding_ids = BTreeSet::new();
        let mut primary_count = 0_usize;
        for binding in &self.resource_bindings {
            validate_binding_id(&binding.binding_id)?;
            validate_json_pointer(&binding.json_pointer)?;
            if !binding.normalization.is_supported() {
                return Err(ArtifactError::UnsupportedResourceNormalization);
            }
            if !binding_ids.insert(binding.binding_id.clone()) {
                return Err(ArtifactError::InvalidResourceBinding(
                    "duplicate binding_id".into(),
                ));
            }
            primary_count += usize::from(binding.primary);
        }
        if primary_count > 1 {
            return Err(ArtifactError::InvalidResourceBinding(
                "at most one binding may be primary".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginManifest {
    protocol_version: u32,
    publisher_issuer: String,
    publisher_key_id: Digest,
    component_digest: Digest,
    backend: ArtifactBackend,
    risk_class: RiskClass,
    abi: ArtifactAbi,
    entrypoint: String,
    requested_host_capabilities: Vec<String>,
    operations: Vec<OperationDefinition>,
}

impl PluginManifest {
    pub fn protocol_version(&self) -> u32 {
        self.protocol_version
    }

    pub fn publisher_issuer(&self) -> &str {
        &self.publisher_issuer
    }

    pub fn publisher_key_id(&self) -> Digest {
        self.publisher_key_id
    }

    pub fn component_digest(&self) -> Digest {
        self.component_digest
    }

    pub fn backend(&self) -> ArtifactBackend {
        self.backend
    }

    pub fn risk_class(&self) -> RiskClass {
        self.risk_class
    }

    pub fn abi(&self) -> ArtifactAbi {
        self.abi
    }

    pub fn entrypoint(&self) -> &str {
        &self.entrypoint
    }

    pub fn operations(&self) -> &[OperationDefinition] {
        &self.operations
    }

    pub(crate) fn operation(&self, selector: &OperationSelector) -> Option<&OperationDefinition> {
        self.operations
            .iter()
            .find(|operation| operation.selector() == selector)
    }

    fn validate(
        &self,
        expected_issuer: &str,
        verified_key_id: &[u8; 32],
    ) -> Result<(), ArtifactError> {
        if self.protocol_version != MANIFEST_PROTOCOL_VERSION {
            return Err(ArtifactError::UnsupportedProtocolVersion(
                self.protocol_version,
            ));
        }
        if self.publisher_issuer != expected_issuer {
            return Err(ArtifactError::PublisherIssuerMismatch);
        }
        if self.publisher_key_id.as_bytes() != verified_key_id {
            return Err(ArtifactError::PublisherKeyIdMismatch);
        }
        if self.risk_class != RiskClass::PureCompute {
            return Err(ArtifactError::UnsupportedRiskClass);
        }
        if self.backend != ArtifactBackend::CoreWasm {
            return Err(ArtifactError::UnsupportedBackend);
        }
        if self.abi != ArtifactAbi::SovereignCoreWasmV1 || self.entrypoint != CORE_WASM_ENTRYPOINT {
            return Err(ArtifactError::UnsupportedAbi);
        }
        if !self.requested_host_capabilities.is_empty() {
            return Err(ArtifactError::HostCapabilitiesForbidden);
        }
        if self.operations.is_empty() {
            return Err(ArtifactError::MissingOperations);
        }

        let mut selectors = BTreeSet::new();
        for operation in &self.operations {
            operation.validate()?;
            if !selectors.insert(operation.selector.clone()) {
                return Err(ArtifactError::DuplicateOperation);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionLimits {
    max_signed_manifest_bytes: usize,
    max_manifest_payload_bytes: usize,
    max_component_bytes: usize,
}

impl AdmissionLimits {
    pub fn new(
        max_signed_manifest_bytes: usize,
        max_manifest_payload_bytes: usize,
        max_component_bytes: usize,
    ) -> Result<Self, ArtifactError> {
        if max_signed_manifest_bytes == 0
            || max_signed_manifest_bytes > HARD_MAX_SIGNED_MANIFEST_BYTES
            || max_manifest_payload_bytes == 0
            || max_manifest_payload_bytes > HARD_MAX_MANIFEST_PAYLOAD_BYTES
            || max_manifest_payload_bytes > max_signed_manifest_bytes
            || max_component_bytes == 0
            || max_component_bytes > HARD_MAX_COMPONENT_BYTES
        {
            return Err(ArtifactError::InvalidVerificationLimits);
        }
        Ok(Self {
            max_signed_manifest_bytes,
            max_manifest_payload_bytes,
            max_component_bytes,
        })
    }

    pub fn max_signed_manifest_bytes(&self) -> usize {
        self.max_signed_manifest_bytes
    }

    pub fn max_manifest_payload_bytes(&self) -> usize {
        self.max_manifest_payload_bytes
    }

    pub fn max_component_bytes(&self) -> usize {
        self.max_component_bytes
    }
}

impl Default for AdmissionLimits {
    fn default() -> Self {
        Self {
            max_signed_manifest_bytes: HARD_MAX_SIGNED_MANIFEST_BYTES,
            max_manifest_payload_bytes: HARD_MAX_MANIFEST_PAYLOAD_BYTES,
            max_component_bytes: HARD_MAX_COMPONENT_BYTES,
        }
    }
}

/// Immutable caller intent fixed before any publisher verification occurs.
/// It identifies one exact signed envelope and one exact component from one
/// expected publisher; it is not an admission or execution authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactVerificationIntent {
    expected_publisher_issuer: String,
    signed_envelope_digest: Digest,
    component_digest: Digest,
}

impl ArtifactVerificationIntent {
    pub fn new(
        expected_publisher_issuer: impl Into<String>,
        signed_envelope_digest: Digest,
        component_digest: Digest,
    ) -> Result<Self, ArtifactError> {
        let expected_publisher_issuer = expected_publisher_issuer.into();
        if expected_publisher_issuer.is_empty()
            || expected_publisher_issuer.trim() != expected_publisher_issuer
            || expected_publisher_issuer.len() > 256
        {
            return Err(ArtifactError::InvalidVerificationIntent);
        }
        Ok(Self {
            expected_publisher_issuer,
            signed_envelope_digest,
            component_digest,
        })
    }

    pub fn expected_publisher_issuer(&self) -> &str {
        &self.expected_publisher_issuer
    }

    pub fn signed_envelope_digest(&self) -> Digest {
        self.signed_envelope_digest
    }

    pub fn component_digest(&self) -> Digest {
        self.component_digest
    }
}

/// Immutable publisher-verification result. The bytes that were hashed are
/// the same owned bytes later handed to the compiler; no source path is kept.
/// This value is not a locally signed admission record.
#[derive(Clone)]
pub struct VerifiedArtifact {
    manifest_digest: Digest,
    component_digest: Digest,
    manifest: Arc<PluginManifest>,
    bytes: Arc<[u8]>,
}

impl fmt::Debug for VerifiedArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedArtifact")
            .field("manifest_digest", &self.manifest_digest)
            .field("component_digest", &self.component_digest)
            .field("manifest", &"<redacted>")
            .field("component_bytes", &"<redacted>")
            .finish()
    }
}

impl VerifiedArtifact {
    pub fn manifest_digest(&self) -> Digest {
        self.manifest_digest
    }

    pub fn component_digest(&self) -> Digest {
        self.component_digest
    }

    pub fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn ensure_digests(
        &self,
        expected_manifest_digest: Digest,
        expected_component_digest: Digest,
    ) -> Result<(), ArtifactError> {
        if self.manifest_digest != expected_manifest_digest {
            return Err(ArtifactError::ManifestDigestMismatch);
        }
        if self.component_digest != expected_component_digest {
            return Err(ArtifactError::ComponentDigestMismatch {
                expected: expected_component_digest,
                actual: self.component_digest,
            });
        }
        Ok(())
    }
}

pub trait TrustedClock {
    fn now_unix(&self) -> i64;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl TrustedClock for SystemClock {
    fn now_unix(&self) -> i64 {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
            Err(error) => -i64::try_from(error.duration().as_secs()).unwrap_or(i64::MAX),
        }
    }
}

pub struct ArtifactVerifier<'a, C = SystemClock> {
    publishers: &'a RoleTrustStore<PublisherRole>,
    limits: AdmissionLimits,
    clock: C,
}

impl<'a> ArtifactVerifier<'a, SystemClock> {
    pub fn new(publishers: &'a RoleTrustStore<PublisherRole>) -> Self {
        Self {
            publishers,
            limits: AdmissionLimits::default(),
            clock: SystemClock,
        }
    }

    pub fn with_limits(
        publishers: &'a RoleTrustStore<PublisherRole>,
        limits: AdmissionLimits,
    ) -> Self {
        Self {
            publishers,
            limits,
            clock: SystemClock,
        }
    }
}

impl<'a, C: TrustedClock> ArtifactVerifier<'a, C> {
    pub fn with_clock(
        publishers: &'a RoleTrustStore<PublisherRole>,
        limits: AdmissionLimits,
        clock: C,
    ) -> Self {
        Self {
            publishers,
            limits,
            clock,
        }
    }

    pub fn verify(
        &self,
        intent: &ArtifactVerificationIntent,
        signed_manifest_cose: &[u8],
        component_bytes: &[u8],
    ) -> Result<VerifiedArtifact, ArtifactError> {
        if signed_manifest_cose.len() > self.limits.max_signed_manifest_bytes {
            return Err(ArtifactError::ManifestTooLarge);
        }
        if component_bytes.len() > self.limits.max_component_bytes {
            return Err(ArtifactError::ComponentTooLarge);
        }

        // Snapshot caller memory at the start of the verification transaction.
        // Digest comparison, signature verification, and later compilation all
        // refer to these immutable allocations even for FFI/mmap callers.
        let bytes: Arc<[u8]> = Arc::from(component_bytes.to_vec());
        let signed_envelope: Arc<[u8]> = Arc::from(signed_manifest_cose.to_vec());

        let signed_envelope_digest = Digest::of_bytes(&signed_envelope);
        if signed_envelope_digest != intent.signed_envelope_digest {
            return Err(ArtifactError::SignedEnvelopeDigestMismatch {
                expected: intent.signed_envelope_digest,
                actual: signed_envelope_digest,
            });
        }
        let component_digest = Digest::of_bytes(&bytes);
        if component_digest != intent.component_digest {
            return Err(ArtifactError::ComponentDigestMismatch {
                expected: intent.component_digest,
                actual: component_digest,
            });
        }

        let verified = self
            .publishers
            .verify(
                &signed_envelope,
                intent.expected_publisher_issuer(),
                self.clock.now_unix(),
            )
            .map_err(map_identity_error)?;
        if verified.payload().len() > self.limits.max_manifest_payload_bytes {
            return Err(ArtifactError::ManifestTooLarge);
        }

        let value = parse_strict_json(verified.payload()).map_err(|error| match error {
            StrictJsonError::DuplicateKey(key) => {
                ArtifactError::InvalidManifest(format!("duplicate JSON key `{key}`"))
            }
            StrictJsonError::Invalid(message) => ArtifactError::InvalidManifest(message),
        })?;
        let canonical = canonicalize(&value)?;
        if canonical != verified.payload() {
            return Err(ArtifactError::NonCanonicalManifest);
        }
        let manifest: PluginManifest = serde_json::from_value(value)
            .map_err(|error| ArtifactError::InvalidManifest(error.to_string()))?;
        manifest.validate(intent.expected_publisher_issuer(), verified.key_id())?;

        if component_digest != manifest.component_digest {
            return Err(ArtifactError::ComponentDigestMismatch {
                expected: manifest.component_digest,
                actual: component_digest,
            });
        }

        Ok(VerifiedArtifact {
            manifest_digest: Digest::domain_separated(MANIFEST_DIGEST_DOMAIN, &canonical),
            component_digest,
            manifest: Arc::new(manifest),
            bytes,
        })
    }
}

pub(crate) fn canonicalize<T: Serialize>(value: &T) -> Result<Vec<u8>, ArtifactError> {
    serde_json_canonicalizer::to_vec(value).map_err(|_| ArtifactError::InputCanonicalizationFailed)
}

fn map_identity_error(error: IdentityError) -> ArtifactError {
    match error {
        IdentityError::UnknownKeyId => ArtifactError::UnknownPublisherKey,
        IdentityError::IssuerMismatch | IdentityError::InvalidIssuer => {
            ArtifactError::PublisherIssuerMismatch
        }
        IdentityError::KeyRevoked => ArtifactError::PublisherKeyRevoked,
        IdentityError::KeyNotYetValid => ArtifactError::PublisherKeyNotYetValid,
        IdentityError::KeyExpired => ArtifactError::PublisherKeyExpired,
        IdentityError::VerificationFailed => ArtifactError::InvalidPublisherSignature,
        IdentityError::InvalidProtectedHeaders
        | IdentityError::UnprotectedHeadersForbidden
        | IdentityError::MissingPayload
        | IdentityError::NonCanonicalCose
        | IdentityError::Cose(_) => ArtifactError::InvalidPublisherEnvelope,
        _ => ArtifactError::PublisherVerificationFailed,
    }
}

fn validate_binding_id(binding_id: &str) -> Result<(), ArtifactError> {
    if binding_id.is_empty()
        || binding_id.len() > 128
        || !binding_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(ArtifactError::InvalidResourceBinding(
            "binding_id must be 1..=128 ASCII identifier bytes".into(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_json_pointer(pointer: &str) -> Result<(), ArtifactError> {
    if pointer.len() > 1024 || (!pointer.is_empty() && !pointer.starts_with('/')) {
        return Err(ArtifactError::InvalidResourceBinding(
            "JSON Pointer must be empty or begin with `/` and fit 1024 bytes".into(),
        ));
    }
    for token in pointer.split('/').skip(1) {
        let bytes = token.as_bytes();
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] == b'~' {
                if index + 1 >= bytes.len() || !matches!(bytes[index + 1], b'0' | b'1') {
                    return Err(ArtifactError::InvalidResourceBinding(
                        "JSON Pointer contains an invalid escape".into(),
                    ));
                }
                index += 2;
            } else {
                index += 1;
            }
        }
    }
    Ok(())
}
