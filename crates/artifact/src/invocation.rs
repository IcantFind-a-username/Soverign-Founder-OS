use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use serde::Serialize;

use crate::manifest::canonicalize;
use crate::schema::parse_strict_input;
use crate::{ArtifactError, Digest, OperationSelector, ResourceBindingRule, VerifiedArtifact};

const INPUT_DIGEST_DOMAIN: &[u8] = b"sovereign.invocation.input.jcs.v1";
const GRANT_COMMITMENT_DOMAIN: &[u8] = b"sovereign.resource-grant.exact-utf8.v1";
const BINDINGS_DIGEST_DOMAIN: &[u8] = b"sovereign.invocation.bindings.jcs.v1";
const MAX_RESOURCE_UTF8_BYTES: usize = 4096;

/// Trusted-host resource value supplied for comparison with a manifest JSON
/// Pointer. Fields are private so a prepared invocation cannot accidentally
/// expose the full grant set to the guest.
#[derive(Clone, PartialEq, Eq)]
pub struct RawResourceGrant {
    binding_id: String,
    resource: String,
}

impl RawResourceGrant {
    pub fn new(binding_id: impl Into<String>, resource: impl Into<String>) -> Self {
        Self {
            binding_id: binding_id.into(),
            resource: resource.into(),
        }
    }

    pub fn binding_id(&self) -> &str {
        &self.binding_id
    }

    pub fn resource(&self) -> &str {
        &self.resource
    }
}

impl fmt::Debug for RawResourceGrant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawResourceGrant")
            .field("grant", &"<redacted>")
            .finish()
    }
}

#[derive(Clone)]
pub struct PreparedInvocation {
    artifact: VerifiedArtifact,
    operation: OperationSelector,
    canonical_input: Arc<[u8]>,
    input_digest: Digest,
    bindings_digest: Digest,
    primary_resource: Option<String>,
    // Deliberately private: capability and sandbox integrations receive only
    // the commitment digest and the explicitly selected primary resource.
    _grant_commitments: Vec<GrantCommitment>,
}

impl fmt::Debug for PreparedInvocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedInvocation")
            .field("artifact", &self.artifact)
            .field("operation", &self.operation)
            .field("canonical_input", &"<redacted>")
            .field("input_digest", &self.input_digest)
            .field("bindings_digest", &self.bindings_digest)
            .field("primary_resource", &"<redacted>")
            .field("grant_commitments", &"<redacted>")
            .finish()
    }
}

impl PreparedInvocation {
    pub fn prepare(
        artifact: &VerifiedArtifact,
        operation: &OperationSelector,
        raw_json: &[u8],
        grants: Vec<RawResourceGrant>,
    ) -> Result<Self, ArtifactError> {
        let definition = artifact
            .manifest()
            .operation(operation)
            .ok_or(ArtifactError::OperationNotDeclared)?;
        let input = parse_strict_input(raw_json, definition.input_limits())?;
        definition.input_schema().validate_value(&input)?;
        let canonical_input = canonicalize(&input)?;
        if canonical_input.len() > definition.input_limits().max_bytes() {
            return Err(ArtifactError::InputTooLarge);
        }

        let supplied = collect_grants(grants)?;
        let (grant_commitments, primary_resource) =
            prepare_grants(&input, definition.resource_bindings(), supplied)?;
        let canonical_commitments = canonicalize(&grant_commitments)?;

        Ok(Self {
            artifact: artifact.clone(),
            operation: operation.clone(),
            input_digest: Digest::domain_separated(INPUT_DIGEST_DOMAIN, &canonical_input),
            bindings_digest: Digest::domain_separated(
                BINDINGS_DIGEST_DOMAIN,
                &canonical_commitments,
            ),
            canonical_input: Arc::from(canonical_input),
            primary_resource,
            _grant_commitments: grant_commitments,
        })
    }

    pub fn artifact(&self) -> &VerifiedArtifact {
        &self.artifact
    }

    pub fn operation(&self) -> &OperationSelector {
        &self.operation
    }

    pub fn canonical_input(&self) -> &[u8] {
        &self.canonical_input
    }

    pub fn input_digest(&self) -> Digest {
        self.input_digest
    }

    pub fn bindings_digest(&self) -> Digest {
        self.bindings_digest
    }

    pub fn primary_resource(&self) -> Option<&str> {
        self.primary_resource.as_deref()
    }

    pub fn ensure_commitments(
        &self,
        expected_input_digest: Digest,
        expected_bindings_digest: Digest,
    ) -> Result<(), ArtifactError> {
        if self.input_digest != expected_input_digest {
            return Err(ArtifactError::InputDigestMismatch);
        }
        if self.bindings_digest != expected_bindings_digest {
            return Err(ArtifactError::ResourceBindingsDigestMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct GrantCommitment {
    binding_id: String,
    resource_digest: Digest,
    primary: bool,
}

fn collect_grants(
    grants: Vec<RawResourceGrant>,
) -> Result<BTreeMap<String, String>, ArtifactError> {
    let mut collected = BTreeMap::new();
    for grant in grants {
        if collected
            .insert(grant.binding_id.clone(), grant.resource)
            .is_some()
        {
            return Err(ArtifactError::DuplicateResourceGrant(grant.binding_id));
        }
    }
    Ok(collected)
}

fn prepare_grants(
    input: &serde_json::Value,
    rules: &[ResourceBindingRule],
    mut supplied: BTreeMap<String, String>,
) -> Result<(Vec<GrantCommitment>, Option<String>), ArtifactError> {
    let mut commitments = Vec::with_capacity(rules.len());
    let mut primary_resource = None;

    for rule in rules {
        if !rule.normalization().is_supported() {
            return Err(ArtifactError::UnsupportedResourceNormalization);
        }
        let value = input
            .pointer(rule.json_pointer())
            .ok_or_else(|| ArtifactError::ResourceBindingNotFound(rule.binding_id().into()))?;
        let resource = value
            .as_str()
            .ok_or_else(|| ArtifactError::ResourceBindingNotString(rule.binding_id().into()))?;
        if resource.is_empty() || resource.len() > MAX_RESOURCE_UTF8_BYTES {
            return Err(ArtifactError::ResourceGrantMismatch(
                rule.binding_id().into(),
            ));
        }
        let granted = supplied
            .remove(rule.binding_id())
            .ok_or_else(|| ArtifactError::MissingResourceGrant(rule.binding_id().into()))?;
        if granted.as_bytes() != resource.as_bytes() {
            return Err(ArtifactError::ResourceGrantMismatch(
                rule.binding_id().into(),
            ));
        }

        if rule.is_primary() {
            primary_resource = Some(resource.to_owned());
        }
        commitments.push(GrantCommitment {
            binding_id: rule.binding_id().into(),
            resource_digest: Digest::domain_separated(GRANT_COMMITMENT_DOMAIN, resource.as_bytes()),
            primary: rule.is_primary(),
        });
    }

    if let Some((unexpected, _)) = supplied.into_iter().next() {
        return Err(ArtifactError::UnexpectedResourceGrant(unexpected));
    }
    commitments.sort_by(|left, right| left.binding_id.cmp(&right.binding_id));
    Ok((commitments, primary_resource))
}
