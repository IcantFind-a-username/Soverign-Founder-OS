use super::fs::{atomic_write_private, read_regular_file};
use super::*;
use std::fmt;
use std::path::Path;

use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Stable device identity derived from an Ed25519 signing key.
///
/// The public key and display identifier are private cached derivations. They
/// are checked against the secret key whenever an identity is loaded.
pub struct DeviceIdentity {
    device_id: String,
    public_key_b64: String,
    pub(crate) signing_key: SigningKey,
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

    pub(crate) fn from_signing_key(signing_key: SigningKey) -> Self {
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

/// Recompute the device id a public key must have. Lets a verifier bind an
/// exported audit history to the identity it claims: if this equals the
/// bundle's `device_id`, the signing key really is that device's key. The
/// input must be canonical padded Base64 of a valid 32-byte Ed25519 key.
pub fn device_id_from_public_key_b64(public_key_b64: &str) -> Result<String, IdentityError> {
    let verifying_key = decode_verifying_key(public_key_b64)?;
    Ok(device_fingerprint(&verifying_key.to_bytes()))
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
