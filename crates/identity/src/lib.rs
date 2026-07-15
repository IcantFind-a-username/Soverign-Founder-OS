use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("invalid key material: {0}")]
    InvalidKey(String),
    #[error("signature verification failed")]
    VerificationFailed,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Stable device identity derived from the public key fingerprint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceIdentity {
    pub device_id: String,
    pub public_key_b64: String,
    #[serde(skip_serializing)]
    signing_key: SigningKey,
}

impl DeviceIdentity {
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let public_key_bytes = verifying_key.to_bytes();
        let device_id = fingerprint(&public_key_bytes);
        Self {
            device_id,
            public_key_b64: STANDARD.encode(public_key_bytes),
            signing_key,
        }
    }

    pub fn sign(&self, message: &[u8]) -> String {
        let signature = self.signing_key.sign(message);
        STANDARD.encode(signature.to_bytes())
    }

    pub fn verify(
        public_key_b64: &str,
        message: &[u8],
        signature_b64: &str,
    ) -> Result<(), IdentityError> {
        let public_bytes = STANDARD
            .decode(public_key_b64)
            .map_err(|e| IdentityError::InvalidKey(e.to_string()))?;
        let key_bytes: [u8; 32] = public_bytes
            .try_into()
            .map_err(|_| IdentityError::InvalidKey("expected 32-byte public key".into()))?;
        let verifying_key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| IdentityError::InvalidKey(e.to_string()))?;

        let sig_bytes = STANDARD
            .decode(signature_b64)
            .map_err(|e| IdentityError::InvalidKey(e.to_string()))?;
        let sig_array: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| IdentityError::InvalidKey("expected 64-byte signature".into()))?;
        let signature = Signature::from_bytes(&sig_array);

        verifying_key
            .verify(message, &signature)
            .map_err(|_| IdentityError::VerificationFailed)
    }

    pub fn save(&self, path: &std::path::Path) -> Result<(), IdentityError> {
        let stored = StoredIdentity {
            device_id: self.device_id.clone(),
            public_key_b64: self.public_key_b64.clone(),
            secret_key_b64: STANDARD.encode(self.signing_key.to_bytes()),
        };
        let json = serde_json::to_vec_pretty(&stored)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    pub fn load(path: &std::path::Path) -> Result<Self, IdentityError> {
        let bytes = std::fs::read(path)?;
        let stored: StoredIdentity = serde_json::from_slice(&bytes)?;
        let secret_bytes = STANDARD
            .decode(&stored.secret_key_b64)
            .map_err(|e| IdentityError::InvalidKey(e.to_string()))?;
        let secret_array: [u8; 32] = secret_bytes
            .try_into()
            .map_err(|_| IdentityError::InvalidKey("expected 32-byte secret key".into()))?;
        let signing_key = SigningKey::from_bytes(&secret_array);
        Ok(Self {
            device_id: stored.device_id,
            public_key_b64: stored.public_key_b64,
            signing_key,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredIdentity {
    device_id: String,
    public_key_b64: String,
    secret_key_b64: String,
}

fn fingerprint(public_key: &[u8; 32]) -> String {
    let digest = Sha256::digest(public_key);
    format!("dev_{}", hex::encode(&digest[..12]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let id = DeviceIdentity::generate();
        let msg = b"sovereign audit event";
        let sig = id.sign(msg);
        DeviceIdentity::verify(&id.public_key_b64, msg, &sig).unwrap();
    }

    #[test]
    fn persist_identity() {
        let dir = std::env::temp_dir().join("sovereign-id-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("device.json");
        let id = DeviceIdentity::generate();
        id.save(&path).unwrap();
        let loaded = DeviceIdentity::load(&path).unwrap();
        assert_eq!(id.device_id, loaded.device_id);
        std::fs::remove_dir_all(dir).ok();
    }
}
