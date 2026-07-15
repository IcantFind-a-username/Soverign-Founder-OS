use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const NONCE_LEN: usize = 12;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("vault not initialized")]
    NotInitialized,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("entry not found: {0}")]
    NotFound(String),
    #[error("invalid vault entry name: {0}")]
    InvalidEntryName(String),
}

#[derive(Debug, Serialize, Deserialize)]
struct VaultManifest {
    version: u32,
    entries: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct EncryptedBlob {
    nonce_b64: String,
    ciphertext_b64: String,
}

/// Local encrypted vault using AES-256-GCM envelope encryption per entry.
pub struct Vault {
    root: std::path::PathBuf,
    key: [u8; 32],
    manifest: VaultManifest,
}

impl Vault {
    pub fn init(root: impl AsRef<std::path::Path>) -> Result<Self, VaultError> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root)?;
        let key_path = root.join("vault.key");
        let key = if key_path.exists() {
            load_key(&key_path)?
        } else {
            let key = generate_key();
            save_key(&key_path, &key)?;
            key
        };
        let manifest_path = root.join("manifest.json");
        let manifest = if manifest_path.exists() {
            let bytes = std::fs::read(&manifest_path)?;
            serde_json::from_slice(&bytes)?
        } else {
            VaultManifest {
                version: 1,
                entries: Vec::new(),
            }
        };
        Ok(Self {
            root,
            key,
            manifest,
        })
    }

    pub fn put(&mut self, name: &str, plaintext: &[u8]) -> Result<(), VaultError> {
        validate_entry_name(name)?;
        let blob = encrypt(&self.key, plaintext)?;
        let path = self.root.join(format!("{name}.enc"));
        let json = serde_json::to_vec_pretty(&blob)?;
        std::fs::write(path, json)?;
        if !self.manifest.entries.contains(&name.to_string()) {
            self.manifest.entries.push(name.to_string());
            self.save_manifest()?;
        }
        Ok(())
    }

    pub fn get(&self, name: &str) -> Result<Vec<u8>, VaultError> {
        validate_entry_name(name)?;
        let path = self.root.join(format!("{name}.enc"));
        if !path.exists() {
            return Err(VaultError::NotFound(name.to_string()));
        }
        let bytes = std::fs::read(path)?;
        let blob: EncryptedBlob = serde_json::from_slice(&bytes)?;
        decrypt(&self.key, &blob)
    }

    pub fn list(&self) -> &[String] {
        &self.manifest.entries
    }

    fn save_manifest(&self) -> Result<(), VaultError> {
        let path = self.root.join("manifest.json");
        let json = serde_json::to_vec_pretty(&self.manifest)?;
        std::fs::write(path, json)?;
        Ok(())
    }
}

fn validate_entry_name(name: &str) -> Result<(), VaultError> {
    let is_single_normal_component = {
        let mut components = std::path::Path::new(name).components();
        matches!(components.next(), Some(std::path::Component::Normal(_)))
            && components.next().is_none()
    };
    if !is_single_normal_component
        || name.contains(['/', '\\'])
        || name.chars().any(char::is_control)
    {
        return Err(VaultError::InvalidEntryName(name.to_string()));
    }
    Ok(())
}

fn generate_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

fn save_key(path: &std::path::Path, key: &[u8; 32]) -> Result<(), VaultError> {
    std::fs::write(path, STANDARD.encode(key))?;
    Ok(())
}

fn load_key(path: &std::path::Path) -> Result<[u8; 32], VaultError> {
    let encoded = std::fs::read_to_string(path)?;
    let bytes = STANDARD
        .decode(encoded.trim())
        .map_err(|_| VaultError::DecryptionFailed)?;
    bytes.try_into().map_err(|_| VaultError::DecryptionFailed)
}

fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<EncryptedBlob, VaultError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| VaultError::DecryptionFailed)?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| VaultError::DecryptionFailed)?;
    Ok(EncryptedBlob {
        nonce_b64: STANDARD.encode(nonce_bytes),
        ciphertext_b64: STANDARD.encode(ciphertext),
    })
}

fn decrypt(key: &[u8; 32], blob: &EncryptedBlob) -> Result<Vec<u8>, VaultError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| VaultError::DecryptionFailed)?;
    let nonce_bytes = STANDARD
        .decode(&blob.nonce_b64)
        .map_err(|_| VaultError::DecryptionFailed)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = STANDARD
        .decode(&blob.ciphertext_b64)
        .map_err(|_| VaultError::DecryptionFailed)?;
    cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| VaultError::DecryptionFailed)
}

pub fn fingerprint(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn put_get_roundtrip() {
        let dir = tempdir().unwrap();
        let mut vault = Vault::init(dir.path()).unwrap();
        vault.put("company_profile", b"stealth startup").unwrap();
        let data = vault.get("company_profile").unwrap();
        assert_eq!(data, b"stealth startup");
    }

    #[test]
    fn rejects_path_traversal_names() {
        let dir = tempdir().unwrap();
        let mut vault = Vault::init(dir.path().join("vault")).unwrap();
        assert!(matches!(
            vault.put("../outside", b"secret"),
            Err(VaultError::InvalidEntryName(_))
        ));
        assert!(!dir.path().join("outside.enc").exists());
    }
}
