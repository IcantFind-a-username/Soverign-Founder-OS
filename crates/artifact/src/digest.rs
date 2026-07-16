use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

const DOMAIN_FRAME: &[u8] = b"sovereign-founder-os\0digest\0v1\0";

/// A fixed-size SHA-256 digest serialized as exactly 64 lowercase hex digits.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Digest(#[serde(with = "lower_hex")] [u8; 32]);

impl Digest {
    /// Hash raw bytes without an application domain. This is used for the
    /// RFC-defined component SHA-256 identifier.
    pub fn of_bytes(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    /// Hash an application value with unambiguous length-prefixed domain
    /// separation. Callers should use a stable protocol-domain constant.
    pub fn domain_separated(domain: &[u8], bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN_FRAME);
        hasher.update((domain.len() as u64).to_be_bytes());
        hasher.update(domain);
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
        Self(hasher.finalize().into())
    }

    pub fn as_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("Digest")
            .field(&self.as_hex())
            .finish()
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.as_hex())
    }
}

impl std::str::FromStr for Digest {
    type Err = DigestError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 64 {
            return Err(DigestError::InvalidLength(value.len()));
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(DigestError::NonCanonicalHex);
        }
        let mut bytes = [0_u8; 32];
        hex::decode_to_slice(value, &mut bytes).map_err(|_| DigestError::InvalidEncoding)?;
        Ok(Self(bytes))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DigestError {
    #[error("digest must contain exactly 64 hex digits, got {0}")]
    InvalidLength(usize),
    #[error("digest must use canonical lowercase hexadecimal")]
    NonCanonicalHex,
    #[error("digest contains invalid hexadecimal")]
    InvalidEncoding,
}

mod lower_hex {
    use serde::{Deserialize, Deserializer, Serializer};

    use super::Digest;

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value
            .parse::<Digest>()
            .map(|digest| *digest.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_is_transparent_fixed_lowercase_hex() {
        let digest = Digest::of_bytes(b"artifact");
        let encoded = serde_json::to_string(&digest).unwrap();
        assert_eq!(encoded, format!("\"{}\"", digest.as_hex()));
        assert_eq!(serde_json::from_str::<Digest>(&encoded).unwrap(), digest);

        let uppercase = format!("\"{}\"", digest.as_hex().to_uppercase());
        assert!(serde_json::from_str::<Digest>(&uppercase).is_err());
        assert!(serde_json::from_str::<Digest>("\"00\"").is_err());
    }

    #[test]
    fn domains_produce_distinct_digests() {
        assert_ne!(
            Digest::domain_separated(b"policy", b"same"),
            Digest::domain_separated(b"claim", b"same")
        );
        assert_ne!(
            Digest::domain_separated(b"policy", b"same"),
            Digest::of_bytes(b"same")
        );
    }
}
