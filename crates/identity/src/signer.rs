use super::*;
use std::fmt;
use std::marker::PhantomData;

use base64::{engine::general_purpose::STANDARD, Engine};
use coset::{iana, CoseSign1Builder, Header, HeaderBuilder, TaggedCborSerializable};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

/// Ed25519 signer whose role is enforced by the type system and COSE domain.
pub struct TypedSigner<R: SigningRole> {
    issuer: String,
    pub(crate) signing_key: SigningKey,
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

    pub(crate) fn from_signing_key(
        signing_key: SigningKey,
        issuer: String,
    ) -> Result<Self, IdentityError> {
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

pub(crate) fn validate_issuer(issuer: &str) -> Result<(), IdentityError> {
    if issuer.is_empty() || issuer.trim() != issuer || issuer.len() > 256 {
        return Err(IdentityError::InvalidIssuer);
    }
    Ok(())
}

pub(crate) fn role_key_id<R: SigningRole>(public_key: &[u8; 32]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(KEY_ID_PREFIX);
    digest.update((R::NAME.len() as u16).to_be_bytes());
    digest.update(R::NAME.as_bytes());
    digest.update(b"\0ed25519\0");
    digest.update(public_key);
    digest.finalize().into()
}

pub(crate) fn expected_protected_header<R: SigningRole>(key_id: &[u8; 32]) -> Header {
    HeaderBuilder::new()
        .algorithm(iana::Algorithm::EdDSA)
        .key_id(key_id.to_vec())
        .content_type(R::CONTENT_TYPE.to_owned())
        .build()
}
