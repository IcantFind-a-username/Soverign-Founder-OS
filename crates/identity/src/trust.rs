use super::signer::{expected_protected_header, role_key_id, validate_issuer};
use super::*;
use std::collections::HashMap;
use std::fmt;
use std::marker::PhantomData;

use coset::{CoseSign1, TaggedCborSerializable};
use ed25519_dalek::{Signature, VerifyingKey};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustStatus {
    Active,
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyValidity {
    not_before_unix: i64,
    not_after_unix: i64,
}

impl KeyValidity {
    pub fn new(not_before_unix: i64, not_after_unix: i64) -> Result<Self, IdentityError> {
        if not_after_unix <= not_before_unix {
            return Err(IdentityError::InvalidValidity);
        }
        Ok(Self {
            not_before_unix,
            not_after_unix,
        })
    }

    pub fn not_before_unix(&self) -> i64 {
        self.not_before_unix
    }

    pub fn not_after_unix(&self) -> i64 {
        self.not_after_unix
    }
}

#[derive(Debug)]
struct TrustedKey {
    pub(crate) issuer: String,
    status: TrustStatus,
    validity: KeyValidity,
    verifying_key: VerifyingKey,
}

/// Role-specific trust store. COSE `kid` selects a locally registered key;
/// no public key supplied by the signed object is ever trusted.
#[derive(Debug)]
pub struct RoleTrustStore<R: SigningRole> {
    keys: HashMap<[u8; 32], TrustedKey>,
    role: PhantomData<R>,
}

impl<R: SigningRole> Default for RoleTrustStore<R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R: SigningRole> RoleTrustStore<R> {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            role: PhantomData,
        }
    }

    pub fn add_key(
        &mut self,
        issuer: impl Into<String>,
        public_key: [u8; 32],
        validity: KeyValidity,
    ) -> Result<[u8; 32], IdentityError> {
        let issuer = issuer.into();
        validate_issuer(&issuer)?;
        let verifying_key = VerifyingKey::from_bytes(&public_key)
            .map_err(|error| IdentityError::InvalidKey(error.to_string()))?;
        let key_id = role_key_id::<R>(&public_key);
        if self.keys.contains_key(&key_id) {
            return Err(IdentityError::DuplicateKeyId);
        }
        self.keys.insert(
            key_id,
            TrustedKey {
                issuer,
                status: TrustStatus::Active,
                validity,
                verifying_key,
            },
        );
        Ok(key_id)
    }

    pub fn trust_signer(
        &mut self,
        signer: &TypedSigner<R>,
        validity: KeyValidity,
    ) -> Result<[u8; 32], IdentityError> {
        self.add_key(signer.issuer(), signer.public_key_bytes(), validity)
    }

    pub fn set_status(
        &mut self,
        key_id: &[u8; 32],
        status: TrustStatus,
    ) -> Result<(), IdentityError> {
        let trusted = self
            .keys
            .get_mut(key_id)
            .ok_or(IdentityError::UnknownKeyId)?;
        trusted.status = status;
        Ok(())
    }

    pub fn revoke(&mut self, key_id: &[u8; 32]) -> Result<(), IdentityError> {
        self.set_status(key_id, TrustStatus::Revoked)
    }

    pub fn verify(
        &self,
        encoded: &[u8],
        expected_issuer: &str,
        now_unix: i64,
    ) -> Result<VerifiedCosePayload, IdentityError> {
        validate_issuer(expected_issuer)?;
        let sign1 = CoseSign1::from_tagged_slice(encoded)
            .map_err(|error| IdentityError::Cose(error.to_string()))?;
        ensure_canonical_cose(encoded, &sign1)?;
        if !sign1.unprotected.is_empty() {
            return Err(IdentityError::UnprotectedHeadersForbidden);
        }

        let key_id: [u8; 32] = sign1
            .protected
            .header
            .key_id
            .as_slice()
            .try_into()
            .map_err(|_| IdentityError::InvalidProtectedHeaders)?;
        let trusted = self.keys.get(&key_id).ok_or(IdentityError::UnknownKeyId)?;
        if trusted.issuer != expected_issuer {
            return Err(IdentityError::IssuerMismatch);
        }
        if trusted.status == TrustStatus::Revoked {
            return Err(IdentityError::KeyRevoked);
        }
        if now_unix < trusted.validity.not_before_unix {
            return Err(IdentityError::KeyNotYetValid);
        }
        if now_unix >= trusted.validity.not_after_unix {
            return Err(IdentityError::KeyExpired);
        }
        if sign1.protected.header != expected_protected_header::<R>(&key_id) {
            return Err(IdentityError::InvalidProtectedHeaders);
        }

        sign1.verify_signature(R::EXTERNAL_AAD, |signature_bytes, to_be_signed| {
            let signature_array: [u8; 64] = signature_bytes
                .try_into()
                .map_err(|_| IdentityError::VerificationFailed)?;
            let signature = Signature::from_bytes(&signature_array);
            trusted
                .verifying_key
                .verify_strict(to_be_signed, &signature)
                .map_err(|_| IdentityError::VerificationFailed)
        })?;

        let payload = sign1.payload.ok_or(IdentityError::MissingPayload)?;
        Ok(VerifiedCosePayload {
            issuer: trusted.issuer.clone(),
            key_id,
            payload,
        })
    }
}

fn ensure_canonical_cose(encoded: &[u8], sign1: &CoseSign1) -> Result<(), IdentityError> {
    let mut canonical = sign1.clone();
    canonical.protected.original_data = None;
    let canonical_bytes = canonical
        .to_tagged_vec()
        .map_err(|error| IdentityError::Cose(error.to_string()))?;
    if canonical_bytes != encoded {
        return Err(IdentityError::NonCanonicalCose);
    }
    Ok(())
}

#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedCosePayload {
    pub(crate) issuer: String,
    pub(crate) key_id: [u8; 32],
    pub(crate) payload: Vec<u8>,
}

impl fmt::Debug for VerifiedCosePayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedCosePayload")
            .field("issuer", &self.issuer)
            .field("key_id", &hex::encode(self.key_id))
            .field("payload_len", &self.payload.len())
            .finish_non_exhaustive()
    }
}

impl VerifiedCosePayload {
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn key_id(&self) -> &[u8; 32] {
        &self.key_id
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }
}
