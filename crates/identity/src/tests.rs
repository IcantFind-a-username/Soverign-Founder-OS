use super::*;

use super::fs::{atomic_write_private_at, open_parent_and_name};
use base64::{engine::general_purpose::STANDARD, Engine};
use coset::{iana, CoseSign1, CoseSign1Builder, Header, HeaderBuilder, TaggedCborSerializable};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use rand::RngCore;
use std::path::PathBuf;

fn test_directory(label: &str) -> PathBuf {
    let mut nonce = [0_u8; 8];
    OsRng.fill_bytes(&mut nonce);
    let path = std::env::temp_dir().join(format!(
        "sovereign-identity-{label}-{}-{}",
        std::process::id(),
        hex::encode(nonce)
    ));
    std::fs::create_dir_all(&path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    path
}

fn validity() -> KeyValidity {
    KeyValidity::new(100, 200).unwrap()
}

fn sign_custom_cose<R: SigningRole>(
    signer: &TypedSigner<R>,
    protected: Header,
    unprotected: Header,
    payload: &[u8],
    external_aad: &[u8],
) -> Vec<u8> {
    CoseSign1Builder::new()
        .protected(protected)
        .unprotected(unprotected)
        .payload(payload.to_vec())
        .create_signature(external_aad, |to_be_signed| {
            signer.signing_key.sign(to_be_signed).to_bytes().to_vec()
        })
        .build()
        .to_tagged_vec()
        .unwrap()
}

#[test]
fn legacy_v1_sign_and_strict_verify_roundtrip() {
    let identity = DeviceIdentity::generate();
    let message = b"sovereign audit event";
    let signature = identity.sign_legacy_v1(message);
    DeviceIdentity::verify_legacy_v1(identity.public_key_b64(), message, &signature).unwrap();
}

#[test]
fn persist_identity_and_reject_key_mismatch() {
    let directory = test_directory("mismatch");
    let path = directory.join("device.json");
    let identity = DeviceIdentity::generate();
    identity.save(&path).unwrap();
    let loaded = DeviceIdentity::load(&path).unwrap();
    assert_eq!(identity.device_id(), loaded.device_id());
    assert_eq!(identity.public_key_b64(), loaded.public_key_b64());

    let mut stored: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    stored["public_key_b64"] = serde_json::Value::String(
        STANDARD.encode(
            DeviceIdentity::generate()
                .signing_key
                .verifying_key()
                .to_bytes(),
        ),
    );
    std::fs::write(&path, serde_json::to_vec_pretty(&stored).unwrap()).unwrap();
    assert!(matches!(
        DeviceIdentity::load(&path),
        Err(IdentityError::KeyMaterialMismatch("public key"))
    ));

    identity.save(&path).unwrap();
    let mut stored: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    stored["device_id"] = serde_json::Value::String("dev_attacker".into());
    std::fs::write(&path, serde_json::to_vec_pretty(&stored).unwrap()).unwrap();
    assert!(matches!(
        DeviceIdentity::load(&path),
        Err(IdentityError::KeyMaterialMismatch("device id"))
    ));
    std::fs::remove_dir_all(directory).ok();
}

#[cfg(unix)]
#[test]
fn save_and_load_enforce_private_owned_single_link_files() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let directory = test_directory("permissions");
    let path = directory.join("device.json");
    let identity = DeviceIdentity::generate();
    identity.save(&path).unwrap();
    let metadata = std::fs::metadata(&path).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
    assert_eq!(metadata.nlink(), 1);

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        DeviceIdentity::load(&path),
        Err(IdentityError::UnsafePath(_))
    ));
    assert!(matches!(
        identity.save(&path),
        Err(IdentityError::UnsafePath(_))
    ));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let hard_link = directory.join("device-hard-link.json");
    std::fs::hard_link(&path, &hard_link).unwrap();
    assert!(matches!(
        DeviceIdentity::load(&path),
        Err(IdentityError::UnsafePath(_))
    ));
    assert!(matches!(
        identity.save(&path),
        Err(IdentityError::UnsafePath(_))
    ));
    std::fs::remove_file(hard_link).unwrap();
    DeviceIdentity::load(&path).unwrap();

    std::fs::remove_dir_all(directory).ok();
}

#[cfg(unix)]
#[test]
fn rejects_symlink_nonregular_and_unsafe_parent_destinations() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let directory = test_directory("unsafe-paths");
    let identity = DeviceIdentity::generate();

    let target = directory.join("target.json");
    std::fs::write(&target, b"target").unwrap();
    let link = directory.join("link.json");
    symlink(&target, &link).unwrap();
    assert!(matches!(
        identity.save(&link),
        Err(IdentityError::UnsafePath(_))
    ));
    assert!(matches!(
        DeviceIdentity::load(&link),
        Err(IdentityError::Io(_)) | Err(IdentityError::UnsafePath(_))
    ));

    let non_regular = directory.join("directory.json");
    std::fs::create_dir(&non_regular).unwrap();
    assert!(matches!(
        identity.save(&non_regular),
        Err(IdentityError::UnsafePath(_))
    ));

    let writable_parent = directory.join("writable-parent");
    std::fs::create_dir(&writable_parent).unwrap();
    std::fs::set_permissions(&writable_parent, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(matches!(
        identity.save(&writable_parent.join("device.json")),
        Err(IdentityError::UnsafePath(_))
    ));
    std::fs::set_permissions(&writable_parent, std::fs::Permissions::from_mode(0o700)).unwrap();

    let real_parent = directory.join("real-parent");
    std::fs::create_dir(&real_parent).unwrap();
    std::fs::set_permissions(&real_parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    let linked_parent = directory.join("linked-parent");
    symlink(&real_parent, &linked_parent).unwrap();
    assert!(matches!(
        identity.save(&linked_parent.join("device.json")),
        Err(IdentityError::UnsafePath(_))
    ));
    std::fs::remove_dir_all(directory).ok();
}

#[cfg(unix)]
#[test]
fn opened_parent_descriptor_survives_path_replacement() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let directory = test_directory("parent-replacement");
    let original_parent = directory.join("original");
    std::fs::create_dir(&original_parent).unwrap();
    std::fs::set_permissions(&original_parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = original_parent.join("device.bin");
    let (opened_parent, name) = open_parent_and_name(&path).unwrap();

    let moved_parent = directory.join("moved");
    std::fs::rename(&original_parent, &moved_parent).unwrap();
    let replacement_parent = directory.join("replacement");
    std::fs::create_dir(&replacement_parent).unwrap();
    std::fs::set_permissions(&replacement_parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    symlink(&replacement_parent, &original_parent).unwrap();

    atomic_write_private_at(&opened_parent, &name, &path, b"stable-parent").unwrap();
    assert_eq!(
        std::fs::read(moved_parent.join("device.bin")).unwrap(),
        b"stable-parent"
    );
    assert!(!replacement_parent.join("device.bin").exists());
    drop(opened_parent);
    std::fs::remove_dir_all(directory).ok();
}

#[test]
fn typed_cose_roundtrip_has_expected_protected_headers() {
    let signer = TypedSigner::<AuthorityRole>::generate("authority.example").unwrap();
    let encoded = signer.sign_cose(br#"{"operation":"draft"}"#).unwrap();
    let parsed = CoseSign1::from_tagged_slice(&encoded).unwrap();
    assert_eq!(
        parsed.protected.header,
        expected_protected_header::<AuthorityRole>(signer.key_id())
    );
    assert!(parsed.unprotected.is_empty());

    let mut store = RoleTrustStore::<AuthorityRole>::new();
    store.trust_signer(&signer, validity()).unwrap();
    let verified = store.verify(&encoded, "authority.example", 150).unwrap();
    assert_eq!(verified.payload(), br#"{"operation":"draft"}"#);
    assert_eq!(verified.issuer(), "authority.example");
    assert_eq!(verified.key_id(), signer.key_id());
}

#[test]
fn role_key_ids_prevent_cross_role_use() {
    let secret = [7_u8; 32];
    let authority = TypedSigner::<AuthorityRole>::from_secret_bytes("same-issuer", secret).unwrap();
    let audit = TypedSigner::<AuditRole>::from_secret_bytes("same-issuer", secret).unwrap();
    assert_ne!(authority.key_id(), audit.key_id());

    let encoded = authority.sign_cose(b"same payload").unwrap();
    let mut audit_store = RoleTrustStore::<AuditRole>::new();
    audit_store.trust_signer(&audit, validity()).unwrap();
    assert!(matches!(
        audit_store.verify(&encoded, "same-issuer", 150),
        Err(IdentityError::UnknownKeyId)
    ));
}

#[test]
fn external_aad_is_verified_after_header_and_key_match() {
    let signer = TypedSigner::<AuthorityRole>::generate("authority.example").unwrap();
    let encoded = sign_custom_cose(
        &signer,
        expected_protected_header::<AuthorityRole>(signer.key_id()),
        HeaderBuilder::new().build(),
        b"capability",
        b"wrong-external-aad",
    );
    let mut store = RoleTrustStore::<AuthorityRole>::new();
    store.trust_signer(&signer, validity()).unwrap();

    assert!(matches!(
        store.verify(&encoded, "authority.example", 150),
        Err(IdentityError::VerificationFailed)
    ));
}

#[test]
fn rejects_protected_header_and_unprotected_downgrades() {
    let signer = TypedSigner::<AuthorityRole>::generate("authority.example").unwrap();
    let mut store = RoleTrustStore::<AuthorityRole>::new();
    store.trust_signer(&signer, validity()).unwrap();
    let empty = || HeaderBuilder::new().build();

    let wrong_algorithm = HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES256)
        .key_id(signer.key_id().to_vec())
        .content_type(AuthorityRole::CONTENT_TYPE.to_owned())
        .build();
    let encoded = sign_custom_cose(
        &signer,
        wrong_algorithm,
        empty(),
        b"capability",
        AuthorityRole::EXTERNAL_AAD,
    );
    assert!(matches!(
        store.verify(&encoded, "authority.example", 150),
        Err(IdentityError::InvalidProtectedHeaders)
    ));

    let wrong_content_type = HeaderBuilder::new()
        .algorithm(iana::Algorithm::EdDSA)
        .key_id(signer.key_id().to_vec())
        .content_type("application/sovereign.audit-event+json;v=1".to_owned())
        .build();
    let encoded = sign_custom_cose(
        &signer,
        wrong_content_type,
        empty(),
        b"capability",
        AuthorityRole::EXTERNAL_AAD,
    );
    assert!(matches!(
        store.verify(&encoded, "authority.example", 150),
        Err(IdentityError::InvalidProtectedHeaders)
    ));

    let encoded = sign_custom_cose(
        &signer,
        expected_protected_header::<AuthorityRole>(signer.key_id()),
        HeaderBuilder::new()
            .key_id(signer.key_id().to_vec())
            .build(),
        b"capability",
        AuthorityRole::EXTERNAL_AAD,
    );
    assert!(matches!(
        store.verify(&encoded, "authority.example", 150),
        Err(IdentityError::UnprotectedHeadersForbidden)
    ));
}

#[test]
fn rejects_noncanonical_cose_and_payload_tampering() {
    let signer = TypedSigner::<PublisherRole>::generate("publisher.example").unwrap();
    let encoded = signer.sign_cose(b"manifest-v1").unwrap();
    let mut store = RoleTrustStore::<PublisherRole>::new();
    store.trust_signer(&signer, validity()).unwrap();

    assert_eq!(encoded[0], 0xd2, "expected canonical CBOR tag 18");
    let mut noncanonical = vec![0xd8, 0x12];
    noncanonical.extend_from_slice(&encoded[1..]);
    assert!(matches!(
        store.verify(&noncanonical, "publisher.example", 150),
        Err(IdentityError::NonCanonicalCose)
    ));

    let mut parsed = CoseSign1::from_tagged_slice(&encoded).unwrap();
    parsed.payload = Some(b"substituted-manifest".to_vec());
    let tampered = parsed.to_tagged_vec().unwrap();
    assert!(matches!(
        store.verify(&tampered, "publisher.example", 150),
        Err(IdentityError::VerificationFailed)
    ));
}

#[test]
fn trust_store_enforces_issuer_revocation_and_validity() {
    let signer = TypedSigner::<AuditRole>::generate("device.example").unwrap();
    let encoded = signer.sign_cose(b"audit-event").unwrap();
    let mut store = RoleTrustStore::<AuditRole>::new();
    let key_id = store.trust_signer(&signer, validity()).unwrap();

    assert!(matches!(
        store.verify(&encoded, "other.example", 150),
        Err(IdentityError::IssuerMismatch)
    ));
    assert!(matches!(
        store.verify(&encoded, "device.example", 99),
        Err(IdentityError::KeyNotYetValid)
    ));
    assert!(matches!(
        store.verify(&encoded, "device.example", 200),
        Err(IdentityError::KeyExpired)
    ));
    store.revoke(&key_id).unwrap();
    assert!(matches!(
        store.verify(&encoded, "device.example", 150),
        Err(IdentityError::KeyRevoked)
    ));
}

#[test]
fn debug_output_redacts_secrets_and_verified_payloads() {
    let secret = [0xa5_u8; 32];
    let identity = DeviceIdentity::from_signing_key(SigningKey::from_bytes(&secret));
    let identity_debug = format!("{identity:?}");
    assert!(!identity_debug.contains(&STANDARD.encode(secret)));
    assert!(!identity_debug.contains("signing_key"));

    let signer = TypedSigner::<AuditRole>::from_secret_bytes("device.example", secret).unwrap();
    let signer_debug = format!("{signer:?}");
    assert!(!signer_debug.contains(&STANDARD.encode(secret)));
    assert!(!signer_debug.contains("signing_key"));

    let verified = VerifiedCosePayload {
        issuer: "device.example".into(),
        key_id: *signer.key_id(),
        payload: b"secret audit payload".to_vec(),
    };
    let verified_debug = format!("{verified:?}");
    assert!(!verified_debug.contains("secret audit payload"));
    assert!(verified_debug.contains("payload_len"));
}
