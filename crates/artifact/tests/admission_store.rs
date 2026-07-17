//! Adversarial tests for the local artifact admission transaction:
//! content-addressed storage, the locally signed admission record, and the
//! fail-closed load path.

use std::path::Path;

use sovereign_artifact::{
    AdmissionLimits, ArtifactError, ArtifactStore, ArtifactVerificationIntent, ArtifactVerifier,
    Digest, InstallationState, OperationSelector, PreparedInvocation, RawResourceGrant,
    TrustedClock, VerifiedArtifact, ADMISSION_RECORD_TYPE, ADMISSION_RECORD_VERSION,
    CANONICALIZATION_PROFILE, CORE_WASM_ENTRYPOINT, MANIFEST_PROTOCOL_VERSION,
};
use sovereign_identity::{AdmissionRole, KeyValidity, PublisherRole, RoleTrustStore, TypedSigner};
use uuid::Uuid;

const NOW: i64 = 1_800_000_000;
const PUBLISHER_ISSUER: &str = "publisher.local";
const ADMISSION_ISSUER: &str = "owner-device.local";
const PUBLISHER_SECRET: [u8; 32] = [0x50; 32];
const ADMISSION_SECRET: [u8; 32] = [0x61; 32];
const RESOURCE: &str = "draft:alpha";

#[derive(Debug, Clone, Copy)]
struct FixedClock(i64);

impl TrustedClock for FixedClock {
    fn now_unix(&self) -> i64 {
        self.0
    }
}

fn selector() -> OperationSelector {
    OperationSelector::new("document.transform", "1.0.0", "render").unwrap()
}

fn verified_artifact(component: &[u8]) -> VerifiedArtifact {
    let publisher =
        TypedSigner::<PublisherRole>::from_secret_bytes(PUBLISHER_ISSUER, PUBLISHER_SECRET)
            .unwrap();
    let manifest = serde_json::json!({
        "protocol_version": MANIFEST_PROTOCOL_VERSION,
        "publisher_issuer": PUBLISHER_ISSUER,
        "publisher_key_id": Digest::from_bytes(*publisher.key_id()),
        "component_digest": Digest::of_bytes(component),
        "backend": "core_wasm",
        "risk_class": "pure_compute",
        "abi": "sovereign_core_wasm_v1",
        "entrypoint": CORE_WASM_ENTRYPOINT,
        "requested_host_capabilities": [],
        "operations": [{
            "selector": {
                "tool_id": "document.transform",
                "tool_version": "1.0.0",
                "operation_id": "render"
            },
            "input_limits": { "max_bytes": 4096, "max_depth": 8 },
            "input_schema": {
                "type": "object",
                "properties": {
                    "content": { "type": "string", "max_utf8_bytes": 2048 },
                    "resource": { "type": "string", "max_utf8_bytes": 256 }
                },
                "required": ["content", "resource"],
                "max_properties": 2
            },
            "resource_bindings": [{
                "binding_id": "primary",
                "json_pointer": "/resource",
                "normalization": "exact_utf8_v1",
                "primary": true
            }]
        }]
    });
    let canonical_manifest = serde_json_canonicalizer::to_vec(&manifest).unwrap();
    let signed_manifest = publisher.sign_cose(&canonical_manifest).unwrap();
    let mut publishers = RoleTrustStore::<PublisherRole>::new();
    publishers
        .trust_signer(&publisher, KeyValidity::new(NOW - 60, NOW + 3_600).unwrap())
        .unwrap();
    let intent = ArtifactVerificationIntent::new(
        PUBLISHER_ISSUER,
        Digest::of_bytes(&signed_manifest),
        Digest::of_bytes(component),
    )
    .unwrap();
    ArtifactVerifier::with_clock(&publishers, AdmissionLimits::default(), FixedClock(NOW))
        .verify(&intent, &signed_manifest, component)
        .unwrap()
}

fn admission_signer() -> TypedSigner<AdmissionRole> {
    TypedSigner::<AdmissionRole>::from_secret_bytes(ADMISSION_ISSUER, ADMISSION_SECRET).unwrap()
}

fn admission_trust() -> RoleTrustStore<AdmissionRole> {
    let mut store = RoleTrustStore::<AdmissionRole>::new();
    store
        .trust_signer(
            &admission_signer(),
            KeyValidity::new(NOW - 60, NOW + 3_600).unwrap(),
        )
        .unwrap();
    store
}

fn prepare(artifact: &VerifiedArtifact, content: &str) -> PreparedInvocation {
    let input = serde_json::to_vec(&serde_json::json!({
        "content": content,
        "resource": RESOURCE
    }))
    .unwrap();
    PreparedInvocation::prepare(
        artifact,
        &selector(),
        &input,
        vec![RawResourceGrant::new("primary", RESOURCE)],
    )
    .unwrap()
}

fn corrupt_stored_file(root: &Path, subdir: &str, name_hex: &str, bytes: &[u8]) {
    let path = root.join(subdir).join(name_hex);
    assert!(path.exists(), "expected stored entry at {}", path.display());
    std::fs::write(path, bytes).unwrap();
}

#[test]
fn admit_then_load_round_trips_the_exact_artifact() {
    let dir = tempfile::tempdir().unwrap();
    let store = ArtifactStore::open(dir.path()).unwrap();
    let artifact = verified_artifact(b"component-alpha");
    let admitted = store
        .admit(&artifact, &admission_signer(), &FixedClock(NOW))
        .unwrap();
    assert_eq!(admitted.record().typ, ADMISSION_RECORD_TYPE);
    assert_eq!(admitted.record().version, ADMISSION_RECORD_VERSION);
    assert_eq!(
        admitted.record().canonicalization_profile,
        CANONICALIZATION_PROFILE
    );
    assert_eq!(
        admitted.record().installation_state,
        InstallationState::Admitted
    );

    let loaded = store
        .load(
            artifact.component_digest(),
            artifact.manifest_digest(),
            &admission_trust(),
            ADMISSION_ISSUER,
            &FixedClock(NOW + 10),
        )
        .unwrap();
    assert_eq!(
        loaded.artifact().component_digest(),
        artifact.component_digest()
    );
    assert_eq!(
        loaded.artifact().manifest_digest(),
        artifact.manifest_digest()
    );
    assert_eq!(loaded.admission_id(), admitted.admission_id());

    // The loaded artifact prepares an invocation with identical commitments,
    // proving the execution-relevant identity survived the store round trip.
    let original = prepare(&artifact, "same input");
    let reloaded = prepare(loaded.artifact(), "same input");
    assert_eq!(original.input_digest(), reloaded.input_digest());
    assert_eq!(original.bindings_digest(), reloaded.bindings_digest());
    assert_eq!(original.canonical_input(), reloaded.canonical_input());
}

#[test]
fn stored_component_substitution_is_detected_on_load() {
    let dir = tempfile::tempdir().unwrap();
    let store = ArtifactStore::open(dir.path()).unwrap();
    let artifact = verified_artifact(b"component-alpha");
    store
        .admit(&artifact, &admission_signer(), &FixedClock(NOW))
        .unwrap();

    corrupt_stored_file(
        dir.path(),
        "objects",
        &artifact.component_digest().as_hex(),
        b"attacker-substituted-bytes",
    );
    let error = store
        .load(
            artifact.component_digest(),
            artifact.manifest_digest(),
            &admission_trust(),
            ADMISSION_ISSUER,
            &FixedClock(NOW + 10),
        )
        .unwrap_err();
    assert!(matches!(
        error,
        ArtifactError::StoredComponentCorrupted { .. }
    ));
}

#[test]
fn stored_manifest_substitution_is_detected_on_load() {
    let dir = tempfile::tempdir().unwrap();
    let store = ArtifactStore::open(dir.path()).unwrap();
    let artifact = verified_artifact(b"component-alpha");
    let other = verified_artifact(b"component-beta");
    store
        .admit(&artifact, &admission_signer(), &FixedClock(NOW))
        .unwrap();

    // Substitute another artifact's canonical manifest bytes under this
    // manifest's digest-shaped filename. The recomputed digest must win.
    let other_store_dir = tempfile::tempdir().unwrap();
    let other_store = ArtifactStore::open(other_store_dir.path()).unwrap();
    other_store
        .admit(&other, &admission_signer(), &FixedClock(NOW))
        .unwrap();
    let other_manifest_bytes = std::fs::read(
        other_store_dir
            .path()
            .join("manifests")
            .join(other.manifest_digest().as_hex()),
    )
    .unwrap();
    corrupt_stored_file(
        dir.path(),
        "manifests",
        &artifact.manifest_digest().as_hex(),
        &other_manifest_bytes,
    );

    let error = store
        .load(
            artifact.component_digest(),
            artifact.manifest_digest(),
            &admission_trust(),
            ADMISSION_ISSUER,
            &FixedClock(NOW + 10),
        )
        .unwrap_err();
    assert_eq!(error, ArtifactError::StoredManifestCorrupted);
}

#[test]
fn tampered_and_cross_role_admission_records_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let store = ArtifactStore::open(dir.path()).unwrap();
    let artifact = verified_artifact(b"component-alpha");
    let admitted = store
        .admit(&artifact, &admission_signer(), &FixedClock(NOW))
        .unwrap();

    let record_path = dir
        .path()
        .join("admissions")
        .join(artifact.manifest_digest().as_hex());
    let original_record = std::fs::read(&record_path).unwrap();

    // Bit-flip in the signed envelope.
    let mut tampered = original_record.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    std::fs::write(&record_path, &tampered).unwrap();
    let error = store
        .load(
            artifact.component_digest(),
            artifact.manifest_digest(),
            &admission_trust(),
            ADMISSION_ISSUER,
            &FixedClock(NOW + 10),
        )
        .unwrap_err();
    assert!(matches!(
        error,
        ArtifactError::InvalidAdmissionSignature
            | ArtifactError::InvalidAdmissionEnvelope
            | ArtifactError::UnknownAdmissionKey
    ));

    // Same secret key signing under the publisher role must not verify as an
    // admission record: the role domain (kid derivation, content type, AAD)
    // differs even though the raw key bytes are identical.
    let publisher_role_signer =
        TypedSigner::<PublisherRole>::from_secret_bytes(ADMISSION_ISSUER, ADMISSION_SECRET)
            .unwrap();
    let claims = serde_json_canonicalizer::to_vec(&admitted.record()).unwrap();
    let cross_role = publisher_role_signer.sign_cose(&claims).unwrap();
    std::fs::write(&record_path, &cross_role).unwrap();
    let error = store
        .load(
            artifact.component_digest(),
            artifact.manifest_digest(),
            &admission_trust(),
            ADMISSION_ISSUER,
            &FixedClock(NOW + 10),
        )
        .unwrap_err();
    assert!(matches!(
        error,
        ArtifactError::UnknownAdmissionKey | ArtifactError::InvalidAdmissionEnvelope
    ));
}

#[test]
fn untrusted_revoked_and_expired_admission_keys_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let store = ArtifactStore::open(dir.path()).unwrap();
    let artifact = verified_artifact(b"component-alpha");
    store
        .admit(&artifact, &admission_signer(), &FixedClock(NOW))
        .unwrap();

    // Empty trust store: the signer is unknown.
    let empty = RoleTrustStore::<AdmissionRole>::new();
    let error = store
        .load(
            artifact.component_digest(),
            artifact.manifest_digest(),
            &empty,
            ADMISSION_ISSUER,
            &FixedClock(NOW + 10),
        )
        .unwrap_err();
    assert_eq!(error, ArtifactError::UnknownAdmissionKey);

    // Revoked key.
    let mut revoked = admission_trust();
    revoked.revoke(admission_signer().key_id()).unwrap();
    let error = store
        .load(
            artifact.component_digest(),
            artifact.manifest_digest(),
            &revoked,
            ADMISSION_ISSUER,
            &FixedClock(NOW + 10),
        )
        .unwrap_err();
    assert_eq!(error, ArtifactError::AdmissionKeyRevoked);

    // Expired key window.
    let error = store
        .load(
            artifact.component_digest(),
            artifact.manifest_digest(),
            &admission_trust(),
            ADMISSION_ISSUER,
            &FixedClock(NOW + 10_000),
        )
        .unwrap_err();
    assert_eq!(error, ArtifactError::AdmissionKeyExpired);

    // Issuer mismatch.
    let error = store
        .load(
            artifact.component_digest(),
            artifact.manifest_digest(),
            &admission_trust(),
            "different-owner.local",
            &FixedClock(NOW + 10),
        )
        .unwrap_err();
    assert_eq!(error, ArtifactError::AdmissionIssuerMismatch);
}

#[test]
fn forged_claims_signed_by_a_trusted_key_still_fail_field_validation() {
    let dir = tempfile::tempdir().unwrap();
    let store = ArtifactStore::open(dir.path()).unwrap();
    let artifact = verified_artifact(b"component-alpha");
    let admitted = store
        .admit(&artifact, &admission_signer(), &FixedClock(NOW))
        .unwrap();
    let record_path = dir
        .path()
        .join("admissions")
        .join(artifact.manifest_digest().as_hex());

    let write_claims = |mutate: &dyn Fn(&mut serde_json::Value)| {
        let mut value = serde_json::to_value(admitted.record()).unwrap();
        mutate(&mut value);
        let canonical = serde_json_canonicalizer::to_vec(&value).unwrap();
        let signed = admission_signer().sign_cose(&canonical).unwrap();
        std::fs::write(&record_path, signed).unwrap();
    };
    let load = || {
        store.load(
            artifact.component_digest(),
            artifact.manifest_digest(),
            &admission_trust(),
            ADMISSION_ISSUER,
            &FixedClock(NOW + 10),
        )
    };

    write_claims(&|value| value["installation_state"] = "revoked".into());
    assert_eq!(
        load().unwrap_err(),
        ArtifactError::AdmissionRecordMismatch("installation_state")
    );

    write_claims(&|value| {
        value["component_digest"] = Digest::of_bytes(b"component-beta").as_hex().into()
    });
    assert_eq!(
        load().unwrap_err(),
        ArtifactError::AdmissionRecordMismatch("component_digest")
    );

    write_claims(&|value| {
        value["effective_host_capabilities"] = serde_json::json!(["filesystem.read"])
    });
    assert_eq!(
        load().unwrap_err(),
        ArtifactError::AdmissionRecordMismatch("effective_host_capabilities")
    );

    write_claims(&|value| value["admitted_at_unix"] = (NOW + 10_000).into());
    assert_eq!(
        load().unwrap_err(),
        ArtifactError::AdmissionRecordMismatch("admitted_at_unix")
    );

    write_claims(&|value| value["typ"] = "sovereign.capability".into());
    assert_eq!(
        load().unwrap_err(),
        ArtifactError::AdmissionRecordMismatch("typ")
    );

    write_claims(&|value| {
        value["unknown_field"] = "unexpected".into();
    });
    assert!(matches!(
        load().unwrap_err(),
        ArtifactError::InvalidAdmissionRecord(_)
    ));
}

#[test]
fn poisoned_content_addressed_entry_is_rejected_before_reuse() {
    let dir = tempfile::tempdir().unwrap();
    let store = ArtifactStore::open(dir.path()).unwrap();
    let artifact = verified_artifact(b"component-alpha");

    // Pre-place attacker bytes at the digest-shaped path before admission.
    std::fs::write(
        dir.path()
            .join("objects")
            .join(artifact.component_digest().as_hex()),
        b"poisoned-entry",
    )
    .unwrap();

    let error = store
        .admit(&artifact, &admission_signer(), &FixedClock(NOW))
        .unwrap_err();
    assert!(matches!(
        error,
        ArtifactError::StoredComponentCorrupted { .. }
    ));
    // Fail-closed: no admission record may be published for the poisoned entry.
    assert!(!dir
        .path()
        .join("admissions")
        .join(artifact.manifest_digest().as_hex())
        .exists());
}

#[test]
fn duplicate_admission_is_rejected_and_original_record_is_preserved() {
    let dir = tempfile::tempdir().unwrap();
    let store = ArtifactStore::open(dir.path()).unwrap();
    let artifact = verified_artifact(b"component-alpha");
    store
        .admit(&artifact, &admission_signer(), &FixedClock(NOW))
        .unwrap();
    let record_path = dir
        .path()
        .join("admissions")
        .join(artifact.manifest_digest().as_hex());
    let original_record = std::fs::read(&record_path).unwrap();

    let error = store
        .admit(&artifact, &admission_signer(), &FixedClock(NOW + 1))
        .unwrap_err();
    assert_eq!(error, ArtifactError::AdmissionRecordExists);
    assert_eq!(std::fs::read(&record_path).unwrap(), original_record);
}

#[test]
fn orphan_temporary_files_are_never_loadable() {
    let dir = tempfile::tempdir().unwrap();
    let store = ArtifactStore::open(dir.path()).unwrap();
    let artifact = verified_artifact(b"component-alpha");

    // Simulate a crash that left temp files but never published entries.
    let component_hex = artifact.component_digest().as_hex();
    let manifest_hex = artifact.manifest_digest().as_hex();
    std::fs::write(
        dir.path()
            .join("objects")
            .join(format!("{component_hex}.tmp-{}", Uuid::new_v4())),
        artifact.bytes(),
    )
    .unwrap();
    std::fs::write(
        dir.path()
            .join("admissions")
            .join(format!("{manifest_hex}.tmp-{}", Uuid::new_v4())),
        b"partial",
    )
    .unwrap();

    let error = store
        .load(
            artifact.component_digest(),
            artifact.manifest_digest(),
            &admission_trust(),
            ADMISSION_ISSUER,
            &FixedClock(NOW + 10),
        )
        .unwrap_err();
    assert_eq!(error, ArtifactError::AdmissionRecordNotFound);
}

#[cfg(unix)]
#[test]
fn symlinked_store_entries_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let store = ArtifactStore::open(dir.path()).unwrap();
    let artifact = verified_artifact(b"component-alpha");
    store
        .admit(&artifact, &admission_signer(), &FixedClock(NOW))
        .unwrap();

    let object_path = dir
        .path()
        .join("objects")
        .join(artifact.component_digest().as_hex());
    let outside = dir.path().join("outside-bytes");
    std::fs::write(&outside, artifact.bytes()).unwrap();
    std::fs::remove_file(&object_path).unwrap();
    std::os::unix::fs::symlink(&outside, &object_path).unwrap();

    let error = store
        .load(
            artifact.component_digest(),
            artifact.manifest_digest(),
            &admission_trust(),
            ADMISSION_ISSUER,
            &FixedClock(NOW + 10),
        )
        .unwrap_err();
    assert_eq!(error, ArtifactError::StoredEntryNotRegularFile);
}
