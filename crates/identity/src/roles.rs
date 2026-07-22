mod role_sealed {
    pub trait Sealed {}
}

/// A closed set of signing roles. External crates can use these roles but
/// cannot introduce a role that accidentally reuses a security domain.
pub trait SigningRole: role_sealed::Sealed + Send + Sync + 'static {
    const NAME: &'static str;
    const CONTENT_TYPE: &'static str;
    const EXTERNAL_AAD: &'static [u8];
}

#[derive(Debug)]
pub enum PublisherRole {}

#[derive(Debug)]
pub enum AuthorityRole {}

#[derive(Debug)]
pub enum AuditRole {}

#[derive(Debug)]
pub enum AdmissionRole {}

#[derive(Debug)]
pub enum ApprovalRole {}

impl role_sealed::Sealed for PublisherRole {}
impl role_sealed::Sealed for AuthorityRole {}
impl role_sealed::Sealed for AuditRole {}
impl role_sealed::Sealed for AdmissionRole {}
impl role_sealed::Sealed for ApprovalRole {}

impl SigningRole for PublisherRole {
    const NAME: &'static str = "publisher";
    const CONTENT_TYPE: &'static str = "application/sovereign.plugin-manifest+json;v=1";
    const EXTERNAL_AAD: &'static [u8] = b"sovereign:plugin-manifest:v1";
}

impl SigningRole for AuthorityRole {
    const NAME: &'static str = "authority";
    const CONTENT_TYPE: &'static str = "application/sovereign.capability+json;v=2";
    const EXTERNAL_AAD: &'static [u8] = b"sovereign:capability:v2";
}

impl SigningRole for AuditRole {
    const NAME: &'static str = "audit";
    const CONTENT_TYPE: &'static str = "application/sovereign.audit-event+json;v=1";
    const EXTERNAL_AAD: &'static [u8] = b"sovereign:audit-event:v1";
}

impl SigningRole for AdmissionRole {
    const NAME: &'static str = "artifact-admission";
    const CONTENT_TYPE: &'static str = "application/sovereign.artifact-admission+json;v=1";
    const EXTERNAL_AAD: &'static [u8] = b"sovereign:artifact-admission:v1";
}

impl SigningRole for ApprovalRole {
    const NAME: &'static str = "approval";
    const CONTENT_TYPE: &'static str = "application/sovereign.approval+json;v=1";
    const EXTERNAL_AAD: &'static [u8] = b"sovereign:approval:v1";
}
