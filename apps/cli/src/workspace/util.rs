use super::*;

pub(super) fn kernel(error: impl std::fmt::Display) -> WorkspaceError {
    WorkspaceError::Storage(format!("kernel chain failed closed: {error}"))
}

/// Parse a decimal money string ("2500", "2500.5", "2500.50") into cents
/// without floating point.
pub fn parse_amount_cents(text: &str) -> Result<u64, WorkspaceError> {
    let text = text.trim();
    let invalid = || WorkspaceError::Invalid("invalid amount".into());
    if text.is_empty() || text.len() > 16 {
        return Err(invalid());
    }
    let (whole, fraction) = match text.split_once('.') {
        Some((whole, fraction)) => (whole, fraction),
        None => (text, ""),
    };
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || fraction.len() > 2
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(invalid());
    }
    let whole: u64 = whole.parse().map_err(|_| invalid())?;
    let fraction_cents = match fraction.len() {
        0 => 0,
        1 => fraction.parse::<u64>().map_err(|_| invalid())? * 10,
        _ => fraction.parse::<u64>().map_err(|_| invalid())?,
    };
    whole
        .checked_mul(100)
        .and_then(|cents| cents.checked_add(fraction_cents))
        .ok_or_else(invalid)
}

pub(super) fn clean_text(field: &str, value: &str) -> Result<String, WorkspaceError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(WorkspaceError::Invalid(format!("{field} is required")));
    }
    clean_optional_text(field, value)
}

pub(super) fn clean_optional_text(field: &str, value: &str) -> Result<String, WorkspaceError> {
    let value = value.trim();
    if value.len() > MAX_TEXT_FIELD_BYTES {
        return Err(WorkspaceError::Invalid(format!("{field} is too long")));
    }
    if value.chars().any(|ch| ch.is_control() && ch != '\n') {
        return Err(WorkspaceError::Invalid(format!(
            "{field} contains control characters"
        )));
    }
    Ok(value.to_owned())
}

/// Validate an optional contact email. Empty is allowed (the founder can add
/// it later). A non-empty value must be a single-line, single-`@` address with
/// no spaces or header-injection characters — enough to place safely in an
/// RFC 5322 `To:` header without claiming full RFC 5321 validation.
pub(super) fn clean_email(value: &str) -> Result<String, WorkspaceError> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(String::new());
    }
    if value.len() > 254 {
        return Err(WorkspaceError::Invalid("email is too long".into()));
    }
    let at_count = value.bytes().filter(|byte| *byte == b'@').count();
    let structural =
        at_count == 1 && !value.starts_with('@') && !value.ends_with('@') && value.contains('.');
    let no_injection = value
        .bytes()
        .all(|byte| !byte.is_ascii_control() && !matches!(byte, b' ' | b'\t' | b',' | b'<' | b'>'));
    if !structural || !no_injection {
        return Err(WorkspaceError::Invalid(
            "email is not a valid address".into(),
        ));
    }
    Ok(value.to_owned())
}

pub(super) fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

pub(super) fn storage(error: impl std::fmt::Display) -> WorkspaceError {
    WorkspaceError::Storage(error.to_string())
}
