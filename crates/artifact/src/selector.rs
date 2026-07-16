use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Structured operation identity. It is deliberately not represented as a
/// dotted string, avoiding collisions between tool and operation segments.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationSelector {
    tool_id: String,
    tool_version: String,
    operation_id: String,
}

impl OperationSelector {
    pub fn new(
        tool_id: impl Into<String>,
        tool_version: impl Into<String>,
        operation_id: impl Into<String>,
    ) -> Result<Self, SelectorError> {
        let selector = Self {
            tool_id: tool_id.into(),
            tool_version: tool_version.into(),
            operation_id: operation_id.into(),
        };
        selector.validate()?;
        Ok(selector)
    }

    pub fn tool_id(&self) -> &str {
        &self.tool_id
    }

    pub fn tool_version(&self) -> &str {
        &self.tool_version
    }

    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub(crate) fn validate(&self) -> Result<(), SelectorError> {
        validate_segment("tool_id", &self.tool_id, 128, true)?;
        validate_segment("tool_version", &self.tool_version, 64, true)?;
        validate_segment("operation_id", &self.operation_id, 128, false)
    }
}

fn validate_segment(
    field: &'static str,
    value: &str,
    maximum: usize,
    allow_plus: bool,
) -> Result<(), SelectorError> {
    if value.is_empty() || value.len() > maximum {
        return Err(SelectorError::InvalidLength {
            field,
            maximum,
            actual: value.len(),
        });
    }
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(byte, b'.' | b'_' | b'-')
            || (allow_plus && byte == b'+')
    }) {
        return Err(SelectorError::InvalidCharacters(field));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SelectorError {
    #[error("{field} must contain 1..={maximum} bytes, got {actual}")]
    InvalidLength {
        field: &'static str,
        maximum: usize,
        actual: usize,
    },
    #[error("{0} contains unsupported characters")]
    InvalidCharacters(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structured_selector_keeps_segments_exact() {
        let selector = OperationSelector::new("document.transform", "1.2.0", "render_pdf").unwrap();
        assert_eq!(selector.tool_id(), "document.transform");
        assert_eq!(selector.tool_version(), "1.2.0");
        assert_eq!(selector.operation_id(), "render_pdf");
        assert!(OperationSelector::new("document", "1", "render/pdf").is_err());
    }
}
