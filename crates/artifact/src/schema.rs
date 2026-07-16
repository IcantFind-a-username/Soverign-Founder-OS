use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Number, Value};

use crate::ArtifactError;

pub const MAX_DECLARED_INPUT_BYTES: usize = 1024 * 1024;
pub const MAX_DECLARED_INPUT_DEPTH: usize = 64;
pub const IJSON_SAFE_INTEGER_MIN: i64 = -9_007_199_254_740_991;
pub const IJSON_SAFE_INTEGER_MAX: i64 = 9_007_199_254_740_991;
const MAX_SCHEMA_PROPERTIES: usize = 256;
const MAX_DECLARED_ARRAY_ITEMS: usize = 65_536;
const DUPLICATE_KEY_MARKER: &str = "sovereign_duplicate_json_key:";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputLimits {
    max_bytes: usize,
    max_depth: usize,
}

impl InputLimits {
    pub fn new(max_bytes: usize, max_depth: usize) -> Result<Self, ArtifactError> {
        let limits = Self {
            max_bytes,
            max_depth,
        };
        limits.validate()?;
        Ok(limits)
    }

    pub fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    pub fn max_depth(&self) -> usize {
        self.max_depth
    }

    pub(crate) fn validate(&self) -> Result<(), ArtifactError> {
        if self.max_bytes == 0 || self.max_bytes > MAX_DECLARED_INPUT_BYTES {
            return Err(ArtifactError::InvalidInputSchema(format!(
                "max_bytes must be in 1..={MAX_DECLARED_INPUT_BYTES}"
            )));
        }
        if self.max_depth == 0 || self.max_depth > MAX_DECLARED_INPUT_DEPTH {
            return Err(ArtifactError::InvalidInputSchema(format!(
                "max_depth must be in 1..={MAX_DECLARED_INPUT_DEPTH}"
            )));
        }
        Ok(())
    }
}

/// Deliberately small, strict recursive JSON schema used at the security
/// boundary. Objects never permit undeclared fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum InputSchema {
    Object {
        properties: BTreeMap<String, InputSchema>,
        required: BTreeSet<String>,
        max_properties: usize,
    },
    Array {
        items: Box<InputSchema>,
        max_items: usize,
    },
    String {
        max_utf8_bytes: usize,
    },
    Integer {
        minimum: Option<i64>,
        maximum: Option<i64>,
    },
    Boolean,
    Null,
}

impl InputSchema {
    pub(crate) fn validate_declaration(&self, limits: &InputLimits) -> Result<(), ArtifactError> {
        limits.validate()?;
        let mut stack = vec![(self, 1_usize)];
        while let Some((schema, depth)) = stack.pop() {
            if depth > limits.max_depth {
                return Err(ArtifactError::InvalidInputSchema(
                    "schema depth exceeds declared input depth".into(),
                ));
            }
            match schema {
                Self::Object {
                    properties,
                    required,
                    max_properties,
                } => {
                    if *max_properties == 0 || *max_properties > MAX_SCHEMA_PROPERTIES {
                        return Err(ArtifactError::InvalidInputSchema(format!(
                            "max_properties must be in 1..={MAX_SCHEMA_PROPERTIES}"
                        )));
                    }
                    if properties.len() > *max_properties {
                        return Err(ArtifactError::InvalidInputSchema(
                            "properties exceed max_properties".into(),
                        ));
                    }
                    if required.iter().any(|name| !properties.contains_key(name)) {
                        return Err(ArtifactError::InvalidInputSchema(
                            "required contains an undeclared property".into(),
                        ));
                    }
                    for name in properties.keys() {
                        validate_property_name(name)?;
                    }
                    for child in properties.values() {
                        stack.push((child, depth + 1));
                    }
                }
                Self::Array { items, max_items } => {
                    if *max_items == 0 || *max_items > MAX_DECLARED_ARRAY_ITEMS {
                        return Err(ArtifactError::InvalidInputSchema(format!(
                            "max_items must be in 1..={MAX_DECLARED_ARRAY_ITEMS}"
                        )));
                    }
                    stack.push((items, depth + 1));
                }
                Self::String { max_utf8_bytes } => {
                    if *max_utf8_bytes == 0 || *max_utf8_bytes > limits.max_bytes {
                        return Err(ArtifactError::InvalidInputSchema(
                            "max_utf8_bytes must fit the operation byte limit".into(),
                        ));
                    }
                }
                Self::Integer { minimum, maximum } => {
                    if minimum.is_some_and(|value| {
                        !(IJSON_SAFE_INTEGER_MIN..=IJSON_SAFE_INTEGER_MAX).contains(&value)
                    }) || maximum.is_some_and(|value| {
                        !(IJSON_SAFE_INTEGER_MIN..=IJSON_SAFE_INTEGER_MAX).contains(&value)
                    }) {
                        return Err(ArtifactError::InvalidInputSchema(format!(
                            "integer bounds must stay in {IJSON_SAFE_INTEGER_MIN}..={IJSON_SAFE_INTEGER_MAX}"
                        )));
                    }
                    if (*minimum).zip(*maximum).is_some_and(|(min, max)| min > max) {
                        return Err(ArtifactError::InvalidInputSchema(
                            "integer minimum exceeds maximum".into(),
                        ));
                    }
                }
                Self::Boolean | Self::Null => {}
            }
        }
        Ok(())
    }

    pub(crate) fn validate_value(&self, value: &Value) -> Result<(), ArtifactError> {
        self.validate_at(value, "")
    }

    fn validate_at(&self, value: &Value, path: &str) -> Result<(), ArtifactError> {
        match self {
            Self::Object {
                properties,
                required,
                max_properties,
            } => {
                let object = value
                    .as_object()
                    .ok_or_else(|| mismatch(path, "expected object"))?;
                if object.len() > *max_properties {
                    return Err(mismatch(path, "object exceeds max_properties"));
                }
                if let Some(unknown) = object.keys().find(|key| !properties.contains_key(*key)) {
                    return Err(mismatch(&child_path(path, unknown), "unknown object field"));
                }
                if let Some(missing) = required.iter().find(|key| !object.contains_key(*key)) {
                    return Err(mismatch(
                        &child_path(path, missing),
                        "required field is missing",
                    ));
                }
                for (name, child) in object {
                    properties
                        .get(name)
                        .expect("unknown fields checked above")
                        .validate_at(child, &child_path(path, name))?;
                }
                Ok(())
            }
            Self::Array { items, max_items } => {
                let array = value
                    .as_array()
                    .ok_or_else(|| mismatch(path, "expected array"))?;
                if array.len() > *max_items {
                    return Err(mismatch(path, "array exceeds max_items"));
                }
                for (index, child) in array.iter().enumerate() {
                    items.validate_at(child, &format!("{path}/{index}"))?;
                }
                Ok(())
            }
            Self::String { max_utf8_bytes } => {
                let string = value
                    .as_str()
                    .ok_or_else(|| mismatch(path, "expected string"))?;
                if string.len() > *max_utf8_bytes {
                    return Err(mismatch(path, "string exceeds max_utf8_bytes"));
                }
                Ok(())
            }
            Self::Integer { minimum, maximum } => {
                let integer = value
                    .as_i64()
                    .ok_or_else(|| mismatch(path, "expected I-JSON safe integer"))?;
                if !(IJSON_SAFE_INTEGER_MIN..=IJSON_SAFE_INTEGER_MAX).contains(&integer) {
                    return Err(mismatch(path, "integer is outside the I-JSON safe range"));
                }
                if minimum.is_some_and(|min| integer < min)
                    || maximum.is_some_and(|max| integer > max)
                {
                    return Err(mismatch(path, "integer is outside the declared range"));
                }
                Ok(())
            }
            Self::Boolean if value.is_boolean() => Ok(()),
            Self::Boolean => Err(mismatch(path, "expected boolean")),
            Self::Null if value.is_null() => Ok(()),
            Self::Null => Err(mismatch(path, "expected null")),
        }
    }
}

fn validate_property_name(name: &str) -> Result<(), ArtifactError> {
    if name.is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
        return Err(ArtifactError::InvalidInputSchema(
            "property names must contain 1..=128 non-control UTF-8 bytes".into(),
        ));
    }
    Ok(())
}

fn mismatch(path: &str, reason: &str) -> ArtifactError {
    ArtifactError::InputSchemaMismatch {
        path: if path.is_empty() {
            "/".into()
        } else {
            path.into()
        },
        reason: reason.into(),
    }
}

fn child_path(parent: &str, name: &str) -> String {
    let escaped = name.replace('~', "~0").replace('/', "~1");
    format!("{parent}/{escaped}")
}

pub(crate) fn parse_strict_input(
    raw_json: &[u8],
    limits: &InputLimits,
) -> Result<Value, ArtifactError> {
    if raw_json.len() > limits.max_bytes {
        return Err(ArtifactError::InputTooLarge);
    }
    let parsed = parse_strict_json(raw_json).map_err(|error| match error {
        StrictJsonError::DuplicateKey(key) => ArtifactError::DuplicateInputKey(key),
        StrictJsonError::Invalid(message) => ArtifactError::InvalidInputJson(message),
    })?;
    if json_depth(&parsed) > limits.max_depth {
        return Err(ArtifactError::InputTooDeep);
    }
    Ok(parsed)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StrictJsonError {
    DuplicateKey(String),
    Invalid(String),
}

pub(crate) fn parse_strict_json(raw_json: &[u8]) -> Result<Value, StrictJsonError> {
    serde_json::from_slice::<StrictJson>(raw_json)
        .map(|parsed| parsed.0)
        .map_err(|error| {
            let message = error.to_string();
            if let Some(marker) = message.find(DUPLICATE_KEY_MARKER) {
                let rest = &message[marker + DUPLICATE_KEY_MARKER.len()..];
                StrictJsonError::DuplicateKey(
                    rest.split(" at line ").next().unwrap_or(rest).to_owned(),
                )
            } else {
                StrictJsonError::Invalid(message)
            }
        })
}

fn json_depth(root: &Value) -> usize {
    let mut maximum = 1;
    let mut stack = vec![(root, 1_usize)];
    while let Some((value, depth)) = stack.pop() {
        maximum = maximum.max(depth);
        match value {
            Value::Array(values) => {
                stack.extend(values.iter().map(|child| (child, depth + 1)));
            }
            Value::Object(values) => {
                stack.extend(values.values().map(|child| (child, depth + 1)));
            }
            _ => {}
        }
    }
    maximum
}

struct StrictJson(Value);

impl<'de> Deserialize<'de> for StrictJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictJsonVisitor)
    }
}

struct StrictJsonVisitor;

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = StrictJson;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("strict JSON")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictJson(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictJson(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictJson(Value::Number(Number::from(value))))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .map(StrictJson)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictJson(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictJson(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJson(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJson(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<StrictJson>()? {
            values.push(value.0);
        }
        Ok(StrictJson(Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(serde::de::Error::custom(format!(
                    "{DUPLICATE_KEY_MARKER}{key}"
                )));
            }
            let value = object.next_value::<StrictJson>()?;
            values.insert(key, value.0);
        }
        Ok(StrictJson(Value::Object(values)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_keys_are_rejected_recursively() {
        let limits = InputLimits::new(1024, 8).unwrap();
        assert_eq!(
            parse_strict_input(br#"{"outer":{"same":1,"same":2}}"#, &limits),
            Err(ArtifactError::DuplicateInputKey("same".into()))
        );
    }
}
