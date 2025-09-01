// SPDX-License-Identifier: Apache-2.0

//! The new way we want to define spans going forward.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    group::{GroupSpec, GroupType, SpanKindSpec},
    v2::{attribute::AttributeRef, signal_id::SignalId, CommonFields},
};

/// A group defines an attribute group, an entity, or a signal.
/// Supported group types are: `attribute_group`, `span`, `event`, `metric`, `entity`, `scope`.
/// Mandatory fields are: `id` and `brief`.
///
/// Note: The `resource` type is no longer used and is an alias for `entity`.
#[derive(Serialize, Deserialize, Debug, Clone, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Span {
    /// The type of the Span. This denotes the identity
    /// of the "shape" of this span, and must be unique.
    pub r#type: SignalId,
    /// Specifies the kind of the span.
    /// Note: only valid if type is span
    pub kind: SpanKindSpec,
    /// The name pattern for the span.
    pub name: SpanName,
    /// List of attributes that belong to the semantic convention.
    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub attributes: Vec<AttributeRef>,
    /// Which resources this span should be associated with.
    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub entity_associations: Vec<String>,
    /// Common fields (like brief, note, annotations).
    #[serde(flatten)]
    pub common: CommonFields,
}

impl Span {
    /// Converts a v2 span group into a v1 GroupSpec.
    #[must_use]
    pub fn into_v1_group(self) -> GroupSpec {
        GroupSpec {
            id: format!("span.{}", &self.r#type),
            r#type: GroupType::Span,
            brief: self.common.brief,
            note: self.common.note,
            prefix: Default::default(),
            extends: None,
            include_groups: self.common.include_groups,
            stability: Some(self.common.stability),
            deprecated: self.common.deprecated,
            attributes: self
                .attributes
                .into_iter()
                .map(|a| a.into_v1_attribute())
                .collect(),
            span_kind: Some(self.kind),
            events: vec![],
            metric_name: None,
            instrument: None,
            unit: None,
            name: None,
            display_name: None,
            body: None,
            annotations: if self.common.annotations.is_empty() {
                None
            } else {
                Some(self.common.annotations)
            },
            entity_associations: self.entity_associations,
            visibility: None,
        }
    }
}

/// Specification of the span name.
#[derive(Serialize, Deserialize, Debug, Clone, JsonSchema)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub struct SpanName {
    /// Required description of how a span name should be created.
    pub note: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_and_translate(v2: &str, v1: &str) {
        let span = serde_yaml::from_str::<Span>(v2).expect("Failed to parse YAML string");
        let expected =
            serde_yaml::from_str::<GroupSpec>(v1).expect("Failed to parse expected YAML");
        assert_eq!(expected, span.into_v1_group());
    }

    #[test]
    fn test_value_spec_display() {
        parse_and_translate(
            // V2 - Span
            r#"type: my_span
name:
  note: "{some} {name}"
stability: stable
kind: client
brief: Test span
"#,
            // V1 - Group
            r#"id: span.my_span
type: span
brief: Test span
name: "{some} {name}"
span_kind: client
stability: stable
"#,
        );
    }
}
