// SPDX-License-Identifier: Apache-2.0

//! Stability filtering before reference resolution.

use std::collections::{HashMap, HashSet};

use weaver_resolved_schema::v2::ResolvedTelemetrySchema;
use weaver_semconv::convert::v1_stability_and_deprecated_to_v2;
use weaver_semconv::semconv::{SemConvSpecWithProvenance, Versioned};
use weaver_semconv::v1::attribute::{AttributeSpec, AttributeType};
use weaver_semconv::v1::group::{AttributeGroupVisibilitySpec, GroupSpec, GroupType};
use weaver_semconv::v1::semconv::SemConvSpecV1;
use weaver_semconv::v1::stability::Stability as LegacyStability;
use weaver_semconv::v2::stability::Stability;

use crate::{Error, LoadedSemconvRegistry};

pub(crate) fn check_dependency(
    repo: &weaver_semconv::registry_repo::RegistryRepo,
    minimum: &Stability,
) -> Result<Stability, Error> {
    let manifest = repo.to_v2_manifest()?;
    if !manifest.stability().meets(minimum) {
        return Err(Error::DependencyStability {
            dependency: manifest.schema_url().to_string(),
            actual: manifest.stability().clone(),
            required: minimum.clone(),
        });
    }
    Ok(manifest.stability().clone())
}

pub(crate) fn filter_bundle(
    schema: crate::WeaverResolvedSchema,
    minimum: &Stability,
) -> Result<crate::WeaverResolvedSchema, Error> {
    let mut schema = match schema {
        crate::WeaverResolvedSchema::V1(schema) => {
            schema
                .try_into()
                .map_err(|e: weaver_resolved_schema::Error| Error::ConversionError {
                    message: e.to_string(),
                })?
        }
        crate::WeaverResolvedSchema::V2(schema) => schema,
    };
    filter_resolved(&mut schema, minimum)?;
    Ok(crate::WeaverResolvedSchema::V2(schema))
}

#[derive(Default)]
struct Index {
    attributes: HashMap<String, Stability>,
    groups: HashMap<String, (Option<Stability>, Option<String>)>,
}

fn level(stability: &Option<LegacyStability>) -> Stability {
    v1_stability_and_deprecated_to_v2(stability.clone(), None)
        .0
        .unwrap_or_default()
}

impl Index {
    fn group_stability(&self, id: &str) -> Option<Stability> {
        let mut id = id;
        let mut visited = HashSet::new();
        while visited.insert(id) {
            let (stability, parent) = self.groups.get(id)?;
            if let Some(stability) = stability {
                return Some(stability.clone());
            }
            match parent {
                Some(parent) => id = parent,
                None => return Some(Stability::Development),
            }
        }
        None
    }

    fn add_group(&mut self, group: &GroupSpec) {
        _ = self.groups.insert(
            group.id.clone(),
            (
                group.stability.as_ref().map(|s| level(&Some(s.clone()))),
                group.extends.clone(),
            ),
        );
        for attr in &group.attributes {
            if let AttributeSpec::Id { id, stability, .. } = attr {
                let key = if group.prefix.is_empty() {
                    id.clone()
                } else {
                    format!("{}.{id}", group.prefix)
                };
                _ = self.attributes.insert(key, level(stability));
            }
        }
    }

    fn add_loaded(&mut self, loaded: &LoadedSemconvRegistry) -> Result<(), Error> {
        match loaded {
            LoadedSemconvRegistry::Unresolved {
                specs,
                dependencies,
                ..
            } => {
                for dependency in dependencies {
                    self.add_loaded(dependency)?;
                }
                for spec in specs {
                    for group in spec.clone().into_v1().spec.groups() {
                        self.add_group(group);
                    }
                }
            }
            LoadedSemconvRegistry::Resolved { schema, .. } => {
                let schema =
                    schema
                        .clone()
                        .try_into()
                        .map_err(|e: weaver_resolved_schema::Error| Error::ConversionError {
                            message: e.to_string(),
                        })?;
                self.add_resolved(&schema);
            }
            LoadedSemconvRegistry::ResolvedV2 { schema, .. } => self.add_resolved(schema),
        }
        Ok(())
    }

    fn add_resolved(&mut self, schema: &ResolvedTelemetrySchema) {
        for attr in &schema.attribute_catalog {
            _ = self
                .attributes
                .entry(attr.key.clone())
                .or_insert_with(|| attr.common.stability.clone());
        }
        for group in &schema.registry.attribute_groups {
            _ = self.groups.insert(
                group.id.to_string(),
                (Some(group.common.stability.clone()), None),
            );
        }
        for (prefix, signals) in [
            (
                "span",
                schema
                    .registry
                    .spans
                    .iter()
                    .map(|s| (s.r#type.to_string(), s.common.stability.clone()))
                    .collect::<Vec<_>>(),
            ),
            (
                "metric",
                schema
                    .registry
                    .metrics
                    .iter()
                    .map(|s| (s.name.to_string(), s.common.stability.clone()))
                    .collect(),
            ),
            (
                "event",
                schema
                    .registry
                    .events
                    .iter()
                    .map(|s| (s.name.to_string(), s.common.stability.clone()))
                    .collect(),
            ),
            (
                "entity",
                schema
                    .registry
                    .entities
                    .iter()
                    .map(|s| (s.r#type.to_string(), s.common.stability.clone()))
                    .collect(),
            ),
        ] {
            for (id, stability) in signals {
                _ = self
                    .groups
                    .insert(format!("{prefix}.{id}"), (Some(stability), None));
            }
        }
    }
}

pub(crate) fn filter_loaded(
    loaded: &mut LoadedSemconvRegistry,
    minimum: &Stability,
) -> Result<(), Error> {
    let mut index = Index::default();
    match loaded {
        LoadedSemconvRegistry::Unresolved {
            specs,
            dependencies,
            ..
        } => {
            for dependency in dependencies.iter() {
                index.add_loaded(dependency)?;
            }
            let normalized: Vec<_> = std::mem::take(specs)
                .into_iter()
                .map(SemConvSpecWithProvenance::into_v1)
                .collect();
            for spec in &normalized {
                for group in spec.spec.groups() {
                    index.add_group(group);
                }
            }
            for spec in normalized {
                let groups = spec
                    .spec
                    .groups()
                    .iter()
                    .filter_map(|group| {
                        let helper = group.r#type == GroupType::AttributeGroup
                            && group.visibility != Some(AttributeGroupVisibilitySpec::Public);
                        if !helper
                            && index
                                .group_stability(&group.id)
                                .is_some_and(|s| !s.meets(minimum))
                        {
                            return None;
                        }
                        let mut group = group.clone();
                        group
                            .attributes
                            .retain_mut(|attr| filter_attribute(attr, &index, minimum));
                        group
                            .attribute_unrefs
                            .retain(|id| index.attributes.get(id).is_none_or(|s| s.meets(minimum)));
                        Some(group)
                    })
                    .collect();
                specs.push(SemConvSpecWithProvenance {
                    spec: Versioned::V1(SemConvSpecV1::new(groups, spec.spec.imports().cloned())),
                    provenance: spec.provenance,
                });
            }
        }
        LoadedSemconvRegistry::Resolved { .. } | LoadedSemconvRegistry::ResolvedV2 { .. } => {}
    }
    Ok(())
}

fn filter_attribute(attr: &mut AttributeSpec, index: &Index, minimum: &Stability) -> bool {
    match attr {
        AttributeSpec::Id {
            stability, r#type, ..
        } => {
            if !level(stability).meets(minimum) {
                return false;
            }
            if let AttributeType::Enum { members, .. } = r#type {
                members.retain(|member| level(&member.stability).meets(minimum));
            }
            true
        }
        AttributeSpec::Ref {
            r#ref, stability, ..
        } => {
            let effective = stability
                .as_ref()
                .map(|s| level(&Some(s.clone())))
                .or_else(|| index.attributes.get(r#ref).cloned());
            effective.is_none_or(|s| s.meets(minimum))
        }
    }
}

fn missing_identity(id: &str, path: &str) -> Error {
    Error::FailToResolveDefinition(weaver_semconv::Error::EntityMissingIdentity {
        group_id: id.to_owned(),
        path_or_url: path.to_owned(),
    })
}

pub(crate) fn check_identity(schema: &ResolvedTelemetrySchema) -> Result<(), Error> {
    for entity in &schema.registry.entities {
        if entity.identity.is_empty() {
            return Err(missing_identity(&entity.r#type, schema.schema_url.as_str()));
        }
    }
    for refinement in &schema.refinements.entities {
        if refinement.entity.identity.is_empty() {
            return Err(missing_identity(&refinement.id, schema.schema_url.as_str()));
        }
    }
    Ok(())
}

pub(crate) fn filter_resolved(
    schema: &mut ResolvedTelemetrySchema,
    minimum: &Stability,
) -> Result<(), Error> {
    use weaver_resolved_schema::v2::attribute::AttributeRef;
    use weaver_semconv::v2::attribute::AttributeType as V2AttributeType;

    let mut mapping = HashMap::new();
    let mut catalog = Vec::new();
    for (old, mut attr) in std::mem::take(&mut schema.attribute_catalog)
        .into_iter()
        .enumerate()
    {
        if !attr.common.stability.meets(minimum) {
            continue;
        }
        if let V2AttributeType::Enum { members } = &mut attr.r#type {
            members.retain(|member| {
                member
                    .stability
                    .as_ref()
                    .unwrap_or(&Stability::Development)
                    .meets(minimum)
            });
        }
        _ = mapping.insert(AttributeRef(old as u32), AttributeRef(catalog.len() as u32));
        catalog.push(attr);
    }
    schema.attribute_catalog = catalog;
    let remap = |reference: &mut AttributeRef| {
        if let Some(new) = mapping.get(reference) {
            *reference = *new;
            true
        } else {
            false
        }
    };
    schema.registry.attributes.retain_mut(remap);
    schema.registry.attribute_groups.retain_mut(|g| {
        g.attributes.retain_mut(|a| remap(&mut a.base));
        g.common.stability.meets(minimum)
    });
    macro_rules! filter_signals {
        ($field:ident, $signal:ident) => {
            schema.registry.$field.retain_mut(|s| {
                s.attributes.retain_mut(|a| remap(&mut a.base));
                s.common.stability.meets(minimum)
            });
            schema.refinements.$field.retain_mut(|r| {
                r.$signal.attributes.retain_mut(|a| remap(&mut a.base));
                r.$signal.common.stability.meets(minimum)
            });
        };
    }
    filter_signals!(spans, span);
    filter_signals!(metrics, metric);
    filter_signals!(events, event);
    let filter_entity = |e: &mut weaver_resolved_schema::v2::entity::Entity| {
        e.identity.retain_mut(remap);
        e.description.retain_mut(|a| remap(&mut a.base));
        e.common.stability.meets(minimum)
    };
    schema.registry.entities.retain_mut(filter_entity);
    schema
        .refinements
        .entities
        .retain_mut(|r| filter_entity(&mut r.entity));
    check_identity(schema)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{WeaverResolver, WeaverResolverConfig};

    const MODEL: &str = r#"
file_format: definition/2
attributes:
  - key: stable.attr
    type: string
    brief: Stable attribute
    stability: stable
  - key: dev.attr
    type: string
    brief: Development attribute
    stability: development
  - key: enum.attr
    type:
      members:
        - id: stable
          stability: stable
        - id: dev
          stability: development
        - id: unspecified
    brief: Enum
    stability: stable
attribute_groups:
  - id: helper
    visibility: internal
    attributes:
      - ref: stable.attr
      - ref: dev.attr
  - id: public.stable
    visibility: public
    brief: Stable public group
    stability: stable
    attributes:
      - ref_group: helper
  - id: public.dev
    visibility: public
    brief: Development public group
    stability: development
    attributes:
      - ref: dev.attr
metrics:
  - name: stable.metric
    requirement_level: recommended
    brief: Stable metric
    stability: stable
    instrument: counter
    unit: '1'
    attributes:
      - ref_group: public.stable
      - ref: enum.attr
  - name: dev.metric
    requirement_level: recommended
    brief: Development metric
    stability: development
    instrument: counter
    unit: '1'
metric_refinements:
  - id: stable.refinement
    ref: stable.metric
  - id: dev.refinement
    ref: dev.metric
entities:
  - type: stable.entity
    requirement_level: recommended
    brief: Stable entity
    stability: stable
    identity:
      - ref: stable.attr
    description:
      - ref: dev.attr
entity_refinements:
  - id: stable.entity.refinement
    ref: stable.entity
spans:
  - type: stable.span
    kind: client
    name:
      note: Operation name
    brief: Stable span
    stability: stable
    requirement_level: recommended
    attributes:
      - ref_group: helper
  - type: dev.span
    kind: client
    name:
      note: Operation name
    brief: Development span
    stability: development
    requirement_level: recommended
span_refinements:
  - id: stable.span.refinement
    ref: stable.span
  - id: dev.span.refinement
    ref: dev.span
events:
  - name: stable.event
    brief: Stable event
    stability: stable
    requirement_level: recommended
    attributes:
      - ref_group: helper
  - name: dev.event
    brief: Development event
    stability: development
    requirement_level: recommended
event_refinements:
  - id: stable.event.refinement
    ref: stable.event
  - id: dev.event.refinement
    ref: dev.event
"#;

    fn resolve(model: &str, minimum: Option<Stability>) -> Result<ResolvedTelemetrySchema, Error> {
        let mut loaded = LoadedSemconvRegistry::create_from_string(model)?;
        if let LoadedSemconvRegistry::Unresolved { specs, .. } = &mut loaded {
            for spec in specs {
                spec.provenance.path = "model.yaml".to_owned();
            }
        }
        if let Some(minimum) = &minimum {
            filter_loaded(&mut loaded, minimum)?;
        }
        let mut resolver = WeaverResolver::new(WeaverResolverConfig {
            stability: minimum.clone(),
            ..Default::default()
        });
        let (resolved, _) = resolver
            .resolve_loaded(loaded)
            .into_result_with_non_fatal()?;
        let resolved = std::sync::Arc::unwrap_or_clone(resolved);
        let resolved = match minimum {
            Some(minimum) => filter_bundle(resolved, &minimum)?,
            None => resolved,
        };
        match resolved {
            crate::WeaverResolvedSchema::V1(schema) => {
                schema
                    .try_into()
                    .map_err(|e: weaver_resolved_schema::Error| Error::ConversionError {
                        message: e.to_string(),
                    })
            }
            crate::WeaverResolvedSchema::V2(schema) => Ok(schema),
        }
    }

    #[test]
    fn stable_filters_helpers_public_groups_refinements_and_entity_attributes() {
        let schema = resolve(MODEL, Some(Stability::Stable)).unwrap();
        assert_eq!(schema.registry.metrics.len(), 1);
        assert_eq!(schema.registry.spans.len(), 1);
        assert_eq!(schema.registry.events.len(), 1);
        assert_eq!(schema.registry.spans[0].attributes.len(), 1);
        assert_eq!(schema.registry.events[0].attributes.len(), 1);
        assert_eq!(schema.refinements.spans.len(), 2);
        assert_eq!(schema.refinements.events.len(), 2);
        assert_eq!(schema.refinements.entities.len(), 2);
        assert_eq!(schema.registry.attribute_groups.len(), 1);
        assert!(schema
            .refinements
            .metrics
            .iter()
            .all(|r| &*r.metric.name == "stable.metric"));
        assert_eq!(schema.registry.entities[0].identity.len(), 1);
        assert!(schema.registry.entities[0].description.is_empty());
        assert!(schema
            .attribute_catalog
            .iter()
            .all(|a| a.common.stability == Stability::Stable));
        let attr = schema
            .attribute_catalog
            .iter()
            .find(|a| a.key == "enum.attr")
            .unwrap();
        let weaver_semconv::v2::attribute::AttributeType::Enum { members } = &attr.r#type else {
            panic!("Expected enum")
        };
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].id, "stable");
    }

    #[test]
    fn development_preserves_unfiltered_output() {
        let all = resolve(MODEL, None).unwrap();
        let development = resolve(MODEL, Some(Stability::Development)).unwrap();
        assert_eq!(
            serde_json::to_value(all).unwrap(),
            serde_json::to_value(development).unwrap()
        );
    }

    #[test]
    fn removed_public_group_uses_existing_reference_error() {
        let model = MODEL.replace("ref_group: public.stable", "ref_group: public.dev");
        assert!(format!(
            "{:?}",
            resolve(&model, Some(Stability::Stable)).unwrap_err()
        )
        .contains("UnresolvedIncludeRef"));
    }

    #[test]
    fn filtering_last_identity_attribute_fails() {
        let model = MODEL.replace(
            "identity:\n      - ref: stable.attr\n    description:\n      - ref: dev.attr",
            "identity:\n      - ref: dev.attr\n    description:\n      - ref: stable.attr",
        );
        assert!(format!(
            "{:?}",
            resolve(&model, Some(Stability::Stable)).unwrap_err()
        )
        .contains("EntityMissingIdentity"));
    }

    #[test]
    fn missing_attribute_is_not_silently_filtered() {
        let model = MODEL.replace("ref: enum.attr", "ref: missing.attr");
        assert!(format!(
            "{:?}",
            resolve(&model, Some(Stability::Stable)).unwrap_err()
        )
        .contains("UnresolvedAttributeRef"));
    }

    #[test]
    fn published_filter_matches_definition_filter() {
        let mut published = resolve(MODEL, None).unwrap();
        filter_resolved(&mut published, &Stability::Stable).unwrap();
        let definitions = resolve(MODEL, Some(Stability::Stable)).unwrap();
        assert_eq!(
            published.registry.metrics.len(),
            definitions.registry.metrics.len()
        );
        assert_eq!(published.registry.entities[0].identity.len(), 1);
        assert!(published.registry.entities[0].description.is_empty());
        for metric in &published.registry.metrics {
            for attr in &metric.attributes {
                assert!(published
                    .attribute_catalog
                    .get(attr.base.0 as usize)
                    .is_some());
            }
        }
        assert_eq!(
            serde_json::to_value(published).unwrap(),
            serde_json::to_value(definitions).unwrap()
        );
    }

    #[test]
    fn filtering_does_not_modify_dependency_definitions() {
        let mut root = LoadedSemconvRegistry::create_from_string(MODEL).unwrap();
        let dependency = LoadedSemconvRegistry::create_from_string(MODEL).unwrap();
        if let LoadedSemconvRegistry::Unresolved { dependencies, .. } = &mut root {
            dependencies.push(dependency);
        }
        filter_loaded(&mut root, &Stability::Stable).unwrap();
        let LoadedSemconvRegistry::Unresolved { dependencies, .. } = root else {
            panic!("Expected definitions")
        };
        let LoadedSemconvRegistry::Unresolved { specs, .. } = &dependencies[0] else {
            panic!("Expected definitions")
        };
        let Versioned::V2(spec) = &specs[0].spec else {
            panic!("Dependency was rewritten")
        };
        assert_eq!(spec.metrics().len(), 2);
        assert_eq!(spec.attributes().len(), 3);
    }

    #[test]
    fn imports_are_filtered_without_rewriting_cached_dependencies() {
        let mut root = LoadedSemconvRegistry::create_from_string(
            "file_format: definition/2\nimports:\n  metrics: ['*']\n",
        )
        .unwrap();
        let mut dependency = resolve(MODEL, None).unwrap();
        dependency.schema_url = "https://dependency.test/1.0.0".try_into().unwrap();
        let dependency_url = dependency.schema_url.clone();
        if let LoadedSemconvRegistry::Unresolved {
            dependencies,
            specs,
            imports,
            ..
        } = &mut root
        {
            let spec = specs[0].clone().into_v1();
            imports.push(weaver_semconv::v1::group::ImportsWithProvenance {
                imports: spec.spec.imports().unwrap().clone(),
                provenance: spec.provenance,
            });
            dependencies.push(LoadedSemconvRegistry::ResolvedV2 {
                schema: dependency,
                direct_dependencies: vec![],
            });
        }
        filter_loaded(&mut root, &Stability::Stable).unwrap();
        let mut resolver = WeaverResolver::new(WeaverResolverConfig::default());
        let (resolved, _) = resolver
            .resolve_loaded(root)
            .into_result_with_non_fatal()
            .unwrap();
        let filtered = filter_bundle(
            std::sync::Arc::unwrap_or_clone(resolved),
            &Stability::Stable,
        )
        .unwrap();
        assert_eq!(filtered.as_v2().unwrap().registry.metrics.len(), 1);
        let cached = resolver
            .resolve_schema(&dependency_url)
            .into_result_with_non_fatal()
            .unwrap()
            .0;
        assert_eq!(cached.as_v2().unwrap().registry.metrics.len(), 2);
    }

    #[test]
    fn mixed_input_resolves_stable_v1_attributes_from_v2() {
        let mut root = LoadedSemconvRegistry::create_from_string(
            &MODEL.replace("ref: enum.attr", "ref: legacy.attr"),
        )
        .unwrap();
        let legacy = LoadedSemconvRegistry::create_from_string(
            r#"
groups:
  - id: registry.legacy
    type: attribute_group
    brief: Legacy attributes
    attributes:
      - id: legacy.attr
        type: int
        brief: Legacy attribute
        stability: stable
"#,
        )
        .unwrap();
        if let (
            LoadedSemconvRegistry::Unresolved { specs, .. },
            LoadedSemconvRegistry::Unresolved {
                specs: legacy_specs,
                ..
            },
        ) = (&mut root, legacy)
        {
            specs.extend(legacy_specs);
        }
        filter_loaded(&mut root, &Stability::Stable).unwrap();
        let mut resolver = WeaverResolver::new(WeaverResolverConfig::default());
        let (schema, _) = resolver
            .resolve_loaded(root)
            .into_result_with_non_fatal()
            .unwrap();
        let schema =
            filter_bundle(std::sync::Arc::unwrap_or_clone(schema), &Stability::Stable).unwrap();
        let schema = schema.as_v2().unwrap();
        assert!(schema.registry.metrics[0]
            .attributes
            .iter()
            .any(|a| schema.attribute_catalog[a.base.0 as usize].key == "legacy.attr"));
    }

    fn load_dependencies(
        minimum: Option<Stability>,
        dependency_stability: Option<&str>,
        transitive_stability: Option<&str>,
        published: bool,
    ) -> Result<LoadedSemconvRegistry, Error> {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let dependency = temp.path().join("dependency");
        let transitive = temp.path().join("transitive");
        for path in [&root, &dependency, &transitive] {
            std::fs::create_dir_all(path).unwrap();
        }
        std::fs::write(root.join("manifest.yaml"), format!("schema_url: https://root.test/1.0.0\ndependencies:\n  - schema_url: https://dependency.test/1.0.0\n    registry_path: {}\n", dependency.display())).unwrap();
        let mut manifest = "schema_url: https://dependency.test/1.0.0\n".to_owned();
        if let Some(stability) = dependency_stability {
            manifest.push_str(&format!("stability: {stability}\n"));
        }
        if let Some(stability) = transitive_stability {
            manifest.push_str(&format!("dependencies:\n  - schema_url: https://transitive.test/1.0.0\n    registry_path: {}\n", transitive.display()));
            std::fs::write(
                transitive.join("manifest.yaml"),
                format!("schema_url: https://transitive.test/1.0.0\nstability: {stability}\n"),
            )
            .unwrap();
        }
        if published {
            let resolved = dependency.join("resolved.yaml");
            manifest.push_str(&format!(
                "file_format: manifest/2.0\nresolved_registry_uri: {}\n",
                resolved.display()
            ));
            let mut schema = resolve(MODEL, None).unwrap();
            schema.schema_url = "https://dependency.test/1.0.0".try_into().unwrap();
            std::fs::write(resolved, serde_yaml::to_string(&schema).unwrap()).unwrap();
        }
        std::fs::write(dependency.join("manifest.yaml"), manifest).unwrap();
        let path = weaver_common::vdir::VirtualDirectoryPath::LocalFolder {
            path: root.display().to_string(),
        };
        let repo =
            weaver_semconv::registry_repo::RegistryRepo::try_new(None, &path, &mut vec![]).unwrap();
        crate::loader::load_semconv_repository_with_cache(
            None,
            repo,
            false,
            &weaver_common::http_auth::HttpAuthResolver::empty(),
            minimum.as_ref(),
        )
        .into_result_with_non_fatal()
        .map(|(loaded, _)| loaded)
    }

    #[test]
    fn dependency_stability_must_meet_threshold() {
        for published in [false, true] {
            assert!(
                load_dependencies(Some(Stability::Stable), Some("stable"), None, published).is_ok()
            );
            assert!(
                load_dependencies(Some(Stability::Beta), Some("stable"), None, published).is_ok()
            );
            for declared in [Some("development"), Some("release_candidate"), None] {
                assert!(matches!(
                    load_dependencies(Some(Stability::Stable), declared, None, published),
                    Err(Error::DependencyStability { .. })
                ));
            }
            assert!(load_dependencies(None, Some("development"), None, published).is_ok());
        }
    }

    #[test]
    fn transitive_dependencies_must_meet_their_parent_stability() {
        for published in [false, true] {
            let error = load_dependencies(
                Some(Stability::Beta),
                Some("stable"),
                Some("beta"),
                published,
            )
            .err()
            .expect("Expected dependency stability error");
            assert!(matches!(
                error,
                Error::DependencyStability {
                    required: Stability::Stable,
                    ..
                }
            ));
            assert!(load_dependencies(
                Some(Stability::Stable),
                Some("stable"),
                Some("stable"),
                published
            )
            .is_ok());
        }
    }
}
