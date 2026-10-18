// SPDX-License-Identifier: Apache-2.0

//! Stability specification for version 2 semantic conventions.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

/// The level of stability for a definition. Defined in [OTEP-232](https://github.com/open-telemetry/oteps/blob/main/text/0232-maturity-of-otel.md)
#[derive(
    Serialize, Deserialize, Clone, Debug, Eq, PartialEq, Hash, JsonSchema, PartialOrd, Ord,
)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum Stability {
    /// A stable definition.
    Stable,
    /// A definition in development. Formally known as experimental.
    #[serde(alias = "experimental")]
    Development,
    /// An alpha definition.
    Alpha,
    /// A beta definition.
    Beta,
    /// A release candidate definition.
    ReleaseCandidate,
}

/// We provide a default for definitions that do not specify a stability.
impl Default for Stability {
    fn default() -> Self {
        Stability::Development
    }
}

impl Stability {
    /// Whether this level meets the requested minimum stability.
    #[must_use]
    pub fn meets(&self, minimum: &Self) -> bool {
        fn rank(level: &Stability) -> u8 {
            match level {
                Stability::Development => 0,
                Stability::Alpha => 1,
                Stability::Beta => 2,
                Stability::ReleaseCandidate => 3,
                Stability::Stable => 4,
            }
        }
        rank(self) >= rank(minimum)
    }
}

impl std::str::FromStr for Stability {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "development" => Ok(Self::Development),
            "alpha" => Ok(Self::Alpha),
            "beta" => Ok(Self::Beta),
            "release_candidate" => Ok(Self::ReleaseCandidate),
            "stable" => Ok(Self::Stable),
            _ => Err(format!("Invalid stability `{value}`; expected development, alpha, beta, release_candidate, or stable")),
        }
    }
}

/// Implements a human readable display for the stability.
impl Display for Stability {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Stability::Stable => write!(f, "stable"),
            Stability::Development => write!(f, "development"),
            Stability::Alpha => write!(f, "alpha"),
            Stability::Beta => write!(f, "beta"),
            Stability::ReleaseCandidate => write!(f, "release_candidate"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimum_stability_includes_requested_level_and_above() {
        let levels = [
            Stability::Development,
            Stability::Alpha,
            Stability::Beta,
            Stability::ReleaseCandidate,
            Stability::Stable,
        ];
        for (minimum_rank, minimum) in levels.iter().enumerate() {
            for (rank, level) in levels.iter().enumerate() {
                assert_eq!(level.meets(minimum), rank >= minimum_rank);
            }
        }
    }

    #[test]
    fn test_deserialize_stability() {
        let stable: Stability = serde_json::from_str("\"stable\"").unwrap();
        assert_eq!(stable, Stability::Stable);

        let development: Stability = serde_json::from_str("\"development\"").unwrap();
        assert_eq!(development, Stability::Development);

        let experimental: Stability = serde_json::from_str("\"experimental\"").unwrap();
        assert_eq!(experimental, Stability::Development);

        let alpha: Stability = serde_json::from_str("\"alpha\"").unwrap();
        assert_eq!(alpha, Stability::Alpha);

        let beta: Stability = serde_json::from_str("\"beta\"").unwrap();
        assert_eq!(beta, Stability::Beta);

        let release_candidate: Stability = serde_json::from_str("\"release_candidate\"").unwrap();
        assert_eq!(release_candidate, Stability::ReleaseCandidate);

        assert!(serde_json::from_str::<Stability>("\"deprecated\"").is_err());
    }

    #[test]
    fn test_display() {
        assert_eq!(Stability::Stable.to_string(), "stable");
        assert_eq!(Stability::Development.to_string(), "development");
        assert_eq!(Stability::Alpha.to_string(), "alpha");
        assert_eq!(Stability::Beta.to_string(), "beta");
        assert_eq!(Stability::ReleaseCandidate.to_string(), "release_candidate");
    }
}
