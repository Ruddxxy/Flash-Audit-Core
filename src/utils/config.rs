use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use anyhow::Result;

/// Risk classification metadata for semantic categorization
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RiskMetadata {
    /// Risk class (e.g., "credential", "api_key", "private_key", "generic")
    #[serde(default = "default_risk_class")]
    pub class: String,
    /// Impact level (e.g., "critical", "high", "medium", "low")
    #[serde(default = "default_risk_impact")]
    pub impact: String,
}

fn default_risk_class() -> String {
    "generic".to_string()
}

fn default_risk_impact() -> String {
    "low".to_string()
}

impl Default for RiskMetadata {
    fn default() -> Self {
        Self {
            class: default_risk_class(),
            impact: default_risk_impact(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Rule {
    pub id: String,
    pub pattern: String,
    #[serde(default)]
    pub description: Option<String>,
    /// Semantic risk metadata for classification
    #[serde(default)]
    pub risk: RiskMetadata,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub rules: Vec<Rule>,
}

impl Config {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    pub fn from_yaml(content: &str) -> Result<Self> {
        let config: Config = serde_yaml::from_str(content)?;
        Ok(config)
    }

    /// Returns the default embedded configuration
    pub fn default_rules() -> Self {
        let yaml = include_str!("../../rules.yaml");
        Self::from_yaml(yaml).expect("Failed to load default rules")
    }
}
