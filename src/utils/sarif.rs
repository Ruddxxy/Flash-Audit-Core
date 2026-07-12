use serde::Serialize;
use crate::scanner::Vulnerability;

/// SARIF 2.1.0 Output Format
/// https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

#[derive(Serialize)]
pub struct SarifReport {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<SarifRun>,
}

#[derive(Serialize)]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
}

#[derive(Serialize)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

#[derive(Serialize)]
pub struct SarifDriver {
    pub name: String,
    pub version: String,
    #[serde(rename = "informationUri")]
    pub information_uri: String,
    pub rules: Vec<SarifRule>,
}

#[derive(Serialize)]
pub struct SarifRule {
    pub id: String,
    pub name: String,
    #[serde(rename = "shortDescription")]
    pub short_description: SarifMessage,
    #[serde(rename = "defaultConfiguration")]
    pub default_configuration: SarifConfiguration,
}

#[derive(Serialize)]
pub struct SarifConfiguration {
    pub level: String,
}

#[derive(Serialize)]
pub struct SarifMessage {
    pub text: String,
}

#[derive(Serialize)]
pub struct SarifResult {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    pub level: String,
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
}

#[derive(Serialize)]
pub struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    pub physical_location: SarifPhysicalLocation,
}

#[derive(Serialize)]
pub struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: SarifArtifactLocation,
    pub region: SarifRegion,
}

#[derive(Serialize)]
pub struct SarifArtifactLocation {
    pub uri: String,
}

#[derive(Serialize)]
pub struct SarifRegion {
    #[serde(rename = "startLine")]
    pub start_line: usize,
}

impl SarifReport {
    pub fn from_vulnerabilities(vulns: &[Vulnerability]) -> Self {
        // Collect unique rules
        let mut rule_ids: Vec<String> = vulns.iter().map(|v| v.rule_id.clone()).collect();
        rule_ids.sort();
        rule_ids.dedup();

        let rules: Vec<SarifRule> = rule_ids
            .iter()
            .map(|id| SarifRule {
                id: id.clone(),
                name: id.replace('_', " ").to_lowercase(),
                short_description: SarifMessage {
                    text: format!("Detected potential secret: {}", id),
                },
                default_configuration: SarifConfiguration {
                    level: "error".to_string(),
                },
            })
            .collect();

        let results: Vec<SarifResult> = vulns
            .iter()
            .map(|v| SarifResult {
                rule_id: v.rule_id.clone(),
                level: "error".to_string(),
                message: SarifMessage {
                    text: v.description.clone().unwrap_or_else(|| {
                        format!("Potential secret detected: {}", v.rule_id)
                    }),
                },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            uri: v.file.clone(),
                        },
                        region: SarifRegion {
                            start_line: v.line,
                        },
                    },
                }],
            })
            .collect();

        SarifReport {
            schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
            version: "2.1.0".to_string(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "FlashAudit".to_string(),
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        information_uri: "https://github.com/Ruddxxy/Flash-Audit-Core".to_string(),
                        rules,
                    },
                },
                results,
            }],
        }
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}
