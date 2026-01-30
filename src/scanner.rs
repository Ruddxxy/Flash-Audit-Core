use serde::Serialize;
use regex::Regex;
use aho_corasick::AhoCorasick;
use sha2::{Sha256, Digest};
use crate::utils::config::{Rule, RiskMetadata};
use crate::utils::entropy;

#[derive(Debug, Serialize, Clone)]
pub struct Vulnerability {
    pub file: String,
    pub line: usize,
    pub match_content: String,
    pub rule_id: String,
    pub description: Option<String>,
    pub risk: RiskMetadata,
    #[serde(skip_serializing)]
    raw_secret: String,
}

impl Vulnerability {
    /// Generate a deterministic fingerprint for this finding.
    /// Logic: SHA256(normalized_secret + rule_id)
    /// Normalization: trim whitespace and quotes
    pub fn generate_fingerprint(&self) -> String {
        let normalized = self.raw_secret
            .trim()
            .trim_matches(|c| c == '"' || c == '\'' || c == '`');

        let mut hasher = Sha256::new();
        hasher.update(normalized.as_bytes());
        hasher.update(self.rule_id.as_bytes());
        hex::encode(hasher.finalize())
    }
}

/// A compiled rule with both keyword trigger and regex validator
struct CompiledRule {
    regex: Regex,
    id: String,
    description: Option<String>,
    risk: RiskMetadata,
    #[allow(dead_code)]
    keyword: String,
}

/// Hybrid Scanner: Aho-Corasick pre-filter + Regex validation
///
/// Performance Strategy:
/// 1. Build Aho-Corasick automaton from all keywords (O(n) single pass)
/// 2. Only run expensive regex on files that contain matching keywords
/// 3. This is 10-100x faster than running all regexes on all files
pub struct Scanner {
    ac: AhoCorasick,
    rules: Vec<CompiledRule>,
    keywords: Vec<String>,
}

impl Scanner {
    pub fn new(rules: Vec<Rule>) -> Self {
        let mut compiled_rules = Vec::new();
        let mut keywords = Vec::new();

        for rule in rules {
            // Extract keyword from pattern for Aho-Corasick
            let keyword = Self::extract_keyword(&rule.pattern);

            match Regex::new(&rule.pattern) {
                Ok(regex) => {
                    keywords.push(keyword.clone());
                    compiled_rules.push(CompiledRule {
                        regex,
                        id: rule.id,
                        description: rule.description,
                        risk: rule.risk,
                        keyword,
                    });
                }
                Err(e) => {
                    eprintln!("Invalid regex '{}': {}", rule.pattern, e);
                }
            }
        }

        // Build Aho-Corasick automaton for fast multi-pattern matching
        let ac = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&keywords)
            .expect("Failed to build Aho-Corasick automaton");

        Self {
            ac,
            rules: compiled_rules,
            keywords,
        }
    }

    /// Extract the most distinctive keyword from a regex pattern
    /// This is used for fast pre-filtering with Aho-Corasick
    fn extract_keyword(pattern: &str) -> String {
        // Common prefixes we want to extract
        let static_patterns = [
            // Private keys
            ("-----BEGIN RSA PRIVATE KEY-----", "BEGIN RSA PRIVATE KEY"),
            ("-----BEGIN OPENSSH PRIVATE KEY-----", "BEGIN OPENSSH PRIVATE KEY"),
            ("-----BEGIN EC PRIVATE KEY-----", "BEGIN EC PRIVATE KEY"),
            ("-----BEGIN PGP PRIVATE KEY", "BEGIN PGP PRIVATE KEY"),
            ("-----BEGIN DSA PRIVATE KEY-----", "BEGIN DSA PRIVATE KEY"),
            ("PuTTY-User-Key-File", "PuTTY-User-Key-File"),

            // Cloud providers
            ("AKIA", "AKIA"),
            ("ghp_", "ghp_"),
            ("gho_", "gho_"),
            ("ghu_", "ghu_"),
            ("ghs_", "ghs_"),
            ("ghr_", "ghr_"),
            ("glpat-", "glpat-"),
            ("xoxb-", "xoxb-"),
            ("xoxp-", "xoxp-"),
            ("xoxa-", "xoxa-"),
            ("AIza", "AIza"),
            ("sk_live_", "sk_live_"),
            ("sk_test_", "sk_test_"),
            ("rk_live_", "rk_live_"),
            ("SG.", "SG."),
            ("SK", "SK"),
            ("npm_", "npm_"),
            ("pypi-", "pypi-"),
            ("shpat_", "shpat_"),
            ("shpss_", "shpss_"),
            ("sq0atp-", "sq0atp-"),
            ("sq0csp-", "sq0csp-"),

            // Database URLs
            ("postgres://", "postgres://"),
            ("postgresql://", "postgresql://"),
            ("mysql://", "mysql://"),
            ("mongodb://", "mongodb://"),
            ("mongodb+srv://", "mongodb+srv://"),
            ("redis://", "redis://"),

            // Webhooks
            ("hooks.slack.com", "hooks.slack.com"),
            ("discord.com/api/webhooks", "discord.com/api/webhooks"),
            ("discordapp.com/api/webhooks", "discordapp.com/api/webhooks"),

            // JWT
            ("eyJ", "eyJ"),

            // Generic (contextual)
            ("password", "password"),
            ("passwd", "passwd"),
            ("secret", "secret"),
            ("api_key", "api_key"),
            ("apikey", "apikey"),
            ("token", "token"),
            ("heroku", "heroku"),
            ("twilio", "twilio"),
        ];

        // Check if pattern contains any known keywords
        for (check, keyword) in static_patterns.iter() {
            if pattern.to_lowercase().contains(&check.to_lowercase()) {
                return keyword.to_string();
            }
        }

        // Fallback: extract first literal sequence from regex
        let mut keyword = String::new();
        let mut in_escape = false;
        let mut in_class = false;
        let mut in_group = false;

        for c in pattern.chars() {
            if in_escape {
                // Handle common escapes
                match c {
                    's' | 'S' | 'd' | 'D' | 'w' | 'W' | 'b' | 'B' => {
                        if keyword.len() >= 3 {
                            break;
                        }
                        keyword.clear();
                    }
                    _ => keyword.push(c),
                }
                in_escape = false;
                continue;
            }

            match c {
                '\\' => in_escape = true,
                '[' => {
                    in_class = true;
                    if keyword.len() >= 3 {
                        break;
                    }
                }
                ']' => in_class = false,
                '(' => {
                    in_group = true;
                    if keyword.len() >= 3 {
                        break;
                    }
                }
                ')' => in_group = false,
                '+' | '*' | '?' | '{' | '}' | '|' | '^' | '$' => {
                    if keyword.len() >= 3 {
                        break;
                    }
                    keyword.clear();
                }
                _ if !in_class && !in_group => {
                    if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' || c == ':' || c == '/' {
                        keyword.push(c);
                    } else if keyword.len() >= 3 {
                        break;
                    }
                }
                _ => {}
            }
        }

        // Minimum keyword length
        if keyword.len() < 3 {
            // Return a generic trigger that will match many files
            return "password".to_string();
        }

        keyword
    }

    /// Fast scan using hybrid Aho-Corasick + Regex
    pub fn scan(&self, content: &[u8], file_path: &str) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        // Convert to string, skip if not valid UTF-8
        let text = match std::str::from_utf8(content) {
            Ok(t) => t,
            Err(_) => return vulns,
        };

        // Phase 1: Fast Aho-Corasick scan to find which rules might match
        let mut candidate_rules: Vec<usize> = Vec::new();
        for mat in self.ac.find_iter(text) {
            let pattern_idx = mat.pattern().as_usize();
            if !candidate_rules.contains(&pattern_idx) {
                candidate_rules.push(pattern_idx);
            }
        }

        // Phase 2: Only run regex for rules that have keyword matches
        for &rule_idx in &candidate_rules {
            let rule = &self.rules[rule_idx];

            for mat in rule.regex.find_iter(text) {
                let line_number = text[..mat.start()].matches('\n').count() + 1;
                let matched_text = mat.as_str();

                // Redact the actual secret
                let redacted = if matched_text.len() > 12 {
                    format!("{}...[REDACTED]", &matched_text[..12])
                } else {
                    matched_text.to_string()
                };

                vulns.push(Vulnerability {
                    file: file_path.to_string(),
                    line: line_number,
                    match_content: redacted,
                    rule_id: rule.id.clone(),
                    description: rule.description.clone(),
                    risk: rule.risk.clone(),
                    raw_secret: matched_text.to_string(),
                });
            }
        }

        vulns
    }

    /// Entropy-based scanning for unknown secret patterns
    pub fn scan_entropy(&self, content: &[u8], file_path: &str, threshold: f32) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        for (token, score) in entropy::find_high_entropy_tokens(content, threshold) {
            let line = if let Some(idx) = content.windows(token.len()).position(|w| w == token.as_bytes()) {
                content[..idx].iter().filter(|&&b| b == b'\n').count() + 1
            } else {
                0
            };

            vulns.push(Vulnerability {
                file: file_path.to_string(),
                line,
                match_content: format!("Entropy: {:.2}", score),
                rule_id: "HIGH_ENTROPY".to_string(),
                description: Some("High entropy string detected".to_string()),
                risk: RiskMetadata {
                    class: "entropy".to_string(),
                    impact: "medium".to_string(),
                },
                raw_secret: token,
            });
        }
        vulns
    }

    /// Get statistics about the scanner
    pub fn stats(&self) -> (usize, usize) {
        (self.rules.len(), self.keywords.len())
    }
}
