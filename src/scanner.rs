use serde::Serialize;
use regex::Regex;
use aho_corasick::AhoCorasick;
use sha2::{Sha256, Digest};
use std::collections::HashMap;
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

/// A compiled rule: a regex validator, optionally gated by a keyword trigger.
struct CompiledRule {
    regex: Regex,
    id: String,
    description: Option<String>,
    risk: RiskMetadata,
}

/// Hybrid Scanner: Aho-Corasick pre-filter + Regex validation
///
/// Performance Strategy:
/// 1. Build one Aho-Corasick automaton from the distinct keywords (O(n) single pass)
/// 2. Only run expensive regex for rules whose keyword appears in the file
/// 3. This is far faster than running every regex over every file
///
/// Correctness requirements the pre-filter must respect:
/// - A keyword may be shared by several rules, so a keyword maps to a *list* of rules.
///   (Previously the keyword list was index-parallel to the rule list, so a shared
///   keyword only ever nominated the first rule that used it.)
/// - Keywords overlap: "SK" is a prefix of "sk_live_". Matching must therefore be
///   overlapping, otherwise the shorter keyword consumes the offset and masks the longer.
/// - A rule whose pattern has no literal that is *guaranteed* to appear in every match
///   gets no keyword at all and is always run. Inventing a trigger for it (the old code
///   fell back to the literal "password") makes the rule unfireable on real input.
pub struct Scanner {
    ac: AhoCorasick,
    rules: Vec<CompiledRule>,
    /// Distinct keywords, positionally aligned with the automaton's PatternIDs.
    keywords: Vec<String>,
    /// PatternID -> every rule index that is triggered by that keyword.
    pattern_to_rules: Vec<Vec<usize>>,
    /// Rules with no sound keyword trigger; their regex runs against every file.
    always_rules: Vec<usize>,
}

impl Scanner {
    pub fn new(rules: Vec<Rule>) -> Self {
        let mut compiled_rules = Vec::new();
        let mut keywords: Vec<String> = Vec::new();
        let mut pattern_to_rules: Vec<Vec<usize>> = Vec::new();
        let mut always_rules: Vec<usize> = Vec::new();
        // Keyword -> its PatternID in the automaton, so duplicates collapse to one pattern.
        let mut keyword_ids: HashMap<String, usize> = HashMap::new();

        for rule in rules {
            let keyword = Self::extract_keyword(&rule.pattern);

            let regex = match Regex::new(&rule.pattern) {
                Ok(regex) => regex,
                Err(e) => {
                    eprintln!("Invalid regex '{}': {}", rule.pattern, e);
                    continue;
                }
            };

            let rule_idx = compiled_rules.len();
            compiled_rules.push(CompiledRule {
                regex,
                id: rule.id,
                description: rule.description,
                risk: rule.risk,
            });

            match keyword {
                Some(kw) => {
                    let pattern_id = *keyword_ids.entry(kw.clone()).or_insert_with(|| {
                        keywords.push(kw);
                        pattern_to_rules.push(Vec::new());
                        keywords.len() - 1
                    });
                    pattern_to_rules[pattern_id].push(rule_idx);
                }
                None => always_rules.push(rule_idx),
            }
        }

        // MatchKind::Standard (the default) is the only mode that supports overlapping
        // iteration, which we rely on so that "SK" cannot mask "sk_live_".
        let ac = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&keywords)
            .expect("Failed to build Aho-Corasick automaton");

        Self {
            ac,
            rules: compiled_rules,
            keywords,
            pattern_to_rules,
            always_rules,
        }
    }

    /// Extract the most distinctive keyword from a regex pattern, for pre-filtering.
    ///
    /// Returns `None` when no literal can be recovered that is guaranteed to appear in
    /// every match (e.g. `[MN][A-Za-z\d]{23,}\.…`, or a pattern whose only literals sit
    /// inside an alternation). Such a rule is always run rather than being gated behind a
    /// keyword that its matches would not contain.
    fn extract_keyword(pattern: &str) -> Option<String> {
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
                return Some(keyword.to_string());
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

        // Minimum keyword length. No usable literal was recovered, so the rule cannot be
        // gated: return None and let it run unconditionally. The old code returned the
        // literal "password" here, which meant e.g. DATADOG_API_KEY only ever fired on a
        // file that happened to contain the word "password".
        if keyword.len() < 3 {
            return None;
        }

        Some(keyword)
    }

    /// Fast scan using hybrid Aho-Corasick + Regex
    pub fn scan(&self, content: &[u8], file_path: &str) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        // Convert to string, skip if not valid UTF-8
        let text = match std::str::from_utf8(content) {
            Ok(t) => t,
            Err(_) => return vulns,
        };

        // Phase 1: Aho-Corasick pre-filter -> the set of rules worth running.
        // Overlapping iteration is required: keywords are prefixes of one another
        // ("SK" / "sk_live_"), and non-overlapping matching would report only the
        // shorter one and silently drop the longer rule.
        let mut nominated = vec![false; self.rules.len()];
        for &rule_idx in &self.always_rules {
            nominated[rule_idx] = true;
        }
        for mat in self.ac.find_overlapping_iter(text) {
            for &rule_idx in &self.pattern_to_rules[mat.pattern().as_usize()] {
                nominated[rule_idx] = true;
            }
        }
        // Ascending rule order keeps the output deterministic.
        let candidate_rules: Vec<usize> = (0..self.rules.len()).filter(|&i| nominated[i]).collect();

        // Phase 2: Only run regex for rules the pre-filter nominated
        for &rule_idx in &candidate_rules {
            let rule = &self.rules[rule_idx];

            for mat in rule.regex.find_iter(text) {
                let line_number = text[..mat.start()].matches('\n').count() + 1;
                let matched_text = mat.as_str();

                // Redact the actual secret. Truncate by characters, not bytes,
                // so multi-byte UTF-8 matches never panic on a slice boundary.
                let redacted = if matched_text.chars().count() > 12 {
                    let prefix: String = matched_text.chars().take(12).collect();
                    format!("{}...[REDACTED]", prefix)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::config::{Config, Rule, RiskMetadata};
    use std::collections::HashSet;

    /// Filler of exactly `n` alphanumeric characters.
    fn alnum(n: usize) -> String {
        const POOL: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        POOL.chars().cycle().take(n).collect()
    }

    /// Filler of exactly `n` lowercase hex characters.
    fn hexs(n: usize) -> String {
        "0123456789abcdef".chars().cycle().take(n).collect()
    }

    /// Build one synthetic secret per rule id in rules.yaml, at runtime.
    ///
    /// Nothing here is a real credential, and just as importantly no *complete* token
    /// appears as a literal anywhere in this file: every value is assembled from a prefix
    /// plus generated filler. A committed fixture of these strings would match GitHub's
    /// own secret-scanning patterns (Slack, Stripe, ...) and is rejected by push
    /// protection -- correctly, since a scanner's test corpus is indistinguishable from
    /// the real thing by design. Generating them at test time keeps the repository free of
    /// detectable secrets while still exercising every rule end to end.
    ///
    /// Each value is shaped to satisfy that rule's regex in rules.yaml.
    fn generated_corpus() -> String {
        let mut l: Vec<String> = Vec::new();
        let mut add = |s: String| l.push(s);

        add("-----BEGIN RSA PRIVATE KEY-----".into());
        add("-----BEGIN OPENSSH PRIVATE KEY-----".into());
        add("-----BEGIN EC PRIVATE KEY-----".into());
        add("-----BEGIN PGP PRIVATE KEY BLOCK-----".into());
        add("-----BEGIN DSA PRIVATE KEY-----".into());
        add("PuTTY-User-Key-File-2: ssh-rsa".into());
        add(format!("aws_access_key_id=\"AKIA{}\"", "IOSFODNN7EXAMPLE"));
        add(format!("aws_secret_access_key=\"{}\"", alnum(40)));
        add(format!("ghp_{}", alnum(36)));
        add(format!("gho_{}", alnum(36)));
        add(format!("ghu_{}", alnum(36)));
        add(format!("ghs_{}", alnum(36)));
        add(format!("ghr_{}", alnum(36)));
        add(format!("glpat-{}", alnum(20)));
        add(format!("GR1348941{}", alnum(20)));
        add(format!("{}-1234567890-1234567890-{}", "xoxb", alnum(24)));
        add(format!("{}-1234567890-1234567890-{}", "xoxp", alnum(24)));
        add(format!(
            "https://hooks.{}.com/services/T12345678/B12345678/{}",
            "slack",
            alnum(24)
        ));
        add(format!("AIza{}", alnum(35)));
        add(format!(
            "123456789-{}012345.apps.googleusercontent.com",
            "abcdefghijklmnopqrstuvwxyz"
        ));
        add(format!("sk_{}_{}", "live", alnum(24)));
        add(format!("sk_{}_{}", "test", alnum(24)));
        add(format!("rk_{}_{}", "live", alnum(24)));
        add("postgres://dbuser:dbpass@localhost:5432/appdb".into());
        add("mysql://dbuser:dbpass@localhost:3306/appdb".into());
        add("mongodb+srv://dbuser:dbpass@cluster.mongodb.net/appdb".into());
        add("redis://:authpass@redis.example.com:6379".into());
        add(format!("SG.{}.{}", alnum(22), alnum(43)));
        add(format!("SK{}", hexs(32)));
        add(format!("twilio_auth_token=\"{}\"", hexs(32)));
        add(format!("npm_{}", alnum(36)));
        add(format!("pypi-{}", alnum(50)));
        add(format!("shpat_{}", hexs(32)));
        add(format!("shpss_{}", hexs(32)));
        add(format!("sq0atp-{}", alnum(22)));
        add(format!("sq0csp-{}", alnum(43)));
        add(format!("M{}.{}.{}", alnum(23), alnum(6), alnum(27)));
        add(format!(
            "https://{}.com/api/webhooks/123456789012345678/{}",
            "discord",
            alnum(30)
        ));
        add("heroku_api_key=\"01234567-89ab-cdef-0123-456789abcdef\"".into());
        add(format!("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.{}", alnum(20)));
        add(format!("AccountKey=\"{}==\"", alnum(86)));
        add(format!(
            "DefaultEndpointsProtocol=https;AccountName=acct;AccountKey={}==",
            alnum(86)
        ));
        add(format!("https://x.blob.core.windows.net/c?sig={}%3D", alnum(43)));
        add(format!("azure_client_secret=\"{}\"", alnum(34)));
        add(format!("dop_v1_{}", hexs(64)));
        add(format!("doo_v1_{}", hexs(64)));
        add(format!("dor_v1_{}", hexs(64)));
        add(format!("datadog_api_key=\"{}\"", hexs(32)));
        add(format!("datadog_app_key=\"{}\"", hexs(40)));
        add(format!("{}-us1", hexs(32)));
        add(format!("key-{}", alnum(32)));
        add(format!("cloudflare_api_key=\"{}\"", hexs(37)));
        add(format!("cloudflare_api_token=\"{}\"", alnum(40)));
        add(format!("AIza{}", alnum(35))); // FIREBASE_API_KEY: same pattern as GOOGLE_API_KEY
        add("https://myapp-1234.firebaseio.com".into());
        add(format!("sk-{}", alnum(48)));
        add(format!("sk-ant-{}", alnum(90)));
        add(format!("hvs.{}", alnum(24)));
        add(format!("hvb.{}", alnum(24)));
        add(format!("atlassian_api_token=\"{}\"", alnum(24)));
        add(format!("lin_api_{}", alnum(40)));
        add(format!("{}_{}", "secret", alnum(43)));
        add(format!("airtable_api_key=\"key{}\"", alnum(14)));
        add(format!(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{}.{}",
            alnum(30),
            alnum(30)
        ));
        add(format!("dp.pt.{}", alnum(40)));
        add(format!("dp.st.{}", alnum(40)));

        l.join("\n") + "\n"
    }

    /// Write `content` to a uniquely-named file under the temp dir, hand back the path.
    /// `tempfile` is not a dependency, so this is std-only.
    fn write_temp(content: &str) -> std::path::PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir()
            .join(format!("flash_audit_corpus_{}_{}.txt", std::process::id(), nanos));
        std::fs::write(&path, content).expect("failed to write temp corpus");
        path
    }

    fn rule(id: &str, pattern: &str) -> Rule {
        Rule {
            id: id.to_string(),
            pattern: pattern.to_string(),
            description: None,
            risk: RiskMetadata::default(),
        }
    }

    #[test]
    fn scan_detects_aws_access_key() {
        let scanner = Scanner::new(vec![rule("aws-access-key", r"AKIA[0-9A-Z]{16}")]);
        let vulns = scanner.scan(b"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n", "creds.env");
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].rule_id, "aws-access-key");
        assert_eq!(vulns[0].line, 1);
    }

    #[test]
    fn scan_reports_no_false_positive_on_clean_text() {
        let scanner = Scanner::new(vec![rule("aws-access-key", r"AKIA[0-9A-Z]{16}")]);
        let vulns = scanner.scan(b"just some ordinary configuration text\n", "app.conf");
        assert!(vulns.is_empty());
    }

    #[test]
    fn scan_reports_correct_line_number() {
        let scanner = Scanner::new(vec![rule("slack-bot", r"xoxb-[0-9A-Za-z-]+")]);
        let content = b"line one\nline two\nSLACK=xoxb-123456789012-abcdef\n";
        let vulns = scanner.scan(content, "cfg");
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].line, 3);
    }

    #[test]
    fn long_secret_is_redacted_with_twelve_char_prefix() {
        let scanner = Scanner::new(vec![rule("github-pat", r"ghp_[0-9A-Za-z]{36}")]);
        let secret = "ghp_1234567890abcdefghijABCDEFGHIJ012345";
        let vulns = scanner.scan(format!("token={secret}").as_bytes(), "cfg");
        assert_eq!(vulns.len(), 1);
        assert!(vulns[0].match_content.ends_with("...[REDACTED]"));
        // Redaction keeps exactly the first 12 characters of the match.
        assert!(vulns[0].match_content.starts_with(&secret[..12]));
    }

    #[test]
    fn multibyte_match_redaction_does_not_panic() {
        // Regression: byte-slicing the first 12 bytes could land mid-codepoint
        // and panic. Redaction now truncates by characters.
        let scanner = Scanner::new(vec![rule("generic-key", r"KEY=\S+")]);
        let vulns = scanner.scan("KEY=café_münchen_schlüssel_secret".as_bytes(), "cfg");
        assert_eq!(vulns.len(), 1);
        assert!(vulns[0].match_content.contains("...[REDACTED]"));
    }

    #[test]
    fn fingerprint_is_deterministic_and_quote_insensitive() {
        let scanner = Scanner::new(vec![rule("slack-bot", r#"xoxb-[0-9A-Za-z-]+"#)]);
        let bare = &scanner.scan(b"t=xoxb-1-abc", "a")[0];
        // Same secret, wrapped in quotes/whitespace, must normalize to the same fingerprint.
        let quoted = Vulnerability {
            raw_secret: "  \"xoxb-1-abc\"  ".to_string(),
            ..bare.clone()
        };
        assert_eq!(bare.generate_fingerprint(), quoted.generate_fingerprint());
    }

    #[test]
    fn extract_keyword_uses_known_prefix() {
        assert_eq!(Scanner::extract_keyword(r"AKIA[0-9A-Z]{16}").as_deref(), Some("AKIA"));
        assert_eq!(Scanner::extract_keyword(r"ghp_[0-9A-Za-z]{36}").as_deref(), Some("ghp_"));
    }

    #[test]
    fn extract_keyword_returns_none_when_no_literal_is_guaranteed() {
        // A pattern with no literal that must appear in every match cannot be gated behind
        // a keyword. It must yield None (-> always run), never an invented trigger.
        assert_eq!(Scanner::extract_keyword(r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}"), None);
    }

    #[test]
    fn embedded_default_rules_all_compile() {
        let cfg = Config::default_rules();
        let rule_count = cfg.rules.len();
        assert!(rule_count >= 60, "expected the full embedded ruleset");
        let scanner = Scanner::new(cfg.rules);
        let (compiled, keywords) = scanner.stats();
        // Every rule must compile to a regex; none may be dropped by a bad pattern.
        assert_eq!(compiled, rule_count);
        // Keywords are deduplicated and some rules are keyword-less, so there are strictly
        // fewer distinct keywords than rules. A shared keyword must not lose a rule --
        // that invariant is covered by the full-ruleset coverage test.
        assert!(keywords > 0 && keywords <= compiled);
    }

    /// Every rule in the shipped ruleset must fire against a matching secret when the WHOLE
    /// ruleset is loaded -- not just when the rule is loaded on its own.
    ///
    /// This is the test that was missing. The pre-filter used to drop 19 of 66 rules
    /// (shared keywords nominating only their first rule, short keywords masking longer
    /// ones, and an invented "password" trigger), and every existing test passed anyway
    /// because they each built a Scanner from one or two rules.
    #[test]
    fn full_ruleset_detects_every_rule_id() {
        use crate::utils::file_loader::FileLoader;

        let cfg = Config::default_rules();
        let expected: Vec<String> = cfg.rules.iter().map(|r| r.id.clone()).collect();

        // Generate the corpus, round-trip it through a real file so FileLoader is on the
        // path too, then scan it exactly as main.rs would.
        let path = write_temp(&generated_corpus());
        let content = FileLoader::load(&path).expect("temp corpus must be loadable");
        let vulns = scanner_scan_and_cleanup(&Scanner::new(cfg.rules), &content, &path);

        let found: HashSet<&str> = vulns.iter().map(|v| v.rule_id.as_str()).collect();
        let missing: Vec<&str> = expected
            .iter()
            .map(|s| s.as_str())
            .filter(|id| !found.contains(id))
            .collect();

        assert!(
            missing.is_empty(),
            "{} of {} rules never fired against the full ruleset: {:?}",
            missing.len(),
            expected.len(),
            missing
        );
    }

    /// Scan, then remove the temp file whatever the outcome.
    fn scanner_scan_and_cleanup(
        scanner: &Scanner,
        content: &[u8],
        path: &std::path::Path,
    ) -> Vec<Vulnerability> {
        let vulns = scanner.scan(content, &path.to_string_lossy());
        let _ = std::fs::remove_file(path);
        vulns
    }
}
