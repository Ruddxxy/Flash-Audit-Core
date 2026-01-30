use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::time::Duration;

const STATE_FILE: &str = ".flashaudit_state.json";

/// Response from the remote state API
#[derive(Debug, Deserialize)]
struct RemoteStateResponse {
    active_hashes: Vec<String>,
}

/// Local state cache for persistence between scans
#[derive(Debug, Serialize, Deserialize, Default)]
struct LocalStateCache {
    hashes: Vec<String>,
}

/// State context for tracking finding fingerprints across scans.
/// Enables detection of fixed (removed) secrets.
pub struct StateContext {
    previous_hashes: HashSet<String>,
    current_hashes: HashSet<String>,
}

impl StateContext {
    /// Create a new empty state context
    pub fn new() -> Self {
        Self {
            previous_hashes: HashSet::new(),
            current_hashes: HashSet::new(),
        }
    }

    /// Fetch previous state from remote API.
    /// Falls back to local cache if API fails, or empty set if both fail.
    pub fn fetch(api_url: &str, api_key: &str, org: &str, repo: &str) -> Self {
        let previous_hashes = Self::fetch_remote(api_url, api_key, org, repo)
            .or_else(Self::load_local_cache)
            .unwrap_or_default();

        Self {
            previous_hashes,
            current_hashes: HashSet::new(),
        }
    }

    /// Fetch state from remote API
    fn fetch_remote(api_url: &str, api_key: &str, org: &str, repo: &str) -> Option<HashSet<String>> {
        // Construct the state URL - replace /events with /state if present
        let base_url = api_url.trim_end_matches('/');
        let state_url = if base_url.ends_with("/events") {
            format!("{}/state", base_url.trim_end_matches("/events"))
        } else {
            format!("{}/state", base_url)
        };

        // Build repo identifier
        let repo_param = if repo.contains('/') {
            repo.to_string()
        } else if !org.is_empty() {
            format!("{}/{}", org, repo)
        } else {
            repo.to_string()
        };

        let url = format!("{}?repo={}", state_url, urlencoding::encode(&repo_param));

        let response = ureq::get(&url)
            .set("X-API-Key", api_key)
            .set("Content-Type", "application/json")
            .timeout(Duration::from_secs(10))
            .call()
            .ok()?;

        let body_str = response.into_string().ok()?;
        let body: RemoteStateResponse = serde_json::from_str(&body_str).ok()?;
        Some(body.active_hashes.into_iter().collect())
    }

    /// Load state from local cache file
    fn load_local_cache() -> Option<HashSet<String>> {
        let content = fs::read_to_string(STATE_FILE).ok()?;
        let cache: LocalStateCache = serde_json::from_str(&content).ok()?;
        Some(cache.hashes.into_iter().collect())
    }

    /// Track a finding fingerprint in the current scan
    pub fn track(&mut self, fingerprint: String) {
        self.current_hashes.insert(fingerprint);
    }

    /// Get all current tracked hashes
    #[allow(dead_code)]
    pub fn current_hashes(&self) -> &HashSet<String> {
        &self.current_hashes
    }

    /// Get hashes that were in previous state but not in current (fixed secrets)
    pub fn get_fixed(&self) -> Vec<String> {
        self.previous_hashes
            .difference(&self.current_hashes)
            .cloned()
            .collect()
    }

    /// Get hashes that are new (in current but not in previous)
    pub fn get_new(&self) -> Vec<String> {
        self.current_hashes
            .difference(&self.previous_hashes)
            .cloned()
            .collect()
    }

    /// Check if a fingerprint existed in previous state
    #[allow(dead_code)]
    pub fn was_known(&self, fingerprint: &str) -> bool {
        self.previous_hashes.contains(fingerprint)
    }

    /// Save current state to local cache file
    pub fn save(&self) -> std::io::Result<()> {
        let cache = LocalStateCache {
            hashes: self.current_hashes.iter().cloned().collect(),
        };
        let content = serde_json::to_string_pretty(&cache)?;
        fs::write(STATE_FILE, content)
    }

    /// Save state to a specific path (for custom cache locations)
    #[allow(dead_code)]
    pub fn save_to<P: AsRef<Path>>(&self, path: P) -> std::io::Result<()> {
        let cache = LocalStateCache {
            hashes: self.current_hashes.iter().cloned().collect(),
        };
        let content = serde_json::to_string_pretty(&cache)?;
        fs::write(path, content)
    }

    /// Load state from a specific path
    pub fn load_from<P: AsRef<Path>>(path: P) -> Option<Self> {
        let content = fs::read_to_string(path).ok()?;
        let cache: LocalStateCache = serde_json::from_str(&content).ok()?;
        Some(Self {
            previous_hashes: cache.hashes.into_iter().collect(),
            current_hashes: HashSet::new(),
        })
    }
}

impl Default for StateContext {
    fn default() -> Self {
        Self::new()
    }
}
