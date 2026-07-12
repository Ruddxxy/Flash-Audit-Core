mod scanner;
mod utils;

use clap::{Parser, ValueEnum};
use rayon::prelude::*;
use ignore::WalkBuilder;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;
use std::process::Command;
use scanner::Scanner;
use utils::file_loader::FileLoader;
use utils::config::Config;
use utils::sarif::SarifReport;
use utils::telemetry::{TelemetryClient, TelemetryEvent, EventType};
use utils::state::StateContext;
use tracing::{info, debug, warn, Level};

#[derive(Debug, Clone, ValueEnum)]
enum OutputFormat {
    Json,
    Sarif,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to scan
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Path to rules.yaml config file
    #[arg(long)]
    rules: Option<PathBuf>,

    /// Output format (json or sarif for GitHub Advanced Security)
    #[arg(long, short, value_enum, default_value_t = OutputFormat::Json)]
    format: OutputFormat,

    /// Enable Shannon Entropy scanning for high-randomness strings
    #[arg(long, default_value_t = false)]
    entropy: bool,

    /// Entropy threshold (higher = stricter, less false positives)
    #[arg(long, default_value_t = 4.5)]
    entropy_threshold: f32,

    /// Verbose output (show skipped files, errors)
    #[arg(short, long, default_value_t = false)]
    verbose: bool,

    /// Only scan files changed since specified git ref (e.g., HEAD~1, main, origin/main)
    #[arg(long, value_name = "REF")]
    git_diff: Option<String>,

    /// Only scan staged files (for pre-commit hooks)
    #[arg(long, default_value_t = false)]
    staged: bool,

    /// URL to report telemetry events (enables stateful risk tracking)
    #[arg(long, value_name = "URL")]
    report_to: Option<String>,

    /// Organization name for telemetry context
    #[arg(long, default_value = "")]
    org: String,

    /// Repository name for telemetry context
    #[arg(long, default_value = "")]
    repo: String,

    /// API key for state sync authentication
    #[arg(long, env = "FLASHAUDIT_API_KEY", default_value = "")]
    api_key: String,
}

/// Get list of files changed since a git ref
fn get_git_diff_files(base_ref: &str, repo_path: &PathBuf) -> Result<Vec<PathBuf>, String> {
    // Validate git ref to prevent command injection
    if !base_ref.chars().all(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | '/' | '.' | '~' | '^')) {
        return Err(format!("Invalid git ref: {}", base_ref));
    }

    // base_ref goes BEFORE the `--`. With it after, git reads the ref as a pathspec, the
    // diff matches nothing, and every scan reports clean. The trailing `--` still
    // terminates the pathspec list so a ref that also names a file stays unambiguous.
    let output = Command::new("git")
        .args(["diff", "--name-only", "--diff-filter=ACMR", base_ref, "--"])
        .current_dir(repo_path)
        .output()
        .map_err(|e| format!("Failed to run git: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("git diff failed: {}", stderr.trim()));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let files: Vec<PathBuf> = stdout
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| repo_path.join(line))
        .filter(|path| path.exists() && path.is_file())
        .collect();

    Ok(files)
}

/// Get list of staged files
fn get_staged_files(repo_path: &PathBuf) -> Result<Vec<PathBuf>, String> {
    let output = Command::new("git")
        .args(["diff", "--name-only", "--cached", "--diff-filter=ACMR"])
        .current_dir(repo_path)
        .output()
        .map_err(|e| format!("Failed to run git: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("git diff --cached failed: {}", stderr.trim()));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let files: Vec<PathBuf> = stdout
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| repo_path.join(line))
        .filter(|path| path.exists() && path.is_file())
        .collect();

    Ok(files)
}

fn main() {
    let args = Args::parse();
    let start = Instant::now();

    // Initialize logging
    let log_level = if args.verbose { Level::DEBUG } else { Level::WARN };
    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .with_target(false)
        .init();

    // Load configuration
    let config = if let Some(rules_path) = &args.rules {
        Config::load(rules_path).unwrap_or_else(|e| {
            eprintln!("Failed to load rules from {:?}: {}", rules_path, e);
            std::process::exit(1);
        })
    } else {
        // Fallback to embedded default rules if no file provided
        Config::default_rules()
    };

    let scanner = Scanner::new(config.rules);
    let (rule_count, keyword_count) = scanner.stats();
    info!("Loaded {} rules with {} keywords", rule_count, keyword_count);

    // Initialize State Engine (fetch previous state for diff detection)
    let repo_id = if args.repo.is_empty() {
        format!("{}/default", args.org)
    } else if args.repo.contains('/') {
        args.repo.clone()
    } else {
        format!("{}/{}", args.org, args.repo)
    };

    let state = if let Some(ref report_url) = args.report_to {
        if !args.api_key.is_empty() {
            StateContext::fetch(report_url, &args.api_key, &args.org, &repo_id)
        } else {
            StateContext::new()
        }
    } else {
        // Try loading from local cache if no remote configured
        StateContext::load_from(".flashaudit_state.json").unwrap_or_default()
    };
    let state = Mutex::new(state);

    // Initialize Telemetry Client (non-blocking background thread)
    let telemetry = if let Some(ref report_url) = args.report_to {
        TelemetryClient::new(report_url.clone())
    } else {
        TelemetryClient::disabled()
    };

    // File Discovery Phase
    let files: Vec<PathBuf> = if args.staged {
        // Scan only staged files (pre-commit hook mode)
        info!("Scanning staged files only");
        match get_staged_files(&args.path) {
            Ok(f) => {
                if f.is_empty() {
                    eprintln!("No staged files to scan");
                    println!("[]");
                    return;
                }
                info!("Found {} staged files", f.len());
                f
            }
            Err(e) => {
                eprintln!("Error getting staged files: {}", e);
                std::process::exit(2);
            }
        }
    } else if let Some(ref base_ref) = args.git_diff {
        // Scan only files changed since base ref (CI mode)
        info!("Scanning files changed since {}", base_ref);
        match get_git_diff_files(base_ref, &args.path) {
            Ok(f) => {
                if f.is_empty() {
                    eprintln!("No files changed since {}", base_ref);
                    println!("[]");
                    return;
                }
                info!("Found {} changed files", f.len());
                f
            }
            Err(e) => {
                eprintln!("Error getting git diff: {}", e);
                std::process::exit(2);
            }
        }
    } else {
        // Full scan: Use `ignore` crate for .gitignore support
        let mut files = Vec::new();
        let walker = WalkBuilder::new(&args.path)
            .standard_filters(true)
            .hidden(false) // Allow scanning .env if not ignored by git
            .build();

        for result in walker {
            match result {
                Ok(entry) => {
                    if entry.file_type().is_some_and(|ft| ft.is_file())
                        && !entry.path().components().any(|c| c.as_os_str() == ".git")
                    {
                        files.push(entry.path().to_owned());
                    }
                }
                Err(err) => warn!("Error walking directory: {}", err),
            }
        }

        if files.is_empty() {
            eprintln!("No files found to scan in {:?}", args.path);
            println!("[]");
            return;
        }
        files
    };

    // Parallel Processing Phase
    let results: Mutex<Vec<scanner::Vulnerability>> = Mutex::new(Vec::new());
    let scanned_count = AtomicUsize::new(0);
    let error_count = AtomicUsize::new(0);
    let org = args.org.clone();
    let repo = args.repo.clone();

    files.par_iter().for_each(|path| {
        match FileLoader::load(path) {
            Ok(content) => {
                scanned_count.fetch_add(1, Ordering::Relaxed);
                debug!("Scanning: {}", path.display());

                let mut vulns = scanner.scan(&content, path.to_string_lossy().as_ref());

                if args.entropy {
                    let entropy_vulns = scanner.scan_entropy(&content, path.to_string_lossy().as_ref(), args.entropy_threshold);
                    vulns.extend(entropy_vulns);
                }

                if !vulns.is_empty() {
                    // Track findings in state and send telemetry
                    for vuln in &vulns {
                        let fingerprint = vuln.generate_fingerprint();

                        // Track in state engine
                        if let Ok(mut state_lock) = state.lock() {
                            state_lock.track(fingerprint.clone());
                        }

                        // Send telemetry event (non-blocking)
                        telemetry.send(TelemetryEvent {
                            event_type: EventType::Found,
                            fingerprint,
                            rule_id: vuln.rule_id.clone(),
                            file: vuln.file.clone(),
                            org: org.clone(),
                            repo: repo.clone(),
                            risk_class: vuln.risk.class.clone(),
                            risk_impact: vuln.risk.impact.clone(),
                        });
                    }

                    if let Ok(mut lock) = results.lock() {
                        lock.extend(vulns);
                    }
                }
            },
            Err(e) => {
                error_count.fetch_add(1, Ordering::Relaxed);
                debug!("Skipped {}: {}", path.display(), e);
            }
        }
    });

    let duration = start.elapsed();

    // Output Phase
    let results = results.into_inner().unwrap_or_else(|e| e.into_inner());
    let scanned = scanned_count.load(Ordering::Relaxed);
    let errors = error_count.load(Ordering::Relaxed);

    // Post-scan: Detect fixed secrets and send telemetry
    let state = state.into_inner().unwrap_or_else(|e| e.into_inner());
    let fixed_hashes = state.get_fixed();
    let new_count = state.get_new().len();
    let fixed_count = fixed_hashes.len();

    // Send REMOVED events for fixed secrets
    for fingerprint in fixed_hashes {
        telemetry.send(TelemetryEvent {
            event_type: EventType::Removed,
            fingerprint,
            rule_id: String::new(),
            file: String::new(),
            org: org.clone(),
            repo: repo.clone(),
            risk_class: String::new(),
            risk_impact: String::new(),
        });
    }

    // Save state for next run
    if let Err(e) = state.save() {
        debug!("Failed to save state cache: {}", e);
    }

    // Flush telemetry before exit
    telemetry.flush();

    // Print summary to stderr (doesn't interfere with JSON/SARIF output)
    eprintln!(
        "Scanned {} files in {:.2}s. {} errors. {} secrets found ({} new, {} fixed).",
        scanned,
        duration.as_secs_f64(),
        errors,
        results.len(),
        new_count,
        fixed_count
    );

    // Output in requested format
    let output_result = match args.format {
        OutputFormat::Json => serde_json::to_string_pretty(&results),
        OutputFormat::Sarif => {
            let sarif = SarifReport::from_vulnerabilities(&results);
            sarif.to_json()
        }
    };

    match output_result {
        Ok(output) => {
            println!("{}", output);
            if !results.is_empty() {
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("Failed to serialize results: {}", e);
            std::process::exit(2);
        }
    }
}
