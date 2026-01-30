# FlashAudit

High-performance secrets scanner written in Rust. Enterprise-ready with SARIF output for GitHub Advanced Security.

**12x faster than Gitleaks. 6x fewer false positives.**

## Features

- **Blazing Fast**: Hybrid Aho-Corasick + Regex engine (8-12x faster than gitleaks)
- **Precise**: 66 specific patterns, zero generic rules = minimal false positives
- **Enterprise Ready**: SARIF 2.1.0 output for GitHub Advanced Security
- **Incremental**: `--git-diff` and `--staged` for CI/pre-commit hooks
- **Stateful Risk Engine**: Track secrets across scans, detect fixed issues
- **Non-Blocking Telemetry**: Optional event reporting with zero latency impact
- **Smart Binary Detection**: 30+ magic byte signatures
- **Configurable**: Load custom rules from YAML with risk metadata
- **CI Ready**: Proper exit codes + cross-platform binaries

## Benchmarks

| Repository | Files | FlashAudit | Gitleaks | Speedup |
|------------|-------|------------|----------|---------|
| Express | 240 | **0.03s** | 0.09s | 3x |
| Django | 7,033 | **0.51s** | 3.93s | 8x |
| Rust Compiler | 57,706 | **1.24s** | 15.23s | **12x** |

**Precision comparison:**
| Repository | FlashAudit | Gitleaks | Notes |
|------------|------------|----------|-------|
| Django | 1 real | 5 (4 FPs) | Gitleaks flags test fixtures |
| Rust | 4 real | 24 (20 FPs) | Gitleaks duplicates same finding |

## Installation

### Quick Install (Recommended)

**Linux / macOS:**
```bash
curl -sSfL https://raw.githubusercontent.com/Ruddxxy/Flash-Audit/main/install.sh | bash
```

**Windows (PowerShell):**
```powershell
irm https://raw.githubusercontent.com/Ruddxxy/Flash-Audit/main/install.ps1 | iex
```

### Other Methods

**Cargo (Rust):**
```bash
cargo install flash_audit
```

**Docker:**
```bash
docker run --rm -v "$(pwd):/repo" ghcr.io/ruddxxy/flash-audit:latest /repo
```

**From Source:**
```bash
git clone https://github.com/Ruddxxy/Flash-Audit.git
cd Flash-Audit
cargo build --release
# Binary at: target/release/flash_audit
```

**Pre-built Binaries:**
Download from [GitHub Releases](https://github.com/Ruddxxy/Flash-Audit/releases)

## Usage

```bash
# Basic scan (JSON output)
flash_audit /path/to/repo

# SARIF output for GitHub Advanced Security
flash_audit --format sarif /path/to/repo > results.sarif

# Incremental: Only scan files changed since main
flash_audit --git-diff main /path/to/repo

# Pre-commit hook: Only scan staged files
flash_audit --staged /path/to/repo

# Custom rules
flash_audit --rules my-rules.yaml /path/to/repo

# Entropy detection
flash_audit --entropy /path/to/repo

# With telemetry and state tracking
export FLASHAUDIT_API_KEY="your-api-key"
flash_audit --report-to https://api.example.com/events \
    --org my-org --repo my-repo /path/to/repo
```

## CI/CD Integration

### GitHub Actions

**Basic Usage:**
```yaml
- uses: Ruddxxy/Flash-Audit@v1
```

**Full Configuration:**
```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  secrets-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: Ruddxxy/Flash-Audit@v1
        with:
          path: '.'
          format: 'sarif'
          upload-sarif: true
          fail-on-finding: true
```

**PR-only Scanning:**
```yaml
- uses: Ruddxxy/Flash-Audit@v1
  with:
    git-diff: ${{ github.event.pull_request.base.sha }}
```

**Manual Setup (without action):**
```yaml
- uses: actions/checkout@v4

- name: Run FlashAudit
  run: |
    curl -sSfL https://raw.githubusercontent.com/Ruddxxy/Flash-Audit/main/install.sh | bash
    flash_audit . --format sarif > results.sarif
  continue-on-error: true

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### Pre-commit Hook

**Using pre-commit framework:**

1. Install pre-commit: `pip install pre-commit`

2. Add to `.pre-commit-config.yaml`:
```yaml
repos:
  - repo: https://github.com/Ruddxxy/Flash-Audit
    rev: v1.0.0  # Use latest version
    hooks:
      - id: flashaudit
```

3. Install: `pre-commit install`

**Manual git hook:**
```bash
# .git/hooks/pre-commit
#!/bin/bash
flash_audit --staged . || { echo "Secrets detected!"; exit 1; }
```

### Docker

```bash
# Scan current directory
docker run --rm -v "$(pwd):/repo" ghcr.io/ruddxxy/flash-audit:latest /repo

# SARIF output
docker run --rm -v "$(pwd):/repo" ghcr.io/ruddxxy/flash-audit:latest /repo --format sarif

# Scan staged files
docker run --rm -v "$(pwd):/repo" ghcr.io/ruddxxy/flash-audit:latest /repo --staged

# Custom rules
docker run --rm -v "$(pwd):/repo" -v "$(pwd)/rules.yaml:/rules.yaml" \
  ghcr.io/ruddxxy/flash-audit:latest /repo --rules /rules.yaml
```

## Output

```
Scanned 500 files in 0.12s. 2 errors. 3 secrets found (2 new, 1 fixed).
[
  {
    "file": "config.env",
    "line": 12,
    "match_content": "sk_live_...[REDACTED]",
    "rule_id": "STRIPE_LIVE_KEY",
    "description": "Stripe Live Secret Key",
    "risk": {
      "class": "api_key",
      "impact": "critical"
    }
  }
]
```

## CLI Options

| Option | Default | Description |
|--------|---------|-------------|
| `[PATH]` | `.` | Directory to scan |
| `-f, --format` | json | Output format: `json` or `sarif` |
| `--rules` | embedded | Path to custom rules.yaml |
| `--git-diff <REF>` | - | Only scan files changed since REF |
| `--staged` | false | Only scan staged files |
| `--entropy` | false | Enable entropy scanning |
| `--entropy-threshold` | 4.5 | Entropy threshold |
| `--report-to <URL>` | - | URL to report telemetry events |
| `--org <ORG>` | - | Organization name for context |
| `--repo <REPO>` | - | Repository name for context |
| `--api-key <KEY>` | env | API key (env: `FLASHAUDIT_API_KEY`) |
| `-v, --verbose` | false | Show debug output |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No secrets |
| 1 | Secrets found |
| 2 | Error |

## Custom Rules

Create `rules.yaml`:

```yaml
rules:
  - id: MY_API_KEY
    pattern: "mycompany_[a-zA-Z0-9]{32}"
    description: "MyCompany API Key"
    risk:
      class: api_key
      impact: high

  - id: INTERNAL_TOKEN
    pattern: "internal_token_[a-zA-Z0-9]{24}"
    description: "Internal Service Token"
    risk:
      class: credential
      impact: critical
```

Use: `flash_audit --rules rules.yaml .`

## Detected Secrets (66 Patterns)

| Category | Patterns |
|----------|----------|
| Private Keys | RSA, OpenSSH, EC, PGP, DSA, PuTTY |
| AWS | Access Key (AKIA), Secret Key |
| GitHub | ghp_, gho_, ghu_, ghs_, ghr_ |
| GitLab | glpat-, GR1348941 |
| Slack | xoxb-, xoxp-, webhooks |
| Google/Firebase | AIza, OAuth Client, firebaseio.com |
| Stripe | sk_live_, sk_test_, rk_live_ |
| Azure | Storage Key, Connection String, SAS Token |
| DigitalOcean | dop_v1_, doo_v1_, dor_v1_ |
| Datadog | API Key, App Key |
| Cloudflare | API Key, API Token |
| AI Services | OpenAI (sk-), Anthropic (sk-ant-) |
| HashiCorp Vault | hvs., hvb. |
| Database URLs | postgres://, mysql://, mongodb://, redis:// |
| Other | SendGrid, Twilio, NPM, PyPI, Shopify, Discord, Heroku, JWT |

## Backend API (Optional)

FlashAudit includes an optional Python backend for centralized tracking.

### Quick Start

```bash
cd backend
pip install -r requirements.txt
export ADMIN_KEY="your-secure-admin-key"
uvicorn main:app --host 0.0.0.0 --port 8000
```

### Docker Compose

```bash
docker-compose up -d backend
```

### Deploy to Render

1. Connect your GitHub repo to [Render](https://render.com)
2. Set root directory to `backend/`
3. Build: `pip install -r requirements.txt`
4. Start: `uvicorn main:app --host 0.0.0.0 --port $PORT`
5. Add `ADMIN_KEY` environment variable

### API Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/health` | GET | None | Health check |
| `/api/v1/state` | GET | X-API-Key | Get active secrets |
| `/api/v1/events` | POST | X-API-Key | Ingest scan events |
| `/api/v1/admin/organizations` | POST | X-Admin-Key | Create organization |

### Connect Scanner to Backend

```bash
export FLASHAUDIT_API_KEY="your-org-api-key"
flash_audit . --report-to https://your-backend.com/api/v1/events \
  --org myorg --repo myrepo
```

## Architecture

```
src/
├── main.rs             # CLI, orchestration
├── scanner.rs          # Hybrid Aho-Corasick + Regex engine
└── utils/
    ├── config.rs       # YAML rules loader
    ├── file_loader.rs  # Smart file loading
    ├── entropy.rs      # Shannon entropy
    ├── sarif.rs        # SARIF output
    ├── state.rs        # Stateful tracking
    └── telemetry.rs    # Event reporting

rules.yaml              # Default rules (embedded)
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License - see [LICENSE](LICENSE) for details.

Free to use, modify, and distribute.
