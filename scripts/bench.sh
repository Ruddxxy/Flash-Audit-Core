#!/usr/bin/env bash
#
# Reproducible wall-clock benchmark for flash_audit against a large, real, secret-sparse
# codebase. Measurement only: it changes nothing in the scanner.
#
#   ./scripts/bench.sh
#
# Writes raw timing output to bench-results.txt and echoes it.
#
# Target: torvalds/linux at --depth 1. It is large, overwhelmingly source, and contains
# essentially no credentials, which is the workload a secrets scanner actually faces --
# nearly every file is a miss, so the run time is dominated by the pre-filter, not by
# match handling. Falls back to kubernetes/kubernetes if the Linux clone fails.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$REPO_ROOT/target/release/flash_audit"
OUT="$REPO_ROOT/bench-results.txt"

PRIMARY_URL="https://github.com/torvalds/linux"
PRIMARY_DIR="/tmp/bench-linux"
FALLBACK_URL="https://github.com/kubernetes/kubernetes"
FALLBACK_DIR="/tmp/bench-kubernetes"

WARMUP=2
RUNS=10

# --- 1. Acquire the target corpus ------------------------------------------------------
TARGET_DIR=""
TARGET_URL=""

clone_if_missing() {
    local url="$1" dir="$2"
    if [ -d "$dir/.git" ]; then
        echo "reusing existing checkout: $dir"
        return 0
    fi
    echo "cloning $url --depth 1 -> $dir"
    git clone --depth 1 "$url" "$dir" >/dev/null 2>&1
}

if clone_if_missing "$PRIMARY_URL" "$PRIMARY_DIR"; then
    TARGET_DIR="$PRIMARY_DIR"; TARGET_URL="$PRIMARY_URL"
elif clone_if_missing "$FALLBACK_URL" "$FALLBACK_DIR"; then
    echo "primary clone failed; fell back to kubernetes"
    TARGET_DIR="$FALLBACK_DIR"; TARGET_URL="$FALLBACK_URL"
else
    echo "FATAL: could not clone either benchmark target. Network blocked?" >&2
    exit 1
fi

# --- 2. Build release if stale ----------------------------------------------------------
echo "building release binary (skipped if fresh)..."
( cd "$REPO_ROOT" && cargo build --release )

# --- 3. Describe exactly what is being scanned ------------------------------------------
# flash_audit walks with the `ignore` crate (honours .gitignore) and skips any path with a
# .git component, so .git is excluded from the scan. Report the corpus the same way.
SIZE_ALL=$(du -sh "$TARGET_DIR" | cut -f1)
SIZE_SCANNED=$(du -sh --exclude=.git "$TARGET_DIR" | cut -f1)
FILE_COUNT=$(find "$TARGET_DIR" -type f -not -path '*/.git/*' | wc -l)

# --- 4. Findings from one representative run --------------------------------------------
# flash_audit exits 1 when it finds secrets, which `set -e`/pipefail would treat as fatal.
FINDINGS_LINE=$( { "$BIN" "$TARGET_DIR" 2>&1 >/dev/null || true; } | tail -1)
FINDINGS_COUNT=$( { "$BIN" "$TARGET_DIR" 2>/dev/null || true; } | grep -c '"rule_id"' || true)

# --- 5. Time it -------------------------------------------------------------------------
TIMING_METHOD=""
TIMING_OUT=""
if command -v hyperfine >/dev/null 2>&1; then
    TIMING_METHOD="hyperfine $(hyperfine --version | awk '{print $2}') (--warmup $WARMUP --runs $RUNS)"
    # flash_audit exits 1 when it finds secrets; hyperfine must not treat that as failure.
    TIMING_OUT=$(hyperfine --warmup "$WARMUP" --runs "$RUNS" -i "$BIN $TARGET_DIR" 2>&1)
else
    TIMING_METHOD="bash loop with date +%s.%N ($RUNS runs, median computed manually) -- hyperfine NOT installed"
    times=()
    for i in $(seq 1 $((WARMUP + RUNS))); do
        s=$(date +%s.%N)
        "$BIN" "$TARGET_DIR" >/dev/null 2>&1 || true
        e=$(date +%s.%N)
        [ "$i" -gt "$WARMUP" ] && times+=("$(echo "$e - $s" | bc)")
    done
    TIMING_OUT=$(printf '%s\n' "${times[@]}" | sort -n | awk '
        {a[NR]=$1}
        END {
            n=NR
            med = (n%2) ? a[(n+1)/2] : (a[n/2]+a[n/2+1])/2
            for (i=1;i<=n;i++) printf "  run %2d: %.3f s\n", i, a[i]
            printf "\n  min   : %.3f s\n  median: %.3f s\n  max   : %.3f s\n", a[1], med, a[n]
        }')
fi

# --- 5b. Ablation: what do the keyword-less ("always-run") rules cost? -------------------
# Six rules have no keyword, so they bypass the Aho-Corasick pre-filter and their regex runs
# against every file. Measure that cost by scanning the same corpus with those rules removed.
# This only feeds a --rules file to the existing binary; rules.yaml and src/ are untouched.
ALWAYS_RUN_IDS="DISCORD_BOT_TOKEN AZURE_STORAGE_KEY DATADOG_API_KEY DATADOG_APP_KEY CLOUDFLARE_API_KEY AIRTABLE_API_KEY"
ABLATION_OUT=""
if command -v python3 >/dev/null 2>&1 && command -v hyperfine >/dev/null 2>&1; then
    python3 - "$REPO_ROOT" "$ALWAYS_RUN_IDS" <<'PY'
import sys, yaml
root, ids = sys.argv[1], set(sys.argv[2].split())
cfg = yaml.safe_load(open(f"{root}/rules.yaml"))
kept = [r for r in cfg["rules"] if r["id"] not in ids]
only_discord = kept + [r for r in cfg["rules"] if r["id"] == "DISCORD_BOT_TOKEN"]
yaml.safe_dump({"rules": cfg["rules"]},  open("/tmp/bench_rules_full.yaml", "w"),      sort_keys=False)
yaml.safe_dump({"rules": kept},          open("/tmp/bench_rules_gated.yaml", "w"),     sort_keys=False)
yaml.safe_dump({"rules": only_discord},  open("/tmp/bench_rules_realistic.yaml", "w"), sort_keys=False)
PY
    ABLATION_OUT=$(hyperfine --warmup "$WARMUP" --runs "$RUNS" -i \
        -n "66 rules, as shipped (6 always-run)" \
            "$BIN $TARGET_DIR --rules /tmp/bench_rules_full.yaml" \
        -n "61 rules (only DISCORD_BOT_TOKEN always-run) = best case for keyword extraction" \
            "$BIN $TARGET_DIR --rules /tmp/bench_rules_realistic.yaml" \
        -n "60 rules (0 always-run) = unreachable floor" \
            "$BIN $TARGET_DIR --rules /tmp/bench_rules_gated.yaml" \
        2>&1)
fi

# --- 6. Report --------------------------------------------------------------------------
{
    echo "flash_audit benchmark"
    echo "====================="
    echo
    echo "binary       : $("$BIN" --version)"
    echo "commit       : $(cd "$REPO_ROOT" && git rev-parse --short HEAD)"
    echo "host         : $(uname -sr) | $(nproc) logical cores"
    echo "rules        : embedded ruleset (no --rules), default flags"
    echo
    echo "target repo  : $TARGET_URL (--depth 1)"
    echo "checkout     : $TARGET_DIR"
    echo "size on disk : $SIZE_ALL total, $SIZE_SCANNED excluding .git"
    echo "files walked : $FILE_COUNT (excluding .git)"
    echo
    echo "scanner says : $FINDINGS_LINE"
    echo "findings     : $FINDINGS_COUNT"
    echo
    echo "timing method: $TIMING_METHOD"
    echo
    echo "$TIMING_OUT"

    if [ -n "$ABLATION_OUT" ]; then
        echo
        echo "----------------------------------------------------------------------------"
        echo "ABLATION: cost of the 6 keyword-less (always-run) rules"
        echo "----------------------------------------------------------------------------"
        echo "always-run rules: $ALWAYS_RUN_IDS"
        echo
        echo "DISCORD_BOT_TOKEN has no literal anywhere in its pattern, so no keyword"
        echo "extractor could ever gate it. The other five could be gated, so the middle"
        echo "row is the realistic ceiling for improving extract_keyword."
        echo
        echo "$ABLATION_OUT"
    fi
} | tee "$OUT"

echo
echo "raw output written to $OUT"
