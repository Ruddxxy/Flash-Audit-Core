#!/bin/sh
set -e

# Replace the build-time placeholder with the runtime API URL.
# Next.js inlines NEXT_PUBLIC_* at build time, so we use sed at container
# start to inject the actual value from the environment.

API_URL="${NEXT_PUBLIC_API_URL:-http://localhost:8000}"

echo "[entrypoint] Injecting API URL: ${API_URL}"

# Verify build output exists
if [ ! -d "/app/.next" ]; then
    echo "[entrypoint] ERROR: /app/.next not found — build may have failed" >&2
    exit 1
fi

# Count and patch JS files
FILE_COUNT=$(find /app/.next -type f -name '*.js' | wc -l)
if [ "$FILE_COUNT" -eq 0 ]; then
    echo "[entrypoint] WARNING: No .js files found in /app/.next" >&2
fi

find /app/.next -type f -name '*.js' -exec sed -i "s|__FLASHAUDIT_API_URL__|${API_URL}|g" {} +

# Verify no placeholders remain
REMAINING=$(grep -rl "__FLASHAUDIT_API_URL__" /app/.next 2>/dev/null || true)
if [ -n "$REMAINING" ]; then
    echo "[entrypoint] WARNING: Placeholder still present in some files" >&2
fi

echo "[entrypoint] Ready (patched ${FILE_COUNT} JS files)"

exec "$@"
