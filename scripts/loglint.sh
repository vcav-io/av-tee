#!/usr/bin/env bash
set -euo pipefail

# CI lint: detect potentially unsafe logging in session-adjacent code.
# Requires annotation-based opt-out only.

RELAY_SRC="packages/tee-relay/src"

# Modules that handle decrypted data
SENSITIVE_MODULES=(
    "$RELAY_SRC/relay.rs"
    "$RELAY_SRC/session.rs"
    "$RELAY_SRC/handlers.rs"
    "$RELAY_SRC/echo.rs"
    "$RELAY_SRC/error.rs"
)

PATTERNS='(tracing::)?(info|warn|error|debug|trace)!|log::(info|warn|error|debug|trace)!|\.context\s*\(|anyhow!\s*\('
GLOBAL_BAN='dbg!|println!|eprintln!'

EXIT_CODE=0

check_line() {
    local file="$1" lineno="$2" line="$3"
    # Auto-pass: annotation present
    echo "$line" | grep -qE '// SAFETY: no plaintext|// LOGLINT:' && return 0
    # Auto-pass: line contains REDACTED (using redacting Debug impl)
    echo "$line" | grep -q 'REDACTED' && return 0
    # Auto-pass: comment-only line
    echo "$line" | grep -qE '^\s*//' && return 0
    return 1
}

# Check sensitive modules for logging patterns
for file in "${SENSITIVE_MODULES[@]}"; do
    [ -f "$file" ] || continue
    # Check for file-level opt-out
    head -5 "$file" | grep -q '// LOGLINT: GLOBAL-SAFE' && continue

    while IFS=: read -r lineno line; do
        if ! check_line "$file" "$lineno" "$line"; then
            echo "LINT: $file:$lineno — unannotated logging in sensitive module"
            echo "  $line"
            EXIT_CODE=1
        fi
    done < <(grep -nE "$PATTERNS" "$file" || true)
done

# Global: dbg!/println!/eprintln! banned in all non-test source
for file in $(find packages -name '*.rs' -not -path '*/tests/*' -not -path '*/target/*'); do
    while IFS=: read -r lineno line; do
        if ! check_line "$file" "$lineno" "$line"; then
            echo "LINT: $file:$lineno — banned macro in non-test code"
            echo "  $line"
            EXIT_CODE=1
        fi
    done < <(grep -nE "$GLOBAL_BAN" "$file" || true)
done

[ $EXIT_CODE -eq 0 ] && echo "loglint: PASS"
exit $EXIT_CODE
