#!/usr/bin/env bash
# ABOUTME: PostToolUse hook that detects credential exposure and destructive SQL in written files.
# ABOUTME: Tier 3 of the claude-guard safety model — warns without blocking.

set -euo pipefail

# Dependency check — fail visibly rather than silently skipping all scans
for cmd in rg jq; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "claude-guard: credential-scanner requires '$cmd' but it is not installed" >&2
        exit 0
    fi
done

INPUT=$(cat)

TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name')

# Only process file-writing tools
case "$TOOL_NAME" in
    Write|Edit|MultiEdit) ;;
    *) exit 0 ;;
esac

FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty')

if [ -z "$FILE_PATH" ]; then
    exit 0
fi

# Skip known safe directories and file types
case "$FILE_PATH" in
    */.git/*) exit 0 ;;
    */.env.example) exit 0 ;;
    */.env.template) exit 0 ;;
    */.env.sample) exit 0 ;;
    */node_modules/*) exit 0 ;;
    */package-lock.json) exit 0 ;;
    */yarn.lock) exit 0 ;;
    */pnpm-lock.yaml) exit 0 ;;
    */Podfile.lock) exit 0 ;;
    */go.sum) exit 0 ;;
    */Cargo.lock) exit 0 ;;
esac

if [ ! -f "$FILE_PATH" ]; then
    exit 0
fi

WARNINGS=""

# --- Credential patterns ---

# AWS Access Key ID
if rg -q 'AKIA[0-9A-Z]{16}' "$FILE_PATH" 2>/dev/null; then
    WARNINGS="${WARNINGS}- AWS Access Key ID detected\n"
fi

# AWS Secret Access Key (40-char base64)
if rg -q 'aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}' "$FILE_PATH" 2>/dev/null; then
    WARNINGS="${WARNINGS}- AWS Secret Access Key detected\n"
fi

# Generic API key patterns
if rg -qi '(api[_-]?key|apikey)\s*[=:]\s*["'\'']?[A-Za-z0-9+/=_-]{20,}' "$FILE_PATH" 2>/dev/null; then
    WARNINGS="${WARNINGS}- Potential API key detected\n"
fi

# Secret/token/password patterns (skip env var references)
if rg -qi '(secret|token|password|credential)\s*[=:]\s*["'\''"][^"'\'']{8,}' "$FILE_PATH" 2>/dev/null; then
    if ! rg -q '(process\.env|os\.environ|\$\{|getenv|ENV\[|var\()' "$FILE_PATH" 2>/dev/null; then
        WARNINGS="${WARNINGS}- Potential secret/token/password hardcoded\n"
    fi
fi

# Private key markers
if rg -q 'PRIVATE KEY-----' "$FILE_PATH" 2>/dev/null; then
    WARNINGS="${WARNINGS}- Private key detected\n"
fi

# GitHub tokens (ghp_, gho_, ghu_, ghs_, ghr_)
if rg -q '(ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9]{20,}' "$FILE_PATH" 2>/dev/null; then
    WARNINGS="${WARNINGS}- GitHub token detected\n"
fi

# GitLab tokens
if rg -q 'glpat-[A-Za-z0-9_-]{20,}' "$FILE_PATH" 2>/dev/null; then
    WARNINGS="${WARNINGS}- GitLab token detected\n"
fi

# Slack tokens
if rg -q 'xox[baprs]-[0-9]{10,}' "$FILE_PATH" 2>/dev/null; then
    WARNINGS="${WARNINGS}- Slack token detected\n"
fi

# Connection strings with credentials
if rg -qi '(postgresql|mysql|mongodb|redis|amqp)://[^:]+:[^@]+@' "$FILE_PATH" 2>/dev/null; then
    if ! rg -q '(process\.env|os\.environ|\$\{|getenv|ENV\[|var\()' "$FILE_PATH" 2>/dev/null; then
        WARNINGS="${WARNINGS}- Database connection string with embedded credentials detected\n"
    fi
fi

# JWT tokens (three base64 segments separated by dots)
if rg -q 'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]' "$FILE_PATH" 2>/dev/null; then
    WARNINGS="${WARNINGS}- JWT token detected\n"
fi

# Google API keys
if rg -q 'AIza[0-9A-Za-z_-]{35}' "$FILE_PATH" 2>/dev/null; then
    WARNINGS="${WARNINGS}- Google API key detected\n"
fi

# Stripe keys
if rg -q '(sk_live_|pk_live_|sk_test_|rk_live_)[A-Za-z0-9]{20,}' "$FILE_PATH" 2>/dev/null; then
    WARNINGS="${WARNINGS}- Stripe API key detected\n"
fi

# --- Destructive SQL in files (Tier 3 warning) ---

# Only check SQL-relevant file extensions
case "$FILE_PATH" in
    *.sql|*.py|*.js|*.ts|*.rb|*.go|*.java|*.php|*.sh|*.bash)
        if rg -qi 'DROP\s+(TABLE|DATABASE|SCHEMA|INDEX)' "$FILE_PATH" 2>/dev/null; then
            WARNINGS="${WARNINGS}- Destructive SQL (DROP) found in file — verify this is intentional\n"
        fi
        if rg -qi 'TRUNCATE\s+' "$FILE_PATH" 2>/dev/null; then
            WARNINGS="${WARNINGS}- Destructive SQL (TRUNCATE) found in file — verify this is intentional\n"
        fi
        if rg -qi 'DELETE\s+FROM\s+\w+\s*;' "$FILE_PATH" 2>/dev/null; then
            if ! rg -qi 'DELETE\s+FROM\s+\w+\s+WHERE' "$FILE_PATH" 2>/dev/null; then
                WARNINGS="${WARNINGS}- DELETE FROM without WHERE clause found in file\n"
            fi
        fi
        ;;
esac

# Output warnings if any found
if [ -n "$WARNINGS" ]; then
    jq -n --arg file "$FILE_PATH" --arg warnings "$WARNINGS" '{
        "additionalContext": ("CREDENTIAL/SAFETY WARNING in " + $file + ":\n" + $warnings + "\nReview the file and ensure no secrets are committed. Use environment variables for sensitive values.")
    }'
fi

exit 0
