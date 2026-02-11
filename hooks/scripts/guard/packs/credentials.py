# ABOUTME: Credential and secret detection patterns for file scanning.
# ABOUTME: Covers AWS, API keys, tokens, private keys, connection strings, JWT, Stripe, Google.
import re

# Credential patterns: (compiled_regex, label, env_var_suppressed)
# When env_var_suppressed is True, the match is skipped if the file also contains
# environment variable references (process.env, os.environ, ${VAR}, etc.)
CREDENTIAL_PATTERNS = [
    (re.compile(r'AKIA[0-9A-Z]{16}'),
     "AWS Access Key ID", False),

    (re.compile(r'aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}'),
     "AWS Secret Access Key", False),

    (re.compile(r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?[A-Za-z0-9+/=_-]{20,}'),
     "Potential API key", False),

    (re.compile(r'(?i)(secret|token|password|credential)\s*[=:]\s*["\'][^"\']{8,}'),
     "Potential secret/token/password hardcoded", True),

    (re.compile(r'PRIVATE KEY-----'),
     "Private key", False),

    (re.compile(r'(ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9]{20,}'),
     "GitHub token", False),

    (re.compile(r'glpat-[A-Za-z0-9_-]{20,}'),
     "GitLab token", False),

    (re.compile(r'xox[baprs]-[0-9]{10,}'),
     "Slack token", False),

    (re.compile(r'(?i)(postgresql|mysql|mongodb|redis|amqp)://[^:]+:[^@]+@'),
     "Database connection string with embedded credentials", True),

    (re.compile(r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]'),
     "JWT token", False),

    (re.compile(r'AIza[0-9A-Za-z_-]{35}'),
     "Google API key", False),

    (re.compile(r'(sk_live_|pk_live_|sk_test_|rk_live_)[A-Za-z0-9]{20,}'),
     "Stripe API key", False),
]

# Environment variable reference patterns used for false positive suppression
ENV_VAR_PATTERN = re.compile(
    r'process\.env|os\.environ|\$\{|getenv|ENV\[|var\('
)

# SQL patterns: (compiled_regex, label)
SQL_PATTERNS = [
    (re.compile(r'(?i)DROP\s+(TABLE|DATABASE|SCHEMA|INDEX)'),
     "Destructive SQL (DROP) found in file — verify this is intentional"),

    (re.compile(r'(?i)TRUNCATE\s+'),
     "Destructive SQL (TRUNCATE) found in file — verify this is intentional"),
]

# DELETE without WHERE is a special case — need to check both patterns
SQL_DELETE_PATTERN = re.compile(r'(?i)DELETE\s+FROM\s+\w+\s*;')
SQL_DELETE_WITH_WHERE = re.compile(r'(?i)DELETE\s+FROM\s+\w+\s+WHERE')

# File extensions where SQL scanning applies
SQL_EXTENSIONS = {
    ".sql", ".py", ".js", ".ts", ".rb", ".go", ".java", ".php", ".sh", ".bash"
}

# File paths that should be skipped entirely
SKIP_PATTERNS = [
    "/.git/",
    "/.env.example",
    "/.env.template",
    "/.env.sample",
    "/node_modules/",
    "/package-lock.json",
    "/yarn.lock",
    "/pnpm-lock.yaml",
    "/Podfile.lock",
    "/go.sum",
    "/Cargo.lock",
]


def should_skip(file_path: str) -> bool:
    """Check if the file should be skipped based on path patterns."""
    for pattern in SKIP_PATTERNS:
        if pattern in file_path or file_path.endswith(pattern.lstrip("/")):
            return True
    return False


def scan_file(file_path: str) -> list[str]:
    """Scan a file for credentials and destructive SQL. Returns list of warnings."""
    import os

    if should_skip(file_path):
        return []

    if not os.path.isfile(file_path):
        return []

    try:
        with open(file_path, "r", errors="ignore") as f:
            content = f.read()
    except OSError:
        return []

    warnings = []
    has_env_vars = bool(ENV_VAR_PATTERN.search(content))

    # Credential patterns
    for pattern, label, env_suppressed in CREDENTIAL_PATTERNS:
        if pattern.search(content):
            if env_suppressed and has_env_vars:
                continue
            warnings.append(f"- {label} detected")

    # SQL patterns (only for relevant file extensions)
    _, ext = os.path.splitext(file_path)
    if ext.lower() in SQL_EXTENSIONS:
        for pattern, label in SQL_PATTERNS:
            if pattern.search(content):
                warnings.append(f"- {label}")

        # Special DELETE without WHERE check
        if SQL_DELETE_PATTERN.search(content):
            if not SQL_DELETE_WITH_WHERE.search(content):
                warnings.append("- DELETE FROM without WHERE clause found in file")

    return warnings
