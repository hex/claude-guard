#!/usr/bin/env python3
# ABOUTME: PreToolUse hook that blocks dangerous commands using a three-tier model.
# ABOUTME: Tier 1 = hard deny, Tier 2 = deny + suggest alternative, Tier 3 = warn via credential-scanner.
"""
Command safety guard for Claude Code.

Intercepts Bash commands before execution and applies a three-tier safety model:
  Tier 1 (Hard Deny): Catastrophic, irreversible operations. Must be run manually.
  Tier 2 (Deny + Redirect): Dangerous but has a safer alternative Claude can use instead.
  Tier 3 (Warn): Handled by credential-scanner.sh, not this script.

Exit behavior:
  - Exit 0 with deny JSON = block the command
  - Exit 0 with no output = allow the command
"""
import json
import re
import sys

# --- Tier 1: Hard Deny ---
# Catastrophic commands that should never be run by an AI agent.
# Format: (regex, category, reason)
TIER1_PATTERNS = [
    # Filesystem catastrophe
    (
        r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+/\s|"
        r"rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+/\s|"
        r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+/\*|"
        r"rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+/\*|"
        r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+/$",
        "filesystem",
        "rm -rf on root filesystem is CATASTROPHIC. This will NOT be executed."
    ),
    (
        r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+~/?\s|"
        r"rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+~/?\s|"
        r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+~/?\*|"
        r"rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+~/?\*|"
        r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+~/?$|"
        r"rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+~/?$|"
        r'rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+\$HOME/?|'
        r'rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+\$HOME/?',
        "filesystem",
        "rm -rf on home directory is CATASTROPHIC. This will NOT be executed."
    ),
    # Disk-level destruction
    (
        r"dd\s+.*of=/dev/",
        "disk",
        "dd to a block device can destroy disk partitions. This will NOT be executed."
    ),
    (
        r"mkfs\.",
        "disk",
        "mkfs formats a filesystem, destroying all data. This will NOT be executed."
    ),
    (
        r"fdisk\s+/dev/",
        "disk",
        "fdisk modifies disk partition tables. This will NOT be executed."
    ),
    # Database catastrophe
    (
        r"DROP\s+DATABASE",
        "database",
        "DROP DATABASE destroys an entire database. This will NOT be executed."
    ),
    (
        r"DROP\s+SCHEMA",
        "database",
        "DROP SCHEMA destroys an entire schema. This will NOT be executed."
    ),
    # Fork bomb / shell denial of service
    (
        r":\(\)\s*\{\s*:\|:\s*&\s*\}\s*;|"
        r"fork\s+while\s+fork|"
        r"while\s+true\s*;\s*do\s+fork",
        "shell",
        "Fork bomb / shell DoS detected. This will NOT be executed."
    ),
    # Kubernetes catastrophe
    (
        r"kubectl\s+delete\s+namespace",
        "kubernetes",
        "Deleting a Kubernetes namespace destroys all resources in it. This will NOT be executed."
    ),
    (
        r"kubectl\s+delete\s+--all",
        "kubernetes",
        "kubectl delete --all removes all resources of that type. This will NOT be executed."
    ),
]

# --- Tier 2: Deny + Redirect ---
# Dangerous commands that have a safer alternative.
# Format: (regex, category, reason, alternative)
TIER2_PATTERNS = [
    # Git force push
    (
        r"git\s+push\s+.*--force(?![-a-z])",
        "git",
        "Force push can destroy remote history.",
        "Use --force-with-lease instead: it fails if someone else pushed."
    ),
    (
        r"git\s+push\s+.*-f\b",
        "git",
        "Force push (-f) can destroy remote history.",
        "Use --force-with-lease instead: it fails if someone else pushed."
    ),
    # Git discard changes
    (
        r"git\s+reset\s+--hard",
        "git",
        "git reset --hard destroys uncommitted changes.",
        "Use 'git stash' first to save changes, then reset."
    ),
    (
        r"git\s+reset\s+--merge",
        "git",
        "git reset --merge can lose uncommitted changes.",
        "Use 'git stash' first to save changes, then reset."
    ),
    (
        r"git\s+checkout\s+--\s+\.",
        "git",
        "git checkout -- . discards all uncommitted changes.",
        "Use 'git stash' to save changes, or 'git diff' to review first."
    ),
    (
        r"git\s+checkout\s+--\s+",
        "git",
        "git checkout -- <path> discards uncommitted changes to that path.",
        "Use 'git stash' first, or 'git diff <path>' to review changes."
    ),
    (
        r"git\s+restore\s+(?!--staged\b)(?!-S\b)(?!.*--staged)",
        "git",
        "git restore discards uncommitted changes.",
        "Use 'git restore --staged' to unstage, or 'git stash' to save changes."
    ),
    # Git clean
    (
        r"git\s+clean\s+-[a-z]*f",
        "git",
        "git clean -f removes untracked files permanently.",
        "Run 'git clean -n' first (dry run) to see what would be removed."
    ),
    # Git branch force delete
    (
        r"git\s+branch\s+-D\b",
        "git",
        "git branch -D force-deletes without checking if the branch is merged.",
        "Use 'git branch -d' instead: it only deletes if the branch is merged."
    ),
    # Git stash loss
    (
        r"git\s+stash\s+drop",
        "git",
        "git stash drop permanently deletes a stashed change.",
        "Run 'git stash list' first to review what would be lost."
    ),
    (
        r"git\s+stash\s+clear",
        "git",
        "git stash clear permanently deletes ALL stashed changes.",
        "Run 'git stash list' first to review what would be lost."
    ),
    # Pre-commit bypass
    (
        r"git\s+commit\s+.*--no-verify",
        "git",
        "Skipping pre-commit hooks bypasses safety checks.",
        "Remove --no-verify and fix any hook failures instead."
    ),
    (
        r"git\s+push\s+.*--no-verify",
        "git",
        "Skipping pre-push hooks bypasses safety checks.",
        "Remove --no-verify and fix any hook failures instead."
    ),
    # Recursive delete (non-root, non-tmp — caught after Tier 1 and allowlist)
    (
        r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f|rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR]",
        "filesystem",
        "rm -rf is destructive and irreversible.",
        "List the directory contents first, then ask the user to confirm deletion."
    ),
    # Separate -r -f flags
    (
        r"rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f|"
        r"rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]",
        "filesystem",
        "rm with separate -r -f flags is destructive.",
        "List the directory contents first, then ask the user to confirm deletion."
    ),
    # Long-form rm options
    (
        r"rm\s+.*--recursive.*--force|rm\s+.*--force.*--recursive",
        "filesystem",
        "rm --recursive --force is destructive.",
        "List the directory contents first, then ask the user to confirm deletion."
    ),
    # Docker destructive operations
    (
        r"docker\s+system\s+prune",
        "docker",
        "docker system prune removes unused containers, networks, images, and optionally volumes.",
        "Run 'docker system prune --dry-run' first to see what would be removed."
    ),
    (
        r"docker\s+rm\s+-f|docker\s+rm\s+--force",
        "docker",
        "docker rm -f force-removes running containers.",
        "Use 'docker stop' first, then 'docker rm' without --force."
    ),
    (
        r"docker\s+volume\s+rm",
        "docker",
        "docker volume rm permanently deletes volume data.",
        "Run 'docker volume ls' first to review, and confirm with the user."
    ),
    (
        r"docker\s+network\s+rm",
        "docker",
        "docker network rm removes a network and disconnects containers.",
        "Run 'docker network ls' first to review, and confirm with the user."
    ),
    (
        r"docker\s+compose\s+down\s+.*-v|docker-compose\s+down\s+.*-v",
        "docker",
        "docker compose down -v destroys all named volumes.",
        "Use 'docker compose down' without -v to preserve volume data."
    ),
    (
        r"docker\s+rmi\s+-f|docker\s+rmi\s+--force",
        "docker",
        "docker rmi -f force-removes images even if containers use them.",
        "Use 'docker rmi' without --force for safe removal."
    ),
    # Permission escalation
    (
        r"chmod\s+777\b|chmod\s+-R\s+777\b|chmod\s+.*777\b",
        "permissions",
        "chmod 777 makes files world-readable, writable, and executable.",
        "Use specific permissions: 755 for directories, 644 for files."
    ),
    # Database operations via CLI (non-catastrophic but dangerous)
    (
        r"DROP\s+TABLE",
        "database",
        "DROP TABLE permanently removes a table and its data.",
        "Add IF EXISTS and confirm the table name with the user first."
    ),
    (
        r"TRUNCATE\s+",
        "database",
        "TRUNCATE removes all rows from a table.",
        "Use DELETE with a WHERE clause for targeted removal, or confirm with the user."
    ),
    (
        r"DELETE\s+FROM\s+\w+\s*;|DELETE\s+FROM\s+\w+\s*$",
        "database",
        "DELETE FROM without WHERE removes all rows.",
        "Add a WHERE clause, or confirm with the user that all rows should be deleted."
    ),
    # Kubernetes dangerous operations
    (
        r"kubectl\s+delete\s+(?!namespace\b)(?!--all\b)",
        "kubernetes",
        "kubectl delete removes Kubernetes resources.",
        "Use 'kubectl delete --dry-run=client' first to preview, and confirm with the user."
    ),
]

# --- Allowlist: Safe patterns that should never be blocked ---
SAFE_PATTERNS = [
    # Git safe operations
    r"git\s+checkout\s+-b\s+",             # Creating new branch
    r"git\s+checkout\s+--orphan\s+",       # Creating orphan branch
    r"git\s+restore\s+--staged\s+(?!.*--worktree)(?!.*-W\b)",  # Unstaging only
    r"git\s+restore\s+-S\s+(?!.*--worktree)(?!.*-W\b)",        # Unstaging short form
    r"git\s+clean\s+-n",                   # Dry run
    r"git\s+clean\s+--dry-run",            # Dry run
    r"git\s+push\s+.*--force-with-lease",  # Safe force push
    r"git\s+push\s+.*--force-if-includes", # Safe force push
    # rm -rf on temp directories
    r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+/tmp/",
    r"rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+/tmp/",
    r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+/var/tmp/",
    r"rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+/var/tmp/",
    r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+\$TMPDIR/",
    r"rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+\$TMPDIR/",
    r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+\$\{TMPDIR",
    r"rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+\$\{TMPDIR",
    r'rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+"\$TMPDIR/',
    r'rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+"\$TMPDIR/',
    r'rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+"\$\{TMPDIR',
    r'rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+"\$\{TMPDIR',
    # Separate flags on temp directories
    r"rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f\s+/tmp/",
    r"rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]\s+/tmp/",
    r"rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f\s+/var/tmp/",
    r"rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]\s+/var/tmp/",
    r"rm\s+.*--recursive.*--force\s+/tmp/",
    r"rm\s+.*--force.*--recursive\s+/tmp/",
    r"rm\s+.*--recursive.*--force\s+/var/tmp/",
    r"rm\s+.*--force.*--recursive\s+/var/tmp/",
    # Docker dry runs
    r"docker\s+system\s+prune\s+.*--dry-run",
    # kubectl dry runs
    r"kubectl\s+delete\s+.*--dry-run",
    # Database safe patterns
    r"DROP\s+TABLE\s+IF\s+EXISTS.*--.*test",   # Test migrations
    r"CREATE\s+.*DROP",                         # CREATE OR REPLACE patterns
]


def deny(reason: str) -> None:
    """Output a deny decision and exit."""
    output = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason
        }
    }
    print(json.dumps(output))
    sys.exit(0)


def format_tier1_deny(reason: str, command: str) -> str:
    """Format a Tier 1 hard deny message."""
    return (
        f"BLOCKED by claude-guard (Tier 1: Hard Deny)\n\n"
        f"Reason: {reason}\n\n"
        f"Command: {command}\n\n"
        f"This command must be run manually by the user if truly needed."
    )


def format_tier2_deny(reason: str, alternative: str, command: str) -> str:
    """Format a Tier 2 deny + redirect message."""
    return (
        f"BLOCKED by claude-guard (Tier 2: Safer Alternative Available)\n\n"
        f"Reason: {reason}\n\n"
        f"Command: {command}\n\n"
        f"Alternative: {alternative}"
    )


def main():
    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError:
        sys.exit(0)

    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input") or {}
    command = tool_input.get("command", "")

    if tool_name != "Bash" or not isinstance(command, str) or not command:
        sys.exit(0)

    # Allowlist check first — safe commands pass immediately
    for pattern in SAFE_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            sys.exit(0)

    # Tier 1: Hard deny — catastrophic, no escape
    for pattern, category, reason in TIER1_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            deny(format_tier1_deny(reason, command))

    # Tier 2: Deny + redirect — suggest safer alternative
    for pattern, category, reason, alternative in TIER2_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            deny(format_tier2_deny(reason, alternative, command))

    # Allow all other commands
    sys.exit(0)


if __name__ == "__main__":
    main()
