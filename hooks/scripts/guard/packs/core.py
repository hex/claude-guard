# ABOUTME: Core security patterns covering filesystem, git, disk, database, docker, kubernetes.
# ABOUTME: Registers Tier 1 (hard deny), Tier 2 (deny+redirect), and allowlist patterns.
from guard.packs import register_tier1, register_tier2, register_allowlist

# =============================================================================
# Tier 1: Hard Deny — catastrophic, irreversible operations
# =============================================================================

# Filesystem catastrophe
register_tier1(
    r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+/\s|"
    r"rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+/\s|"
    r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+/\*|"
    r"rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+/\*|"
    r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+/$",
    "filesystem",
    "rm -rf on root filesystem is CATASTROPHIC. This will NOT be executed.",
)

register_tier1(
    r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+~/?\s|"
    r"rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+~/?\s|"
    r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+~/?\*|"
    r"rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+~/?\*|"
    r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+~/?$|"
    r"rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+~/?$|"
    r'rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+\$HOME/?|'
    r'rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+\$HOME/?',
    "filesystem",
    "rm -rf on home directory is CATASTROPHIC. This will NOT be executed.",
)

# Disk-level destruction
register_tier1(
    r"dd\s+.*of=/dev/",
    "disk",
    "dd to a block device can destroy disk partitions. This will NOT be executed.",
)

register_tier1(
    r"mkfs\.",
    "disk",
    "mkfs formats a filesystem, destroying all data. This will NOT be executed.",
)

register_tier1(
    r"fdisk\s+/dev/",
    "disk",
    "fdisk modifies disk partition tables. This will NOT be executed.",
)

# Database catastrophe (case-insensitive: SQL keywords vary in case)
register_tier1(
    r"(?i)DROP\s+DATABASE",
    "database",
    "DROP DATABASE destroys an entire database. This will NOT be executed.",
)

register_tier1(
    r"(?i)DROP\s+SCHEMA",
    "database",
    "DROP SCHEMA destroys an entire schema. This will NOT be executed.",
)

# Fork bomb / shell denial of service
register_tier1(
    r":\(\)\s*\{\s*:\|:\s*&\s*\}\s*;|"
    r"fork\s+while\s+fork|"
    r"while\s+true\s*;\s*do\s+fork",
    "shell",
    "Fork bomb / shell DoS detected. This will NOT be executed.",
)

# Kubernetes catastrophe
register_tier1(
    r"kubectl\s+delete\s+namespace",
    "kubernetes",
    "Deleting a Kubernetes namespace destroys all resources in it. This will NOT be executed.",
)

register_tier1(
    r"kubectl\s+delete\s+.*--all",
    "kubernetes",
    "kubectl delete --all removes all resources of that type. This will NOT be executed.",
)

# =============================================================================
# Tier 2: Deny + Redirect — dangerous but has safer alternative
# =============================================================================

# Git force push
register_tier2(
    r"git\s+push\s+.*--force(?![-a-z])",
    "git",
    "Force push can destroy remote history.",
    "Use --force-with-lease instead: it fails if someone else pushed.",
)

register_tier2(
    r"git\s+push\s+.*-f\b",
    "git",
    "Force push (-f) can destroy remote history.",
    "Use --force-with-lease instead: it fails if someone else pushed.",
)

# Git discard changes
register_tier2(
    r"git\s+reset\s+--hard",
    "git",
    "git reset --hard destroys uncommitted changes.",
    "Use 'git stash' first to save changes, then reset.",
)

register_tier2(
    r"git\s+reset\s+--merge",
    "git",
    "git reset --merge can lose uncommitted changes.",
    "Use 'git stash' first to save changes, then reset.",
)

register_tier2(
    r"git\s+checkout\s+--\s+\.",
    "git",
    "git checkout -- . discards all uncommitted changes.",
    "Use 'git stash' to save changes, or 'git diff' to review first.",
)

register_tier2(
    r"git\s+checkout\s+--\s+",
    "git",
    "git checkout -- <path> discards uncommitted changes to that path.",
    "Use 'git stash' first, or 'git diff <path>' to review changes.",
)

register_tier2(
    r"git\s+restore\s+(?!--staged\b)(?!-S\b)(?!.*--staged)",
    "git",
    "git restore discards uncommitted changes.",
    "Use 'git restore --staged' to unstage, or 'git stash' to save changes.",
)

# Git clean
register_tier2(
    r"git\s+clean\s+-[a-z]*f",
    "git",
    "git clean -f removes untracked files permanently.",
    "Run 'git clean -n' first (dry run) to see what would be removed.",
)

# Git branch force delete
register_tier2(
    r"git\s+branch\s+-D\b",
    "git",
    "git branch -D force-deletes without checking if the branch is merged.",
    "Use 'git branch -d' instead: it only deletes if the branch is merged.",
)

# Git stash loss
register_tier2(
    r"git\s+stash\s+drop",
    "git",
    "git stash drop permanently deletes a stashed change.",
    "Run 'git stash list' first to review what would be lost.",
)

register_tier2(
    r"git\s+stash\s+clear",
    "git",
    "git stash clear permanently deletes ALL stashed changes.",
    "Run 'git stash list' first to review what would be lost.",
)

# Pre-commit bypass
register_tier2(
    r"git\s+commit\s+.*--no-verify",
    "git",
    "Skipping pre-commit hooks bypasses safety checks.",
    "Remove --no-verify and fix any hook failures instead.",
)

register_tier2(
    r"git\s+push\s+.*--no-verify",
    "git",
    "Skipping pre-push hooks bypasses safety checks.",
    "Remove --no-verify and fix any hook failures instead.",
)

# Recursive delete (non-root, non-tmp — caught after Tier 1 and allowlist)
register_tier2(
    r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f|rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR]",
    "filesystem",
    "rm -rf is destructive and irreversible.",
    "List the directory contents first, then ask the user to confirm deletion.",
)

# Separate -r -f flags
register_tier2(
    r"rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f|"
    r"rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]",
    "filesystem",
    "rm with separate -r -f flags is destructive.",
    "List the directory contents first, then ask the user to confirm deletion.",
)

# Long-form rm options
register_tier2(
    r"rm\s+.*--recursive.*--force|rm\s+.*--force.*--recursive",
    "filesystem",
    "rm --recursive --force is destructive.",
    "List the directory contents first, then ask the user to confirm deletion.",
)

# Docker destructive operations
register_tier2(
    r"docker\s+system\s+prune",
    "docker",
    "docker system prune removes unused containers, networks, images, and optionally volumes.",
    "Run 'docker system prune --dry-run' first to see what would be removed.",
)

register_tier2(
    r"docker\s+rm\s+-f|docker\s+rm\s+--force",
    "docker",
    "docker rm -f force-removes running containers.",
    "Use 'docker stop' first, then 'docker rm' without --force.",
)

register_tier2(
    r"docker\s+volume\s+rm",
    "docker",
    "docker volume rm permanently deletes volume data.",
    "Run 'docker volume ls' first to review, and confirm with the user.",
)

register_tier2(
    r"docker\s+network\s+rm",
    "docker",
    "docker network rm removes a network and disconnects containers.",
    "Run 'docker network ls' first to review, and confirm with the user.",
)

register_tier2(
    r"docker\s+compose\s+down\s+.*-v|docker-compose\s+down\s+.*-v",
    "docker",
    "docker compose down -v destroys all named volumes.",
    "Use 'docker compose down' without -v to preserve volume data.",
)

register_tier2(
    r"docker\s+rmi\s+-f|docker\s+rmi\s+--force",
    "docker",
    "docker rmi -f force-removes images even if containers use them.",
    "Use 'docker rmi' without --force for safe removal.",
)

# Permission escalation
register_tier2(
    r"chmod\s+777\b|chmod\s+-R\s+777\b|chmod\s+.*777\b",
    "permissions",
    "chmod 777 makes files world-readable, writable, and executable.",
    "Use specific permissions: 755 for directories, 644 for files.",
)

# Database operations via CLI (case-insensitive: SQL keywords vary in case)
register_tier2(
    r"(?i)DROP\s+TABLE",
    "database",
    "DROP TABLE permanently removes a table and its data.",
    "Add IF EXISTS and confirm the table name with the user first.",
)

register_tier2(
    r"(?i)TRUNCATE\s+",
    "database",
    "TRUNCATE removes all rows from a table.",
    "Use DELETE with a WHERE clause for targeted removal, or confirm with the user.",
)

register_tier2(
    r"(?i)DELETE\s+FROM\s+\w+\s*(?:;|$)",
    "database",
    "DELETE FROM without WHERE removes all rows.",
    "Add a WHERE clause, or confirm with the user that all rows should be deleted.",
)

# Kubernetes dangerous operations
register_tier2(
    r"kubectl\s+delete\s+(?!namespace\b)(?!--all\b)",
    "kubernetes",
    "kubectl delete removes Kubernetes resources.",
    "Use 'kubectl delete --dry-run=client' first to preview, and confirm with the user.",
)

# =============================================================================
# Allowlist: Safe patterns that should never be blocked
# =============================================================================

# Git safe operations
register_allowlist(r"git\s+checkout\s+-b\s+")
register_allowlist(r"git\s+checkout\s+--orphan\s+")
register_allowlist(r"git\s+restore\s+--staged\s+(?!.*--worktree)(?!.*-W\b)")
register_allowlist(r"git\s+restore\s+-S\s+(?!.*--worktree)(?!.*-W\b)")
register_allowlist(r"git\s+clean\s+-n")
register_allowlist(r"git\s+clean\s+--dry-run")
register_allowlist(r"git\s+push\s+.*--force-with-lease")
register_allowlist(r"git\s+push\s+.*--force-if-includes")

# rm -rf on temp directories
register_allowlist(r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+/tmp/")
register_allowlist(r"rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+/tmp/")
register_allowlist(r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+/var/tmp/")
register_allowlist(r"rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+/var/tmp/")
register_allowlist(r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+\$TMPDIR/")
register_allowlist(r"rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+\$TMPDIR/")
register_allowlist(r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+\$\{TMPDIR")
register_allowlist(r"rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+\$\{TMPDIR")
register_allowlist(r'rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+"\$TMPDIR/')
register_allowlist(r'rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+"\$TMPDIR/')
register_allowlist(r'rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+"\$\{TMPDIR')
register_allowlist(r'rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+"\$\{TMPDIR')

# Separate flags on temp directories
register_allowlist(r"rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f\s+/tmp/")
register_allowlist(r"rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]\s+/tmp/")
register_allowlist(r"rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f\s+/var/tmp/")
register_allowlist(r"rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]\s+/var/tmp/")
register_allowlist(r"rm\s+.*--recursive.*--force\s+/tmp/")
register_allowlist(r"rm\s+.*--force.*--recursive\s+/tmp/")
register_allowlist(r"rm\s+.*--recursive.*--force\s+/var/tmp/")
register_allowlist(r"rm\s+.*--force.*--recursive\s+/var/tmp/")

# Docker dry runs
register_allowlist(r"docker\s+system\s+prune\s+.*--dry-run")

# kubectl dry runs
register_allowlist(r"kubectl\s+delete\s+.*--dry-run")

# Database safe patterns (case-insensitive: SQL keywords vary in case)
register_allowlist(r"(?i)DROP\s+TABLE\s+IF\s+EXISTS.*--.*test")
register_allowlist(r"(?i)CREATE\s+.*DROP")
