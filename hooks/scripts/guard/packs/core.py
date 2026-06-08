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

# Discard working-tree changes without -- (sibling of 'git checkout -- .')
register_tier2(
    r"git\s+checkout\s+\.(?:/|\s|$)",
    "git",
    "git checkout . discards all uncommitted changes in the working tree.",
    "Use 'git stash' to save changes, or 'git diff' to review first.",
)

# Git history rewriting and ref destruction
register_tier2(
    r"git\s+filter-branch\b",
    "git",
    "git filter-branch rewrites the entire repository history.",
    "Confirm the rewrite is intended and work on a backup clone first.",
)

register_tier2(
    r"git\s+reflog\s+expire\b",
    "git",
    "git reflog expire discards the reflog that makes recent operations recoverable.",
    "Avoid expiring the reflog unless you intend to make recent operations unrecoverable.",
)

register_tier2(
    r"git\s+gc\s+.*--prune=(?:now|all)\b",
    "git",
    "git gc --prune=now permanently removes unreachable objects.",
    "Use plain 'git gc' to keep the default grace period.",
)

register_tier2(
    r"git\s+update-ref\s+-d\b",
    "git",
    "git update-ref -d deletes a ref directly, bypassing branch-delete safety.",
    "Use 'git branch -d' so merge status is checked first.",
)

register_tier2(
    r"git\s+push\s+.*--mirror\b",
    "git",
    "git push --mirror overwrites ALL remote refs to match local.",
    "Push specific refs instead of mirroring the entire repository.",
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
    r"rm\s+(?:-[a-zA-Z]+\s+){0,6}-[rR]\s+(?:-[a-zA-Z]+\s+){0,6}-f|"
    r"rm\s+(?:-[a-zA-Z]+\s+){0,6}-f\s+(?:-[a-zA-Z]+\s+){0,6}-[rR]",
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

# Destructive move to /dev/null
register_tier2(
    r"mv\s+\S+\s+/dev/null",
    "filesystem",
    "Moving files or directories to /dev/null destroys them.",
    "Use 'rm' with confirmation, or move to a backup location instead.",
)

# Bulk delete via find (no rm token to match the rm rules above)
register_tier2(
    r"find\s+.*-delete\b",
    "filesystem",
    "find -delete recursively removes every matching file.",
    "Run the find without -delete first to list what would be removed.",
)

register_tier2(
    r"find\s+.*-exec\s+rm\b",
    "filesystem",
    "find -exec rm deletes every matching file.",
    "Run the find without -exec first to list what would be removed.",
)

# Unrecoverable file destruction
register_tier2(
    r"\bshred\s+\S",
    "filesystem",
    "shred overwrites a file so its contents cannot be recovered.",
    "Confirm the target; use 'rm' if recoverability is acceptable.",
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

register_tier2(
    r"kubectl\s+drain\b",
    "kubernetes",
    "kubectl drain evicts all pods from a node.",
    "Run 'kubectl get pods --field-selector spec.nodeName=<node>' first to review impact.",
)

# =============================================================================
# Tier 2: Process, service, and scheduler control
# =============================================================================

register_tier2(
    r"crontab\s+-r\b",
    "scheduler",
    "crontab -r deletes ALL cron jobs with no confirmation.",
    "Run 'crontab -l' first to review, and back it up before removing.",
)

register_tier2(
    r"\bkill\s+(?:-\S+\s+)?-1\b",
    "process",
    "kill -1 signals every process you own, ending the session.",
    "Target a specific PID instead of -1.",
)

register_tier2(
    r"systemctl\s+(?:stop|disable)\b",
    "service",
    "systemctl stop/disable takes a service down or prevents it starting at boot.",
    "Confirm the service and environment; use 'systemctl status' to inspect first.",
)

# Recursive chmod/chown on a system path (project-relative paths are allowed)
register_tier2(
    r"(?:chmod|chown)\s+-R\b.*\s/(?:etc|usr|bin|sbin|var|lib|lib64|boot|root|sys)(?:/|\s|$)|"
    r"(?:chmod|chown)\s+-R\b[^/]*\s/(?:\s|$)",
    "permissions",
    "Recursive chmod/chown on a system path can break the operating system.",
    "Scope the recursion to a project directory, not a system path.",
)

# =============================================================================
# Tier 2: Remote code execution via package installers (URL/VCS specs only)
# =============================================================================

register_tier2(
    r"\bpip3?\s+install\s+(?:--?\S+\s+)*(?:https?://|git\+)",
    "supply-chain",
    "pip install from a URL or VCS runs setup code from an untrusted source.",
    "Install from PyPI by name, or vet and pin the source first.",
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

# rm -rf on a temp directory is allowed, but ONLY when a temp path is the sole
# target of the statement (nothing rides along) and has no '..' escape out of the
# temp dir. _TEMP_TAIL enforces both: reject '..', then require end-of-segment so
# a second target like '/etc' cannot slip past on the same rm.
_TEMP_DIR = r'(?:/tmp/|/var/tmp/|"?\$\{?TMPDIR\}?/?)'
_TEMP_TAIL = r"(?!\S*\.\.)\S*\s*$"
_RM_RECURSIVE_FORMS = (
    r"-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*",
    r"-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*",
    r"(?:-[a-zA-Z]+\s+){0,6}-[rR]\s+(?:-[a-zA-Z]+\s+){0,6}-f",
    r"(?:-[a-zA-Z]+\s+){0,6}-f\s+(?:-[a-zA-Z]+\s+){0,6}-[rR]",
    r"--recursive\s+--force",
    r"--force\s+--recursive",
)
for _flags in _RM_RECURSIVE_FORMS:
    register_allowlist(rf"rm\s+(?:{_flags})\s+{_TEMP_DIR}{_TEMP_TAIL}")

# Docker dry runs
register_allowlist(r"docker\s+system\s+prune\s+.*--dry-run")

# kubectl dry runs
register_allowlist(r"kubectl\s+delete\s+.*--dry-run")

# Database safe patterns (case-insensitive: SQL keywords vary in case)
register_allowlist(r"(?i)DROP\s+TABLE\s+IF\s+EXISTS\s+\w*test\w*")
register_allowlist(r"(?i)CREATE\s+(?:OR\s+REPLACE\s+)?(?:TABLE|VIEW|INDEX)\s+.*DROP\s+(?:TABLE|VIEW|INDEX)\s+IF\s+EXISTS")
