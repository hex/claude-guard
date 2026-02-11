---
name: Guard Rules
description: This skill should be used when a command is blocked by claude-guard, when the response contains "BLOCKED by claude-guard", when the user asks "why was my command blocked", "what commands are blocked", "guard rules", "safety rules", or when Claude is about to execute a potentially dangerous command. Covers git force push, git reset --hard, git checkout --, git clean, git commit --no-verify, rm -rf, chmod 777, DROP TABLE, TRUNCATE, DELETE without WHERE, docker system prune, docker compose down -v, kubectl delete, and credential exposure warnings after file writes.
version: 2026.2.1
---

# Guard Rules

The claude-guard plugin enforces a three-tier safety model that prevents destructive operations before they execute and warns about credential exposure after file writes. Understanding these tiers enables working effectively within the safety boundaries and selecting safe alternatives without triggering blocks.

## Three-Tier Safety Model

### Tier 1: Hard Deny

Catastrophic, irreversible commands that must never be executed by an AI agent. When a command is blocked at this tier, inform the user that the command must be run manually if truly needed. Do not attempt to find workarounds or alternative phrasings.

**Categories:**
- Filesystem catastrophe: `rm -rf /`, `rm -rf ~`, `rm -rf $HOME`
- Disk destruction: `dd` writing to block devices, `mkfs`, `fdisk`
- Database catastrophe: `DROP DATABASE`, `DROP SCHEMA`
- Kubernetes catastrophe: `kubectl delete namespace`, `kubectl delete --all`

### Tier 2: Deny + Redirect

Dangerous commands that have a safer alternative. When blocked at this tier, use the suggested alternative immediately instead of asking the user to run the original command.

**Git Operations:**

| Blocked Command | Safe Alternative |
|---|---|
| `git push --force` / `-f` | `git push --force-with-lease` |
| `git reset --hard` | `git stash` first, then reset |
| `git reset --merge` | `git stash` first, then reset |
| `git checkout -- .` or `git checkout -- <path>` | `git stash` or `git diff` first |
| `git restore` (not --staged) | `git restore --staged` or `git stash` |
| `git clean -f` | `git clean -n` (dry run) first |
| `git branch -D` | `git branch -d` (merge check) |
| `git stash drop/clear` | `git stash list` first |
| `git commit --no-verify` | Remove flag, fix hook failures |
| `git push --no-verify` | Remove flag, fix hook failures |

**Filesystem Operations:**

| Blocked Command | Safe Alternative |
|---|---|
| `rm -rf <directory>` (also `rm -r -f`, `rm --recursive --force`) | List contents first, ask user to confirm |
| `chmod 777` | Use specific permissions (755, 644) |

**Docker Operations:**

| Blocked Command | Safe Alternative |
|---|---|
| `docker system prune` | `docker system prune --dry-run` first |
| `docker rm -f` | `docker stop` then `docker rm` |
| `docker volume rm` | `docker volume ls` first |
| `docker network rm` | `docker network ls` first |
| `docker compose down -v` | `docker compose down` (no -v) |
| `docker rmi -f` | `docker rmi` without force |

**Database Operations:**

| Blocked Command | Safe Alternative |
|---|---|
| `DROP TABLE` | Add `IF EXISTS`, confirm with user |
| `TRUNCATE` | Use `DELETE` with `WHERE` clause |
| `DELETE FROM` without `WHERE` | Add `WHERE` clause or confirm with user |

**Kubernetes Operations:**

| Blocked Command | Safe Alternative |
|---|---|
| `kubectl delete <resource>` | `kubectl delete --dry-run=client` first |

### Tier 3: Warn

Detected after file writes. These do not block execution but add warning context. Review the warning and take corrective action if credentials were accidentally written.

**Credential Patterns Detected:**
- AWS access keys and secret keys
- API keys, secrets, tokens, passwords (hardcoded, not env var references)
- Private keys (PEM format)
- GitHub/GitLab/Slack tokens
- Google API keys, Stripe keys
- Database connection strings with embedded credentials
- JWT tokens

**Destructive SQL in Files:**
- `DROP TABLE/DATABASE/SCHEMA/INDEX` statements
- `TRUNCATE` statements
- `DELETE FROM` without `WHERE` clause

**Scan scope:** Credential patterns are checked in all written files except `.git/`, `.env.example`, `.env.template`, `.env.sample`, `node_modules/`, and lock files (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `Podfile.lock`, `go.sum`, `Cargo.lock`). Destructive SQL scanning only applies to `.sql`, `.py`, `.js`, `.ts`, `.rb`, `.go`, `.java`, `.php`, `.sh`, and `.bash` files.

## Allowlisted Safe Patterns

The following commands are always permitted, even if they partially match a blocked pattern:

- `git checkout -b` (creating a new branch)
- `git checkout --orphan` (creating an orphan branch)
- `git restore --staged` / `-S` (unstaging files, not modifying working tree)
- `git clean -n` / `--dry-run` (previewing what would be removed)
- `git push --force-with-lease` / `--force-if-includes`
- `rm -rf /tmp/*`, `/var/tmp/*`, `$TMPDIR/*` (temp directory cleanup)
- `docker system prune --dry-run`
- `kubectl delete --dry-run`

## Working Within Guard Boundaries

### When a Command is Blocked

1. Read the block message — it specifies the tier and reason
2. For Tier 1: Inform the user and do not retry or work around the block
3. For Tier 2: Use the suggested alternative command immediately
4. Never attempt to bypass the guard by reformulating the command

### Preventing Blocks Proactively

Before executing commands, verify they follow these patterns:

- **Git pushes**: Always use `--force-with-lease` instead of `--force`
- **File deletion**: List contents with `ls` before using `rm -rf`
- **Git cleanup**: Run dry-run first (`git clean -n`)
- **Docker cleanup**: Run dry-run first (`docker system prune --dry-run`)
- **Database changes**: Include `WHERE` clauses in `DELETE` statements
- **Permissions**: Use specific modes (755, 644) instead of 777
- **Credentials**: Use environment variables, never hardcode secrets

### Credential Safety in Files

When writing files that handle configuration or authentication:

- Reference environment variables (`process.env.API_KEY`, `os.environ["SECRET"]`, `${VAR}`)
- Never write literal API keys, tokens, or passwords into source files
- Use `.env.example` files with placeholder values for documentation
- Connection strings should use env var interpolation for credentials

## Source of Truth

For the authoritative and up-to-date list of all patterns, read the hook scripts directly:
- **Command guard patterns:** `$CLAUDE_PLUGIN_ROOT/hooks/scripts/command-guard.py`
- **Credential scanner patterns:** `$CLAUDE_PLUGIN_ROOT/hooks/scripts/credential-scanner.sh`

The tables in this skill provide a quick reference, but the scripts are the definitive source if discrepancies arise.
