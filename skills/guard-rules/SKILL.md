---
name: Guard Rules
description: This skill should be used when a command is blocked by claude-guard, when the response contains "BLOCKED by claude-guard", when the user asks "why was my command blocked", "what commands are blocked", "guard rules", "safety rules", or when Claude is about to execute a potentially dangerous command. Covers git force push, git reset --hard, git checkout --, git clean, git commit --no-verify, rm -rf, chmod 777, DROP TABLE, TRUNCATE, DELETE without WHERE, docker system prune, docker compose down -v, kubectl delete, terraform destroy, aws s3 rm, gh repo delete, Route53 delete, and credential exposure warnings after file writes.
version: 2026.2.11
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
- AWS catastrophe: `aws s3 rb --force`, `aws ec2 terminate-instances`, `aws rds delete-db-instance`, `aws rds delete-db-cluster`
- GCP catastrophe: `gcloud projects delete`
- GitHub CLI catastrophe: `gh repo delete`
- DNS catastrophe: `aws route53 delete-hosted-zone`

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

**Cloud Operations (AWS/GCP/Azure):**

| Blocked Command | Safe Alternative |
|---|---|
| `aws s3 rm --recursive` | `aws s3 rm --dryrun` first |
| `gcloud compute instances delete` | List instances first, confirm with user |
| `gcloud sql instances delete` | Verify instance name, confirm with user |
| `gsutil rm -r` | `gsutil ls` first |
| `az group delete` | `az group delete --dry-run` first |
| `az vm delete` | List VMs first, confirm with user |
| `az storage account delete` | List storage first, confirm with user |
| `az sql server delete` | Verify server name, confirm with user |

**Infrastructure as Code:**

| Blocked Command | Safe Alternative |
|---|---|
| `terraform destroy` | `terraform plan -destroy` first |
| `terraform apply -destroy` | `terraform plan -destroy` first |
| `pulumi destroy` | `pulumi preview --diff` first |
| `cdk destroy` | `cdk diff` first |

**GitHub CLI:**

| Blocked Command | Safe Alternative |
|---|---|
| `gh release delete` | `gh release list` first |
| `gh secret delete` | `gh secret list` first |

**DNS Operations:**

| Blocked Command | Safe Alternative |
|---|---|
| `aws route53 change-resource-record-sets` (DELETE action) | List records first, confirm with user |
| `gcloud dns managed-zones delete` | `gcloud dns managed-zones list` first |
| `az network dns zone delete` | `az network dns zone list` first |

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

## Context Classification

The guard uses context-aware matching to avoid false positives. Patterns are only matched against executed code, not string data:

- **Safe wrapper arguments**: Quoted strings in `echo`, `printf`, `grep`, `sed`, `awk`, `git commit -m`, etc. are treated as data and not matched
- **Variable assignments**: `MSG="git push --force"` is a variable assignment, not executed
- **Comments**: Text after `#` is ignored
- **Execution bridges**: `bash -c`, `eval`, `source`, `pipe | bash` — string arguments to these ARE matched because they will be executed
- **Inline interpreters**: `python -c`, `ruby -e`, `perl -e`, `node -e` with destructive patterns are blocked

## Command Normalization

Commands are normalized before matching to prevent evasion:

- Path prefixes stripped: `/usr/bin/git` becomes `git`
- Whitespace collapsed: `git   push   --force` becomes `git push --force`
- `env` wrappers stripped: `env VAR=val git push --force` becomes `git push --force`

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
- `aws s3 rm --dryrun`, `aws ... --dry-run` (AWS dry run)
- `az ... --dry-run` (Azure dry run)

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
- **Cloud operations**: Use `--dryrun`/`--dry-run` flags when available
- **Infrastructure**: Run `plan` or `preview` before `destroy`

### Credential Safety in Files

When writing files that handle configuration or authentication:

- Reference environment variables (`process.env.API_KEY`, `os.environ["SECRET"]`, `${VAR}`)
- Never write literal API keys, tokens, or passwords into source files
- Use `.env.example` files with placeholder values for documentation
- Connection strings should use env var interpolation for credentials

## Explain Mode

For debugging false positives or understanding guard decisions, set `CLAUDE_GUARD_EXPLAIN=1` in the environment. The guard will output its decision pipeline to stderr without affecting the JSON protocol on stdout.

## Source of Truth

For the authoritative and up-to-date list of all patterns, read the pack files directly:
- **Core patterns:** `$CLAUDE_PLUGIN_ROOT/hooks/scripts/guard/packs/core.py`
- **Cloud patterns:** `$CLAUDE_PLUGIN_ROOT/hooks/scripts/guard/packs/cloud.py`
- **Infrastructure patterns:** `$CLAUDE_PLUGIN_ROOT/hooks/scripts/guard/packs/infra.py`
- **CI/CD patterns:** `$CLAUDE_PLUGIN_ROOT/hooks/scripts/guard/packs/cicd.py`
- **DNS patterns:** `$CLAUDE_PLUGIN_ROOT/hooks/scripts/guard/packs/dns.py`
- **Credential patterns:** `$CLAUDE_PLUGIN_ROOT/hooks/scripts/guard/packs/credentials.py`

The tables in this skill provide a quick reference, but the pack files are the definitive source if discrepancies arise.
