# claude-guard

Safety guardian plugin for Claude Code that prevents destructive commands, blocks credential exposure, and redirects dangerous operations to safer alternatives.

## Features

### Three-Tier Safety Model

- **Tier 1 (Hard Deny)**: Catastrophic commands that must be run manually — `rm -rf /`, `dd` to block devices, `DROP DATABASE`, `kubectl delete namespace`
- **Tier 2 (Deny + Redirect)**: Dangerous commands with a safer alternative — `git push --force` redirected to `--force-with-lease`, `rm -rf` requires listing contents first, `docker system prune` redirected to `--dry-run`
- **Tier 3 (Warn)**: Credential and secret detection in written files — AWS keys, API tokens, private keys, connection strings, JWT tokens, and destructive SQL patterns

### Protected Categories

| Category | Tier 1 (Hard Deny) | Tier 2 (Redirect) | Tier 3 (Warn) |
|---|---|---|---|
| Git | | force push, reset --hard, branch -D, clean -f, stash drop, --no-verify | |
| Filesystem | rm -rf /, rm -rf ~ | rm -rf (other dirs), chmod 777 | |
| Disk | dd, mkfs, fdisk | | |
| Database | DROP DATABASE/SCHEMA | DROP TABLE, TRUNCATE, DELETE without WHERE | Destructive SQL in files |
| Docker | | system prune, rm -f, volume rm, compose down -v | |
| Kubernetes | delete namespace, delete --all | delete (other resources) | |
| Credentials | | | AWS, API keys, tokens, private keys, connection strings, JWT |

### Smart Allowlisting

Safe variants are never blocked:
- `git push --force-with-lease` (safe force push)
- `git clean -n` (dry run)
- `rm -rf /tmp/*` (temp directory cleanup)
- `docker system prune --dry-run`
- `kubectl delete --dry-run`

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
| `credential-scanner.sh` | PostToolUse hook | Warns about credential exposure (Tier 3) |
| `guard-rules` | Skill | Teaches Claude the safety rules proactively |
| `status` | Command | Shows active protections |

## Requirements

- `jq` (for JSON parsing in credential scanner)
- `rg` (ripgrep, for pattern matching in credential scanner)
- Python 3.6+ (for command guard)

## Coexistence

This plugin coexists safely with any existing safety hooks in your `settings.json`. If both the plugin and existing hooks block the same command, the first deny stops execution — no conflicts.
