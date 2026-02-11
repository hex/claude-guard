---
description: Show active claude-guard protections, categories, and pattern counts
allowed-tools: Read, Bash(*)
argument-hint: "[category]"
---

# Guard Status

Display the active protections provided by the claude-guard plugin. If an optional category argument is provided, show detailed patterns for that category only.

## Instructions

Read the pattern packs to extract the current protection rules:

- `$CLAUDE_PLUGIN_ROOT/hooks/scripts/guard/packs/core.py`
- `$CLAUDE_PLUGIN_ROOT/hooks/scripts/guard/packs/cloud.py`
- `$CLAUDE_PLUGIN_ROOT/hooks/scripts/guard/packs/infra.py`
- `$CLAUDE_PLUGIN_ROOT/hooks/scripts/guard/packs/cicd.py`
- `$CLAUDE_PLUGIN_ROOT/hooks/scripts/guard/packs/dns.py`
- `$CLAUDE_PLUGIN_ROOT/hooks/scripts/guard/packs/credentials.py`

Present a summary organized by tier:

### Format

```
claude-guard status
==================

Tier 1: Hard Deny (catastrophic, must run manually)
  - filesystem: N patterns
  - disk: N patterns
  - database: N patterns
  - kubernetes: N patterns
  - aws: N patterns
  - gcp: N patterns
  - github-cli: N patterns
  - dns: N patterns

Tier 2: Deny + Redirect (safer alternative suggested)
  - git: N patterns
  - filesystem: N patterns
  - docker: N patterns
  - database: N patterns
  - kubernetes: N patterns
  - permissions: N patterns
  - aws: N patterns
  - gcp: N patterns
  - azure: N patterns
  - terraform: N patterns
  - pulumi: N patterns
  - cdk: N patterns
  - github-cli: N patterns
  - dns: N patterns

Tier 3: Warn (credential scanner)
  - credential patterns: N patterns
  - destructive SQL: N patterns

Allowlisted safe patterns: N patterns

Pipeline features:
  - Command normalization: path stripping, whitespace collapse, env prefix removal
  - Context classification: string literal / comment / execution bridge detection
  - Explain mode: set CLAUDE_GUARD_EXPLAIN=1 for pipeline trace on stderr
```

If a category argument is provided (e.g., `/guard:status git`), show the detailed patterns for that category including the blocked command regex and the safe alternative.

Count patterns by parsing the Python source files directly — do not hardcode counts.
