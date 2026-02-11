---
name: status
description: Show active claude-guard protections, categories, and pattern counts
allowed-tools:
  - Read
  - Bash
argument-hint: "[category]"
---

# Guard Status

Display the active protections provided by the claude-guard plugin. If an optional category argument is provided, show detailed patterns for that category only.

## Instructions

Read the command guard script at `$CLAUDE_PLUGIN_ROOT/hooks/scripts/command-guard.py` and the credential scanner at `$CLAUDE_PLUGIN_ROOT/hooks/scripts/credential-scanner.sh` to extract the current protection rules.

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

Tier 2: Deny + Redirect (safer alternative suggested)
  - git: N patterns
  - filesystem: N patterns
  - docker: N patterns
  - database: N patterns
  - kubernetes: N patterns
  - permissions: N patterns

Tier 3: Warn (credential scanner)
  - credential patterns: N patterns
  - destructive SQL: N patterns

Allowlisted safe patterns: N patterns
```

If a category argument is provided (e.g., `/guard:status git`), show the detailed patterns for that category including the blocked command regex and the safe alternative.

Count patterns by parsing the Python and Bash source files directly — do not hardcode counts.
