#!/usr/bin/env python3
# ABOUTME: PreToolUse hook that blocks dangerous commands using a three-tier model.
# ABOUTME: Tier 1 = hard deny, Tier 2 = deny + suggest alternative, Tier 3 = warn via credential-scanner.
"""
Command safety guard for Claude Code.

Intercepts Bash commands before execution and applies a three-tier safety model:
  Tier 1 (Hard Deny): Catastrophic, irreversible operations. Must be run manually.
  Tier 2 (Deny + Redirect): Dangerous but has a safer alternative Claude can use instead.
  Tier 3 (Warn): Handled by credential-scanner.py, not this script.

Pipeline: normalize → classify → allowlist → tier1 → tier2

Exit behavior:
  - Exit 0 with deny JSON = block the command
  - Exit 0 with no output = allow the command
"""
import os
import sys

# Add scripts directory to path so guard package is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from guard.protocol import read_input, deny, format_tier1, format_tier2
from guard.packs import load_all, allowlist_rules, tier1_rules, tier2_rules
from guard.normalize import normalize
from guard.classify import get_effective_command, check_execution_bridges
from guard.explain import trace


def matches(pattern, *candidates: str) -> bool:
    """Check if a pattern matches any of the candidate strings."""
    return any(pattern.search(c) for c in candidates)


def main():
    input_data = read_input()
    if not input_data:
        sys.exit(0)

    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input") or {}
    command = tool_input.get("command", "")

    if tool_name != "Bash" or not isinstance(command, str) or not command:
        sys.exit(0)

    # Load all pattern packs
    load_all()

    trace("input", f"Command: {command}")

    # Phase 1: Normalize
    normalized = normalize(command)
    if normalized != command:
        trace("normalize", f"Normalized: {normalized}")
    else:
        trace("normalize", "No changes")

    # Phase 2: Classify — check execution bridges first (separate from pattern matching)
    bridge_result = check_execution_bridges(command)
    if bridge_result:
        is_dangerous, reason = bridge_result
        if is_dangerous:
            trace("bridge", f"Execution bridge detected: {reason}")
            deny(format_tier1(reason, command))
    else:
        trace("bridge", "No execution bridges detected")

    # Phase 3: Build effective command (safe quoted strings and comments blanked)
    effective = get_effective_command(command)
    effective_norm = get_effective_command(normalized)
    if effective != command:
        trace("classify", f"Effective command: {effective}")
    else:
        trace("classify", "Effective command unchanged (no safe regions blanked)")

    # Phase 4: Allowlist check — safe commands pass immediately
    # Check all forms: original (for backward compat), normalized, and effective
    for pattern in allowlist_rules():
        if matches(pattern, command, normalized, effective, effective_norm):
            trace("allowlist", f"Matched allowlist pattern: {pattern.pattern}")
            trace("result", "ALLOW (allowlisted)")
            sys.exit(0)

    # Phase 5: Tier 1 — hard deny, catastrophic
    # Match against effective command (context-aware) to avoid false positives
    # on string literals and comments
    for pattern, category, reason in tier1_rules():
        if matches(pattern, effective, effective_norm):
            trace("tier 1", f"Matched [{category}]: {pattern.pattern}")
            trace("result", f"DENY (Tier 1): {reason}")
            deny(format_tier1(reason, command))

    # Phase 6: Tier 2 — deny + redirect
    for pattern, category, reason, alternative in tier2_rules():
        if matches(pattern, effective, effective_norm):
            trace("tier 2", f"Matched [{category}]: {pattern.pattern}")
            trace("result", f"DENY (Tier 2): {reason}")
            deny(format_tier2(reason, alternative, command))

    # Allow all other commands
    trace("result", "ALLOW (no patterns matched)")
    sys.exit(0)


if __name__ == "__main__":
    main()
