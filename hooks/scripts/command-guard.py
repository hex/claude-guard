#!/usr/bin/env python3
# ABOUTME: PreToolUse hook that blocks dangerous commands using a three-tier model.
# ABOUTME: Tier 1 = hard deny, Tier 2 = deny + suggest alternative, Tier 3 = warn via credential-scanner.
"""
Command safety guard for Claude Code.

Intercepts Bash commands before execution and applies a three-tier safety model:
  Tier 1 (Hard Deny): Catastrophic, irreversible operations. Must be run manually.
  Tier 2 (Deny + Redirect): Dangerous but has a safer alternative Claude can use instead.
  Tier 3 (Warn): Handled by credential-scanner.py, not this script.

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


def matches(pattern, command: str, normalized: str) -> bool:
    """Check if a pattern matches either the raw or normalized command."""
    return pattern.search(command) or pattern.search(normalized)


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

    normalized = normalize(command)

    # Allowlist check first — safe commands pass immediately
    for pattern in allowlist_rules():
        if matches(pattern, command, normalized):
            sys.exit(0)

    # Tier 1: Hard deny — catastrophic, no escape
    for pattern, category, reason in tier1_rules():
        if matches(pattern, command, normalized):
            deny(format_tier1(reason, command))

    # Tier 2: Deny + redirect — suggest safer alternative
    for pattern, category, reason, alternative in tier2_rules():
        if matches(pattern, command, normalized):
            deny(format_tier2(reason, alternative, command))

    # Allow all other commands
    sys.exit(0)


if __name__ == "__main__":
    main()
