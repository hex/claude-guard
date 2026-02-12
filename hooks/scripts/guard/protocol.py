#!/usr/bin/env python3
# ABOUTME: JSON protocol for Claude Code hook I/O.
# ABOUTME: Reads HookInput from stdin, writes deny/warn responses to stdout.
import json
import sys


def read_input() -> dict:
    """Read and parse JSON hook input from stdin. Returns empty dict on failure."""
    try:
        return json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        return {}


def deny(reason: str) -> None:
    """Output a PreToolUse deny decision and exit."""
    print(reason, file=sys.stderr)
    output = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }
    print(json.dumps(output))
    sys.exit(0)


def warn(context: str) -> None:
    """Output a PostToolUse warning (additionalContext) and exit."""
    output = {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": context,
        }
    }
    print(json.dumps(output))
    sys.exit(0)


SEPARATOR = "\u2500" * 49


def format_tier1(reason: str, command: str) -> str:
    """Format a Tier 1 hard deny message."""
    return (
        f"\U0001f534 BLOCKED by claude-guard (Tier 1: Hard Deny)\n\n"
        f"Command: {command}\n\n"
        f"{SEPARATOR}\n"
        f"{reason}\n"
        f"{SEPARATOR}\n\n"
        f"This command must be run manually by the user if truly needed."
    )


def format_tier2(reason: str, alternative: str, command: str) -> str:
    """Format a Tier 2 deny + redirect message."""
    return (
        f"\U0001f6e1\ufe0f BLOCKED by claude-guard (Tier 2: Safer Alternative Available)\n\n"
        f"Command: {command}\n\n"
        f"{SEPARATOR}\n"
        f"{reason}\n"
        f"{SEPARATOR}\n\n"
        f"Alternative: {alternative}"
    )
