#!/usr/bin/env python3
# ABOUTME: JSON protocol for Claude Code hook I/O.
# ABOUTME: Reads HookInput from stdin, writes deny/ask/warn responses to stdout.
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


def ask(reason: str) -> None:
    """Output a PreToolUse ask decision (user confirmation prompt) and exit."""
    print(reason, file=sys.stderr)
    output = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
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


_RULE = "\u2500" * 50


def format_tier1(reason: str) -> str:
    """Format a Tier 1 hard deny message. The harness shows the command itself."""
    return (
        f"\n"
        f"\U0001f534  claude-guard \u00b7 Tier 1 \u2014 blocked\n"
        f"{_RULE}\n"
        f"RISK   {reason}\n"
        f"Run it yourself in a terminal if you truly need it.\n"
        f"{_RULE}\n"
    )


def format_tier2(reason: str, alternative: str) -> str:
    """Format a Tier 2 confirmation message. The harness shows the command itself."""
    return (
        f"\n"
        f"\U0001f6e1\ufe0f  claude-guard \u00b7 Tier 2 \u2014 confirm\n"
        f"{_RULE}\n"
        f"RISK   {reason}\n"
        f"SAFER  {alternative}\n"
        f"{_RULE}\n"
    )
