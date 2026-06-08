#!/usr/bin/env python3
# ABOUTME: PreToolUse hook that blocks dangerous commands using a three-tier model.
# ABOUTME: Tier 1 = hard deny, Tier 2 = deny + suggest alternative, Tier 3 = warn via credential-scanner.
"""
Command safety guard for Claude Code.

Intercepts Bash commands before execution and applies a three-tier safety model:
  Tier 1 (Hard Deny): Catastrophic, irreversible operations. Must be run manually.
  Tier 2 (Deny + Redirect): Dangerous but has a safer alternative Claude can use instead.
  Tier 3 (Warn): Handled by credential-scanner.py, not this script.

Pipeline: normalize → bridge check → classify → per-segment (tier1 → allowlist → tier2)

Exit behavior:
  - Exit 0 with deny JSON = block the command
  - Exit 0 with no output = allow the command
"""
import os
import re
import sys

# Add scripts directory to path so guard package is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from guard.protocol import read_input, deny, ask, format_tier1, format_tier2
from guard.packs import load_all, allowlist_rules, tier1_rules, tier2_rules
from guard.normalize import normalize
from guard.classify import get_effective_command, check_execution_bridges
from guard.explain import trace


# Statement separators. The command is split on these so an allowlisted segment
# (e.g. `git clean -n`) cannot shield a dangerous one chained after it
# (e.g. `&& rm -rf /`). Pipes are not separators here — they are handled by the
# execution-bridge check.
_SEGMENT_SPLIT = re.compile(r'(?:&&|\|\||;)')


def segments(text: str):
    """Split a command into statement segments, dropping empty ones."""
    return [s for s in _SEGMENT_SPLIT.split(text) if s.strip()]


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
    if effective != command:
        trace("classify", f"Effective command: {effective}")
    else:
        trace("classify", "Effective command unchanged (no safe regions blanked)")

    # Phase 4: Tier 1 — catastrophic and allowlist-immune. Matched against the
    # whole effective command (and its normalized form) so a pattern that spans a
    # statement separator, like a fork bomb, is still caught.
    whole_forms = (effective, normalize(effective))
    for pattern, category, reason in tier1_rules():
        if any(pattern.search(form) for form in whole_forms):
            trace("tier 1", f"Matched [{category}]: {pattern.pattern}")
            trace("result", f"DENY (Tier 1): {reason}")
            deny(format_tier1(reason, command))

    # Phases 5-6: Tier 2 — evaluated per statement segment so an allowlisted
    # segment (e.g. `git clean -n`) cannot shield a dangerous one chained after
    # it, and the allowlist only clears the segment it matches. Each segment is
    # checked as written and normalized, so path/env-prefix evasions are caught
    # without normalization stripping a legitimate argument path (e.g. /tmp/).
    pending_ask = None
    for segment in segments(effective):
        forms = (segment, normalize(segment))

        if any(p.search(form) for p in allowlist_rules() for form in forms):
            trace("allowlist", f"Segment allowlisted: {segment.strip()}")
            continue

        for pattern, category, reason, alternative in tier2_rules():
            if any(pattern.search(form) for form in forms):
                trace("tier 2", f"Matched [{category}] in: {segment.strip()}")
                pending_ask = (reason, alternative)
                break

        if pending_ask is not None:
            break

    if pending_ask is not None:
        reason, alternative = pending_ask
        trace("result", f"ASK (Tier 2): {reason}")
        ask(format_tier2(reason, alternative, command))

    # Allow all other commands
    trace("result", "ALLOW (no patterns matched)")
    sys.exit(0)


if __name__ == "__main__":
    main()
