# ABOUTME: Pipeline tracing for debugging guard decisions.
# ABOUTME: Enabled via CLAUDE_GUARD_EXPLAIN=1, writes trace lines to stderr.
import os
import sys

_enabled = None


def is_enabled() -> bool:
    """Check if explain mode is active (CLAUDE_GUARD_EXPLAIN=1)."""
    global _enabled
    if _enabled is None:
        _enabled = os.environ.get("CLAUDE_GUARD_EXPLAIN", "") == "1"
    return _enabled


def trace(phase: str, message: str) -> None:
    """Write a trace line to stderr if explain mode is enabled."""
    if is_enabled():
        print(f"[{phase}] {message}", file=sys.stderr)
