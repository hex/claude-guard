#!/usr/bin/env python3
# ABOUTME: PostToolUse hook that detects credential exposure and destructive SQL in written files.
# ABOUTME: Tier 3 of the claude-guard safety model — warns without blocking.
"""
Credential and SQL safety scanner for Claude Code.

Scans files after Write/Edit/MultiEdit operations for:
  - Hardcoded credentials (AWS keys, API tokens, private keys, etc.)
  - Destructive SQL statements (DROP, TRUNCATE, DELETE without WHERE)

Exit behavior:
  - Exit 0 with additionalContext JSON = add warning context
  - Exit 0 with no output = file is clean
"""
import os
import sys

# Add scripts directory to path so guard package is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from guard.protocol import read_input, warn
from guard.packs.credentials import scan_file


def main():
    input_data = read_input()
    if not input_data:
        sys.exit(0)

    tool_name = input_data.get("tool_name", "")

    # Only process file-writing tools
    if tool_name not in ("Write", "Edit", "MultiEdit"):
        sys.exit(0)

    tool_input = input_data.get("tool_input") or {}
    file_path = tool_input.get("file_path", "")

    if not file_path:
        sys.exit(0)

    warnings = scan_file(file_path)

    if warnings:
        warn_text = "\n".join(warnings)
        warn(
            f"CREDENTIAL/SAFETY WARNING in {file_path}:\n"
            f"{warn_text}\n"
            f"\nReview the file and ensure no secrets are committed. "
            f"Use environment variables for sensitive values."
        )

    sys.exit(0)


if __name__ == "__main__":
    main()
