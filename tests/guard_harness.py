#!/usr/bin/env python3
# ABOUTME: Shared test harness that drives command-guard.py as a subprocess.
# ABOUTME: One definition of the JSON stdin/stdout contract for all guard tests.
import json
import os
import subprocess

GUARD_SCRIPT = os.path.join(
    os.path.dirname(__file__), "..", "hooks", "scripts", "command-guard.py"
)


def run_guard(command):
    """Run command-guard.py with a Bash tool input; return parsed output or None (allow)."""
    input_data = json.dumps({
        "tool_name": "Bash",
        "tool_input": {"command": command},
    })
    result = subprocess.run(
        ["python3", GUARD_SCRIPT],
        input=input_data,
        capture_output=True,
        text=True,
    )
    if result.stdout.strip():
        return json.loads(result.stdout)
    return None


def run_guard_raw(payload):
    """Run command-guard.py with a raw string or dict payload; return the CompletedProcess.

    For edge cases the Bash-only run_guard cannot express (non-Bash tools,
    malformed stdin).
    """
    stdin_text = payload if isinstance(payload, str) else json.dumps(payload)
    return subprocess.run(
        ["python3", GUARD_SCRIPT],
        input=stdin_text,
        capture_output=True,
        text=True,
    )


def assert_denied(tc, command, msg=""):
    """Assert the command is hard-denied (Tier 1)."""
    output = run_guard(command)
    tc.assertIsNotNone(output, f"Expected deny for: {command}. {msg}")
    decision = output["hookSpecificOutput"]["permissionDecision"]
    tc.assertEqual(decision, "deny", f"Expected deny for: {command}. {msg}")


def assert_asks(tc, command, msg=""):
    """Assert the command triggers a user confirmation prompt (Tier 2)."""
    output = run_guard(command)
    tc.assertIsNotNone(output, f"Expected ask for: {command}. {msg}")
    decision = output["hookSpecificOutput"]["permissionDecision"]
    tc.assertEqual(decision, "ask", f"Expected ask for: {command}. {msg}")


def assert_allowed(tc, command, msg=""):
    """Assert the command is allowed (no guard output)."""
    output = run_guard(command)
    tc.assertIsNone(output, f"Expected allow for: {command}. Got: {output}. {msg}")
