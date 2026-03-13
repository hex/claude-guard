#!/usr/bin/env python3
# ABOUTME: Tests for command normalization (path stripping, env prefix, whitespace).
# ABOUTME: Verifies normalization integrates correctly with the guard pipeline.
import json
import os
import subprocess
import unittest

GUARD_SCRIPT = os.path.join(
    os.path.dirname(__file__), "..", "hooks", "scripts", "command-guard.py"
)


def run_guard(command: str) -> dict | None:
    """Run command-guard.py with a Bash tool input and return parsed output."""
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


def assert_asks(tc, command, msg=""):
    """Assert the command triggers a user confirmation prompt (Tier 2)."""
    output = run_guard(command)
    tc.assertIsNotNone(output, f"Expected ask for: {command}. {msg}")
    decision = output["hookSpecificOutput"]["permissionDecision"]
    tc.assertEqual(decision, "ask", f"Expected ask for: {command}. {msg}")


def assert_allowed(tc, command, msg=""):
    output = run_guard(command)
    tc.assertIsNone(output, f"Expected allow for: {command}. Got: {output}. {msg}")


class TestPathNormalization(unittest.TestCase):
    """Full paths to executables should still trigger patterns."""

    def test_usr_bin_git_force_push(self):
        assert_asks(self, "/usr/bin/git push --force origin main")

    def test_usr_local_bin_git_reset_hard(self):
        assert_asks(self, "/usr/local/bin/git reset --hard HEAD~1")

    def test_usr_bin_rm_rf(self):
        assert_asks(self, "/usr/bin/rm -rf ./build")

    def test_opt_homebrew_bin_terraform_destroy(self):
        assert_asks(self, "/opt/homebrew/bin/terraform destroy")

    def test_full_path_still_allows_safe(self):
        assert_allowed(self, "/usr/bin/git status")

    def test_full_path_allows_force_with_lease(self):
        assert_allowed(self, "/usr/bin/git push --force-with-lease origin")


class TestEnvPrefix(unittest.TestCase):
    """Commands wrapped in env should still be checked."""

    def test_env_git_force_push(self):
        assert_asks(self, "env GIT_SSH_COMMAND='ssh -i key' git push --force origin main")

    def test_env_multiple_vars(self):
        assert_asks(self, "env FOO=bar BAZ=qux git reset --hard HEAD")

    def test_bare_env_safe_command(self):
        assert_allowed(self, "env HOME=/tmp git status")

    def test_env_force_with_lease_allowed(self):
        assert_allowed(self, "env GIT_SSH_COMMAND='ssh -i key' git push --force-with-lease origin")


class TestWhitespaceNormalization(unittest.TestCase):
    """Extra whitespace should not prevent pattern matching."""

    def test_extra_spaces(self):
        assert_asks(self, "git   push   --force   origin   main")

    def test_leading_trailing_whitespace(self):
        assert_asks(self, "  git push --force origin main  ")

    def test_tabs(self):
        assert_asks(self, "git\tpush\t--force\torigin\tmain")


class TestGitConfigPrefix(unittest.TestCase):
    """git -c key=value config overrides should not bypass patterns."""

    def test_git_c_push_force(self):
        assert_asks(self, "git -c user.name=x push --force origin main")

    def test_git_c_multiple_configs(self):
        assert_asks(self, "git -c user.name=x -c user.email=y push --force origin")

    def test_git_c_reset_hard(self):
        assert_asks(self, "git -c core.autocrlf=false reset --hard HEAD")

    def test_git_c_safe_command(self):
        assert_allowed(self, "git -c core.autocrlf=true status")

    def test_git_c_force_with_lease_allowed(self):
        assert_allowed(self, "git -c user.name=x push --force-with-lease origin")


if __name__ == "__main__":
    unittest.main()
