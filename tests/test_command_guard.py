#!/usr/bin/env python3
# ABOUTME: Test suite for command-guard.py PreToolUse hook.
# ABOUTME: Tests all tiers, allowlist, case sensitivity, and safe commands.
"""
Tests the command guard by invoking it as a subprocess with JSON on stdin,
exactly as Claude Code does. This exercises the real entry point and I/O path.
"""
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


def assert_denied(test_case: unittest.TestCase, command: str, msg: str = ""):
    """Assert the command is denied by the guard."""
    output = run_guard(command)
    test_case.assertIsNotNone(output, f"Expected deny for: {command}")
    decision = output["hookSpecificOutput"]["permissionDecision"]
    test_case.assertEqual(decision, "deny", f"Expected deny for: {command}. {msg}")


def assert_allowed(test_case: unittest.TestCase, command: str, msg: str = ""):
    """Assert the command is allowed by the guard."""
    output = run_guard(command)
    test_case.assertIsNone(output, f"Expected allow for: {command}. Got: {output}. {msg}")


class TestTier1HardDeny(unittest.TestCase):
    """Tier 1: Catastrophic commands that must never execute."""

    def test_rm_rf_root(self):
        assert_denied(self, "rm -rf / ")

    def test_rm_rf_home(self):
        assert_denied(self, "rm -rf ~ ")

    def test_rm_rf_home_var(self):
        assert_denied(self, "rm -rf $HOME/")

    def test_dd_block_device(self):
        assert_denied(self, "dd if=/dev/zero of=/dev/sda")

    def test_mkfs(self):
        assert_denied(self, "mkfs.ext4 /dev/sda1")

    def test_fdisk(self):
        assert_denied(self, "fdisk /dev/sda")

    def test_drop_database_upper(self):
        assert_denied(self, "mysql -e 'DROP DATABASE prod'")

    def test_drop_database_lower(self):
        assert_denied(self, "mysql -e 'drop database prod'")

    def test_drop_schema(self):
        assert_denied(self, "psql -c 'DROP SCHEMA public'")

    def test_fork_bomb(self):
        assert_denied(self, ":(){ :|:& };")

    def test_kubectl_delete_namespace(self):
        assert_denied(self, "kubectl delete namespace production")

    def test_kubectl_delete_all(self):
        assert_denied(self, "kubectl delete pods --all")


class TestTier2DenyRedirect(unittest.TestCase):
    """Tier 2: Dangerous commands with safer alternatives."""

    def test_git_push_force(self):
        assert_denied(self, "git push --force origin main")

    def test_git_push_f(self):
        assert_denied(self, "git push -f origin main")

    def test_git_reset_hard(self):
        assert_denied(self, "git reset --hard HEAD~1")

    def test_git_reset_merge(self):
        assert_denied(self, "git reset --merge HEAD~1")

    def test_git_checkout_dot(self):
        assert_denied(self, "git checkout -- .")

    def test_git_checkout_file(self):
        assert_denied(self, "git checkout -- src/file.ts")

    def test_git_restore_file(self):
        assert_denied(self, "git restore src/file.ts")

    def test_git_clean_f(self):
        assert_denied(self, "git clean -fd")

    def test_git_branch_force_delete(self):
        assert_denied(self, "git branch -D feature/old")

    def test_git_stash_drop(self):
        assert_denied(self, "git stash drop stash@{0}")

    def test_git_stash_clear(self):
        assert_denied(self, "git stash clear")

    def test_git_commit_no_verify(self):
        assert_denied(self, "git commit --no-verify -m test")

    def test_rm_rf_build(self):
        assert_denied(self, "rm -rf ./build")

    def test_docker_system_prune(self):
        assert_denied(self, "docker system prune -a")

    def test_docker_rm_force(self):
        assert_denied(self, "docker rm -f mycontainer")

    def test_docker_volume_rm(self):
        assert_denied(self, "docker volume rm data_vol")

    def test_docker_network_rm(self):
        assert_denied(self, "docker network rm mynet")

    def test_docker_compose_down_v(self):
        assert_denied(self, "docker compose down -v")

    def test_docker_rmi_force(self):
        assert_denied(self, "docker rmi -f myimage")

    def test_chmod_777(self):
        assert_denied(self, "chmod 777 /var/www")

    def test_drop_table_upper(self):
        assert_denied(self, "psql -c 'DROP TABLE users'")

    def test_drop_table_lower(self):
        assert_denied(self, "psql -c 'drop table users'")

    def test_truncate_upper(self):
        assert_denied(self, "mysql -e 'TRUNCATE users'")

    def test_truncate_lower(self):
        assert_denied(self, "mysql -e 'truncate users'")

    def test_delete_without_where_upper(self):
        assert_denied(self, "psql -c 'DELETE FROM users;'")

    def test_delete_without_where_lower(self):
        assert_denied(self, "psql -c 'delete from users;'")

    def test_kubectl_delete_pod(self):
        assert_denied(self, "kubectl delete pod my-pod")


class TestAllowlist(unittest.TestCase):
    """Allowlisted safe patterns that must never be blocked."""

    def test_git_checkout_new_branch(self):
        assert_allowed(self, "git checkout -b feature/new")

    def test_git_checkout_orphan(self):
        assert_allowed(self, "git checkout --orphan clean-start")

    def test_git_restore_staged(self):
        assert_allowed(self, "git restore --staged src/file.ts")

    def test_git_clean_dry_run(self):
        assert_allowed(self, "git clean -n")

    def test_git_push_force_with_lease(self):
        assert_allowed(self, "git push --force-with-lease origin")

    def test_rm_rf_tmp(self):
        assert_allowed(self, "rm -rf /tmp/build-cache/")

    def test_docker_prune_dry_run(self):
        assert_allowed(self, "docker system prune --dry-run")

    def test_kubectl_delete_dry_run(self):
        assert_allowed(self, "kubectl delete pod x --dry-run=client")


class TestCaseSensitivity(unittest.TestCase):
    """Git flags are case-sensitive: -d (safe) vs -D (dangerous)."""

    def test_git_branch_lowercase_d_allowed(self):
        assert_allowed(self, "git branch -d feature/old")

    def test_git_branch_uppercase_D_blocked(self):
        assert_denied(self, "git branch -D feature/old")


class TestSafeCommands(unittest.TestCase):
    """Ordinary commands that should never be blocked."""

    def test_git_status(self):
        assert_allowed(self, "git status")

    def test_git_log(self):
        assert_allowed(self, "git log --oneline -5")

    def test_ls(self):
        assert_allowed(self, "ls -la")

    def test_npm_install(self):
        assert_allowed(self, "npm install")

    def test_echo(self):
        assert_allowed(self, "echo hello")


class TestNonBashTools(unittest.TestCase):
    """Non-Bash tool invocations should pass through without checking."""

    def test_write_tool_passes(self):
        input_data = json.dumps({
            "tool_name": "Write",
            "tool_input": {"file_path": "/tmp/test.txt", "content": "rm -rf /"},
        })
        result = subprocess.run(
            ["python3", GUARD_SCRIPT],
            input=input_data,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.stdout.strip(), "")

    def test_invalid_json_passes(self):
        result = subprocess.run(
            ["python3", GUARD_SCRIPT],
            input="not json",
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
