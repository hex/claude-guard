#!/usr/bin/env python3
# ABOUTME: Test suite for credential-scanner.py PostToolUse hook.
# ABOUTME: Tests credential detection, SQL scanning, file skip logic, and false positive suppression.
"""
Tests the credential scanner by invoking it as a subprocess with JSON on stdin
and temp files containing test patterns, exactly as Claude Code does.
"""
import json
import os
import subprocess
import tempfile
import unittest

SCANNER_SCRIPT = os.path.join(
    os.path.dirname(__file__), "..", "hooks", "scripts", "credential-scanner.py"
)


def run_scanner(tool_name: str, file_path: str) -> dict | None:
    """Run credential-scanner.py with a PostToolUse input and return parsed output."""
    input_data = json.dumps({
        "tool_name": tool_name,
        "tool_input": {"file_path": file_path},
    })
    result = subprocess.run(
        ["python3", SCANNER_SCRIPT],
        input=input_data,
        capture_output=True,
        text=True,
    )
    if result.stdout.strip():
        return json.loads(result.stdout)
    return None


def write_temp_file(content: str, suffix: str = ".py") -> str:
    """Write content to a temp file and return its path."""
    f = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False)
    f.write(content)
    f.close()
    return f.name


class TestCredentialDetection(unittest.TestCase):
    """Credential patterns that should trigger warnings."""

    def tearDown(self):
        # Clean up any temp files created during tests
        for attr in dir(self):
            if attr.startswith("_tmp_"):
                try:
                    os.unlink(getattr(self, attr))
                except OSError:
                    pass

    def _scan(self, content: str, suffix: str = ".py") -> dict | None:
        path = write_temp_file(content, suffix)
        self._tmp_path = path
        try:
            return run_scanner("Write", path)
        finally:
            os.unlink(path)

    def _assert_warns(self, content: str, expected_fragment: str, suffix: str = ".py"):
        result = self._scan(content, suffix)
        self.assertIsNotNone(result, f"Expected warning for content with {expected_fragment}")
        ctx = result.get("additionalContext", "")
        self.assertIn(expected_fragment, ctx, f"Expected '{expected_fragment}' in: {ctx}")

    def _assert_no_warning(self, content: str, suffix: str = ".py"):
        result = self._scan(content, suffix)
        self.assertIsNone(result, f"Expected no warning, got: {result}")

    # --- AWS ---
    def test_aws_access_key(self):
        self._assert_warns("key = 'AKIAIOSFODNN7EXAMPLE'", "AWS Access Key ID")

    def test_aws_secret_key(self):
        self._assert_warns(
            "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "AWS Secret Access Key",
        )

    # --- API keys ---
    def test_generic_api_key(self):
        self._assert_warns(
            'api_key = "sk-abcdefghij1234567890abcd"', "API key"
        )

    # --- Secrets/tokens ---
    def test_hardcoded_secret(self):
        self._assert_warns(
            'secret = "my-super-secret-value-here"', "secret/token/password"
        )

    def test_hardcoded_token(self):
        self._assert_warns(
            'token = "abcdefghijklmnop"', "secret/token/password"
        )

    # --- Private keys ---
    def test_private_key(self):
        self._assert_warns("-----BEGIN RSA PRIVATE KEY-----", "Private key")

    # --- GitHub tokens ---
    def test_github_token(self):
        self._assert_warns(
            "token = ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef", "GitHub token"
        )

    # --- GitLab tokens ---
    def test_gitlab_token(self):
        self._assert_warns("token = glpat-ABCDEFGHIJ1234567890", "GitLab token")

    # --- Slack tokens ---
    def test_slack_token(self):
        self._assert_warns("SLACK_TOKEN=xoxb-1234567890123", "Slack token")

    # --- Connection strings ---
    def test_postgres_connection_string(self):
        self._assert_warns(
            "DATABASE_URL=postgresql://user:password@localhost:5432/db",
            "connection string",
        )

    # --- JWT ---
    def test_jwt_token(self):
        self._assert_warns(
            "token = eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
            "JWT token",
        )

    # --- Google API ---
    def test_google_api_key(self):
        self._assert_warns(
            "GOOGLE_KEY=AIzaSyB-abc123def456ghi789jkl012mno345p",
            "Google API key",
        )

    # --- Stripe ---
    def test_stripe_live_key(self):
        self._assert_warns(
            "STRIPE_KEY=sk_live_abcdefghij1234567890", "Stripe API key"
        )


class TestSQLDetection(unittest.TestCase):
    """Destructive SQL patterns in files."""

    def _scan(self, content: str, suffix: str = ".sql") -> dict | None:
        path = write_temp_file(content, suffix)
        try:
            return run_scanner("Write", path)
        finally:
            os.unlink(path)

    def _assert_warns(self, content: str, expected_fragment: str, suffix: str = ".sql"):
        result = self._scan(content, suffix)
        self.assertIsNotNone(result, f"Expected warning for SQL: {content[:50]}")
        ctx = result.get("additionalContext", "")
        self.assertIn(expected_fragment, ctx, f"Expected '{expected_fragment}' in: {ctx}")

    def test_drop_table(self):
        self._assert_warns("DROP TABLE users;", "DROP")

    def test_drop_database(self):
        self._assert_warns("DROP DATABASE production;", "DROP")

    def test_truncate(self):
        self._assert_warns("TRUNCATE TABLE sessions;", "TRUNCATE")

    def test_delete_without_where(self):
        self._assert_warns("DELETE FROM users;", "DELETE FROM without WHERE")

    def test_delete_with_where_is_safe(self):
        path = write_temp_file("DELETE FROM users WHERE id = 5;", suffix=".sql")
        try:
            result = run_scanner("Write", path)
            if result:
                ctx = result.get("additionalContext", "")
                self.assertNotIn("DELETE FROM without WHERE", ctx)
        finally:
            os.unlink(path)

    def test_sql_only_checked_in_relevant_files(self):
        """SQL patterns should not trigger in .txt files."""
        path = write_temp_file("DROP TABLE users;", suffix=".txt")
        try:
            result = run_scanner("Write", path)
            if result:
                ctx = result.get("additionalContext", "")
                self.assertNotIn("DROP", ctx)
        finally:
            os.unlink(path)


class TestFileSkipLogic(unittest.TestCase):
    """Files that should be skipped entirely."""

    def test_skip_git_directory(self):
        result = run_scanner("Write", "/repo/.git/config")
        self.assertIsNone(result)

    def test_skip_env_example(self):
        result = run_scanner("Write", "/repo/.env.example")
        self.assertIsNone(result)

    def test_skip_env_template(self):
        result = run_scanner("Write", "/repo/.env.template")
        self.assertIsNone(result)

    def test_skip_node_modules(self):
        result = run_scanner("Write", "/repo/node_modules/pkg/index.js")
        self.assertIsNone(result)

    def test_skip_package_lock(self):
        result = run_scanner("Write", "/repo/package-lock.json")
        self.assertIsNone(result)

    def test_skip_go_sum(self):
        result = run_scanner("Write", "/repo/go.sum")
        self.assertIsNone(result)


class TestFalsePositiveSuppression(unittest.TestCase):
    """Env var references should not trigger credential warnings."""

    def _scan(self, content: str) -> dict | None:
        path = write_temp_file(content)
        try:
            return run_scanner("Write", path)
        finally:
            os.unlink(path)

    def test_env_var_reference_suppresses_secret(self):
        """Files using process.env should not trigger secret warnings."""
        result = self._scan(
            'const secret = process.env.SECRET_KEY;\n'
            'secret = "longfakesecretvalue"'
        )
        if result:
            ctx = result.get("additionalContext", "")
            self.assertNotIn("secret/token/password", ctx)

    def test_os_environ_suppresses_secret(self):
        """Files using os.environ should not trigger secret warnings."""
        result = self._scan(
            'import os\n'
            'secret = os.environ["SECRET_KEY"]\n'
            'password = "longfakepassword"'
        )
        if result:
            ctx = result.get("additionalContext", "")
            self.assertNotIn("secret/token/password", ctx)

    def test_connection_string_with_env_var_suppressed(self):
        """Connection strings using env vars should not trigger."""
        result = self._scan(
            'DATABASE_URL=postgresql://${DB_USER}:${DB_PASS}@localhost/db'
        )
        if result:
            ctx = result.get("additionalContext", "")
            self.assertNotIn("connection string", ctx)


class TestToolFiltering(unittest.TestCase):
    """Only Write/Edit/MultiEdit tools should be scanned."""

    def test_bash_tool_ignored(self):
        input_data = json.dumps({
            "tool_name": "Bash",
            "tool_input": {"command": "echo AKIAIOSFODNN7EXAMPLE"},
        })
        result = subprocess.run(
            ["python3", SCANNER_SCRIPT],
            input=input_data,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.stdout.strip(), "")

    def test_read_tool_ignored(self):
        input_data = json.dumps({
            "tool_name": "Read",
            "tool_input": {"file_path": "/tmp/test.py"},
        })
        result = subprocess.run(
            ["python3", SCANNER_SCRIPT],
            input=input_data,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.stdout.strip(), "")


if __name__ == "__main__":
    unittest.main()
