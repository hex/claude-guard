#!/usr/bin/env python3
# ABOUTME: Direct unit tests for classify.py pure functions (blanking, comment scan).
# ABOUTME: Exercises the parsing functions in-process, where SEC-1/SEC-2 lived.
"""
The subprocess-level tests only observe the final deny/ask/allow decision.
A blanking or comment-scan bug that does not happen to flip a decision on the
tested inputs would slip through. These tests assert the pure functions'
outputs directly, so the parsing behaviour is pinned regardless of the tiers.
"""
import os
import sys
import unittest

sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "..", "hooks", "scripts")
)

from guard.classify import get_effective_command, find_comment_start, find_quoted_regions


class TestGetEffectiveCommand(unittest.TestCase):
    """Blanking replaces inert literals with spaces but never live expansions."""

    def test_double_quoted_command_substitution_preserved(self):
        # $(...) inside double quotes executes at runtime; it must reach the tiers.
        self.assertIn("rm -rf ~", get_effective_command('echo "$(rm -rf ~)"'))

    def test_backtick_substitution_preserved(self):
        self.assertIn("rm -rf ~", get_effective_command('echo "`rm -rf ~`"'))

    def test_plain_literal_blanked(self):
        # A pure literal arg to a safe wrapper is data and is blanked out.
        self.assertNotIn("rm -rf /", get_effective_command('echo "rm -rf /"'))

    def test_single_quoted_substitution_blanked(self):
        # Single quotes do not expand $(...), so it is literal data — safe to blank.
        self.assertNotIn("rm -rf ~", get_effective_command("echo '$(rm -rf ~)'"))


class TestFindCommentStart(unittest.TestCase):
    """Only a real shell comment '#' should be reported."""

    def test_word_boundary_comment(self):
        cmd = "echo hi # rm -rf /"
        self.assertEqual(find_comment_start(cmd, find_quoted_regions(cmd)),
                         cmd.index("#"))

    def test_parameter_length_is_not_a_comment(self):
        # '#' inside ${#var} is the length operator, not a comment start.
        cmd = "echo ${#PATH} && rm -rf /"
        self.assertIsNone(find_comment_start(cmd, find_quoted_regions(cmd)))

    def test_no_comment(self):
        cmd = "rm -rf /tmp/build"
        self.assertIsNone(find_comment_start(cmd, find_quoted_regions(cmd)))


class TestImportSafety(unittest.TestCase):
    """PEP 604 unions (int | None) are evaluated at import time and raise
    TypeError on Python 3.9. If the guard's import crashes, the PreToolUse hook
    exits non-zero with no deny decision and Claude Code runs the command
    unguarded — a fail-OPEN. `from __future__ import annotations` defers the
    annotations to strings so the module imports cleanly on 3.9."""

    def test_union_annotations_are_deferred(self):
        self.assertIsInstance(
            find_comment_start.__annotations__["return"], str,
            "classify.py annotations must be deferred (from __future__ import "
            "annotations) so the guard does not fail open on Python 3.9",
        )


if __name__ == "__main__":
    unittest.main()
