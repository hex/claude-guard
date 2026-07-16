#!/usr/bin/env python3
# ABOUTME: Unit tests for the guard's user-facing message formatting.
# ABOUTME: Locks the Tier 1 deny and Tier 2 confirm message layout.
import inspect
import os
import sys
import unittest

sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "..", "hooks", "scripts")
)

from guard.protocol import format_tier1, format_tier2


class TestTier2Message(unittest.TestCase):
    def setUp(self):
        self.msg = format_tier2(
            "force push can destroy remote history",
            "use --force-with-lease, it fails if someone else pushed",
        )

    def test_labels_risk_and_safer(self):
        self.assertIn("Risk:", self.msg)
        self.assertIn("Safer:", self.msg)

    def test_labels_left_aligned_and_values_align(self):
        # Labels start the line (no width-varying glyph prefix), and the risk and
        # safer values begin at the same column so the rows read as a table.
        def value_col(line):
            i = line.index(":") + 1
            while i < len(line) and line[i] == " ":
                i += 1
            return i
        lines = self.msg.splitlines()
        risk = [l for l in lines if l.startswith("Risk:")]
        safer = [l for l in lines if l.startswith("Safer:")]
        self.assertTrue(risk and safer, "Risk:/Safer: must start their own lines")
        self.assertEqual(value_col(risk[0]), value_col(safer[0]))

    def test_includes_reason_and_alternative(self):
        self.assertIn("force push can destroy remote history", self.msg)
        self.assertIn("use --force-with-lease", self.msg)

    def test_takes_no_command(self):
        # The harness already shows the command; the guard must not repeat it.
        self.assertNotIn("command", inspect.signature(format_tier2).parameters)

    def test_no_heavy_rule(self):
        self.assertNotIn("─" * 10, self.msg)

    def test_names_the_guard(self):
        self.assertIn("claude-guard", self.msg)


class TestTier1Message(unittest.TestCase):
    def setUp(self):
        self.msg = format_tier1("deletes the entire root filesystem")

    def test_labels_risk(self):
        self.assertIn("Risk:", self.msg)

    def test_includes_reason(self):
        self.assertIn("deletes the entire root filesystem", self.msg)

    def test_takes_no_command(self):
        self.assertNotIn("command", inspect.signature(format_tier1).parameters)

    def test_no_heavy_rule(self):
        self.assertNotIn("─" * 10, self.msg)

    def test_names_the_guard(self):
        self.assertIn("claude-guard", self.msg)


class TestTier1ReasonsNotRedundant(unittest.TestCase):
    """The Tier 1 frame header already says the command is blocked, so the
    per-rule reason strings should not repeat 'This will NOT be executed.'"""

    def test_reasons_do_not_repeat_the_header(self):
        from guard.packs import load_all, tier1_rules
        load_all()
        offenders = [
            reason for _, _, reason in tier1_rules()
            if "not be executed" in reason.lower()
        ]
        self.assertEqual(offenders, [], f"redundant with header: {offenders}")


if __name__ == "__main__":
    unittest.main()
