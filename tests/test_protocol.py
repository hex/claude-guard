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


def value_col(line):
    """Column where the value starts, after the leading label word and padding."""
    i = 0
    while i < len(line) and line[i] != " ":  # skip the label
        i += 1
    while i < len(line) and line[i] == " ":  # skip the padding
        i += 1
    return i


class TestTier2Message(unittest.TestCase):
    def setUp(self):
        self.msg = format_tier2(
            "force push can destroy remote history",
            "use --force-with-lease, it fails if someone else pushed",
        )

    def test_uppercase_labels(self):
        self.assertIn("RISK", self.msg)
        self.assertIn("SAFER", self.msg)

    def test_includes_reason_and_alternative(self):
        self.assertIn("force push can destroy remote history", self.msg)
        self.assertIn("use --force-with-lease", self.msg)

    def test_takes_no_command(self):
        # The harness already shows the command; the guard must not repeat it.
        self.assertNotIn("command", inspect.signature(format_tier2).parameters)

    def test_risk_and_safer_values_align(self):
        lines = self.msg.splitlines()
        risk = next(l for l in lines if l.startswith("RISK"))
        safer = next(l for l in lines if l.startswith("SAFER"))
        self.assertEqual(value_col(risk), value_col(safer))

    def test_framed_by_two_rules(self):
        # Plain ─ rules top and bottom. The corner/rail box variants rendered
        # broken in the harness; simple horizontal rules do not.
        lines = self.msg.splitlines()
        rules = [i for i, l in enumerate(lines) if l and set(l) == {"─"}]
        title = next(i for i, l in enumerate(lines) if "claude-guard" in l)
        last_nonempty = max(i for i, l in enumerate(lines) if l.strip())
        self.assertEqual(len(rules), 2)
        self.assertEqual(rules[0], title + 1)
        self.assertEqual(rules[-1], last_nonempty)

    def test_no_broken_box_chars(self):
        self.assertFalse(any(c in self.msg for c in "│┌└┐┘"))

    def test_padded_with_blank_lines(self):
        self.assertTrue(self.msg.startswith("\n"))
        self.assertTrue(self.msg.endswith("\n"))

    def test_names_the_guard(self):
        self.assertIn("claude-guard", self.msg)


class TestTier1Message(unittest.TestCase):
    def setUp(self):
        self.msg = format_tier1("deletes the entire root filesystem")

    def test_uppercase_risk_label(self):
        self.assertIn("RISK", self.msg)

    def test_includes_reason(self):
        self.assertIn("deletes the entire root filesystem", self.msg)

    def test_takes_no_command(self):
        self.assertNotIn("command", inspect.signature(format_tier1).parameters)

    def test_framed_by_two_rules(self):
        lines = self.msg.splitlines()
        rules = [i for i, l in enumerate(lines) if l and set(l) == {"─"}]
        title = next(i for i, l in enumerate(lines) if "claude-guard" in l)
        last_nonempty = max(i for i, l in enumerate(lines) if l.strip())
        self.assertEqual(len(rules), 2)
        self.assertEqual(rules[0], title + 1)
        self.assertEqual(rules[-1], last_nonempty)

    def test_no_broken_box_chars(self):
        self.assertFalse(any(c in self.msg for c in "│┌└┐┘"))

    def test_padded_with_blank_lines(self):
        self.assertTrue(self.msg.startswith("\n"))
        self.assertTrue(self.msg.endswith("\n"))

    def test_names_the_guard(self):
        self.assertIn("claude-guard", self.msg)


class TestStringsAreConcise(unittest.TestCase):
    """RISK/SAFER lines wrap on narrow terminals when the strings run long."""

    LIMIT = 62

    def test_reasons_within_limit(self):
        from guard.packs import load_all, tier1_rules, tier2_rules
        load_all()
        reasons = [r for _, _, r in tier1_rules()]
        reasons += [r for _, _, r, _ in tier2_rules()]
        over = sorted((len(r), r) for r in reasons if len(r) > self.LIMIT)
        self.assertEqual(over, [], f"{len(over)} reasons over {self.LIMIT}: {over}")

    def test_alternatives_within_limit(self):
        from guard.packs import load_all, tier2_rules
        load_all()
        alts = [a for _, _, _, a in tier2_rules()]
        over = sorted((len(a), a) for a in alts if len(a) > self.LIMIT)
        self.assertEqual(over, [], f"{len(over)} alternatives over {self.LIMIT}: {over}")


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
