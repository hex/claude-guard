# ABOUTME: Pattern pack registry that collects rules from all domain packs.
# ABOUTME: Each pack registers its patterns at import time via register().
import re

# Tier 1: Hard deny — (compiled_regex, category, reason)
_tier1 = []

# Tier 2: Deny + redirect — (compiled_regex, category, reason, alternative)
_tier2 = []

# Allowlist: Safe patterns — compiled regexes
_allowlist = []


def register_tier1(pattern: str, category: str, reason: str) -> None:
    """Register a Tier 1 (hard deny) pattern."""
    _tier1.append((re.compile(pattern), category, reason))


def register_tier2(
    pattern: str, category: str, reason: str, alternative: str
) -> None:
    """Register a Tier 2 (deny + redirect) pattern."""
    _tier2.append((re.compile(pattern), category, reason, alternative))


def register_allowlist(pattern: str) -> None:
    """Register an allowlisted safe pattern."""
    _allowlist.append(re.compile(pattern))


def tier1_rules():
    """Return all registered Tier 1 rules."""
    return _tier1


def tier2_rules():
    """Return all registered Tier 2 rules."""
    return _tier2


def allowlist_rules():
    """Return all registered allowlist rules."""
    return _allowlist


def load_all():
    """Import all pack modules to trigger registration."""
    from guard.packs import core  # noqa: F401
