# ABOUTME: CI/CD patterns for GitHub CLI destructive operations.
# ABOUTME: Blocks repo/release/secret deletion, allows creation and listing.
from guard.packs import register_tier1, register_tier2

# =============================================================================
# GitHub CLI (gh)
# =============================================================================

register_tier1(
    r"gh\s+repo\s+delete",
    "cicd",
    "Deleting a GitHub repository is permanent and destroys all code, issues, and PRs. This will NOT be executed.",
)

register_tier2(
    r"gh\s+release\s+delete",
    "cicd",
    "Deleting a release removes the release and its assets.",
    "Run 'gh release list' first to review releases.",
)

register_tier2(
    r"gh\s+secret\s+delete",
    "cicd",
    "Deleting a secret removes it from the repository.",
    "Run 'gh secret list' first to review secrets.",
)
