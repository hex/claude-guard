# ABOUTME: CI/CD patterns for GitHub (gh) and GitLab (glab) CLI destructive operations.
# ABOUTME: Blocks repo/release/secret/variable/token/MR/issue deletion, allows creation and listing.
from guard.packs import register_tier1, register_tier2

# =============================================================================
# GitHub CLI (gh)
# =============================================================================

register_tier1(
    r"gh\s+repo\s+delete",
    "cicd",
    "Deleting a repo is permanent: destroys code, issues, and PRs.",
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

register_tier2(
    r"gh\s+extension\s+install\b",
    "cicd",
    "gh extension install runs third-party code on your machine.",
    "Review the extension's source before installing.",
)

# =============================================================================
# GitLab CLI (glab)
# =============================================================================

register_tier1(
    r"glab\s+(repo|project)\s+delete",
    "cicd",
    "Deleting a project is permanent: destroys code, issues, MRs.",
)

register_tier2(
    r"glab\s+release\s+delete",
    "cicd",
    "Deleting a release removes the release and its assets.",
    "Run 'glab release list' first to review releases.",
)

register_tier2(
    r"glab\s+var(iable)?\s+(delete|remove)\b",
    "cicd",
    "Deleting a CI/CD variable can break pipelines that use it.",
    "Run 'glab variable list' first to review variables.",
)

register_tier2(
    r"glab\s+(repo|project)\s+update\b.*--archive(?!=(false|False|FALSE|f|F|0)\b)",
    "cicd",
    "Archiving makes the project read-only and hides it.",
    "Reversible with '--archive=false'; confirm intent.",
)

register_tier2(
    r"glab\s+token\s+(revoke|rm)\b",
    "cicd",
    "Revoking a token breaks any automation using it.",
    "Run 'glab token list' first to review tokens.",
)

register_tier2(
    r"glab\s+(ci|pipe|pipeline)\s+delete\b",
    "cicd",
    "Deleting a pipeline removes its records and job logs.",
    "Run 'glab ci list' first to review pipelines.",
)

register_tier2(
    r"glab\s+ssh-key\s+delete",
    "cicd",
    "Deleting an SSH key removes it from your GitLab account.",
    "Run 'glab ssh-key list' first to review keys.",
)

register_tier2(
    r"glab\s+gpg-key\s+delete",
    "cicd",
    "Deleting a GPG key removes it from your GitLab account.",
    "Run 'glab gpg-key list' first to review keys.",
)

register_tier2(
    r"glab\s+deploy-key\s+delete",
    "cicd",
    "Deleting a deploy key removes it from the project.",
    "Run 'glab deploy-key list' first to review keys.",
)

register_tier2(
    r"glab\s+deploy-token\s+del(ete)?\b",
    "cicd",
    "Deleting a deploy token breaks any automation using it.",
    "Run 'glab deploy-token list' first to review tokens.",
)

register_tier2(
    r"glab\s+securefile\s+(remove|rm|delete)\b",
    "cicd",
    "Deleting a secure file can break pipelines that use it.",
    "Run 'glab securefile list' first to review files.",
)

register_tier2(
    r"glab\s+mr\s+del(ete)?\b",
    "cicd",
    "Deleting an MR removes it and its discussion.",
    "Close it instead with 'glab mr close' to preserve history.",
)

register_tier2(
    r"glab\s+issue\s+del(ete)?\b",
    "cicd",
    "Deleting an issue permanently removes it and its discussion.",
    "Close it instead with 'glab issue close' to preserve history.",
)

register_tier2(
    r"glab\s+work-items?\s+delete",
    "cicd",
    "Deleting a work item permanently removes it.",
    "Irreversible; there is no close subcommand. Confirm intent.",
)
