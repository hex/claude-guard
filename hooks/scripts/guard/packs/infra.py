# ABOUTME: Infrastructure-as-code patterns for Terraform, Pulumi, and CDK.
# ABOUTME: Blocks destroy operations, allows plan/preview/synth.
from guard.packs import register_tier2, register_allowlist

# =============================================================================
# Terraform
# =============================================================================

register_tier2(
    r"terraform\s+destroy",
    "infra",
    "terraform destroy removes all managed infrastructure.",
    "Run 'terraform plan -destroy' first to preview what would be destroyed.",
)

register_tier2(
    r"terraform\s+apply\s+.*-destroy",
    "infra",
    "terraform apply -destroy removes all managed infrastructure.",
    "Run 'terraform plan -destroy' first to preview what would be destroyed.",
)

# =============================================================================
# Pulumi
# =============================================================================

register_tier2(
    r"pulumi\s+destroy",
    "infra",
    "pulumi destroy removes all managed infrastructure.",
    "Run 'pulumi preview --destroy' first to preview what would be destroyed.",
)

# =============================================================================
# AWS CDK
# =============================================================================

register_tier2(
    r"cdk\s+destroy",
    "infra",
    "cdk destroy removes all CloudFormation stacks and their resources.",
    "Run 'cdk diff' first to review the current state.",
)
