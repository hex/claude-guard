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

register_tier2(
    r"terraform\s+apply\s+.*-auto-approve",
    "infra",
    "terraform apply -auto-approve applies the plan with no confirmation prompt.",
    "Run 'terraform plan' and review, then apply without -auto-approve to confirm interactively.",
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

# =============================================================================
# Orchestration / GitOps teardown
# =============================================================================

register_tier2(
    r"helm\s+uninstall\b|helm\s+delete\b",
    "infra",
    "helm uninstall removes a release and all its Kubernetes resources.",
    "Run 'helm list' first to review, and 'helm get manifest' to see what would be removed.",
)

register_tier2(
    r"argocd\s+app\s+delete\b",
    "infra",
    "argocd app delete removes the application and its managed resources.",
    "Run 'argocd app get' first to review what is managed.",
)

register_tier2(
    r"flux\s+delete\b",
    "infra",
    "flux delete removes a Flux resource and what it reconciles.",
    "Run 'flux get all' first to review.",
)
