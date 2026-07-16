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
    "Run 'terraform plan -destroy' first to preview the destroy.",
)

register_tier2(
    r"terraform\s+apply\s+.*-destroy",
    "infra",
    "terraform apply -destroy removes all managed infrastructure.",
    "Run 'terraform plan -destroy' first to preview the destroy.",
)

register_tier2(
    r"terraform\s+apply\s+.*-auto-approve",
    "infra",
    "terraform apply -auto-approve applies with no confirmation.",
    "Run 'terraform plan' first, then apply without -auto-approve.",
)

# =============================================================================
# Pulumi
# =============================================================================

register_tier2(
    r"pulumi\s+destroy",
    "infra",
    "pulumi destroy removes all managed infrastructure.",
    "Run 'pulumi stack' first to review what would be destroyed.",
)

# =============================================================================
# AWS CDK
# =============================================================================

register_tier2(
    r"cdk\s+destroy",
    "infra",
    "cdk destroy removes all CloudFormation stacks and resources.",
    "Run 'cdk diff' first to review the current state.",
)

# =============================================================================
# Orchestration / GitOps teardown
# =============================================================================

register_tier2(
    r"helm\s+uninstall\b|helm\s+delete\b",
    "infra",
    "helm uninstall removes a release and its Kubernetes resources.",
    "Run 'helm list' and 'helm get manifest' first to review.",
)

register_tier2(
    r"argocd\s+app\s+delete\b",
    "infra",
    "argocd app delete removes the app and its managed resources.",
    "Run 'argocd app get' first to review what is managed.",
)

register_tier2(
    r"flux\s+delete\b",
    "infra",
    "flux delete removes a Flux resource and what it reconciles.",
    "Run 'flux get all' first to review.",
)
