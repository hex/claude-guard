# ABOUTME: Cloud provider CLI patterns for AWS, GCP, and Azure.
# ABOUTME: Blocks destructive operations like instance termination, storage deletion, database drops.
from guard.packs import register_tier1, register_tier2, register_allowlist

# =============================================================================
# AWS CLI
# =============================================================================

# Tier 1: Catastrophic AWS operations
register_tier1(
    r"aws\s+ec2\s+terminate-instances",
    "cloud",
    "Terminating EC2 instances destroys them permanently. This will NOT be executed.",
)

register_tier1(
    r"aws\s+rds\s+delete-db-cluster",
    "cloud",
    "Deleting an RDS cluster destroys the database and all data. This will NOT be executed.",
)

register_tier1(
    r"aws\s+rds\s+delete-db-instance",
    "cloud",
    "Deleting an RDS instance destroys the database. This will NOT be executed.",
)

# Tier 2: Destructive but recoverable AWS operations
register_tier2(
    r"aws\s+s3\s+rm\s+.*--recursive",
    "cloud",
    "aws s3 rm --recursive deletes all objects in the path.",
    "Run 'aws s3 ls <path>' first to review, or add --dryrun to preview deletions.",
)

register_tier2(
    r"aws\s+s3\s+rb\s+.*--force",
    "cloud",
    "aws s3 rb --force empties and deletes the entire bucket.",
    "Run 'aws s3 ls <bucket>' first to review contents.",
)

# Allowlist: safe AWS operations
register_allowlist(r"aws\s+s3\s+rm\s+.*--dryrun")

# =============================================================================
# GCP CLI
# =============================================================================

# Tier 1: Catastrophic GCP operations
register_tier1(
    r"gcloud\s+projects\s+delete",
    "cloud",
    "Deleting a GCP project destroys all resources in it. This will NOT be executed.",
)

# Tier 2: Destructive GCP operations
register_tier2(
    r"gcloud\s+compute\s+instances\s+delete",
    "cloud",
    "Deleting compute instances destroys them.",
    "Run 'gcloud compute instances list' first to review.",
)

register_tier2(
    r"gcloud\s+sql\s+instances\s+delete",
    "cloud",
    "Deleting a Cloud SQL instance destroys the database.",
    "Run 'gcloud sql instances list' first to review.",
)

register_tier2(
    r"gsutil\s+rm\s+-r",
    "cloud",
    "gsutil rm -r recursively deletes all objects.",
    "Run 'gsutil ls <path>' first to review contents.",
)

# =============================================================================
# Azure CLI
# =============================================================================

# Tier 2: Destructive Azure operations
register_tier2(
    r"az\s+group\s+delete",
    "cloud",
    "Deleting a resource group destroys all resources in it.",
    "Run 'az group show --name <name>' first to review, or add --dry-run.",
)

register_tier2(
    r"az\s+vm\s+delete",
    "cloud",
    "Deleting a VM destroys it.",
    "Run 'az vm show' first to review.",
)

register_tier2(
    r"az\s+storage\s+account\s+delete",
    "cloud",
    "Deleting a storage account destroys all data in it.",
    "Run 'az storage account show' first to review.",
)

register_tier2(
    r"az\s+sql\s+server\s+delete",
    "cloud",
    "Deleting a SQL server destroys all databases on it.",
    "Run 'az sql server show' first to review.",
)

# Allowlist: safe Azure operations
register_allowlist(r"az\s+group\s+delete\s+.*--dry-run")
