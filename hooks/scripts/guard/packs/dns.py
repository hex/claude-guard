# ABOUTME: DNS management patterns for Route53, Cloud DNS, and Azure DNS.
# ABOUTME: Blocks zone deletion and record deletion operations.
from guard.packs import register_tier1, register_tier2

# =============================================================================
# AWS Route53
# =============================================================================

register_tier1(
    r"aws\s+route53\s+delete-hosted-zone",
    "dns",
    "Deleting a Route53 hosted zone removes all DNS records. This will NOT be executed.",
)

register_tier2(
    r'aws\s+route53\s+change-resource-record-sets\s+.*"DELETE"',
    "dns",
    "Deleting Route53 DNS records can break service resolution.",
    "Run 'aws route53 list-resource-record-sets' first to review records.",
)

# =============================================================================
# GCP Cloud DNS
# =============================================================================

register_tier2(
    r"gcloud\s+dns\s+managed-zones\s+delete",
    "dns",
    "Deleting a Cloud DNS zone removes all DNS records.",
    "Run 'gcloud dns managed-zones list' first to review.",
)

# =============================================================================
# Azure DNS
# =============================================================================

register_tier2(
    r"az\s+network\s+dns\s+zone\s+delete",
    "dns",
    "Deleting an Azure DNS zone removes all DNS records.",
    "Run 'az network dns zone list' first to review.",
)
