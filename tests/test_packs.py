#!/usr/bin/env python3
# ABOUTME: Tests for new security packs: cloud, infra, cicd, dns.
# ABOUTME: Verifies blocking and allowlisting for each domain.
"""
Tests new security packs by invoking command-guard.py as a subprocess,
same as the existing test_command_guard.py tests.
"""
import json
import os
import subprocess
import unittest

GUARD_SCRIPT = os.path.join(
    os.path.dirname(__file__), "..", "hooks", "scripts", "command-guard.py"
)


def run_guard(command: str) -> dict | None:
    """Run command-guard.py with a Bash tool input and return parsed output."""
    input_data = json.dumps({
        "tool_name": "Bash",
        "tool_input": {"command": command},
    })
    result = subprocess.run(
        ["python3", GUARD_SCRIPT],
        input=input_data,
        capture_output=True,
        text=True,
    )
    if result.stdout.strip():
        return json.loads(result.stdout)
    return None


def assert_denied(tc, command, msg=""):
    output = run_guard(command)
    tc.assertIsNotNone(output, f"Expected deny for: {command}. {msg}")
    decision = output["hookSpecificOutput"]["permissionDecision"]
    tc.assertEqual(decision, "deny", f"Expected deny for: {command}. {msg}")


def assert_allowed(tc, command, msg=""):
    output = run_guard(command)
    tc.assertIsNone(output, f"Expected allow for: {command}. Got: {output}. {msg}")


# =============================================================================
# Cloud pack tests
# =============================================================================

class TestCloudAWS(unittest.TestCase):
    """AWS CLI destructive operations."""

    def test_s3_rm_recursive(self):
        assert_denied(self, "aws s3 rm s3://my-bucket --recursive")

    def test_s3_rb_force(self):
        assert_denied(self, "aws s3 rb s3://my-bucket --force")

    def test_ec2_terminate(self):
        assert_denied(self, "aws ec2 terminate-instances --instance-ids i-1234")

    def test_rds_delete_cluster(self):
        assert_denied(self, "aws rds delete-db-cluster --db-cluster-identifier prod")

    def test_rds_delete_instance(self):
        assert_denied(self, "aws rds delete-db-instance --db-instance-identifier prod")

    def test_s3_cp_allowed(self):
        assert_allowed(self, "aws s3 cp file.txt s3://my-bucket/")

    def test_s3_ls_allowed(self):
        assert_allowed(self, "aws s3 ls s3://my-bucket")

    def test_s3_rm_single_object_allowed(self):
        assert_allowed(self, "aws s3 rm s3://my-bucket/file.txt")

    def test_s3_rm_dryrun_allowed(self):
        assert_allowed(self, "aws s3 rm s3://my-bucket --recursive --dryrun")


class TestCloudGCP(unittest.TestCase):
    """GCP CLI destructive operations."""

    def test_compute_delete(self):
        assert_denied(self, "gcloud compute instances delete my-vm")

    def test_sql_delete(self):
        assert_denied(self, "gcloud sql instances delete my-db")

    def test_storage_rm_recursive(self):
        assert_denied(self, "gsutil rm -r gs://my-bucket")

    def test_project_delete(self):
        assert_denied(self, "gcloud projects delete my-project")

    def test_compute_list_allowed(self):
        assert_allowed(self, "gcloud compute instances list")

    def test_gsutil_ls_allowed(self):
        assert_allowed(self, "gsutil ls gs://my-bucket")


class TestCloudAzure(unittest.TestCase):
    """Azure CLI destructive operations."""

    def test_group_delete(self):
        assert_denied(self, "az group delete --name my-rg")

    def test_vm_delete(self):
        assert_denied(self, "az vm delete --name my-vm --resource-group rg")

    def test_storage_delete(self):
        assert_denied(self, "az storage account delete --name mystorage")

    def test_sql_delete(self):
        assert_denied(self, "az sql server delete --name myserver")

    def test_group_list_allowed(self):
        assert_allowed(self, "az group list")

    def test_vm_list_allowed(self):
        assert_allowed(self, "az vm list")

    def test_group_delete_dry_run_allowed(self):
        assert_allowed(self, "az group delete --name my-rg --dry-run")


# =============================================================================
# Infrastructure pack tests
# =============================================================================

class TestInfra(unittest.TestCase):
    """Infrastructure-as-code destructive operations."""

    def test_terraform_destroy(self):
        assert_denied(self, "terraform destroy")

    def test_terraform_destroy_auto_approve(self):
        assert_denied(self, "terraform destroy -auto-approve")

    def test_terraform_apply_destroy(self):
        assert_denied(self, "terraform apply -destroy")

    def test_pulumi_destroy(self):
        assert_denied(self, "pulumi destroy")

    def test_cdk_destroy(self):
        assert_denied(self, "cdk destroy")

    def test_terraform_plan_allowed(self):
        assert_allowed(self, "terraform plan")

    def test_terraform_apply_allowed(self):
        assert_allowed(self, "terraform apply")

    def test_pulumi_preview_allowed(self):
        assert_allowed(self, "pulumi preview")

    def test_pulumi_up_allowed(self):
        assert_allowed(self, "pulumi up")

    def test_cdk_synth_allowed(self):
        assert_allowed(self, "cdk synth")

    def test_cdk_diff_allowed(self):
        assert_allowed(self, "cdk diff")


# =============================================================================
# CI/CD pack tests
# =============================================================================

class TestCICD(unittest.TestCase):
    """GitHub CLI and CI/CD destructive operations."""

    def test_gh_repo_delete(self):
        assert_denied(self, "gh repo delete my-org/my-repo")

    def test_gh_release_delete(self):
        assert_denied(self, "gh release delete v1.0.0")

    def test_gh_secret_delete(self):
        assert_denied(self, "gh secret delete MY_SECRET")

    def test_gh_repo_create_allowed(self):
        assert_allowed(self, "gh repo create my-repo")

    def test_gh_pr_create_allowed(self):
        assert_allowed(self, "gh pr create --title 'fix'")

    def test_gh_release_create_allowed(self):
        assert_allowed(self, "gh release create v1.0.0")

    def test_gh_secret_set_allowed(self):
        assert_allowed(self, "gh secret set MY_SECRET")

    def test_gh_repo_list_allowed(self):
        assert_allowed(self, "gh repo list")


# =============================================================================
# DNS pack tests
# =============================================================================

class TestDNS(unittest.TestCase):
    """DNS destructive operations."""

    def test_route53_delete_hosted_zone(self):
        assert_denied(self, "aws route53 delete-hosted-zone --id Z1234")

    def test_route53_change_delete(self):
        assert_denied(self, "aws route53 change-resource-record-sets --hosted-zone-id Z1234 --change-batch '{\"Changes\":[{\"Action\":\"DELETE\"'")

    def test_gcloud_dns_delete_zone(self):
        assert_denied(self, "gcloud dns managed-zones delete my-zone")

    def test_az_dns_delete_zone(self):
        assert_denied(self, "az network dns zone delete --name example.com")

    def test_route53_list_allowed(self):
        assert_allowed(self, "aws route53 list-hosted-zones")

    def test_gcloud_dns_list_allowed(self):
        assert_allowed(self, "gcloud dns managed-zones list")

    def test_az_dns_list_allowed(self):
        assert_allowed(self, "az network dns zone list")


if __name__ == "__main__":
    unittest.main()
