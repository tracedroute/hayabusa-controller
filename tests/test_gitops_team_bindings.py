"""Team-scoped GitOps bindings + owned-path publish gates."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from app.config import get_settings
from app.gitops_store import GitOpsStore
from app.rbac_store import RbacStore
from app.secrets_vault import SecretsVault


class GitOpsTeamBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        os.environ["CONTROLLER_SECRET_KEY"] = "unit-test-controller-secret-key-32b!!"
        os.environ["CONTROLLER_DATA_DIR"] = str(root)
        os.environ["CONTROLLER_ALLOW_INSECURE_DEFAULTS"] = "1"
        get_settings.cache_clear()
        settings = get_settings()
        self.vault = SecretsVault(settings)
        self.vault.put("gitops_netops_pat", "ghp_test_token_not_real")
        self.rbac = RbacStore(root)
        self.gitops = GitOpsStore(root)
        # Bootstrap admin + team
        self.rbac.ensure_bootstrap_admin(
            username="admin",
            email="admin@example.com",
            sub="admin-sub",
            provider="manual",
        )
        # Find admin key
        cat = self.rbac.public_catalog()
        self.admin_key = str((cat.get("users") or [{}])[0].get("user_key") or "")
        self.assertTrue(self.admin_key)
        team = self.rbac.create_team(name="netops", member_keys=[self.admin_key])
        self.assertTrue(team.get("ok"), team)
        self.team_id = team["team"]["id"]
        # Outsider user (no team)
        self.rbac.upsert_user(
            username="outsider",
            email="out@example.com",
            sub="out-sub",
            provider="manual",
            roles=["operator"],
            team_ids=[],
        )
        cat2 = self.rbac.public_catalog()
        self.outsider_key = next(
            u["user_key"] for u in cat2["users"] if u.get("username") == "outsider" or "out@" in (u.get("email") or "")
        )

    def tearDown(self) -> None:
        get_settings.cache_clear()
        self.tmp.cleanup()

    def test_binding_requires_known_team(self) -> None:
        bad = self.gitops.upsert_team_binding(
            {
                "team_id": "nope",
                "provider": "github",
                "base_url": "https://github.com",
                "repo": "acme/iac",
                "auth_secret_key": "gitops_netops_pat",
            },
            known_team_ids={self.team_id},
        )
        self.assertFalse(bad.get("ok"))
        ok = self.gitops.upsert_team_binding(
            {
                "team_id": self.team_id,
                "provider": "github",
                "base_url": "https://github.com",
                "repo": "acme/netops-iac",
                "auth_secret_key": "gitops_netops_pat",
            },
            known_team_ids={self.team_id},
        )
        self.assertTrue(ok.get("ok"), ok)
        self.assertEqual(ok["binding"]["team_id"], self.team_id)

    def test_publish_authz_requires_team_and_linked_provider(self) -> None:
        bind = self.gitops.upsert_team_binding(
            {
                "team_id": self.team_id,
                "provider": "github",
                "base_url": "https://github.com",
                "repo": "acme/netops-iac",
                "auth_secret_key": "gitops_netops_pat",
                "require_linked_provider": True,
            },
            known_team_ids={self.team_id},
        )
        bid = bind["binding"]["id"]
        # Member without GitHub link
        _b, err = self.gitops.authorize_publish(
            user_key=self.admin_key, binding_id=bid, user_team_ids=[self.team_id]
        )
        self.assertEqual(err.get("code"), "provider_not_linked")
        # Link github
        linked = self.gitops.link_account(
            self.admin_key, provider="github", login="admin-gh", oauth_id="99"
        )
        self.assertTrue(linked.get("ok"))
        binding, err2 = self.gitops.authorize_publish(
            user_key=self.admin_key, binding_id=bid, user_team_ids=[self.team_id]
        )
        self.assertTrue(err2.get("ok"))
        self.assertEqual(binding["repo"], "acme/netops-iac")
        # Outsider not on team
        _b3, err3 = self.gitops.authorize_publish(
            user_key=self.outsider_key, binding_id=bid, user_team_ids=[]
        )
        self.assertEqual(err3.get("code"), "not_team_member")

    def test_strict_owned_export_filters_by_team(self) -> None:
        self.rbac.set_playbook_owner(
            "Ansible/playbooks/netops/ping.yml",
            owner_type="team",
            owner_id=self.team_id,
        )
        self.rbac.set_playbook_owner(
            "Ansible/playbooks/other/secret.yml",
            owner_type="user",
            owner_id=self.outsider_key,
        )
        files = {
            "Ansible/playbooks/netops/ping.yml": "- hosts: all\n",
            "Ansible/playbooks/other/secret.yml": "- hosts: none\n",
        }

        def read_file(rel: str) -> str | None:
            return files.get(rel)

        def list_tree(rel: str) -> list:
            return []

        out = self.rbac.export_strictly_owned_files(
            self.admin_key,
            read_file=read_file,
            list_tree=list_tree,
            team_id=self.team_id,
        )
        self.assertTrue(out.get("ok"), out)
        paths = [f["path"] for f in out.get("files") or []]
        self.assertIn("Ansible/playbooks/netops/ping.yml", paths)
        self.assertNotIn("Ansible/playbooks/other/secret.yml", paths)


if __name__ == "__main__":
    unittest.main()
