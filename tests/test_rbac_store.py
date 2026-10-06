"""RBAC + tools-not-on-controller checks."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from app.rbac_store import RbacStore


class RbacStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.rbac = RbacStore(Path(self.tmp.name))

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_five_passes_roles_teams_owners(self) -> None:
        for i in range(1, 6):
            with self.subTest(pass_no=i):
                # Fresh store each pass
                store = RbacStore(Path(self.tmp.name) / f"pass{i}")
                admin = store.ensure_bootstrap_admin(username="admin", sub="manual:admin")
                self.assertTrue(admin)
                self.assertIn("manage_rbac", store.user_permissions(admin))
                team = store.create_team(name=f"team-{i}", member_keys=[admin])
                self.assertTrue(team.get("ok"))
                path = f"Ansible/playbooks/p{i}.yml"
                own = store.set_playbook_owner(path, owner_type="team", owner_id=team["team"]["id"])
                self.assertTrue(own.get("ok"))
                self.assertTrue(store.can_access_playbook(admin, path, write=True))
                op = store.upsert_user(username=f"op{i}", roles=["operator"])
                self.assertTrue(op.get("ok"))
                self.assertFalse(store.can_access_playbook(op["user"]["user_key"], path, write=False))


if __name__ == "__main__":
    unittest.main()
