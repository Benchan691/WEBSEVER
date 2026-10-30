import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/audit_local_rbac.py"
SPEC = importlib.util.spec_from_file_location("rbac_audit", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class OfflineAuditTests(unittest.TestCase):
    def test_legacy_foreign_orphan_records_reported_without_credentials(self):
        a, b, foreign = ({"$oid": value * 24} for value in "abc")
        accounts = [{"_id": a, "username": "legacy", "username_key": "legacy", "auth_source": "account_hub", "password": "MUST-NOT-APPEAR", "zimbra_password": "SECRET"}, {"_id": b, "username_key": "local", "auth_source": "local", "rbac_schema": 1, "organization_id": a}]
        subscriptions = [{"_id": a, "owner_user_id": a}, {"_id": b, "owner_user_id": b, "organization_id": foreign}, {"_id": foreign, "owner_user_id": foreign}]
        encoded = json.dumps(MODULE.audit(accounts, subscriptions))
        for secret in ("MUST-NOT-APPEAR", "SECRET"):
            self.assertNotIn(secret, encoded)
        for issue in ("owner_requires_local_provisioning", "owner_organization_mismatch", "owner_not_found_in_accounts"):
            self.assertIn(issue, encoded)

    def test_cli_is_deterministic_and_preserves_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            accounts, subscriptions = (Path(directory) / name for name in ("accounts.json", "subscriptions.json"))
            accounts.write_text('[{"_id":{"$oid":"aaaaaaaaaaaaaaaaaaaaaaaa"},"username":"legacy","auth_source":"zimbra","password":"secret"}]')
            subscriptions.write_text('{"_id":{"$oid":"bbbbbbbbbbbbbbbbbbbbbbbb"},"owner_user_id":{"$oid":"aaaaaaaaaaaaaaaaaaaaaaaa"}}\n')
            original = accounts.read_bytes(), subscriptions.read_bytes()
            command = ["python3", str(SCRIPT), "--accounts", str(accounts), "--subscriptions", str(subscriptions)]
            first = subprocess.check_output(command)
            self.assertEqual(first, subprocess.check_output(command))
            self.assertEqual(original, (accounts.read_bytes(), subscriptions.read_bytes()))
            self.assertNotIn(b'"password"', first)
            self.assertEqual(json.loads(first)["counts"]["subscriptions"], 1)

    def test_string_legacy_org_ids_are_not_tenant_membership(self):
        self.assertFalse(MODULE.object_id("a" * 24))
        self.assertTrue(MODULE.object_id({"$oid": "a" * 24}))
        self.assertFalse(MODULE.object_id({"$oid": "invalid"}))
