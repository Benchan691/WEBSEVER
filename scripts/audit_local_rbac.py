#!/usr/bin/env python3
"""Read offline mongoexport JSON; audit identities and ownership without DB access.

This command never edits inputs, converts accounts, copies password material,
contacts MongoDB, or applies a migration. Use exports from a restored backup.
"""
import argparse
from collections import Counter
import json
from pathlib import Path


def records(path):
    if path is None:
        return []
    text = Path(path).read_text(encoding="utf-8").strip()
    values = json.loads(text) if text.startswith("[") else [json.loads(line) for line in text.splitlines() if line.strip()]
    if not isinstance(values, list) or any(not isinstance(item, dict) for item in values):
        raise ValueError("Expected mongoexport JSON objects or a JSON array")
    return values


def identifier(value):
    if isinstance(value, dict) and set(value) == {"$oid"}:
        return value["$oid"]
    return value if isinstance(value, str) else None


def object_id(value):
    result = identifier(value)
    return isinstance(value, dict) and isinstance(result, str) and len(result) == 24 and all(char in "0123456789abcdefABCDEF" for char in result)


def audit(accounts, subscriptions, reports=(), legacy=()):
    by_id = {identifier(row.get("_id")): row for row in accounts if identifier(row.get("_id"))}
    identity_rows = []
    for row in accounts:
        ready = row.get("auth_source") == "local" and row.get("rbac_schema") == 1
        hints = {key: row[key] for key in ("organization", "organization_id", "team", "account_hub_organization", "account_hub_organization_id", "zimbra_organization", "zimbra_organization_id") if row.get(key)}
        identity_rows.append({"id": identifier(row.get("_id")), "username": row.get("username", ""), "auth_source": row.get("auth_source", "unknown"), "rbac_ready": ready, "reserved_bootstrap": bool(row.get("reserved_bootstrap")), "organization_hints_unverified": hints})
    subscription_rows = []
    for row in subscriptions:
        owner_id = identifier(row.get("owner_user_id"))
        manager_id = identifier(row.get("managed_by_user_id"))
        owner = by_id.get(owner_id)
        issues = []
        if not object_id(row.get("organization_id")):
            issues.append("missing_or_legacy_organization_id")
        if owner is None:
            issues.append("owner_not_found_in_accounts")
        elif owner.get("auth_source") != "local" or owner.get("rbac_schema") != 1:
            issues.append("owner_requires_local_provisioning")
        elif identifier(owner.get("organization_id")) != identifier(row.get("organization_id")):
            issues.append("owner_organization_mismatch")
        if manager_id and manager_id not in by_id:
            issues.append("manager_not_found_in_accounts")
        subscription_rows.append({"id": identifier(row.get("_id")), "owner_user_id": owner_id, "managed_by_user_id": manager_id, "organization_id": identifier(row.get("organization_id")), "issues": issues, "auto_provisioned": bool(row.get("auto_provisioned"))})
    usernames = Counter(str(row.get("username_key", "")) for row in accounts)
    emails = Counter(str(row.get("email_key")) for row in accounts if row.get("email_key") is not None)
    return {
        "schema_version": 1,
        "mode": "offline_read_only_no_migration",
        "counts": {"accounts": len(accounts), "subscriptions": len(subscriptions), "report_jobs": len(reports), "legacy_collection_records": len(legacy)},
        "auth_sources": dict(sorted(Counter(str(row.get("auth_source", "unknown")) for row in accounts).items())),
        "duplicate_username_keys": sorted(key for key, count in usernames.items() if count > 1),
        "duplicate_email_keys": sorted(key for key, count in emails.items() if count > 1),
        "accounts_missing_username_key": sum(not row.get("username_key") for row in accounts),
        "identities": sorted(identity_rows, key=lambda row: str(row["id"])),
        "subscription_relationships": sorted(subscription_rows, key=lambda row: str(row["id"])),
        "reports_without_typed_organization_id": sorted(str(identifier(row.get("_id"))) for row in reports if not object_id(row.get("organization_id"))),
        "recovery": "Approve explicit account-to-organization and role mappings on a restored database. Preserve IDs, recipients, profiles, cursors, history and the private backup. Issue independent random local passwords. See docs/LOCAL_RBAC_MIGRATION.md.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--accounts", type=Path, required=True)
    parser.add_argument("--subscriptions", type=Path, required=True)
    parser.add_argument("--report-jobs", type=Path)
    parser.add_argument("--legacy", type=Path, action="append", default=[])
    args = parser.parse_args()
    result = audit(records(args.accounts), records(args.subscriptions), records(args.report_jobs), [row for path in args.legacy for row in records(path)])
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
