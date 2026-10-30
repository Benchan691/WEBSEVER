# Existing account audit, migration and recovery

## What was audited

The source audit found `accounts` records identified by `auth_source` (`local`, `zimbra`, and historical `account_hub` records), local bcrypt `password` fields, external mailbox credential/folder fields, and organization names/IDs that previously came from external systems. Old AccountHub roles and organization flags are not trusted by this implementation.

`sub_account` references `owner_user_id` and `managed_by_user_id`, alongside recipient lists, organization display metadata, newsletter/report profiles, delivery cursors and scheduling state. Historical subscriptions can lack tenant IDs or refer to accounts outside `accounts`. Report jobs previously relied on manager IDs, and old jobs may also lack tenant IDs. Delivery/statistics history is keyed by subscription IDs, so those IDs must remain stable.

The implementation reviewed these schemas and code paths. No live database was opened, counted, exported, modified or migrated. Actual record counts and identity matches must be established from your backup using the offline audit below.

## Startup behavior

Normal startup creates new RBAC indexes and the single reserved bootstrap account. For the configured existing **local bootstrap administrator only**, startup explicitly sets `role=superadmin`, `reserved_bootstrap=true`, `rbac_schema=1`, restores its enabled status and removes tenant/role associations. Its password hash is preserved. Identity conflicts stop startup rather than taking over another record. This requested bootstrap transition is not applied to other accounts.

Startup does not convert external users, import legacy collections, backfill subscriptions, deduplicate data, or delete old credentials. Old sessions are rejected by the new signed local-session format. Existing external/legacy accounts are inert until individually recovered. Scheduling skips subscriptions unless their owner is an active local RBAC user with a matching typed organization ID and the necessary delivery permissions.

## 1. Back up and restore-test

Before operating a candidate deployment:

1. Capture the source revision, current image/binary, runtime assets, Compose/systemd configuration, complete `.env`, application JSON config and newsletter files. Keep any original provider encryption keys in the private rollback backup.
2. Back up the whole application database, including accounts, legacy auth/subscription collections, `sub_account`, reports and inputs/results, delivery/statistics history and template settings. Keep index metadata.
3. Restore into a **separate** candidate database. Do not use `--drop` against the live database. Test that the old release can still use the original snapshot.
4. Keep schedulers disabled in the candidate. Establish a change-freeze/final-backup window before cutover so subscription changes made after the snapshot are reconciled.

See the host deployment guide for example backup and shadow-database commands. None of them has been executed by this implementation task.

## 2. Audit offline JSON exports

Export from the restored snapshot with `mongoexport` in ordinary JSON-lines format or with `--jsonArray`. Supply `accounts.json`, `sub_account.json`, and optionally `report_jobs.json` and legacy collection exports:

```sh
python3 scripts/audit_local_rbac.py \
  --accounts /private/restored-exports/accounts.json \
  --subscriptions /private/restored-exports/sub_account.json \
  --report-jobs /private/restored-exports/report_jobs.json \
  --legacy /private/restored-exports/auth.json \
  --legacy /private/restored-exports/subscriptions.json \
  > /private/restored-exports/local-rbac-audit.json
```

Omit optional files that do not exist. The tool reads files only, never contacts MongoDB, never changes inputs and never outputs passwords/tokens. It reports source counts, unverified organization hints, duplicate login keys, missing owners/managers, scope mismatches and unscoped reports. Legacy-only collections are counted for reconciliation; their different schemas require manual field review.

For each user, obtain verified identity/organization membership from an administrator. Create a reviewed mapping with the existing account ID, unique normalized username, new application organization ObjectId, custom role ID (or explicit organization-admin appointment), and the exact subscription/report IDs that belong to that organization. Do not infer access from a matching organization name, email domain, external organization ID, or old role flag. Resolve duplicate keys and orphan references explicitly; never delete records to make an index build succeed.

## 3. Provision organizations and roles

Start the candidate against the restored database with scheduling disabled. Sign in as the configured bootstrap account and use `/management` to create organizations and custom roles. Provision new accounts normally. The **Appoint org administrator** action is restricted to superadmin and never changes the reserved bootstrap identity.

For pre-existing external accounts, keep their `_id` when recovering them so subscription relationships remain intact. Accounts that exist only in a legacy collection need an explicitly reviewed import and owner-ID mapping; the application does not read that collection as an authentication source.

## 4. Recover one existing account explicitly

This is a manual recovery recipe for a **restored candidate database**, not an automatic/live migration. Review every ID and field before executing it.

Generate a fresh random local temporary password privately. Use the application password-hash helper; it runs before configuration/database initialization and reads the password from standard input:

```sh
python3 -c 'import getpass; print(getpass.getpass("New temporary LOCAL password (12+ characters): "))' \
  | ./target/release/webserver-rust --local-password-hash
```

Deliver the temporary password securely. Never use the old external password or decrypt/copy `zimbra_password` into the local `password` field.

In `mongosh` connected explicitly to the restored candidate DB, substitute the **approved** identifiers and generated bcrypt hash. The schema marker makes this update idempotent: repeating it will not replace the password of an account already recovered to schema 1.

```javascript
const accountId = ObjectId('APPROVED_EXISTING_ACCOUNT_ID');
const organizationId = ObjectId('NEW_APPLICATION_ORGANIZATION_ID');
const customRoleId = ObjectId('APPROVED_CUSTOM_ROLE_ID');
const migrationId = 'local-rbac-reviewed-20261030';

// Inspect the target and organization/role before changing it.
db.accounts.findOne({_id: accountId}, {_id: 1, username: 1, auth_source: 1, organization_id: 1, role_id: 1, reserved_bootstrap: 1, rbac_schema: 1});
db.organizations.findOne({_id: organizationId, disabled: false});
db.roles.findOne({_id: customRoleId, organization_id: organizationId, type: 'custom'});

// Apply only after review. Never run this for the reserved bootstrap account.
db.accounts.updateOne(
  {_id: accountId, reserved_bootstrap: {$ne: true}, rbac_schema: {$ne: 1}},
  {$set: {
    auth_source: 'local', rbac_schema: NumberInt(1), role: 'user',
    organization_id: organizationId, role_id: customRoleId,
    username_key: 'APPROVED_NORMALIZED_USERNAME',
    password: 'GENERATED_BCRYPT_HASH',
    session_version: UUID().toString(),
    must_change_password: true,
    temporary_password_expires_at: new Date(Date.now() + 24*3600*1000),
    disabled: false, local_rbac_migration_id: migrationId,
    updated_at: new Date()
  }}
);
```

Check `matchedCount`. Zero means the account was already migrated or the precondition did not match: inspect it; do not remove the guard to force the update. Reissue an expired temporary password later through the local reset API. To appoint an organization administrator, first recover/provision a normal local account in that organization, then use the explicit superadmin appointment action.

Historical provider fields remain inert in the preserved record. Their eventual removal is a separate, reviewed cleanup after backup retention and rollback requirements have been satisfied.

## 5. Bind existing subscriptions and reports

For every approved subscription, verify its existing owner ID and recipients/profiles/cursors. Apply a conditional update to its existing record; do not recreate it or reset scheduling/delivery history:

```javascript
// Substitute reviewed existing IDs. A record already marked migrated is skipped.
db.sub_account.updateOne(
  {_id: ObjectId('APPROVED_SUBSCRIPTION_ID'), owner_user_id: accountId,
   local_rbac_migration_id: {$ne: migrationId}},
  {$set: {organization_id: organizationId,
          organization: 'APPROVED_ORGANIZATION_DISPLAY_NAME',
          local_rbac_migration_id: migrationId, updated_at: new Date()}}
);
```

If an owner reference points into a legacy collection, map it to the recovered/provisioned local account ID explicitly and record its original value in the private migration ledger. Review manager references separately. No bulk match by email or username is authorized by this recipe.

Bind historical report jobs to exactly one approved organization using the same conditional marker. Translations must have the same organization ID as their source. Keep job IDs and input/result relationships intact. Legacy jobs with unresolved ownership stay visible only to superadmin; do not make them globally readable.

Do not enable profiles or the scheduler until the audit shows no unexpected ownership/scope mismatches, users have changed temporary passwords, tenant permission checks are verified, and the intended owner's role includes `subscriptions.send` (plus `reports.create` for scheduled reports).

## 6. Verify and roll back

Test two organizations with different accounts: list/detail/export/update/delete/reset/assign routes, report previews/downloads/translations, subscription inventories/statistics, and operation health must never reveal foreign tenant records. Confirm self-promotion, role-ceiling violations, reserved-role creation, bootstrap disable/delete/role-change and legacy sign-in all fail. Restart and verify the superadmin password has not reverted.

For rollback, stop the candidate and its scheduler, restore the previous image/binary, assets and private configuration, and reconnect the previous release to the untouched original database or a separately restored pre-change snapshot. Preserve the candidate database and its new activity for reconciliation. Do not restore over a live database or delete the new collections as an automatic rollback step. Since prior code reset bootstrap passwords at startup, retain the previous bootstrap environment value as part of the original configuration backup.

## Break-glass password recovery (offline operator procedure)

Normal account-management APIs cannot reset superadmin. If its password is lost, first rehearse recovery on a restored backup. For an actual recovery, schedule maintenance, stop every application instance/scheduler and take a fresh private backup. Generate a new independent local password/hash with `--local-password-hash` as above. Confirm that exactly one known local bootstrap record exists and verify its immutable ID and configured username.

Apply this narrowly scoped update only after substituting the reviewed ID/username/hash in `mongosh` connected to the intended maintenance database:

```javascript
db.accounts.updateOne(
  {_id: ObjectId('VERIFIED_BOOTSTRAP_ID'), username_key: 'CONFIGURED_BOOTSTRAP_USERNAME',
   auth_source: 'local', reserved_bootstrap: true, role: 'superadmin'},
  {$set: {password: 'GENERATED_NEW_LOCAL_BCRYPT_HASH',
          session_version: UUID().toString(), must_change_password: false,
          disabled: false, rbac_schema: NumberInt(1), updated_at: new Date()},
   $unset: {temporary_password_expires_at: ''}}
);
```

Require `matchedCount: 1`; otherwise stop and investigate the backup/identity rather than relaxing the filter. Preserve the account ID, reserved flag and role. Restart with the unchanged bootstrap username and verify the new local password survives a second restart. Do not attempt recovery by deleting the bootstrap account or changing only its environment password. This is an explicit offline recovery action, never a startup migration or user-management operation.
