# Local RBAC implementation and scope reference

## Branch and working directory

The implementation is in `worktrees/local-rbac` on `feature/local-rbac-organization-management`, starting from base `6aae75b861a0003af176564f1e903c1680cf877a` (`redesign/unified-news-collection`). The original checkout's Git metadata was read-only, so a separate local checkout was created inside the workspace. Its `origin` points to the original local repository; it has not been pushed.

The original `main` and `origin/main` remain at `847d0c21eb9d893f7ccf7e61681cd387ddb45fc2`. Original tracked files and the untracked `output/` directory were not changed. The original checkout now also contains the new untracked `worktrees/` directory.

## Permission catalog

Checkbox values come exclusively from this catalog. Requests with arbitrary, duplicate or non-string permissions are rejected. Global-only entries cannot be granted to custom roles, even by superadmin; they are inherent to the reserved account. All organization administrators hold the 24 tenant permissions, restricted to their own organization.

| Permission | Group | Action | Scope |
| --- | --- | --- | --- |
| `users.view` | Users | View organization accounts | Own organization / shared advisory reference data |
| `users.create` | Users | Provision local accounts | Own organization / shared advisory reference data |
| `users.edit` | Users | Edit or disable accounts | Own organization / shared advisory reference data |
| `users.delete` | Users | Retire accounts (preserve records) | Own organization / shared advisory reference data |
| `users.reset_password` | Users | Issue temporary passwords | Own organization / shared advisory reference data |
| `users.assign_roles` | Users | Assign custom roles | Own organization / shared advisory reference data |
| `roles.view` | Roles | View roles and permission catalog | Own organization / shared advisory reference data |
| `roles.create` | Roles | Create custom roles | Own organization / shared advisory reference data |
| `roles.edit` | Roles | Edit custom roles | Own organization / shared advisory reference data |
| `roles.delete` | Roles | Retire custom roles | Own organization / shared advisory reference data |
| `organizations.view` | Organizations | View own organization | Own organization / shared advisory reference data |
| `organizations.manage` | Organizations | Manage organizations and appoint administrators | Reserved superadmin only |
| `subscriptions.view` | Subscriptions | View organization subscriptions and inventories | Own organization / shared advisory reference data |
| `subscriptions.create` | Subscriptions | Create subscriptions | Own organization / shared advisory reference data |
| `subscriptions.edit` | Subscriptions | Edit subscriptions and schedules | Own organization / shared advisory reference data |
| `subscriptions.delete` | Subscriptions | Delete subscriptions | Own organization / shared advisory reference data |
| `subscriptions.send` | Subscriptions | Send statistics and enable scheduled delivery | Own organization / shared advisory reference data |
| `reviews.view` | Reviews and newsletters | Browse and search shared advisory sources | Own organization / shared advisory reference data |
| `reviews.export` | Reviews and newsletters | Export advisory records | Own organization / shared advisory reference data |
| `newsletters.view` | Reviews and newsletters | Preview shared advisory newsletters | Own organization / shared advisory reference data |
| `reports.view` | Reports | View organization jobs, logs and previews | Own organization / shared advisory reference data |
| `reports.create` | Reports | Generate and translate reports | Own organization / shared advisory reference data |
| `reports.manage` | Reports | Cancel and delete organization reports | Own organization / shared advisory reference data |
| `reports.export` | Reports | Download organization reports | Own organization / shared advisory reference data |
| `operations.view` | Operations | View organization delivery health | Own organization / shared advisory reference data |
| `operations.configure` | Operations | Edit global newsletter templates and source settings | Reserved superadmin only |
| `operations.purge_cache` | Operations | Purge shared report caches | Reserved superadmin only |

## Scope and delegation rules

- Only the existing configured local bootstrap identity becomes the reserved `superadmin`; routine user/role APIs cannot create, grant, disable, demote, reset or delete it. It has no tenant/custom role association. New deployments create exactly this reserved identity. A unique partial index prevents multiple reserved bootstrap records.
- Only superadmin creates/renames/disables organizations or appoints organization administrators. A disabled organization loses login/session access and background delivery.
- Tenant authorization uses BSON `ObjectId` organization IDs. Display names, emails, external organization IDs and legacy strings do not prove membership. Tenant users/roles/subscriptions/report jobs must match the actor's exact ID. Superadmin explicitly selects the target organization when creating scoped resources.
- Custom roles have one immutable organization and creator (`delegated_by_user_id`). A creator can only delegate currently held catalog permissions. Ordinary role assignment only accepts custom roles, only for other accounts in the permitted organization, and rejects a target or requested role above the actor's current authority.
- Each local account has at most one assigned role. An account with no valid role can change its own profile/password in Settings but has no application permissions.
- Self role/account changes through management APIs, editing one's own role or a delegation ancestor, creating reserved role names/types and cross-organization mutations are rejected. Profile self service only accepts email; password changes require the current password.
- Effective custom permissions are intersected with the creator chain on every request. Missing/foreign/disabled roles or creators, invalid catalog values, cycles and chains exceeding 32 steps grant no permissions. Role retirement or creator revocation therefore affects delegated authority without waiting for cookies to expire.
- Stored resources are filtered by organization for list, detail, export, preview and mutation operations. Reports retain organization IDs in translations and scheduler-generated jobs. Operation health starts with scoped subscriptions before reading their delivery history.
- Advisory/news/source-catalog records are shared reference data. Access still requires reviews/newsletter permissions; mutable global template settings and shared-cache purges remain superadmin-only. Static CSS, JS, images and the local login page are public assets; they contain no account credentials.
- User/role retirement preserves stored records. Password reset and role/account status changes rotate session versions. A signed local session never accepts historical provider cookies; user/role/org data is reloaded for authorization.
- Subscription ownership is immutable through editing. Its owner must be an active local user in the chosen organization. Delivery schedules require `subscriptions.send`; report schedules also require `reports.create`. The scheduler additionally rechecks the owner's current authority and first-login completion.
- Unknown HTTP paths/verbs and missing/invalid permission values default to deny. Server-side checks are independent of menu/button visibility. Browser mutations also check Origin; authenticated responses use `Cache-Control: no-store`.

## Account lifecycle

Provision/reset generates a random 32-byte secret, stores its bcrypt hash, displays the temporary password once, and expires it in 24 hours. First-login sessions are limited to Settings, password change and logout. Replacement passwords must differ from the temporary/current password and satisfy 12-character / 72-byte limits. External passwords are never accepted as provisioning/reset input or used by the authentication path. Because their plaintext is unavailable, the application cannot compare a user's chosen replacement with an unknown external password; administrators and users must choose an application-unique password.

## Migration

See [LOCAL_RBAC_MIGRATION.md](LOCAL_RBAC_MIGRATION.md) for schema audit, offline export auditing, explicit idempotent per-account/per-resource recovery, backup, rollback and unexecuted manual commands. No automatic account conversion or subscription cleanup runs. Actual production-record counts were not obtained because live database access is outside this task.

## Database integration checks

Four MongoDB integration tests (including the new complete local-RBAC HTTP lifecycle) are opt-in. Run them only against a disposable local server; each uses a generated test database and deletes that test database:

```sh
RBAC_TEST_MONGO_URI=mongodb://127.0.0.1:29876/ \
SUBSCRIPTION_TEST_MONGO_URI=mongodb://127.0.0.1:29876/ \
STATISTICS_TEST_MONGO_URI=mongodb://127.0.0.1:29876/ \
REPORT_TEST_MONGO_URI=mongodb://127.0.0.1:29876/ \
  cargo test --locked -- --ignored
```

The local task sandbox refused creation of the disposable MongoDB TCP listener (`Operation not permitted`). Consequently those integration tests and a database-backed browser sign-in rehearsal could not run here. The default suite exercises the production permission/delegation resolver, route guard, anonymous HTTP dispatch, cookie verification, bootstrap mutation plan, tenant scope filters, CSV/filter/report behavior and template rendering without opening a database.

See [VERIFICATION.md](VERIFICATION.md) for the final executed results and changed-file inventory.
