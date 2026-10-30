# Security newsletter portal — local authentication and RBAC

Rust/Axum application with local username/password login, application-managed organizations, and a fixed permission catalog. Implementation branch: `feature/local-rbac-organization-management`, based on `redesign/unified-news-collection`.

## Run locally

1. Copy `.env.example` to `.env` and configure MongoDB, a long random `FLASK_SECRET_KEY`, and the bootstrap username/password.
2. Use a new, empty development database or a restored backup. Never point a trial deployment at the live application database.
3. Set `WEB_AUTH_COOKIE_SECURE=false` only for loopback HTTP development. Production HTTPS uses `true`.
4. Run `cargo run --release`. Open `/login`, then `/management` as the bootstrap account.

First startup creates the configured local bootstrap account as the reserved `superadmin`, or explicitly reserves the existing matching local bootstrap administrator. Its password hash is preserved on subsequent startups. Changing `WEB_AUTH_BOOTSTRAP_PASSWORD` does **not** reset an existing account. Keep `WEB_AUTH_BOOTSTRAP_USERNAME` stable; startup refuses identity conflicts.

All other accounts are provisioned in **Accounts & roles**. Provisioning and reset generate independent random temporary local passwords, displayed once, valid for 24 hours. Users must replace them before accessing application features. Local replacement passwords require 12 or more characters and at most 72 UTF-8 bytes. External credentials are never imported, decrypted, or used to authenticate.

## Organizations and roles

Only the reserved superadmin manages organizations and appoints organization administrators. Organization administrators hold the tenant permission catalog within their organization. Authorized users can create custom roles, limited to their current permissions, and assign one custom role to another local user in the same organization.

Authorization is enforced centrally on HTTP methods and routes and through organization filters for stored resources. Unknown routes, invalid permissions, missing roles and unscoped records grant no access. Advisory source data is shared read-only reference material; accounts, roles, subscriptions, reports and delivery health are organization scoped. Three global permissions remain superadmin-only.

Delegated permissions are intersected with the creator's current permissions on every request. Disabling a creator, retiring an ancestor role, or revoking its permissions removes dependent authority. Users cannot change their own role, modify a delegation ancestor, or manage the reserved superadmin through ordinary account APIs. Retiring users and roles preserves their database records and dependent history.

See [the permission catalog and scope rules](docs/LOCAL_RBAC.md), [the HTTP API](APIs.md), and [migration and recovery](docs/LOCAL_RBAC_MIGRATION.md).

## Existing data

There is no automatic account conversion, subscription backfill, duplicate cleanup, or live migration. Existing external identities, legacy collections, subscriptions, recipients, filters and history are retained. Unmigrated identities cannot sign in. Unscoped or externally owned subscriptions are skipped by scheduled delivery.

Audit exports from a restored backup with `scripts/audit_local_rbac.py`; review every account/organization/role/ownership mapping before applying the documented recovery procedure. The bootstrap account transition and new indexes are the only authentication initialization changes at normal startup.

## News, reports and email

The portal reads unified advisory records from `VULNERABILITIES_DATABASE` / `VULNERABILITIES_COLLECTION` (default `news`) and the crawler's `source_catalog`. A provider named `zimbra` may still supply product advisories; that reference-feed support is independent of authentication.

Subscriptions retain newsletter and report profiles, vendor/product CSV filtering, To/CC/BCC recipients, report previews, cron schedules and monthly delivery statistics. Owners must be active local accounts in the same organization. New profiles start disabled. Enabling delivery requires `subscriptions.send`; scheduled reports also require `reports.create`. The scheduler rechecks the owner's current scope and authority before processing subscriptions. SMTP handles all outgoing delivery.

`RUST_SCHEDULER_ENABLED=false` is the default. Enable it only after migration and SMTP verification, on one instance per database. Disable the previous scheduler before enabling a replacement.

## Verification

```sh
cargo fmt -- --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
python3 -m unittest discover -s tests -p 'test_*.py' -v
bash -n setup.sh
node --check static/js/auth/management.js
node --check static/js/subscriptions/index.js
node --check static/js/reports/index.js
node --check static/js/operations/index.js
```

MongoDB integration tests are opt-in and require a disposable local database. See `docs/LOCAL_RBAC.md` for commands and verification limitations.

## Deployment

Follow [DEPLOY_LOCAL_RBAC_100.80.2.110.md](DEPLOY_LOCAL_RBAC_100.80.2.110.md) to transfer the local source, prepare a candidate database, validate, cut over and roll back on `100.80.2.110`. It supports deployment without pushing a branch. Nothing in these instructions has been deployed automatically.

`setup.sh` remains available as an interactive Linux installer for a branch that is available to its source repository. It backs up configuration, preserves local edits and starts with scheduling disabled. For this unpushed branch, use the offline transfer procedure in the deployment guide.
