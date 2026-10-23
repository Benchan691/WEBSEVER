# webserver-rust

Rust implementation of the security newsletter portal. The new authentication store is `web.accounts`; the legacy `web.auth` and `web.subscriptions` collections are never read or migrated.

## Interactive server setup

Copy `setup.sh` to the Linux server, then run:

```sh
sudo bash setup.sh --repo /root/WEBSEVER
```

The first choice is **Locally (Rust + systemd)** or **In Docker (Docker Compose)**.
There is also a configuration-only option. Local setup installs Rust 1.91 and
build prerequisites when needed; Docker setup can install missing Engine/Compose
packages from the server's configured apt repositories. Other distributions must
provide these prerequisites themselves. GitHub access and an existing MongoDB
deployment are required; MongoDB is not installed by this script.

The installer handles a checkout still on `main`, different directory ownership,
single-branch clones, and uncommitted edits. It archives working files and saves
local edits in a Git stash before switching to `redesign/unified-news-collection`.
Existing commits are preserved under backup branch names. Existing JSON settings
are merged with new defaults; secrets, SMTP settings, and a valid existing Zimbra
encryption key are retained. Configuration prompts hide secret values. If multiple
servers share Zimbra accounts, enter the same `ZIMBRA_CREDENTIAL_KEY` on every server.

Deployment files live in `/opt/webserver-rust-setup`; private backups live in
`/var/backups/webserver-rust-setup`. Local setup creates
`webserver-rust-setup.service`, running as root for a root-owned server installation.
Docker setup manages the `webserver-rust-setup` Compose project. Both modes keep
the deployed runtime separate from the Git checkout and check both login pages
on a candidate port before replacing an explicitly selected existing deployment.
If installation fails, the script attempts to restore the original checkout,
configuration, and services, retaining all backups and stashes.

The login-page checks verify application startup and MongoDB account initialization;
test an actual Zimbra login and SMTP delivery yourself before enabling scheduled
mail. The scheduler remains disabled unless you enable it in the final prompt.
Run it on only one instance per shared database. Data migration, AccountHub identity
and subscription migration, and removal of legacy review views are separate tasks;
this installer does not run `vuln-scrape unify-mongo` or delete database data.

```sh
bash setup.sh --check
python3 -m unittest discover -s tests -p 'test_setup.py' -v
```

## Configure and run

1. Copy `.env.example` to `.env`.
2. Set `LOCAL_MONGO_URI`, `FLASK_SECRET_KEY`, `WEB_AUTH_BOOTSTRAP_USERNAME`, and `WEB_AUTH_BOOTSTRAP_PASSWORD`.
3. Generate a dedicated 32-byte key for `ZIMBRA_CREDENTIAL_KEY`, for example:

   ```sh
   openssl rand -base64 32
   ```

4. Set the Zimbra URL and SMTP settings. Keep `ZIMBRA_VERIFY_TLS=true` in production.
5. Run `cargo run --release` and open `http://localhost:9100`.

The first startup creates unique username and email indexes and bootstraps one local administrator in `web.accounts`. It does not copy records from the legacy collections. Local administrator login is `/login/local`; normal users submit their full Zimbra email address and password at `/login`.

## Vulnerability news data

The crawler and portal share one physical MongoDB collection, configured with
`VULNERABILITIES_COLLECTION=news`. Every document records its provider in
`source.provider`; the portal uses that field for source labels, filters,
templates, reports, and delivery history. The portal does not require MongoDB
`*_review` views.

Cyberclawer publishes its effective scraper provider list to the
`vulnerabilities.source_catalog` collection. Run `vuln-scrape
sync-source-catalog` to publish the list without scraping; catch-up also
refreshes it before a cycle. The subscription picker reads this catalog and
filters the unified `news` collection by `source.provider`, including sources
that do not currently have news records. The UI displays provider IDs without
the legacy `_review` suffix.

Before switching an existing deployment, run the crawler migration as a dry
run and then perform the validated cutover:

```sh
vuln-scrape unify-mongo --dry-run
vuln-scrape unify-mongo
```

The migration builds and validates a shadow collection before renaming it to
`news`, preserves the original physical collections as timestamped backups,
and removes the obsolete review views only after validation succeeds. Keep the
backups until the Rust portal, filters, previews, and scheduled delivery have
been verified.

## Authentication and mail delivery

After a successful Zimbra `AuthRequest`, the service ensures the configured `news` folder with `GetFolderRequest`/`CreateFolderRequest`, then stores the mailbox credential encrypted with AES-256-GCM. Passwords are never returned to a browser or written to logs. All notification and scheduled email is sent through the configured SMTP transport.

## Subscriptions

Each Zimbra account receives one protected, owner-scoped `sub_account` record when it first signs in (and existing accounts are backfilled at startup). Its newsletter and report profiles start disabled, so the user can enable and configure delivery without waiting for a separate subscription record. Zimbra users can add more subscriptions and view or manage only their own records; the automatic record cannot be deleted by the Zimbra user, while user-created records can be deleted. Zimbra users can edit the To, CC, and BCC recipients on their own subscriptions, including external addresses without including their own mailbox. The local administrator can manage every subscription and may enter multiple external recipients. New delivery history includes `subscription_id`, so records from older deployments cannot suppress delivery for a new subscription.

Each subscription supports optional `cc` and `bcc` email-address arrays in addition
to its `emails` (To) list. Copies apply to subscription notifications, newsletters,
scheduled reports, and monthly delivery statistics. Each To recipient still gets
an individual email; CC/BCC recipients receive a copy of each. BCC addresses are
included in the SMTP envelope but omitted from the message headers. Addresses are
validated and deduplicated across To, CC, and BCC, with at most 50 unique recipients.
Existing subscriptions default to empty copy lists. A new Zimbra subscription
starts with the account's email as its To recipient; users can replace it with
other addresses. Login and startup preserve saved recipients, while the Zimbra
account and subscription ownership remain unchanged.

Download each person's saved product inventories using **Download saved CSV**
in the newsletter or report section of the subscription editor.
Exports use the same four columns and pipe-separated aliases as the import
template, so they can be imported again. Downloads contain saved data, not pending
form changes, and use the same subscription ownership and administrator scopes.
The API is `GET /api/subscriptions/{id}/vendor-products.csv?profile=newsletter`
or `profile=report` (the default).

The scheduler is disabled by default. Enable it only after SMTP delivery has been tested:

```sh
RUST_SCHEDULER_ENABLED=true cargo run --release
```

Newsletter delivery statistics summarize the previous calendar month in Hong
Kong time, with successful delivery counts and shares for each source. Counts
are scoped to the subscription and personalized for each recipient; selected
sources with no deliveries remain visible. The subscription editor can preview
the styled email or send it immediately. When the monthly schedule is enabled,
the scheduler sends on the 1st at 09:00 HKT, catches up a missed run, and records
each recipient's completed month to avoid resending on subsequent ticks or
restarts. New subscriptions begin with their signup month.

## Checks

```sh
cargo fmt -- --check
cargo test
cargo build --release
node --check static/js/subscriptions/index.js
```

## Docker deployment

`Dockerfile` builds the Rust binary in a pinned Rust builder image and copies only the runtime assets into a Debian image. Use `docker-compose.example.yml` as the candidate service. Deploy beside the existing service on an alternate port with `RUST_SCHEDULER_ENABLED=false`, verify local login, a test Zimbra login, `web.accounts`, folder setup, subscription ownership, and SMTP delivery, then switch the port mapping. Keep the previous image, compose file, source tree, `.env`, and MongoDB backups for rollback.

For the report preview fix, see [deployment and verification steps](DEPLOY_REPORT_PREVIEW_FIX.md), including updates to an existing Docker Compose, systemd, or manual deployment.
