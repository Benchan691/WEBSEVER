# webserver-rust

Rust implementation of the security newsletter portal. The new authentication store is `web.accounts`; the legacy `web.auth` and `web.subscriptions` collections are never read or migrated.

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

Each Zimbra account receives one protected, owner-scoped `sub_account` record when it first signs in (and existing accounts are backfilled at startup). Its newsletter and report profiles start disabled, so the user can enable and configure delivery without waiting for a separate subscription record. Zimbra users can add more subscriptions and view or manage only their own records; the automatic record cannot be deleted by the Zimbra user, while user-created records can be deleted. Recipients on Zimbra-owned records remain fixed to the Zimbra email. The local administrator can manage every subscription and may enter multiple external recipients. New delivery history includes `subscription_id`, so records from older deployments cannot suppress delivery for a new subscription.

The scheduler is disabled by default. Enable it only after SMTP delivery has been tested:

```sh
RUST_SCHEDULER_ENABLED=true cargo run --release
```

## Checks

```sh
cargo fmt -- --check
cargo test
cargo build --release
node --check static/js/subscriptions/index.js
```

## Docker deployment

`Dockerfile` builds the Rust binary in a pinned Rust builder image and copies only the runtime assets into a Debian image. Use `docker-compose.example.yml` as the candidate service. Deploy beside the existing service on an alternate port with `RUST_SCHEDULER_ENABLED=false`, verify local login, a test Zimbra login, `web.accounts`, folder setup, subscription ownership, and SMTP delivery, then switch the port mapping. Keep the previous image, compose file, source tree, `.env`, and MongoDB backups for rollback.
