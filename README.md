# webserver-rust

Rust implementation of the cybersecurity portal in the neighboring `webserver` project. It uses the same MongoDB databases and the existing browser templates and assets. The Python project is not needed at runtime.

## Run locally

1. Copy `.env.example` to `.env` and set `LOCAL_MONGO_URI`, `FLASK_SECRET_KEY`, and the bootstrap administrator credentials.
2. Run `cargo run --release` from this folder.
3. Open `http://localhost:9100`.

`PORT` changes the listening port. `WEBSERVER_ROOT` changes the folder containing `templates`, `static`, and `config`. `WEB_DATABASE` and `VULNERABILITIES_DATABASE` can point to separate test databases. `APP_CONFIG` selects a different JSON config file. Environment variables override JSON settings.

The app creates or repairs the configured local bootstrap administrator at startup. Account Hub login is enabled with `ACCOUNT_HUB_ENABLED=true` and its two configured URLs. For the current Account Hub deployment, use the `/accounthub-api-gateway/auth/user/oauth/login` login API and `/accounthub-api-gateway/user/open-api/v1/user/view/info` user-info API. Account Hub users must have the configured system role (set `ACCOUNT_HUB_REQUIRED_ROLE` in `.env`; it defaults to `CVE-SYSTEM` and accepts values such as `CVE-SYSTEM-admin`). A system role matching `<required-role>-admin` makes the user an organization administrator; the portal stores the organization ID returned by Account Hub and scopes the **Organization members** panel to that organization. Every user, including the local bootstrap account and organization administrators, can edit only their own profile in **Settings**. Local administrator sign-in remains at `/login/local`. Set `RUST_SCHEDULER_ENABLED=true` after validating subscription filters and SMTP output in your environment.

When Account Hub is enabled, the scheduler can reconcile local Hub identities every five minutes. Set `ACCOUNT_HUB_DIRECTORY_URL` to the complete user-directory API endpoint (the current UI route `/oganization-user` uses `/accounthub-api-gateway/user/open-api/v1/getAllPersonnelList` behind the scenes) and put its Bearer service token in `ACCOUNT_HUB_DIRECTORY_TOKEN`; the token is never stored in MongoDB. `ACCOUNT_HUB_SYNC_INTERVAL_SECONDS` controls the interval and defaults to 300 seconds. The synchronizer updates active users and removes a user plus its portal subscriptions only after a successful, complete directory response confirms that the identity is disabled or missing. Network failures, unauthorized responses, empty lists, and incomplete pages leave local data unchanged. The Operations page reports the last synchronization status and counts.

## Features

- Signed login sessions, local and Account Hub login, account administration, and role based access.
- Subscription profiles, email recipients, vendor/product CSV import, structured vendor/product matching, previews, and MongoDB storage.
- Review collection browsing, search, selection scoring, and JSON export.
- Fixed template and enriched report jobs, progress, preview/download, cancellation, and translation.
- Source specific newsletter rendering, including HPE and Zimbra layouts, and operations pages. Scheduled reports and newsletter delivery are available behind `RUST_SCHEDULER_ENABLED`.
- SMTP delivery configured through the same `SMTP_*` environment variables as the Python app.

## Validation

Run `cargo check` and `cargo test`. For an end to end check, use separate `WEB_DATABASE` and `PORT` values before starting the server, then test sign-in and the API routes with that isolated database. Enriched reports additionally require Tavily and a reachable llama-server.

## Source compatibility

The frontend assets are carried over from the current Python working tree. The Rust service uses the existing `web` and `vulnerabilities` collection names and does not migrate data. The Rust code covers the browser and API routes, but its enriched report pipeline, cache behavior, and some source formatting and scheduled delivery details are still simpler than the Python implementation. Compare those outputs with your production data before replacing a deployment. Scheduled delivery is disabled by default.
