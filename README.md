# webserver-rust

Rust implementation of the cybersecurity portal in the neighboring `webserver` project. It uses the same MongoDB databases and the existing browser templates and assets. The Python project is not needed at runtime.

## Run locally

1. Copy `.env.example` to `.env` and set `LOCAL_MONGO_URI`, `FLASK_SECRET_KEY`, and the bootstrap administrator credentials.
2. Run `cargo run --release` from this folder.
3. Open `http://localhost:9100`.

`PORT` changes the listening port. `WEBSERVER_ROOT` changes the folder containing `templates`, `static`, and `config`. `WEB_DATABASE` and `VULNERABILITIES_DATABASE` can point to separate test databases. `APP_CONFIG` selects a different JSON config file. Environment variables override JSON settings.

The app creates or repairs the configured local bootstrap administrator at startup. Account Hub login is enabled with `ACCOUNT_HUB_ENABLED=true` and its two configured URLs. Local administrator sign-in remains at `/login/local`. Set `RUST_SCHEDULER_ENABLED=true` after validating subscription filters and SMTP output in your environment.

## Features

- Signed login sessions, local and Account Hub login, account administration, and role based access.
- Subscription profiles, email recipients, vendor/product CSV import, previews, and MongoDB storage.
- Review collection browsing, search, selection scoring, and JSON export.
- Fixed template and enriched report jobs, progress, preview/download, cancellation, and translation.
- Newsletter rendering and operations pages. Scheduled reports and newsletter delivery are available behind `RUST_SCHEDULER_ENABLED`.
- SMTP delivery configured through the same `SMTP_*` environment variables as the Python app.

## Validation

Run `cargo check` and `cargo test`. For an end to end check, use separate `WEB_DATABASE` and `PORT` values before starting the server, then test sign-in and the API routes with that isolated database. Enriched reports additionally require Tavily and a reachable llama-server.

## Source compatibility

The frontend assets are carried over from the current Python working tree. The Rust service uses the existing `web` and `vulnerabilities` collection names and does not migrate data. Some advanced source specific normalization, confidence aware vendor matching, and AI evidence caching are not yet equivalent to the Python implementation; review those paths before replacing a production deployment.
