# Deploy local authentication and organization RBAC to 100.80.2.110

This guide transfers the **local working tree** without pushing a branch. No deployment or database migration has been performed by Codex. The code is in:

```text
/Users/chankokpan/Documents/webserver-rust/worktrees/local-rbac
branch: feature/local-rbac-organization-management
base: 6aae75b861a0003af176564f1e903c1680cf877a
```

Use your own SSH account and the actual current service/database paths. The server's current layout and installed services were not inspected. Do not change the original checkout's `main`, discard `output/`, or run migration against its live database. Review [verification results](docs/VERIFICATION.md) and [migration/recovery instructions](docs/LOCAL_RBAC_MIGRATION.md) first. MongoDB-backed integration/browser checks remain a required operator check before cutover.

## 1. Review and package on your Mac

```sh
cd /Users/chankokpan/Documents/webserver-rust/worktrees/local-rbac
git branch --show-current
git status --short
git diff --check
cargo fmt -- --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

Package the current edited files, including new untracked implementation files. The explicit file list excludes `.git`, `.env`, `output/`, target build files and the original checkout. Committing or pushing is not required for this transfer:

```sh
tar --exclude='__pycache__' --exclude='.DS_Store' \
  -czf /tmp/webserver-local-rbac.tar.gz \
  Cargo.toml Cargo.lock Dockerfile docker-compose.example.yml .env.example \
  setup.sh README.md APIs.md DEPLOY_LOCAL_RBAC_100.80.2.110.md \
  config src templates static scripts tests docs
shasum -a 256 /tmp/webserver-local-rbac.tar.gz
```

Set your SSH username, then transfer:

```sh
printf 'SSH username for 100.80.2.110: '
read -r DEPLOY_SSH_USER
scp /tmp/webserver-local-rbac.tar.gz "$DEPLOY_SSH_USER@100.80.2.110:/tmp/"
ssh "$DEPLOY_SSH_USER@100.80.2.110"
```

The archive contains the local uncommitted implementation; a `git bundle` alone would omit those edits. Keep a copy of the archive/checksum with your release records.

## 2. Prepare a new directory on the server

Commands below assume Bash on the server and Docker Engine with Compose v2 already installed. MongoDB tools (`mongodump`, `mongorestore`, `mongoexport`, `mongosh`) are needed for data preparation.

```sh
umask 077
DEPLOY_SOURCE_DIR="$HOME/webserver-rbac-$(date +%Y%m%d-%H%M%S)"
mkdir "$DEPLOY_SOURCE_DIR"
tar -xzf /tmp/webserver-local-rbac.tar.gz -C "$DEPLOY_SOURCE_DIR"
cd "$DEPLOY_SOURCE_DIR"
sha256sum /tmp/webserver-local-rbac.tar.gz
docker version
docker compose version
```

This is a fresh runtime/source directory. Do not extract over the current deployment. Record the existing service/container name and current listening ports with `docker ps` and/or `systemctl status YOUR_CURRENT_SERVICE`.

## 3. Back up and prepare a separate application database

For a rehearsal, snapshot the current application DB and restore a separate candidate namespace. For the final cutover, first freeze user writes and pause the old scheduler, then take the final snapshot and repeat preparation in a **fresh** candidate database. Keep the old database and runtime for rollback.

```sh
BACKUP_DIR="$HOME/webserver-rbac-backups/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"
CANDIDATE_WEB_DATABASE="web_local_rbac_$(date +%Y%m%d_%H%M%S)"
printf 'MongoDB URI for backup/restore (input hidden): '
read -r -s RBAC_MONGO_URI
printf '\n'
mongodump --uri "$RBAC_MONGO_URI" --db web --out "$BACKUP_DIR/mongo"
mongorestore --uri "$RBAC_MONGO_URI" \
  --nsInclude 'web.*' --nsFrom 'web.*' \
  --nsTo "${CANDIDATE_WEB_DATABASE}.*" "$BACKUP_DIR/mongo"
printf 'Candidate application database: %s\n' "$CANDIDATE_WEB_DATABASE"
```

Replace `web` if the existing application database has another name. Use the correctly authorized URI, including required authSource/TLS parameters. Keep the backup directory private. Also copy the previous `.env`, JSON config, Compose/systemd definition, image tag/binary and newsletter assets to that backup. Do not print them or place secrets in the source archive.

No `--drop` command is needed. Never reuse an existing candidate namespace that already contains user data. Keep shared vulnerability source data unchanged; only the candidate application DB receives the new account/role/subscription/report metadata.

## 4. Configure the candidate

```sh
cp .env.example .env
chmod 600 .env
openssl rand -hex 32
```

Put the generated random value in `FLASK_SECRET_KEY`. Edit `.env` with your editor; do not paste passwords into shell history. Configure:

```dotenv
LOCAL_MONGO_URI=mongodb://host.docker.internal:27017/
# If MONGO_URI is also set, it takes precedence: set both to the intended instance.
WEB_DATABASE=web_local_rbac_REPLACE_WITH_THE_CANDIDATE_DATABASE_ABOVE
VULNERABILITIES_DATABASE=vulnerabilities
VULNERABILITIES_COLLECTION=news
ACCOUNT_COLLECTION=accounts
FLASK_SECRET_KEY=REPLACE_WITH_RANDOM_SECRET
WEB_AUTH_BOOTSTRAP_USERNAME=admin
WEB_AUTH_BOOTSTRAP_PASSWORD=REPLACE_WITH_NEW_INITIAL_LOCAL_PASSWORD
WEB_AUTH_COOKIE_SECURE=false
RUST_SCHEDULER_ENABLED=false
```

Use the existing bootstrap username if the restored DB contains that local account. Its **existing password remains in effect**; the environment bootstrap password only creates a new bootstrap account. The example password must be 12+ characters and at most 72 UTF-8 bytes. A naming collision with an external account is rejected; follow the documented recovery rather than deleting the conflicting record.

`host.docker.internal` reaches the server host through Compose's host-gateway mapping. If MongoDB is in another container/network or on another machine, use its reachable hostname and correct TLS/authentication URI instead. The MongoDB listener/firewall must permit the container connection. Do not assume `localhost` inside the application container means the server host.

Configure SMTP in `.env` if required, preserving the correct transport, sender and credentials. Leave scheduling disabled. The candidate configuration should not include external sign-in URLs or keys. Private rollback backups still retain the original deployment's configuration.

## 5. Build and start the isolated candidate

The supplied Compose example binds only `127.0.0.1:19100` on the server and keeps scheduling off:

```sh
docker compose -p webserver-local-rbac -f docker-compose.example.yml config --quiet
docker compose -p webserver-local-rbac -f docker-compose.example.yml build --pull
docker compose -p webserver-local-rbac -f docker-compose.example.yml up -d
docker compose -p webserver-local-rbac -f docker-compose.example.yml logs --tail 100 web
curl --fail http://127.0.0.1:19100/login
```

The fixed container name is `webserver-rust-candidate`. If another candidate already uses that name, choose a different `container_name` in your copy of the Compose file before starting; do not remove another deployment's container. If port 19100 is occupied, set a different `RUST_WEB_PORT` in the candidate `.env`.

On your Mac, open a tunnel in a separate terminal (use your SSH account):

```sh
ssh -N -L 19100:127.0.0.1:19100 YOUR_SSH_USER@100.80.2.110
```

Open `http://localhost:19100/login`. `WEB_AUTH_COOKIE_SECURE=false` is for this loopback HTTP tunnel only. It must become `true` before publishing through HTTPS.

If using native Rust instead of Docker: build with Rust 1.91+, `cargo build --release --locked`; run the binary from this new source directory with `WEBSERVER_ROOT` set to that directory, `PORT=19100`, and scheduling disabled. Native mode binds all interfaces, so use a firewall/reverse proxy to restrict the candidate; the Compose loopback binding is the preferred isolated trial here.

## 6. Recover existing users and verify scope

Follow [docs/LOCAL_RBAC_MIGRATION.md](docs/LOCAL_RBAC_MIGRATION.md) against the candidate database. Export and run the offline audit before applying any reviewed account mapping. Create organizations and custom roles, recover existing accounts while preserving their IDs, bind their subscriptions/reports explicitly, then appoint organization administrators.

In the UI:

1. Sign in at `/login` as superadmin. Open **Accounts & roles**.
2. Create organization A and B. Provision local users without roles, then appoint the intended organization administrators.
3. Use a temporary local password for each first login. Verify Settings is the only available area until it is changed.
4. Create named custom roles using the grouped checkboxes. Try an unknown permission, a permission the actor lacks, a reserved name/type, a foreign organization ID, a stronger role assignment and a self role change: every attempt must fail.
5. Test A and B against user/role/subscription/report list, detail, edit, delete, CSV export, report preview/download/translation and operation health. Foreign IDs must not reveal data or allow changes.
6. Attempt to disable, reset, demote or retire superadmin through ordinary APIs. Verify rejection. Restart the candidate and verify the reserved administrator still works with its existing local password.
7. Verify historical external credentials/cookies cannot authenticate. Confirm legacy unresolved subscriptions remain retained and do not deliver mail.
8. Check filters, CSV import/export and report previews. Test SMTP only with addresses you control. Verify roles without delivery permission cannot enable schedules or send statistics.

Run the optional MongoDB integration tests in a disposable local environment as described in `docs/LOCAL_RBAC.md`; never point test variables at production. The implementation task could not run DB-backed checks because its sandbox blocked a local listener.

## 7. Publish HTTPS and cut over

Keep the previous runtime/database available. Once candidate validation and final data reconciliation pass:

1. Set `WEB_AUTH_COOKIE_SECURE=true` in the candidate `.env` and recreate the candidate container.
2. Configure the existing HTTPS reverse proxy to send requests to `http://127.0.0.1:19100`. Preserve the **public Host header** so Origin validation works. For Nginx, the relevant location is:

   ```nginx
   location / {
       proxy_pass http://127.0.0.1:19100;
       proxy_set_header Host $http_host;
       proxy_set_header X-Forwarded-Proto $scheme;
       proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
   }
   ```

   Supply a trusted certificate for the actual hostname or for IP `100.80.2.110` if using the IP directly. Do not expose local-password login over plain network HTTP. Run the proxy's configuration test before reloading it.
3. Recheck login, first password change and permission-denied behavior through the real HTTPS address.
4. Stop the old scheduler/service before enabling any new scheduled delivery. Initially keep the new scheduler disabled. Once intended owners have completed first login and hold delivery/report permissions, set `RUST_SCHEDULER_ENABLED=true` and recreate the candidate:

   ```sh
   docker compose -p webserver-local-rbac -f docker-compose.example.yml up -d --force-recreate
   docker compose -p webserver-local-rbac -f docker-compose.example.yml logs --tail 100 web
   ```

Exactly one scheduler should run for each application database. Preserve the chosen image, source archive, private config and migration ledger as the release record. `setup.sh` fetches its configured branch; use it only after that branch is deliberately made available. It is not needed for this offline deployment.

## 8. Rollback

```sh
cd "$DEPLOY_SOURCE_DIR"
docker compose -p webserver-local-rbac -f docker-compose.example.yml stop web
```

Revert the reverse proxy to the previous runtime and restart the old service with its original private configuration and original DB (or a separately restored pre-change snapshot). Keep the new candidate DB and its post-cutover activity for reconciliation. Do not run `down -v`, delete databases, remove collections or restore over a live DB as an automatic rollback. Restore provider keys only with the old release that used them.

If the application refuses bootstrap startup due to a username conflict, restore the original configured bootstrap username or recover the known local bootstrap account from the backup. Changing only `WEB_AUTH_BOOTSTRAP_PASSWORD` does not reset it. Offline password recovery is documented in `docs/LOCAL_RBAC_MIGRATION.md`.
