# Report preview fix — historical reference

The deployment steps below describe the earlier report-only release. For this local-RBAC branch, use [DEPLOY_LOCAL_RBAC_100.80.2.110.md](DEPLOY_LOCAL_RBAC_100.80.2.110.md), including its separate candidate database, account recovery and HTTPS checks. Do not use the old in-place transfer procedure to deploy the authentication changes.

These steps deploy the fix to the server at `100.114.50.103:9100`.
Build on the server (or with the project's Dockerfile). The binary built on this
Mac is a macOS binary and should not be copied to a Linux server.

## What was fixed

- Fixed Template previews omitted their source selection. The backend's
  `collections_mode=selected` default then excluded every document. Reports now
  default to the `cve` provider, and empty selections on existing report profiles
  are repaired when matching without requiring a database migration.
- The preview API omitted confidence counts and always returned an empty example
  list. It now returns confirmed, probable, and possible counts with inventory
  evidence and actual CVE identifiers.
- Matching previously considered only the newest 10,000 candidate documents.
  It now scans until the match limit is reached or all candidates are exhausted.
- Database query errors now produce an error instead of a successful zero-match
  preview. The subscriptions script version was changed to refresh cached code.

Newsletter source selection still supports selecting no sources. Reports retain
their severity and inventory filters, including the opt-in for possible matches.
The preview returns up to 100 matching records; report runs use up to 500.

## 1. Find the existing deployment and back up its code

Replace `YOUR_USER` and `/actual/path/webserver-rust` below with your SSH username
and the server's existing project directory. These values cannot be determined
from the public URL.

On the server:

```sh
ssh YOUR_USER@100.114.50.103
cd /actual/path/webserver-rust
task_report_backup="$PWD/../webserver-rust-before-report-fix-$(date +%Y%m%d-%H%M%S).tar.gz"
tar -czf "$task_report_backup" Cargo.toml Cargo.lock src static templates config Dockerfile
printf 'Code backup: %s\n' "$task_report_backup"
```

For Docker, identify the existing container and Compose project:

```sh
docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Ports}}'
docker compose ls
```

For systemd, find the service, then read its startup command:

```sh
systemctl list-units --type=service --all | grep -Ei 'webserver|rust|cve'
sudo systemctl cat YOUR_SERVICE.service
```

Note the Compose file and service name, or the systemd `ExecStart` and
`WorkingDirectory`. Keep your existing port mapping, `.env`, MongoDB settings,
and scheduler setting.

## 2. Copy the local source and browser assets

Run this in a terminal on your Mac, replacing the SSH username and destination:

```sh
rsync -av \
  --exclude='.git/' \
  --exclude='target/' \
  --exclude='.env' \
  --exclude='config/config.json' \
  --exclude='docker-compose*.yml' \
  --exclude='compose*.yml' \
  --exclude='output/' \
  --exclude='*.log' \
  --exclude='.DS_Store' \
  /Users/chankokpan/Documents/webserver-rust/ \
  YOUR_USER@100.114.50.103:/actual/path/webserver-rust/
```

This transfers the full source needed to compile it and the updated HTML and
JavaScript. It preserves the server's environment, runtime configuration, and
Compose files. It does not delete destination files.

## 3A. If the server uses Docker Compose

On the server, in the existing project directory, use the real Compose file and
web service name. `compose.yml` and `web` below are examples:

```sh
cd /actual/path/webserver-rust
docker compose -f compose.yml config --services
task_previous_image=$(docker compose -f compose.yml images -q web)
docker image tag "$task_previous_image" webserver-rust:before-report-preview-fix
docker compose -f compose.yml build web
docker compose -f compose.yml up -d --no-deps web
docker compose -f compose.yml ps
docker compose -f compose.yml logs --tail=100 web
```

Build success is required before starting the updated container. If the build
fails, the current container stays running. A plain `docker compose restart`
does not rebuild the binary or copy the updated assets into the image.

The repository's `docker-compose.example.yml` is intended for a candidate on
port **19100**. Use your existing production Compose file for an update to port
**9100**. If testing a separate candidate, leave its scheduler disabled to avoid
duplicate scheduled deliveries, and keep the production instance running until
verification succeeds.

Docker's command references:
[build](https://docs.docker.com/reference/cli/docker/compose/build/) and
[up](https://docs.docker.com/reference/cli/docker/compose/up/).

## 3B. If the server uses systemd or a manually started binary

Build from the server's project directory:

```sh
cd /actual/path/webserver-rust
cargo build --release --locked
```

If systemd's `ExecStart` points to this project's `target/release/webserver-rust`,
restart that service after the build succeeds:

```sh
sudo systemctl restart YOUR_SERVICE.service
sudo systemctl status YOUR_SERVICE.service --no-pager
sudo journalctl -u YOUR_SERVICE.service -n 100 --no-pager
```

If `ExecStart` points to an installed binary such as
`/usr/local/bin/webserver-rust`, replace **that actual path**. For the example path:

```sh
sudo cp -p /usr/local/bin/webserver-rust /usr/local/bin/webserver-rust.before-report-fix
sudo install -m 0755 target/release/webserver-rust /usr/local/bin/webserver-rust.next
sudo mv /usr/local/bin/webserver-rust.next /usr/local/bin/webserver-rust
sudo systemctl restart YOUR_SERVICE.service
```

Ensure the service reads templates and static assets from the updated project
directory. `WEBSERVER_ROOT=/actual/path/webserver-rust` can specify that directory
if your service already uses a relocated binary. If your deployment stores assets
in another directory, copy the updated `templates/subscriptions/index.html` and
`static/js/subscriptions/index.js` there too.

For a manually started process, stop the existing process after a successful
build and start it again with the same command, working directory, environment,
and process manager you currently use. Do not start a second process on port 9100.

## 4. Verify the deployed preview

1. Sign in at <http://100.114.50.103:9100/subscriptions> and reload the page.
   A hard reload is `Cmd+Shift+R` on your Mac.
2. Edit a subscription, enable its report profile, and load an inventory CSV
   containing a vendor/product known to occur in your CVE data.
3. Use **All time** initially. Leave severity boxes unchecked to include all
   known severities; enable **Include unknown severity** if the relevant records
   have no severity. Choose **Fixed Template**, then **Enriched Weekly**.
4. Confirm the preview shows matching CVE IDs, nonzero confidence counts when
   there are inventory matches, and vendor/product evidence below the summary.
   Possible matches appear only when **Include possible matches** is enabled.
5. Save the subscription if you changed its settings, then check its preview again.

If the browser's Network panel is open, the
`POST /api/subscriptions/report-preview` response should now include
`confirmed_count`, `probable_count`, `possible_count`, and populated
`match_examples` for inventory matches. These confidence counts should sum to
`count` when inventory filtering is enabled. `top_cves` should contain CVE IDs,
not MongoDB ObjectIds.

A genuine zero is still possible when the inventory, severity, time window, or
provider data has no match. Reports default to documents with
`source.provider="cve"` in the configured `VULNERABILITIES_COLLECTION` (normally
`vulnerabilities.news`). A data-loading error should be visible as an error.

## Rollback

Restore the code backup into the same project directory and rebuild/restart using
the same deployment method:

```sh
cd /actual/path/webserver-rust
tar -xzf /actual/path/to/webserver-rust-before-report-fix-TIMESTAMP.tar.gz
```

For an immediate Docker rollback, make a temporary copy of your production Compose
file, set the web service's `image` to
`webserver-rust:before-report-preview-fix`, and start it using that copy with
`up -d --no-deps --no-build --pull never web`. Keep the original Compose project
name (use `-p YOUR_EXISTING_PROJECT` if necessary) so this replaces the current
service. Restore the source backup before any future rebuild.

For an installed systemd binary, restore the saved
`webserver-rust.before-report-fix` binary and the backed-up assets, then restart
the service. No database schema migration is required for this fix.

## Local regression checks

```sh
cargo fmt -- --check
cargo test --locked
cargo build --release --locked
node --check static/js/subscriptions/index.js
```

An additional integration test inserts 10,001 unrelated records before matching
CVEs and verifies both preview modes, source isolation, confidence counts,
possible-match opt-in, and database read errors. To run it against a disposable
local MongoDB (it creates and drops a uniquely named test database):

```sh
REPORT_TEST_MONGO_URI='mongodb://127.0.0.1:27017/' \
  cargo test --locked preview_matches_inventory_beyond_ten_thousand_candidates -- --ignored
```
