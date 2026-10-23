#!/usr/bin/env bash
# Interactive Linux installer. Run: sudo bash setup.sh
# Keep this file self-contained: it must also work when copied to a server on main.
set -Eeuo pipefail
umask 077

TARGET_BRANCH=redesign/unified-news-collection
DEFAULT_REPOSITORY=https://github.com/Benchan691/WEBSEVER.git
INSTALL_ROOT=/opt/webserver-rust-setup
BACKUP_ROOT=/var/backups/webserver-rust-setup
UNIT_NAME=webserver-rust-setup.service
UNIT_DIR=/etc/systemd/system
COMPOSE_PROJECT=webserver-rust-setup
REPO_DIR= BACKUP_DIR= RELEASE_DIR= ORIGINAL_BRANCH= ORIGINAL_HEAD=
STASH_SHA= SAVED_TARGET_BRANCH= CANDIDATE_PID= CANDIDATE_CONTAINER=
LEGACY_KIND= LEGACY_NAME= LEGACY_ENABLED= LEGACY_RESTART=
SOURCE_CHANGED=0 SERVICE_CHANGED=0 COMPOSE_CHANGED=0 LEGACY_STOPPED=0
SUCCESS=0 ROLLING_BACK=0

say() { printf '\n%s\n' "$*"; }
die() { printf '\nERROR: %s\n' "$*" >&2; return 1; }
read_value() {
    local label=$1 default=${2:-}
    if [[ -n "$default" ]]; then printf '%s [%s]: ' "$label" "$default" >&3;
    else printf '%s: ' "$label" >&3; fi
    IFS= read -r REPLY <&3 || return 1
    REPLY=${REPLY:-$default}
}
confirm() {
    local label=$1 default=${2:-n} answer
    while true; do
        if [[ "$default" == y ]]; then printf '%s [Y/n]: ' "$label" >&3;
        else printf '%s [y/N]: ' "$label" >&3; fi
        IFS= read -r answer <&3 || return 1
        answer=${answer:-$default}
        case "$answer" in y|Y|yes|YES) return 0 ;; n|N|no|NO) return 1 ;; esac
    done
}
g() { git -c "safe.directory=$REPO_DIR" -C "$REPO_DIR" "$@"; }

# Python handles data, never sources .env as executable shell code, and keeps
# secret values out of shell arguments, command output, and process listings.
config_helper() {
    python3 - "$@" <<'PY_SETUP'
import base64
import copy
import getpass
import json
import os
from pathlib import Path
import re
import secrets
import socket
import sys
import tempfile
from urllib.parse import urlsplit

ASSIGNMENT = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")

def decode_value(raw, known):
    """The single-line dotenvy syntax used by this installer and .env.example."""
    result, quote, escaped, end = [], None, False, False
    i = 0
    while i < len(raw):
        ch = raw[i]
        if end:
            if ch == '#':
                break
            if not ch.isspace():
                raise ValueError('Unsupported .env value after whitespace')
        elif escaped:
            escapes = {'n': '\n', '\\': '\\', '"': '"', "'": "'", '$': '$', ' ': ' '}
            if ch not in escapes:
                raise ValueError('Unsupported .env escape; use the configuration backup')
            result.append(escapes[ch])
            escaped = False
        elif quote == "'":
            if ch == "'":
                quote = None
            else:
                result.append(ch)
        elif ch == '\\':
            escaped = True
        elif ch == '$':
            match = re.match(r'\$(?:\{([^}]+)\}|([A-Za-z0-9_]+))', raw[i:])
            if match:
                name = match.group(1) or match.group(2)
                result.append(os.environ.get(name, known.get(name, '')))
                i += len(match.group(0)) - 1
            else:
                result.append(ch)
        elif quote == '"':
            if ch == '"':
                quote = None
            else:
                result.append(ch)
        elif ch in ('"', "'"):
            quote = ch
        elif ch.isspace():
            end = True
        else:
            result.append(ch)
        i += 1
    if quote or escaped:
        raise ValueError('Multiline or unterminated .env value; backup is unchanged')
    return ''.join(result)

def read_env(path):
    values = {}
    text = path.read_text() if path.exists() else ''
    for line in text.splitlines():
        match = ASSIGNMENT.match(line)
        if match:
            # dotenvy::from_path retains the first occurrence of a key.
            value = decode_value(match.group(2).rstrip(), values)
            values.setdefault(match.group(1), value)
    return text, values

def encode_value(value):
    if '\x00' in value or '\r' in value:
        raise ValueError('NUL and carriage returns are not supported in .env values')
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"').replace('$', '\\$').replace('\n', '\\n') + '"'

def atomic_text(path, text, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.' + path.name + '.', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

def update_env(path, updates):
    text = path.read_text() if path.exists() else ''
    lines = []
    for line in text.splitlines():
        match = ASSIGNMENT.match(line)
        if not match or match.group(1) not in updates:
            lines.append(line)
    lines.append('')
    lines.append('# Values maintained by setup.sh')
    lines.extend(key + '=' + encode_value(str(value)) for key, value in updates.items())
    atomic_text(path, '\n'.join(lines).lstrip('\n') + '\n')

def merge_settings(defaults, previous):
    result = copy.deepcopy(defaults)
    for key, value in previous.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = merge_settings(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result

def prompt(label, default=''):
    with open('/dev/tty', 'r+') as tty:
        tty.write(label + (f' [{default}]' if default else '') + ': ')
        tty.flush()
        answer = tty.readline()
    if not answer:
        raise EOFError('Interactive input ended')
    return answer.rstrip('\n') or default

def hidden(label, current='', default=''):
    hint = ' (Enter to keep configured value)' if current else ''
    with open('/dev/tty', 'w') as tty:
        answer = getpass.getpass(label + hint + ': ', stream=tty)
    return answer or current or default

def valid_key(value):
    try:
        return len(base64.b64decode(value, validate=True)) == 32
    except (ValueError, TypeError):
        return False

def is_placeholder(value):
    return not value or value in ('change-me', 'replace-with-a-long-random-secret', 'replace-with-a-strong-password')

def require_port(value):
    if not value.isdigit() or not 1 <= int(value) <= 65535:
        raise ValueError('Port must be between 1 and 65535')
    return value

def docker_mongo_uri(value):
    # Only loopback hosts in the authority are rewritten, including replica sets.
    scheme, rest = value.split('://', 1)
    if scheme != 'mongodb':
        return value
    boundary = re.search(r'[/?]', rest)
    index = boundary.start() if boundary else len(rest)
    authority, suffix = rest[:index], rest[index:]
    credentials, separator, hosts = authority.rpartition('@')
    if not separator:
        hosts = authority
    hosts = re.sub(r'(^|,)(localhost|127\.0\.0\.1|\[::1\])(?=[:,]|$)', r'\1host.docker.internal', hosts)
    return scheme + '://' + (credentials + '@' if separator else '') + hosts + suffix

def configure(repo, backup, mode):
    original_env = backup / '.env'
    _, env = read_env(original_env if original_env.exists() else repo / '.env')
    config_path = repo / 'config/config.json'
    defaults = json.loads(config_path.read_text())
    old_path = backup / 'config/config.json'
    previous = json.loads(old_path.read_text()) if old_path.exists() else {}
    if not isinstance(defaults, dict) or not isinstance(previous, dict):
        raise ValueError('config/config.json must be a JSON object')
    config = merge_settings(defaults, previous)
    mongo = hidden('MongoDB URI (hidden; default mongodb://127.0.0.1:27017/)', env.get('MONGO_URI') or env.get('LOCAL_MONGO_URI', ''), 'mongodb://127.0.0.1:27017/')
    if not mongo.startswith(('mongodb://', 'mongodb+srv://')):
        raise ValueError('MongoDB URI must start with mongodb:// or mongodb+srv://')
    if mode == 'docker':
        rewritten = docker_mongo_uri(mongo)
        if rewritten != mongo:
            print('Docker: the local MongoDB hostname will use host.docker.internal.')
        mongo = rewritten
    mongodb = config.get('mongodb', {})
    web_db = prompt('Web database', env.get('WEB_DATABASE') or mongodb.get('web_database', 'web'))
    vuln_db = prompt('Vulnerability database', env.get('VULNERABILITIES_DATABASE') or mongodb.get('vulnerabilities_database', 'vulnerabilities'))
    print('This branch uses accounts for authentication and news for unified provider documents.')
    username = prompt('Local administrator username', env.get('WEB_AUTH_BOOTSTRAP_USERNAME') or config.get('web_auth', {}).get('bootstrap_username', 'admin'))
    old_password = env.get('WEB_AUTH_BOOTSTRAP_PASSWORD', '')
    if is_placeholder(old_password):
        old_password = ''
    while True:
        password = hidden('Local administrator password (8+ characters, at most 72 UTF-8 bytes)', old_password)
        if password == old_password and old_password and len(password.encode()) <= 72:
            break
        if len(password) < 8 or len(password.encode()) > 72:
            print('Choose at least 8 characters and at most 72 UTF-8 bytes.')
        elif hidden('Confirm administrator password') == password:
            break
        else:
            print('Passwords did not match.')
    session_key = env.get('FLASK_SECRET_KEY', '')
    if is_placeholder(session_key):
        session_key = secrets.token_hex(32)
        print('Generated a new session signing key.')
    zimbra = config.get('zimbra', {})
    zimbra_url = prompt('Zimbra HTTPS URL', env.get('ZIMBRA_BASE_URL') or zimbra.get('base_url', 'https://zmailbox.citictel-cpc.com'))
    url = urlsplit(zimbra_url)
    if url.scheme != 'https' or not url.hostname or url.username or url.password:
        raise ValueError('Use a valid HTTPS Zimbra URL without embedded credentials')
    zimbra_folder = prompt('Zimbra news folder', env.get('ZIMBRA_FOLDER_NAME') or zimbra.get('folder_name', 'news'))
    encryption_key = env.get('ZIMBRA_CREDENTIAL_KEY', '').strip()
    if encryption_key:
        if not valid_key(encryption_key):
            raise ValueError('Saved ZIMBRA_CREDENTIAL_KEY is invalid. Recover the correct shared key before continuing')
        print('Keeping the existing Zimbra encryption key.')
    else:
        print('If another server uses this accounts collection, paste its SAME encryption key.')
        encryption_key = hidden('Shared Zimbra encryption key (hidden; Enter only for a NEW accounts collection)')
        if not encryption_key:
            if prompt('Type NEW to generate a key for a new accounts collection') != 'NEW':
                raise ValueError('No encryption key selected')
            encryption_key = base64.b64encode(secrets.token_bytes(32)).decode()
        if not valid_key(encryption_key):
            raise ValueError('ZIMBRA_CREDENTIAL_KEY must be base64 encoding of exactly 32 bytes')
    port = require_port(prompt('Public HTTP port', env.get('PORT', '9100')))
    updates = {
        'LOCAL_MONGO_URI': mongo, 'MONGO_URI': mongo,
        'WEB_DATABASE': web_db, 'VULNERABILITIES_DATABASE': vuln_db,
        'VULNERABILITIES_COLLECTION': 'news', 'ACCOUNT_COLLECTION': 'accounts',
        'FLASK_SECRET_KEY': session_key, 'WEB_AUTH_BOOTSTRAP_USERNAME': username,
        'WEB_AUTH_BOOTSTRAP_PASSWORD': password,
        'ZIMBRA_BASE_URL': zimbra_url.rstrip('/'), 'ZIMBRA_FOLDER_NAME': zimbra_folder,
        'ZIMBRA_TIMEOUT_SECONDS': env.get('ZIMBRA_TIMEOUT_SECONDS', '10'),
        'ZIMBRA_VERIFY_TLS': 'true', 'ZIMBRA_CREDENTIAL_KEY': encryption_key,
        'PORT': port, 'RUST_SCHEDULER_ENABLED': 'false',
    }
    if prompt('Configure SMTP now? (otherwise existing values are kept)', 'yes').lower() in ('y', 'yes'):
        updates['SMTP_HOST'] = prompt('SMTP host (optional)', env.get('SMTP_HOST', ''))
        if updates['SMTP_HOST']:
            updates['SMTP_PORT'] = require_port(prompt('SMTP port', env.get('SMTP_PORT', '587')))
            updates['SMTP_USERNAME'] = prompt('SMTP username (optional)', env.get('SMTP_USERNAME', ''))
            updates['SMTP_PASSWORD'] = hidden('SMTP password (optional)', env.get('SMTP_PASSWORD', ''))
            updates['SMTP_FROM'] = prompt('SMTP sender address', env.get('SMTP_FROM', ''))
            current_transport = 'tls' if env.get('SMTP_USE_SSL', '').lower() == 'true' else ('plain' if env.get('SMTP_USE_TLS', '').lower() == 'false' else 'starttls')
            transport = prompt('SMTP transport: starttls, tls, or plain', current_transport)
            if transport not in ('starttls', 'tls', 'plain'):
                raise ValueError('Invalid SMTP transport')
            updates['SMTP_USE_TLS'] = str(transport == 'starttls').lower()
            updates['SMTP_USE_SSL'] = str(transport == 'tls').lower()
    newsletter = env.get('NEWSLETTER_ROOT') or config.get('newsletter_root', 'newsletters')
    newsletter_path = Path(newsletter)
    if not newsletter_path.is_absolute():
        newsletter_path = repo / newsletter_path
    newsletter_path = newsletter_path.resolve()
    updates['NEWSLETTER_ROOT'] = str(newsletter_path)
    if (repo / '.env').exists():
        # Preserve comments and settings that this installer does not manage.
        original_text = original_env.read_text() if original_env.exists() else (repo / '.env').read_text()
        atomic_text(repo / '.env', original_text)
    elif original_env.exists():
        atomic_text(repo / '.env', original_env.read_text())
    update_env(repo / '.env', updates)
    config.setdefault('mongodb', {}).update(web_database=web_db, vulnerabilities_database=vuln_db, vulnerabilities_collection='news')
    config['account_collection'] = 'accounts'
    atomic_text(config_path, json.dumps(config, indent=2, ensure_ascii=False) + '\n')
    atomic_text(backup / 'settings.json', json.dumps({'port': int(port), 'newsletter_path': str(newsletter_path.resolve())}))
    print('Configuration saved. Secret values were not printed. Scheduled delivery is disabled.')

def main():
    operation = sys.argv[1]
    if operation == 'configure':
        configure(Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4])
    elif operation == 'get':
        print(json.loads(Path(sys.argv[2]).read_text())[sys.argv[3]])
    elif operation == 'scheduler':
        for filename in sys.argv[3:]:
            update_env(Path(filename), {'RUST_SCHEDULER_ENABLED': sys.argv[2]})
    elif operation == 'free-port':
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            print(sock.getsockname()[1])
    elif operation == 'port-free':
        with socket.socket() as sock:
            try:
                sock.bind(('0.0.0.0', int(sys.argv[2])))
            except OSError:
                sys.exit(1)
    elif operation == 'compose':
        release, image, port, newsletter, output = sys.argv[2:]
        # JSON is valid YAML. Values are quoted without shell/YAML interpolation.
        data = {'services': {'web': {
            'image': image, 'restart': 'unless-stopped',
            'ports': [port + ':9100'],
            'environment': {'WEBSERVER_ROOT': '/app', 'PORT': '9100', 'NEWSLETTER_ROOT': '/app/newsletters'},
            'extra_hosts': ['host.docker.internal:host-gateway'],
            'volumes': [
                {'type': 'bind', 'source': release + '/.env', 'target': '/app/.env', 'read_only': True},
                {'type': 'bind', 'source': release + '/config', 'target': '/app/config', 'read_only': True},
                {'type': 'bind', 'source': newsletter, 'target': '/app/newsletters'},
            ],
        }}}
        # Compose interpolates dollars even in JSON strings.
        atomic_text(Path(output), json.dumps(data, indent=2).replace('$', '$$') + '\n')
    else:
        raise ValueError('Unknown helper operation')

if __name__ == '__main__':
    try:
        main()
    except (ValueError, EOFError, OSError) as error:
        print('Configuration error: ' + str(error), file=sys.stderr)
        sys.exit(1)
PY_SETUP
}

ensure_tools() {
    local missing= tool
    for tool in git python3 curl tar; do
        command -v "$tool" >/dev/null 2>&1 || missing="$missing $tool"
    done
    if [[ -n "$missing" ]]; then
        command -v apt-get >/dev/null 2>&1 || die "Install these tools first:$missing"
        confirm "Install missing prerequisites using apt-get?$missing" y || die 'Prerequisites are required.'
        apt-get update
        apt-get install -y git python3 curl ca-certificates tar
    fi
}

ensure_docker() {
    local packages= compose_package=
    if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
        command -v apt-get >/dev/null 2>&1 || die 'Install Docker Engine and the Compose v2 plugin first, or select local installation.'
        confirm 'Install missing Docker/Compose packages from the configured apt repositories?' y || return 1
        apt-get update
        if ! command -v docker >/dev/null 2>&1; then packages=docker.io; fi
        if ! docker compose version >/dev/null 2>&1; then
            if apt-cache show docker-compose-v2 >/dev/null 2>&1; then compose_package=docker-compose-v2;
            elif apt-cache show docker-compose-plugin >/dev/null 2>&1; then compose_package=docker-compose-plugin;
            else die 'No Compose v2 package is available in the configured apt repositories. Install the official Compose plugin, then rerun.'; fi
        fi
        # Both variables contain only installer-selected package names.
        apt-get install -y ${packages:+"$packages"} ${compose_package:+"$compose_package"}
    fi
    if ! docker info >/dev/null 2>&1; then
        command -v systemctl >/dev/null 2>&1 || die 'Start the Docker daemon, then rerun.'
        confirm 'Start Docker and enable it at boot?' y || return 1
        systemctl enable --now docker
    fi
    docker info >/dev/null
    docker compose version >/dev/null
}

snapshot_repository() {
    ORIGINAL_BRANCH=$(g symbolic-ref --quiet --short HEAD || true)
    ORIGINAL_HEAD=$(g rev-parse HEAD)
    printf '%s\n' "$ORIGINAL_BRANCH" > "$BACKUP_DIR/original-branch"
    printf '%s\n' "$ORIGINAL_HEAD" > "$BACKUP_DIR/original-head"
    g status --short > "$BACKUP_DIR/git-status.txt"
    g diff --binary HEAD > "$BACKUP_DIR/local-changes.patch"
    if [[ -f "$REPO_DIR/.env" ]]; then cp -p "$REPO_DIR/.env" "$BACKUP_DIR/.env"; fi
    if [[ -d "$REPO_DIR/config" ]]; then cp -a "$REPO_DIR/config" "$BACKUP_DIR/config"; fi
    say "Saving working files to $BACKUP_DIR/working-tree.tar.gz"
    tar -C "$REPO_DIR" --exclude='./.git' --exclude='./target' --exclude='./node_modules' \
        --exclude='./outputs' --exclude='./output' -czf "$BACKUP_DIR/working-tree.tar.gz" .
    g branch "backup/setup-$SETUP_ID" HEAD
    if [[ -n "$(g status --porcelain --untracked-files=normal)" ]]; then
        g stash push --include-untracked --message "setup.sh backup $SETUP_ID"
        STASH_SHA=$(g rev-parse refs/stash)
        printf '%s\n' "$STASH_SHA" > "$BACKUP_DIR/stash-commit"
    fi
    SOURCE_CHANGED=1
}

switch_branch() {
    local remote="refs/remotes/origin/$TARGET_BRANCH"
    local refspecs
    refspecs=$(g config --get-all remote.origin.fetch || true)
    if ! printf '%s\n' "$refspecs" | grep -Fxq '+refs/heads/*:refs/remotes/origin/*' && \
        ! printf '%s\n' "$refspecs" | grep -Fxq "+refs/heads/$TARGET_BRANCH:$remote"; then
        # A single-branch clone must also learn this mapping so tracking and
        # subsequent plain git pull commands can resolve the new upstream.
        g remote set-branches --add origin "$TARGET_BRANCH"
    fi
    # Fetch only the required ref, including repositories cloned with --single-branch.
    g fetch origin "refs/heads/$TARGET_BRANCH:$remote"
    if g show-ref --verify --quiet "refs/heads/$TARGET_BRANCH"; then
        if ! g merge-base --is-ancestor "refs/heads/$TARGET_BRANCH" "$remote"; then
            say "The local $TARGET_BRANCH branch has commits outside origin."
            confirm 'Preserve that branch under a backup name and deploy origin?' n || return 1
            SAVED_TARGET_BRANCH="backup/target-$SETUP_ID"
            g branch -m "$TARGET_BRANCH" "$SAVED_TARGET_BRANCH"
            g switch --create "$TARGET_BRANCH" --track "origin/$TARGET_BRANCH"
        else
            g switch "$TARGET_BRANCH"
            g merge --ff-only "$remote"
        fi
    else
        g switch --create "$TARGET_BRANCH" --track "origin/$TARGET_BRANCH"
    fi
    g branch --set-upstream-to="origin/$TARGET_BRANCH" "$TARGET_BRANCH"
    [[ -f "$REPO_DIR/src/zimbra.rs" ]] || die 'Selected branch does not contain the Zimbra implementation.'
}

restore_source() {
    [[ "$SOURCE_CHANGED" == 1 ]] || return 0
    say 'Restoring the previous checkout and configuration.'
    # Retain anything the installer configured on the new branch, too.
    if [[ -n "$(g status --porcelain --untracked-files=normal)" ]]; then
        g stash push --include-untracked --message "setup.sh incomplete deployment $SETUP_ID" || return 1
    fi
    if [[ -n "$ORIGINAL_BRANCH" ]]; then
        if [[ "$(g rev-parse "refs/heads/$ORIGINAL_BRANCH" 2>/dev/null || true)" != "$ORIGINAL_HEAD" ]]; then
            # Preserve the new branch and recreate the previous branch at its
            # exact commit, including an update that originally started on target.
            g switch --detach "$ORIGINAL_HEAD" || return 1
            if g show-ref --verify --quiet "refs/heads/$ORIGINAL_BRANCH"; then
                g branch -m "$ORIGINAL_BRANCH" "backup/incomplete-$SETUP_ID" || return 1
            fi
            g switch --create "$ORIGINAL_BRANCH" "$ORIGINAL_HEAD" || return 1
        else
            g switch "$ORIGINAL_BRANCH" || return 1
        fi
    else
        g switch --detach "$ORIGINAL_HEAD" || return 1
    fi
    if [[ -n "$STASH_SHA" ]]; then g stash apply --index "$STASH_SHA" || return 1; fi
    if [[ -f "$BACKUP_DIR/.env" ]]; then
        cp -p "$BACKUP_DIR/.env" "$REPO_DIR/.env"
    elif [[ -f "$REPO_DIR/.env" ]]; then
        mv "$REPO_DIR/.env" "$BACKUP_DIR/new-deployment.env"
    fi
    SOURCE_CHANGED=0
}

stop_candidate() {
    if [[ -n "$CANDIDATE_PID" ]]; then
        kill "$CANDIDATE_PID" 2>/dev/null || true
        wait "$CANDIDATE_PID" 2>/dev/null || true
        CANDIDATE_PID=
    fi
    if [[ -n "$CANDIDATE_CONTAINER" ]]; then
        docker logs "$CANDIDATE_CONTAINER" > "$BACKUP_DIR/candidate.log" 2>&1 || true
        docker rm --force "$CANDIDATE_CONTAINER" >/dev/null 2>&1 || true
        CANDIDATE_CONTAINER=
    fi
}

rollback_runtime() {
    local source_restored=${1:-0}
    if [[ "$SERVICE_CHANGED" == 1 ]]; then
        systemctl stop "$UNIT_NAME" || true
        if [[ -f "$BACKUP_DIR/managed.service" ]]; then
            cp -p "$BACKUP_DIR/managed.service" "$UNIT_DIR/$UNIT_NAME"
        else
            rm -f "$UNIT_DIR/$UNIT_NAME"
        fi
        systemctl daemon-reload
        if [[ -f "$BACKUP_DIR/managed-service-enabled" ]]; then systemctl enable "$UNIT_NAME";
        else systemctl disable "$UNIT_NAME" >/dev/null 2>&1 || true; fi
        if [[ -f "$BACKUP_DIR/managed-service-active" ]]; then systemctl start "$UNIT_NAME"; fi
    fi
    if [[ "$COMPOSE_CHANGED" == 1 ]]; then
        docker compose -p "$COMPOSE_PROJECT" -f "$INSTALL_ROOT/compose.json" down || true
        if [[ -f "$BACKUP_DIR/managed-compose.json" ]]; then
            cp -p "$BACKUP_DIR/managed-compose.json" "$INSTALL_ROOT/compose.json"
            if [[ -f "$BACKUP_DIR/managed-compose-active" ]]; then
                docker compose -p "$COMPOSE_PROJECT" -f "$INSTALL_ROOT/compose.json" up -d --no-deps --no-build web
            fi
        fi
    fi
    if [[ "$LEGACY_STOPPED" == 1 && "$source_restored" == 0 ]]; then
        if [[ "$LEGACY_KIND" == systemd ]]; then
            if [[ "$LEGACY_ENABLED" == enabled ]]; then systemctl enable "$LEGACY_NAME"; fi
            systemctl start "$LEGACY_NAME"
        else
            docker update --restart="$LEGACY_RESTART" "$LEGACY_NAME" >/dev/null
            docker start "$LEGACY_NAME" >/dev/null
        fi
    fi
}

failed() {
    local status=${1:-1}
    [[ "$ROLLING_BACK" == 0 ]] || exit "$status"
    ROLLING_BACK=1
    trap - ERR INT TERM
    set +e
    stop_candidate
    restore_source
    local source_status=$?
    rollback_runtime "$source_status"
    if [[ "$source_status" != 0 ]]; then
        printf 'Source restoration needs attention. Legacy services were not restarted automatically.\n' >&2
    fi
    printf '\nInstallation did not complete (exit %s). Backup: %s\n' "$status" "${BACKUP_DIR:-not yet created}" >&2
    printf 'No database collections or views were migrated or deleted.\n' >&2
    exit "$status"
}

wait_for_login() {
    local port=$1 attempt
    for attempt in $(seq 1 40); do
        if curl --noproxy '*' --connect-timeout 1 --max-time 2 --fail --silent \
            "http://127.0.0.1:$port/login" > "$BACKUP_DIR/login-check.html"; then
            if grep -q 'Zimbra email address' "$BACKUP_DIR/login-check.html" && \
                curl --noproxy '*' --max-time 2 --fail --silent \
                    "http://127.0.0.1:$port/login/local" > /dev/null; then return 0; fi
        fi
        if [[ -n "$CANDIDATE_PID" ]] && ! kill -0 "$CANDIDATE_PID" 2>/dev/null; then break; fi
        sleep 2
    done
    die "Login checks failed on port $port. Private logs are in $BACKUP_DIR."
}

choose_legacy() {
    config_helper port-free "$PUBLIC_PORT" && return 0
    say "Port $PUBLIC_PORT is currently occupied. The candidate will be tested before cutover."
    if command -v ss >/dev/null 2>&1; then ss -ltnp "sport = :$PUBLIC_PORT" || true; fi
    if command -v docker >/dev/null 2>&1; then docker ps --format 'table {{.Names}}\t{{.Ports}}' || true; fi
    # An earlier setup deployment will be replaced by its own manager.
    if [[ "$MODE" == native ]] && systemctl is-active --quiet "$UNIT_NAME"; then
        say "The managed service $UNIT_NAME will be restarted after the candidate passes."
        return 0
    fi
    if [[ "$MODE" == docker && -f "$INSTALL_ROOT/compose.json" ]] && \
        [[ -n "$(docker compose -p "$COMPOSE_PROJECT" -f "$INSTALL_ROOT/compose.json" ps --status running -q web)" ]]; then
        say 'The previous setup Compose deployment will be replaced after the candidate passes.'
        return 0
    fi
    read_value 'Current deployment: 1=systemd service, 2=Docker container, 3=cancel' 3
    case "$REPLY" in
        1)
            LEGACY_KIND=systemd
            read_value 'Existing systemd service name'
            LEGACY_NAME=$REPLY
            [[ "$LEGACY_NAME" =~ ^[A-Za-z0-9_.@-]+\.service$ && "$LEGACY_NAME" != -* ]] || die 'Enter an exact .service name.'
            systemctl is-active --quiet "$LEGACY_NAME" || die 'That service is not active.'
            LEGACY_ENABLED=$(systemctl is-enabled "$LEGACY_NAME" 2>/dev/null || true)
            ;;
        2)
            LEGACY_KIND=docker
            read_value 'Existing Docker container name'
            LEGACY_NAME=$REPLY
            [[ "$LEGACY_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || die 'Invalid container name.'
            [[ "$(docker inspect --format '{{.State.Running}}' "$LEGACY_NAME")" == true ]] || die 'That container is not running.'
            LEGACY_RESTART=$(docker inspect --format '{{.HostConfig.RestartPolicy.Name}}' "$LEGACY_NAME")
            if [[ "$LEGACY_RESTART" == on-failure ]]; then
                LEGACY_RESTART="on-failure:$(docker inspect --format '{{.HostConfig.RestartPolicy.MaximumRetryCount}}' "$LEGACY_NAME")"
            fi
            ;;
        *) die 'Choose another public port or identify the existing deployment before continuing.' ;;
    esac
    confirm "Stop $LEGACY_NAME at cutover and disable its automatic restart after success?" n || return 1
}

stop_legacy() {
    [[ -n "$LEGACY_NAME" ]] || return 0
    LEGACY_STOPPED=1
    if [[ "$LEGACY_KIND" == systemd ]]; then systemctl stop "$LEGACY_NAME";
    else docker stop "$LEGACY_NAME" >/dev/null; fi
    config_helper port-free "$PUBLIC_PORT" || die 'The public port is still occupied; cutover was stopped.'
}

retire_legacy() {
    [[ "$LEGACY_STOPPED" == 1 ]] || return 0
    if [[ "$LEGACY_KIND" == systemd ]]; then
        if [[ "$LEGACY_ENABLED" == enabled ]]; then systemctl disable "$LEGACY_NAME"; fi
    else
        docker update --restart=no "$LEGACY_NAME" >/dev/null
    fi
}

build_native() {
    command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]] || die 'systemd is not running; select Docker or prepare-only.'
    if [[ -n "$(systemctl show --property=DropInPaths --value "$UNIT_NAME" 2>/dev/null)" ]]; then
        die "$UNIT_NAME has custom systemd overrides; move them aside or choose a different deployment method."
    fi
    if ! command -v cc >/dev/null 2>&1; then
        command -v apt-get >/dev/null 2>&1 || die 'Install a C linker/build-essential first.'
        confirm 'Install native build prerequisites with apt-get?' y || return 1
        apt-get update
        apt-get install -y build-essential pkg-config ca-certificates
    fi
    export PATH="${HOME}/.cargo/bin:$PATH"
    if ! command -v rustup >/dev/null 2>&1; then
        confirm 'Install the official Rust toolchain using https://sh.rustup.rs?' y || return 1
        curl --proto '=https' --tlsv1.2 --fail --silent --show-error https://sh.rustup.rs -o "$BACKUP_DIR/rustup-init.sh"
        sh "$BACKUP_DIR/rustup-init.sh" -y --profile minimal --default-toolchain 1.91.0 --no-modify-path
    fi
    rustup toolchain install 1.91.0 --profile minimal
    (cd "$REPO_DIR" && cargo +1.91.0 build --release --locked --target-dir "$BACKUP_DIR/build")
    install -m 0755 "$BACKUP_DIR/build/release/webserver-rust" "$RELEASE_DIR/webserver-rust"
    local candidate_port
    candidate_port=$(config_helper free-port)
    say "Testing the new binary on 127.0.0.1:$candidate_port with its scheduler disabled."
    env -i PATH="$PATH" HOME="$HOME" WEBSERVER_ROOT="$RELEASE_DIR" PORT="$candidate_port" \
        RUST_SCHEDULER_ENABLED=false "$RELEASE_DIR/webserver-rust" > "$BACKUP_DIR/candidate.log" 2>&1 &
    CANDIDATE_PID=$!
    wait_for_login "$candidate_port"
    stop_candidate
}

activate_native() {
    local unit="$UNIT_DIR/$UNIT_NAME"
    if [[ -e "$unit" ]]; then cp -p "$unit" "$BACKUP_DIR/managed.service"; fi
    if systemctl is-active --quiet "$UNIT_NAME"; then touch "$BACKUP_DIR/managed-service-active"; fi
    if systemctl is-enabled --quiet "$UNIT_NAME"; then touch "$BACKUP_DIR/managed-service-enabled"; fi
    cat > "$BACKUP_DIR/new.service" <<EOF_UNIT
[Unit]
Description=Rust security newsletter portal
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$RELEASE_DIR
Environment=WEBSERVER_ROOT=$RELEASE_DIR
ExecStart=$RELEASE_DIR/webserver-rust
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF_UNIT
    systemd-analyze verify "$BACKUP_DIR/new.service"
    stop_legacy
    SERVICE_CHANGED=1
    install -m 0644 "$BACKUP_DIR/new.service" "$unit"
    systemctl daemon-reload
    systemctl restart "$UNIT_NAME"
    wait_for_login "$PUBLIC_PORT"
    systemctl is-active --quiet "$UNIT_NAME"
    systemctl enable "$UNIT_NAME"
}

prepare_docker_context() {
    local context=$1
    mkdir "$context"
    cp -a "$REPO_DIR/Cargo.toml" "$REPO_DIR/Cargo.lock" "$REPO_DIR/Dockerfile" \
        "$REPO_DIR/src" "$REPO_DIR/templates" "$REPO_DIR/static" "$context/"
    mkdir "$context/config"
    # Build defaults into the image; local secrets/settings are runtime mounts.
    g show "origin/$TARGET_BRANCH:config/config.json" > "$context/config/config.json"
    cp -a "$REPO_DIR/config/translations.json" "$context/config/"
}

build_docker() {
    command -v docker >/dev/null 2>&1 || die 'Install Docker Engine and its Compose plugin first, or choose systemd.'
    docker info >/dev/null
    docker compose version >/dev/null
    if [[ ! -f "$INSTALL_ROOT/compose.json" ]] && \
        [[ -n "$(docker ps --all --quiet --filter "label=com.docker.compose.project=$COMPOSE_PROJECT")" ]]; then
        die "Docker project $COMPOSE_PROJECT already exists without an installer manifest; deployment was stopped."
    fi
    local context="$BACKUP_DIR/docker-build" candidate_port
    prepare_docker_context "$context"
    IMAGE_TAG="webserver-rust:setup-$SETUP_ID"
    docker build --tag "$IMAGE_TAG" "$context"
    candidate_port=$(config_helper free-port)
    CANDIDATE_CONTAINER="webserver-rust-check-$SETUP_ID"
    docker run --detach --name "$CANDIDATE_CONTAINER" \
        --publish "127.0.0.1:$candidate_port:9100" \
        --add-host host.docker.internal:host-gateway \
        --env WEBSERVER_ROOT=/app --env PORT=9100 --env RUST_SCHEDULER_ENABLED=false \
        --env NEWSLETTER_ROOT=/app/newsletters \
        --mount "type=bind,source=$RELEASE_DIR/.env,target=/app/.env,readonly" \
        --mount "type=bind,source=$RELEASE_DIR/config,target=/app/config,readonly" \
        --mount "type=bind,source=$NEWSLETTER_PATH,target=/app/newsletters" \
        "$IMAGE_TAG" >/dev/null
    wait_for_login "$candidate_port"
    stop_candidate
    config_helper compose "$RELEASE_DIR" "$IMAGE_TAG" "$PUBLIC_PORT" "$NEWSLETTER_PATH" "$BACKUP_DIR/new-compose.json"
    docker compose -p "$COMPOSE_PROJECT" -f "$BACKUP_DIR/new-compose.json" config --quiet
}

activate_docker() {
    if [[ -f "$INSTALL_ROOT/compose.json" ]]; then
        cp -p "$INSTALL_ROOT/compose.json" "$BACKUP_DIR/managed-compose.json"
        if [[ -n "$(docker compose -p "$COMPOSE_PROJECT" -f "$INSTALL_ROOT/compose.json" ps --status running -q web)" ]]; then
            touch "$BACKUP_DIR/managed-compose-active"
        fi
    fi
    stop_legacy
    COMPOSE_CHANGED=1
    install -m 0600 "$BACKUP_DIR/new-compose.json" "$INSTALL_ROOT/compose.json"
    docker compose -p "$COMPOSE_PROJECT" -f "$INSTALL_ROOT/compose.json" up -d --no-deps --no-build web
    wait_for_login "$PUBLIC_PORT"
}

usage() {
    cat <<'EOF_HELP'
Usage: sudo bash setup.sh [--repo /root/WEBSEVER]
       bash setup.sh --help
       bash setup.sh --check

Interactive Linux installation/update of redesign/unified-news-collection.
Modes: native Rust + systemd, Docker Compose, or configuration only.
Backs up local files/configuration, stashes edits, preserves divergent commits,
and tests the new application before stopping a selected old deployment.
The script does not migrate MongoDB collections or delete Git stashes/backups.
--check only checks syntax/prerequisites; it does not install or contact services.
EOF_HELP
}

main() {
    local requested_repo= default_repo= mode_answer
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --repo) [[ $# -ge 2 ]] || die '--repo requires a directory'; requested_repo=$2; shift 2 ;;
            *) die "Unknown argument: $1" ;;
        esac
    done
    [[ "$(uname -s)" == Linux ]] || die 'Run this installer on the Linux server.'
    [[ "$(id -u)" == 0 ]] || die 'Run sudo bash setup.sh (root is required for deployment and private backups).'
    exec 3<> /dev/tty
    say 'Interactive security newsletter portal installation'
    say 'This branch uses Zimbra login, web.accounts, and unified news documents.'
    say 'AccountHub identities/subscription ownership are not migrated. Existing settings and keys will be preserved.'
    say 'Where would you like to install?'
    printf '  1) Locally (Rust + systemd)\n  2) In Docker (Docker Compose)\n  3) Configure only, without starting a service\n'
    read_value 'Installation method' 1
    mode_answer=$REPLY
    case "$mode_answer" in 1) MODE=native ;; 2) MODE=docker ;; 3) MODE=prepare ;; *) die 'Choose 1, 2, or 3.' ;; esac
    ensure_tools
    if [[ "$MODE" == native ]]; then
        say 'The local systemd service runs as root, matching a root-owned server installation.'
        command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]] || die 'systemd is not running; rerun and select Docker or configure-only.'
    elif [[ "$MODE" == docker ]]; then
        ensure_docker
    fi
    default_repo=${requested_repo:-/root/WEBSEVER}
    read_value 'Project checkout directory' "$default_repo"
    REPO_DIR=$(python3 -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).expanduser().resolve())' "$REPLY")
    [[ "$REPO_DIR" != / && "$REPO_DIR" != *$'\n'* && "$REPO_DIR" != *$'\r'* ]] || die 'Invalid repository path.'
    if ! g rev-parse --git-dir >/dev/null 2>&1; then
        [[ ! -e "$REPO_DIR" ]] || [[ -z "$(ls -A "$REPO_DIR")" ]] || die 'The selected directory exists and is not a Git checkout.'
        confirm "Clone $DEFAULT_REPOSITORY into $REPO_DIR?" y || return 1
        git clone --branch "$TARGET_BRANCH" "$DEFAULT_REPOSITORY" "$REPO_DIR"
    fi
    [[ "$(g rev-parse --show-toplevel)" == "$REPO_DIR" ]] || die 'Select the repository root directory.'
    if [[ -n "$(g ls-files -u)" ]]; then die 'Resolve the existing Git merge conflicts before installing.'; fi
    g branch --show-current
    g status --short
    say 'Runtime releases: /opt/webserver-rust-setup. Private backups: /var/backups/webserver-rust-setup.'
    confirm "Back up local work and install origin/$TARGET_BRANCH?" y || return 1
    SETUP_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
    mkdir -p "$BACKUP_ROOT" "$INSTALL_ROOT/releases"
    chmod 0700 "$BACKUP_ROOT" "$INSTALL_ROOT"
    BACKUP_DIR="$BACKUP_ROOT/$SETUP_ID"
    RELEASE_DIR="$INSTALL_ROOT/releases/$SETUP_ID"
    mkdir -m 0700 "$BACKUP_DIR" "$RELEASE_DIR"
    install -m 0700 "${BASH_SOURCE[0]}" "$INSTALL_ROOT/setup.sh"
    trap 'failed $?' ERR
    trap 'failed 130' INT
    trap 'failed 143' TERM
    snapshot_repository
    switch_branch
    config_helper configure "$REPO_DIR" "$BACKUP_DIR" "$MODE"
    PUBLIC_PORT=$(config_helper get "$BACKUP_DIR/settings.json" port)
    NEWSLETTER_PATH=$(config_helper get "$BACKUP_DIR/settings.json" newsletter_path)
    [[ "$NEWSLETTER_PATH" != *','* && "$NEWSLETTER_PATH" != *$'\n'* ]] || die 'Newsletter path cannot contain a comma or newline.'
    mkdir -p "$NEWSLETTER_PATH"
    cp -a "$REPO_DIR/templates" "$REPO_DIR/static" "$REPO_DIR/config" "$RELEASE_DIR/"
    cp -p "$REPO_DIR/.env" "$RELEASE_DIR/.env"
    # Runtime root is independent of the checkout, even if an old .env had WEBSERVER_ROOT.
    if [[ "$MODE" == native ]]; then
        choose_legacy
        build_native
        activate_native
    elif [[ "$MODE" == docker ]]; then
        choose_legacy
        build_docker
        activate_docker
    else
        say 'Configuration prepared. No service was started or restarted.'
    fi
    if [[ "$MODE" != prepare ]]; then
        say 'Both Zimbra and local-administrator login pages passed the HTTP checks.'
        say 'Test an actual Zimbra login, subscription ownership, and SMTP delivery in the browser.'
        say 'For a shared database, run scheduled delivery on only one server.'
        if confirm 'Enable scheduled email delivery on THIS instance now?' n; then
            config_helper scheduler true "$REPO_DIR/.env" "$RELEASE_DIR/.env"
            if [[ "$MODE" == native ]]; then systemctl restart "$UNIT_NAME";
            else docker compose -p "$COMPOSE_PROJECT" -f "$INSTALL_ROOT/compose.json" up -d --force-recreate --no-deps --no-build web; fi
            wait_for_login "$PUBLIC_PORT"
        fi
        retire_legacy
    fi
    SUCCESS=1
    trap - ERR INT TERM
    say "Completed. Branch: $(g branch --show-current), commit: $(g rev-parse --short HEAD)"
    say "Backup: $BACKUP_DIR"
    printf 'Rerun installer: bash %q --repo %q\n' "$INSTALL_ROOT/setup.sh" "$REPO_DIR"
    if [[ -n "$STASH_SHA" ]]; then say "Original local changes are preserved in Git stash commit $STASH_SHA."; fi
    if [[ "$MODE" != prepare ]]; then
        say "Open http://SERVER_IP:$PUBLIC_PORT/login or /login/local. Runtime .env: $RELEASE_DIR/.env"
        if [[ "$MODE" == native ]]; then say "Service: $UNIT_NAME (journalctl -u $UNIT_NAME)";
        else say "Compose: docker compose -p $COMPOSE_PROJECT -f $INSTALL_ROOT/compose.json logs --tail=100 web"; fi
    fi
    say 'MongoDB data was not migrated. Coordinate crawler news migration separately with servers still on main.'
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    case "${1:-}" in
        --help|-h) usage; exit 0 ;;
        --check)
            bash -n "${BASH_SOURCE[0]}"
            for setup_tool in git python3 curl tar; do
                command -v "$setup_tool" >/dev/null 2>&1 || { printf 'Missing: %s\n' "$setup_tool"; exit 1; }
            done
            printf 'Syntax and basic prerequisites passed. Deployment target must be Linux.\n'
            exit 0 ;;
    esac
    # A stash/checkout can remove the downloaded installer. Execute a private
    # copy outside the repository before reading any interactive answers.
    if [[ "${1:-}" != --internal-copy ]]; then
        setup_copy=$(mktemp "${TMPDIR:-/tmp}/webserver-setup.XXXXXXXX")
        cp "${BASH_SOURCE[0]}" "$setup_copy"
        chmod 0700 "$setup_copy"
        exec bash "$setup_copy" --internal-copy "$@"
    fi
    shift
    trap 'rm -f -- "${BASH_SOURCE[0]}"' EXIT
    main "$@"
fi
