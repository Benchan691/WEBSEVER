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
    [[ "$REPLY" != :cancel ]] || return 130
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

choose_recovery() {
    local label=$1 configure=${2:-no}
    say "$label" >&3
    while true; do
        if [[ "$configure" == yes ]]; then
            read_value '1=retry, 2=re-enter configuration, 3=cancel and restore' 1 || return 130
            case "$REPLY" in 1) RETRY_ACTION=retry; return 0 ;; 2) RETRY_ACTION=configure; return 0 ;; 3) RETRY_ACTION=cancel; return 0 ;; esac
        else
            read_value '1=retry after fixing the cause, 2=cancel' 1 || return 130
            case "$REPLY" in 1) RETRY_ACTION=retry; return 0 ;; 2) RETRY_ACTION=cancel; return 0 ;; esac
        fi
        say 'Enter one of the listed choices.' >&3
    done
}

# Only wrap individual commands, not compound Bash stages: putting a function
# in an if-condition disables errexit inside that entire function.
retry_command() {
    local label=$1 status
    shift
    while true; do
        if "$@"; then return 0; else status=$?; fi
        [[ "$status" != 130 && "$status" != 143 ]] || return "$status"
        choose_recovery "$label failed (exit $status)." || return 130
        [[ "$RETRY_ACTION" == retry ]] || return "$status"
    done
}

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
    if answer.rstrip('\n') == ':cancel':
        raise EOFError('Configuration cancelled')
    return answer.rstrip('\n') or default

def hidden(label, current='', default=''):
    hint = ' (Enter to keep configured value)' if current else ''
    with open('/dev/tty', 'w') as tty:
        answer = getpass.getpass(label + hint + ': ', stream=tty)
    if answer == ':cancel':
        raise EOFError('Configuration cancelled')
    return answer or current or default

def validated(reader, validator):
    while True:
        value = reader()
        if value == ':cancel':
            raise EOFError('Configuration cancelled')
        try:
            return validator(value)
        except ValueError as error:
            print('Invalid entry: ' + str(error) + '. Please retype this value.')

def require_choice(value, choices):
    value = value.strip().lower()
    if value not in choices:
        raise ValueError('Choose ' + ', '.join(choices))
    return value

def require_mongo(value):
    if not value.startswith(('mongodb://', 'mongodb+srv://')) or any(ch.isspace() for ch in value):
        raise ValueError('MongoDB URI must start with mongodb:// or mongodb+srv:// and contain no unescaped whitespace')
    if not re.split(r'[/?]', value.split('://', 1)[1], 1)[0]:
        raise ValueError('MongoDB URI requires a host')
    return value

def require_zimbra_url(value):
    try:
        url = urlsplit(value)
        valid = url.scheme == 'https' and url.hostname and not url.username and not url.password
        valid = valid and not any(ch.isspace() for ch in value) and (url.port is None or 1 <= url.port <= 65535)
    except ValueError:
        valid = False
    if not valid:
        raise ValueError('Use a valid HTTPS Zimbra URL without embedded credentials')
    return value

def require_key(value):
    value = value.strip()
    if not valid_key(value):
        raise ValueError('The encryption key must be base64 encoding of exactly 32 bytes')
    return value

def require_newsletter_path(value, repo):
    if not value or any(ch in value for ch in (',', '\n', '\r', '\x00')):
        raise ValueError('The directory must be nonempty and contain no commas or line breaks')
    try:
        path = Path(value).expanduser()
        path = (repo / path).resolve() if not path.is_absolute() else path.resolve()
        if path.exists() and not path.is_dir():
            raise ValueError('Select a directory rather than a file')
    except OSError:
        raise ValueError('The directory path cannot be resolved') from None
    return path

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

def configure(repo, backup, mode, reuse_current=False):
    original_env = backup / '.env'
    env_path = repo / '.env' if reuse_current else (original_env if original_env.exists() else repo / '.env')
    original_text, env = read_env(env_path)
    config_path = repo / 'config/config.json'
    defaults = json.loads(config_path.read_text())
    old_path = config_path if reuse_current else backup / 'config/config.json'
    previous = json.loads(old_path.read_text()) if old_path.exists() else {}
    if not isinstance(defaults, dict) or not isinstance(previous, dict):
        raise ValueError('config/config.json must be a JSON object')
    config = merge_settings(defaults, previous)
    mongo = validated(lambda: hidden('MongoDB URI (hidden; default mongodb://127.0.0.1:27017/)', env.get('MONGO_URI') or env.get('LOCAL_MONGO_URI', ''), 'mongodb://127.0.0.1:27017/'), require_mongo)
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
    zimbra_url = validated(lambda: prompt('Zimbra HTTPS URL', env.get('ZIMBRA_BASE_URL') or zimbra.get('base_url', 'https://zmailbox.citictel-cpc.com')), require_zimbra_url)
    zimbra_folder = prompt('Zimbra news folder', env.get('ZIMBRA_FOLDER_NAME') or zimbra.get('folder_name', 'news'))
    encryption_key = env.get('ZIMBRA_CREDENTIAL_KEY', '').strip()
    if encryption_key:
        if not valid_key(encryption_key):
            print('The saved Zimbra encryption key is invalid. Enter the original shared key to preserve encrypted credentials.')
            encryption_key = validated(lambda: hidden('Correct shared Zimbra encryption key (hidden)'), require_key)
        else:
            print('Keeping the existing Zimbra encryption key.')
    else:
        print('If another server uses this accounts collection, paste its SAME encryption key.')
        while True:
            encryption_key = hidden('Shared Zimbra encryption key (hidden; Enter only for a NEW accounts collection)')
            if encryption_key == ':cancel':
                raise EOFError('Configuration cancelled')
            if not encryption_key:
                if prompt('Type NEW to generate a key, or Enter to return to key entry') != 'NEW':
                    print('No key generated. Enter the shared key or confirm NEW for a new collection.')
                    continue
                encryption_key = base64.b64encode(secrets.token_bytes(32)).decode()
            if valid_key(encryption_key):
                break
            print('Invalid encryption key. Paste a key that decodes to exactly 32 bytes.')
    port = validated(lambda: prompt('Public HTTP port', env.get('PORT', '9100')), require_port)
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
    smtp_choice = validated(lambda: prompt('Configure SMTP now? (otherwise existing values are kept)', 'yes'), lambda value: require_choice(value, ('yes', 'y', 'no', 'n')))
    if smtp_choice in ('y', 'yes'):
        updates['SMTP_HOST'] = prompt('SMTP host (optional)', env.get('SMTP_HOST', ''))
        if updates['SMTP_HOST']:
            updates['SMTP_PORT'] = validated(lambda: prompt('SMTP port', env.get('SMTP_PORT', '587')), require_port)
            updates['SMTP_USERNAME'] = prompt('SMTP username (optional)', env.get('SMTP_USERNAME', ''))
            updates['SMTP_PASSWORD'] = hidden('SMTP password (optional)', env.get('SMTP_PASSWORD', ''))
            updates['SMTP_FROM'] = prompt('SMTP sender address', env.get('SMTP_FROM', ''))
            current_transport = 'tls' if env.get('SMTP_USE_SSL', '').lower() == 'true' else ('plain' if env.get('SMTP_USE_TLS', '').lower() == 'false' else 'starttls')
            transport = validated(lambda: prompt('SMTP transport: starttls, tls, or plain', current_transport), lambda value: require_choice(value, ('starttls', 'tls', 'plain')))
            updates['SMTP_USE_TLS'] = str(transport == 'starttls').lower()
            updates['SMTP_USE_SSL'] = str(transport == 'tls').lower()
    newsletter = env.get('NEWSLETTER_ROOT') or config.get('newsletter_root', 'newsletters')
    newsletter_path = validated(lambda: prompt('Newsletter files directory', newsletter), lambda value: require_newsletter_path(value, repo))
    updates['NEWSLETTER_ROOT'] = str(newsletter_path)
    # Preserve comments, unrelated settings, and corrected values on a retry.
    atomic_text(repo / '.env', original_text)
    update_env(repo / '.env', updates)
    config.setdefault('mongodb', {}).update(web_database=web_db, vulnerabilities_database=vuln_db, vulnerabilities_collection='news')
    config['account_collection'] = 'accounts'
    atomic_text(config_path, json.dumps(config, indent=2, ensure_ascii=False) + '\n')
    atomic_text(backup / 'settings.json', json.dumps({'port': int(port), 'newsletter_path': str(newsletter_path.resolve())}))
    print('Configuration saved. Secret values were not printed. Scheduled delivery is disabled.')

def main():
    operation = sys.argv[1]
    if operation == 'configure':
        configure(Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4], len(sys.argv) > 5 and sys.argv[5] == 'current')
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
    except EOFError as error:
        print(str(error), file=sys.stderr)
        sys.exit(130)
    except (ValueError, OSError) as error:
        print('Configuration error: ' + str(error), file=sys.stderr)
        sys.exit(1)
PY_SETUP
}

configure_interactively() {
    local use_current=${1:-original} status
    while true; do
        if config_helper configure "$REPO_DIR" "$BACKUP_DIR" "$MODE" "$use_current"; then return 0;
        else status=$?; fi
        [[ "$status" != 130 ]] || return 130
        say "Check $REPO_DIR/.env and config/config.json if a saved file could not be read."
        choose_recovery 'Configuration could not be saved.' || return 130
        [[ "$RETRY_ACTION" == retry ]] || return "$status"
        use_current=current
    done
}

refresh_runtime_config() {
    PUBLIC_PORT=$(config_helper get "$BACKUP_DIR/settings.json" port)
    NEWSLETTER_PATH=$(config_helper get "$BACKUP_DIR/settings.json" newsletter_path)
    retry_command 'Create newsletter directory' mkdir -p "$NEWSLETTER_PATH"
    retry_command 'Copy runtime configuration' cp -a "$REPO_DIR/config/." "$RELEASE_DIR/config/"
    retry_command 'Copy runtime secrets' cp -p "$REPO_DIR/.env" "$RELEASE_DIR/.env"
}

reconfigure_runtime() {
    configure_interactively current
    refresh_runtime_config
}

ensure_tools() {
    local missing= tool
    for tool in git python3 curl tar; do
        command -v "$tool" >/dev/null 2>&1 || missing="$missing $tool"
    done
    if [[ -n "$missing" ]]; then
        command -v apt-get >/dev/null 2>&1 || die "Install these tools first:$missing"
        confirm "Install missing prerequisites using apt-get?$missing" y || die 'Prerequisites are required.'
        retry_command 'Refresh apt packages' apt-get update
        retry_command 'Install prerequisites' apt-get install -y git python3 curl ca-certificates tar
    fi
}

ensure_docker() {
    local packages= compose_package=
    if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
        command -v apt-get >/dev/null 2>&1 || die 'Install Docker Engine and the Compose v2 plugin first, or select local installation.'
        confirm 'Install missing Docker/Compose packages from the configured apt repositories?' y || return 1
        retry_command 'Refresh apt packages' apt-get update
        if ! command -v docker >/dev/null 2>&1; then packages=docker.io; fi
        if ! docker compose version >/dev/null 2>&1; then
            if apt-cache show docker-compose-v2 >/dev/null 2>&1; then compose_package=docker-compose-v2;
            elif apt-cache show docker-compose-plugin >/dev/null 2>&1; then compose_package=docker-compose-plugin;
            else die 'No Compose v2 package is available in the configured apt repositories. Install the official Compose plugin, then rerun.'; fi
        fi
        # Both variables contain only installer-selected package names.
        retry_command 'Install Docker/Compose' apt-get install -y ${packages:+"$packages"} ${compose_package:+"$compose_package"}
    fi
    if ! docker info >/dev/null 2>&1; then
        command -v systemctl >/dev/null 2>&1 || die 'Start the Docker daemon, then rerun.'
        confirm 'Start Docker and enable it at boot?' y || return 1
        retry_command 'Start Docker' systemctl enable --now docker
    fi
    retry_command 'Connect to Docker' docker info >/dev/null
    retry_command 'Check Docker Compose' docker compose version >/dev/null
}

snapshot_repository() {
    ORIGINAL_BRANCH=$(g symbolic-ref --quiet --short HEAD || true)
    ORIGINAL_HEAD=$(g rev-parse HEAD)
    printf '%s\n' "$ORIGINAL_BRANCH" > "$BACKUP_DIR/original-branch"
    printf '%s\n' "$ORIGINAL_HEAD" > "$BACKUP_DIR/original-head"
    g status --short > "$BACKUP_DIR/git-status.txt"
    g diff --binary HEAD > "$BACKUP_DIR/local-changes.patch"
    if [[ -f "$REPO_DIR/.env" ]]; then retry_command 'Back up secrets' cp -p "$REPO_DIR/.env" "$BACKUP_DIR/.env"; fi
    if [[ -d "$REPO_DIR/config" ]]; then retry_command 'Back up configuration' cp -a "$REPO_DIR/config" "$BACKUP_DIR/config"; fi
    say "Saving working files to $BACKUP_DIR/working-tree.tar.gz"
    retry_command 'Archive working files' tar -C "$REPO_DIR" --exclude='./.git' --exclude='./target' --exclude='./node_modules' \
        --exclude='./outputs' --exclude='./output' -czf "$BACKUP_DIR/working-tree.tar.gz" .
    g branch "backup/setup-$SETUP_ID" HEAD
    if [[ -n "$(g status --porcelain --untracked-files=normal)" ]]; then
        retry_command 'Save local edits in Git stash' g stash push --include-untracked --message "setup.sh backup $SETUP_ID"
        STASH_SHA=$(g rev-parse refs/stash)
        SOURCE_CHANGED=1
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
    retry_command 'Fetch deployment branch from GitHub' g fetch origin "refs/heads/$TARGET_BRANCH:$remote"
    if g show-ref --verify --quiet "refs/heads/$TARGET_BRANCH"; then
        if ! g merge-base --is-ancestor "refs/heads/$TARGET_BRANCH" "$remote"; then
            say "The local $TARGET_BRANCH branch has commits outside origin."
            confirm 'Preserve that branch under a backup name and deploy origin?' n || return 1
            SAVED_TARGET_BRANCH="backup/target-$SETUP_ID"
            g branch -m "$TARGET_BRANCH" "$SAVED_TARGET_BRANCH"
            retry_command 'Check out deployment branch' g switch --create "$TARGET_BRANCH" --track "origin/$TARGET_BRANCH"
        else
            retry_command 'Check out deployment branch' g switch "$TARGET_BRANCH"
            retry_command 'Fast-forward deployment branch' g merge --ff-only "$remote"
        fi
    else
        retry_command 'Check out deployment branch' g switch --create "$TARGET_BRANCH" --track "origin/$TARGET_BRANCH"
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

probe_login() {
    local port=$1 attempt
    for attempt in $(seq 1 40); do
        if curl --noproxy '*' --connect-timeout 1 --max-time 2 --fail --silent \
            "http://127.0.0.1:$port/login" > "$BACKUP_DIR/login-check.html"; then
            if grep -q 'Zimbra email address' "$BACKUP_DIR/login-check.html" && \
                curl --noproxy '*' --max-time 2 --fail --silent \
                    "http://127.0.0.1:$port/login/local" > /dev/null; then return 0; fi
        fi
        if [[ -n "$CANDIDATE_PID" ]] && ! kill -0 "$CANDIDATE_PID" 2>/dev/null; then break; fi
        if [[ -n "$CANDIDATE_CONTAINER" ]] && \
            [[ "$(docker inspect --format '{{.State.Running}}' "$CANDIDATE_CONTAINER" 2>/dev/null || true)" != true ]]; then break; fi
        sleep 2
    done
    return 1
}

wait_for_login() { probe_login "$1"; }

test_candidate() {
    local candidate_port started
    while true; do
        candidate_port=$(config_helper free-port)
        say "Testing the new application on 127.0.0.1:$candidate_port with its scheduler disabled."
        started=0
        if [[ "$MODE" == native ]]; then
            env -i PATH="$PATH" HOME="$HOME" WEBSERVER_ROOT="$RELEASE_DIR" PORT="$candidate_port" \
                RUST_SCHEDULER_ENABLED=false "$RELEASE_DIR/webserver-rust" > "$BACKUP_DIR/candidate.log" 2>&1 &
            CANDIDATE_PID=$!
            started=1
        else
            CANDIDATE_CONTAINER="webserver-rust-check-$SETUP_ID"
            if docker run --detach --name "$CANDIDATE_CONTAINER" \
                --publish "127.0.0.1:$candidate_port:9100" \
                --add-host host.docker.internal:host-gateway \
                --env WEBSERVER_ROOT=/app --env PORT=9100 --env RUST_SCHEDULER_ENABLED=false \
                --env NEWSLETTER_ROOT=/app/newsletters \
                --mount "type=bind,source=$RELEASE_DIR/.env,target=/app/.env,readonly" \
                --mount "type=bind,source=$RELEASE_DIR/config,target=/app/config,readonly" \
                --mount "type=bind,source=$NEWSLETTER_PATH,target=/app/newsletters" \
                "$IMAGE_TAG" >/dev/null; then started=1; fi
        fi
        if [[ "$started" == 1 ]] && wait_for_login "$candidate_port"; then
            stop_candidate
            return 0
        fi
        stop_candidate
        choose_recovery "Candidate startup failed. Private logs: $BACKUP_DIR/candidate.log" yes || return 130
        case "$RETRY_ACTION" in
            retry) ;;
            configure) reconfigure_runtime; choose_legacy ;;
            cancel) return 1 ;;
        esac
    done
}

start_and_verify_runtime() {
    while true; do
        if [[ "$MODE" == native ]]; then
            if systemctl restart "$UNIT_NAME" && wait_for_login "$PUBLIC_PORT" && \
                systemctl is-active --quiet "$UNIT_NAME"; then return 0; fi
        else
            if docker compose -p "$COMPOSE_PROJECT" -f "$INSTALL_ROOT/compose.json" up -d --force-recreate --no-deps --no-build web && \
                wait_for_login "$PUBLIC_PORT"; then return 0; fi
        fi
        choose_recovery "Service startup failed on port $PUBLIC_PORT. Check its service/container logs." yes || return 130
        case "$RETRY_ACTION" in
            retry) ;;
            configure)
                reconfigure_runtime
                if [[ "$MODE" == docker ]]; then
                    config_helper compose "$RELEASE_DIR" "$IMAGE_TAG" "$PUBLIC_PORT" "$NEWSLETTER_PATH" "$BACKUP_DIR/new-compose.json"
                    retry_command 'Update Compose configuration' install -m 0600 "$BACKUP_DIR/new-compose.json" "$INSTALL_ROOT/compose.json"
                fi
                ;;
            cancel) return 1 ;;
        esac
    done
}

choose_legacy() {
    while true; do
    if [[ "$LEGACY_STOPPED" == 0 ]]; then LEGACY_NAME=; LEGACY_KIND=; fi
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
    read_value '1=existing systemd service, 2=existing Docker container, 3=change configuration/port, 4=cancel' 3
    case "$REPLY" in
        1)
            LEGACY_KIND=systemd
            while true; do
                read_value 'Existing systemd service name (or :cancel)'
                LEGACY_NAME=$REPLY
                if [[ "$LEGACY_NAME" =~ ^[A-Za-z0-9_.@-]+\.service$ && "$LEGACY_NAME" != -* ]] && \
                    systemctl is-active --quiet "$LEGACY_NAME"; then break; fi
                say 'Enter the exact name of an active .service. Please retype it.'
            done
            LEGACY_ENABLED=$(systemctl is-enabled "$LEGACY_NAME" 2>/dev/null || true)
            ;;
        2)
            LEGACY_KIND=docker
            while true; do
                read_value 'Existing Docker container name (or :cancel)'
                LEGACY_NAME=$REPLY
                if [[ "$LEGACY_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] && \
                    [[ "$(docker inspect --format '{{.State.Running}}' "$LEGACY_NAME" 2>/dev/null || true)" == true ]]; then break; fi
                say 'That container name is invalid or not running. Please retype it.'
            done
            LEGACY_RESTART=$(docker inspect --format '{{.HostConfig.RestartPolicy.Name}}' "$LEGACY_NAME")
            if [[ "$LEGACY_RESTART" == on-failure ]]; then
                LEGACY_RESTART="on-failure:$(docker inspect --format '{{.HostConfig.RestartPolicy.MaximumRetryCount}}' "$LEGACY_NAME")"
            fi
            ;;
        3) reconfigure_runtime; continue ;;
        4) return 1 ;;
        *) say 'Choose 1, 2, 3, or 4.'; continue ;;
    esac
    if confirm "Stop $LEGACY_NAME at cutover and disable its automatic restart after success?" n; then return 0; fi
    done
}

stop_legacy() {
    [[ -n "$LEGACY_NAME" ]] || return 0
    LEGACY_STOPPED=1
    if [[ "$LEGACY_KIND" == systemd ]]; then retry_command 'Stop selected legacy service' systemctl stop "$LEGACY_NAME";
    else retry_command 'Stop selected legacy container' docker stop "$LEGACY_NAME" >/dev/null; fi
    while ! config_helper port-free "$PUBLIC_PORT"; do
        choose_recovery "Port $PUBLIC_PORT is still occupied. Free it before retrying, or choose another port." yes || return 130
        case "$RETRY_ACTION" in retry) ;; configure) reconfigure_runtime ;; cancel) return 1 ;; esac
    done
}

retire_legacy() {
    [[ "$LEGACY_STOPPED" == 1 ]] || return 0
    if [[ "$LEGACY_KIND" == systemd ]]; then
        if [[ "$LEGACY_ENABLED" == enabled ]]; then retry_command 'Disable legacy service autostart' systemctl disable "$LEGACY_NAME"; fi
    else
        retry_command 'Disable legacy container autostart' docker update --restart=no "$LEGACY_NAME" >/dev/null
    fi
}

build_native() {
    command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]] || die 'systemd is not running; select Docker or prepare-only.'
    while [[ -n "$(systemctl show --property=DropInPaths --value "$UNIT_NAME" 2>/dev/null)" ]]; do
        choose_recovery "$UNIT_NAME has custom overrides. Resolve them before retrying." || return 130
        [[ "$RETRY_ACTION" == retry ]] || return 1
    done
    if ! command -v cc >/dev/null 2>&1; then
        command -v apt-get >/dev/null 2>&1 || die 'Install a C linker/build-essential first.'
        confirm 'Install native build prerequisites with apt-get?' y || return 1
        retry_command 'Refresh apt packages' apt-get update
        retry_command 'Install native build prerequisites' apt-get install -y build-essential pkg-config ca-certificates
    fi
    export PATH="${HOME}/.cargo/bin:$PATH"
    if ! command -v rustup >/dev/null 2>&1; then
        confirm 'Install the official Rust toolchain using https://sh.rustup.rs?' y || return 1
        retry_command 'Download Rust installer' curl --proto '=https' --tlsv1.2 --fail --silent --show-error https://sh.rustup.rs -o "$BACKUP_DIR/rustup-init.sh"
        retry_command 'Install Rust' sh "$BACKUP_DIR/rustup-init.sh" -y --profile minimal --default-toolchain 1.91.0 --no-modify-path
    fi
    retry_command 'Install Rust toolchain' rustup toolchain install 1.91.0 --profile minimal
    retry_command 'Build Rust application' cargo +1.91.0 build --manifest-path "$REPO_DIR/Cargo.toml" --release --locked --target-dir "$BACKUP_DIR/build"
    retry_command 'Stage compiled application' install -m 0755 "$BACKUP_DIR/build/release/webserver-rust" "$RELEASE_DIR/webserver-rust"
    test_candidate
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
    retry_command 'Validate systemd service' systemd-analyze verify "$BACKUP_DIR/new.service"
    stop_legacy
    SERVICE_CHANGED=1
    retry_command 'Install systemd service' install -m 0644 "$BACKUP_DIR/new.service" "$unit"
    retry_command 'Reload systemd configuration' systemctl daemon-reload
    start_and_verify_runtime
    retry_command 'Enable managed service' systemctl enable "$UNIT_NAME"
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
    retry_command 'Connect to Docker' docker info >/dev/null
    retry_command 'Check Docker Compose' docker compose version >/dev/null
    if [[ ! -f "$INSTALL_ROOT/compose.json" ]] && \
        [[ -n "$(docker ps --all --quiet --filter "label=com.docker.compose.project=$COMPOSE_PROJECT")" ]]; then
        die "Docker project $COMPOSE_PROJECT already exists without an installer manifest; deployment was stopped."
    fi
    local context="$BACKUP_DIR/docker-build"
    prepare_docker_context "$context"
    IMAGE_TAG="webserver-rust:setup-$SETUP_ID"
    retry_command 'Build Docker image' docker build --tag "$IMAGE_TAG" "$context"
    test_candidate
    config_helper compose "$RELEASE_DIR" "$IMAGE_TAG" "$PUBLIC_PORT" "$NEWSLETTER_PATH" "$BACKUP_DIR/new-compose.json"
    retry_command 'Validate Compose configuration' docker compose -p "$COMPOSE_PROJECT" -f "$BACKUP_DIR/new-compose.json" config --quiet
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
    retry_command 'Install Compose configuration' install -m 0600 "$BACKUP_DIR/new-compose.json" "$INSTALL_ROOT/compose.json"
    start_and_verify_runtime
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
Invalid entries can be retyped. Failed commands offer retry or cancellation;
startup failures also offer configuration correction. Type :cancel to leave.
--check only checks syntax/prerequisites; it does not install or contact services.
EOF_HELP
}

choose_installation_mode() {
    while true; do
        say 'Where would you like to install?'
        printf '  1) Locally (Rust + systemd)\n  2) In Docker (Docker Compose)\n  3) Configure only, without starting a service\n'
        read_value 'Installation method (or :cancel)' 1
        case "$REPLY" in
            1)
                if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
                    MODE=native
                    say 'The local systemd service runs as root, matching a root-owned server installation.'
                    return 0
                fi
                say 'systemd is not running. Choose Docker or configure-only, or type :cancel.'
                ;;
            2) MODE=docker; return 0 ;;
            3) MODE=prepare; return 0 ;;
            *) say 'Invalid installation method. Choose 1, 2, or 3.' ;;
        esac
    done
}

choose_repository() {
    local default_repo=$1
    while true; do
        read_value 'Project checkout directory (or :cancel)' "$default_repo"
        if ! REPO_DIR=$(python3 -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).expanduser().resolve())' "$REPLY"); then
            say 'The directory could not be resolved. Please retype it.'
            continue
        fi
        if [[ "$REPO_DIR" == / || "$REPO_DIR" == *$'\n'* || "$REPO_DIR" == *$'\r'* ]]; then
            say 'Invalid repository path. Please choose a project directory.'
            continue
        fi
        if ! g rev-parse --git-dir >/dev/null 2>&1; then
            if [[ -e "$REPO_DIR" ]] && { [[ ! -d "$REPO_DIR" ]] || [[ -n "$(ls -A "$REPO_DIR")" ]]; }; then
                say 'That path is not an empty directory or a Git checkout. Please choose another path.'
                continue
            fi
            if ! confirm "Clone $DEFAULT_REPOSITORY into $REPO_DIR?" y; then continue; fi
            retry_command 'Clone repository' git clone --branch "$TARGET_BRANCH" "$DEFAULT_REPOSITORY" "$REPO_DIR"
        fi
        if [[ "$(g rev-parse --show-toplevel)" != "$REPO_DIR" ]]; then
            default_repo=$(g rev-parse --show-toplevel)
            say "Select the repository root: $default_repo"
            continue
        fi
        if [[ -n "$(g ls-files -u)" ]]; then
            choose_recovery 'Resolve the existing merge conflicts in another terminal, then retry.' || return 130
            [[ "$RETRY_ACTION" == retry ]] || return 1
            continue
        fi
        return 0
    done
}

main() {
    local requested_repo=
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
    say 'Invalid entries can be retyped; type :cancel to stop. Failed steps offer retry choices.'
    choose_installation_mode
    ensure_tools
    if [[ "$MODE" == docker ]]; then ensure_docker; fi
    choose_repository "${requested_repo:-/root/WEBSEVER}"
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
    configure_interactively
    retry_command 'Stage application files' cp -a "$REPO_DIR/templates" "$REPO_DIR/static" "$REPO_DIR/config" "$RELEASE_DIR/"
    refresh_runtime_config
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
            retry_command 'Enable scheduled delivery' config_helper scheduler true "$REPO_DIR/.env" "$RELEASE_DIR/.env"
            start_and_verify_runtime
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
