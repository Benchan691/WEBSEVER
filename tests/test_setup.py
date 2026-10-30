"""Installer regressions using disposable local Git repositories and mocked managers.

Run: python3 -m unittest discover -s tests -p 'test_setup.py' -v
No SSH, root access, database, Docker daemon, or systemd service is needed.
"""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


PROJECT = Path(__file__).resolve().parents[1]
SCRIPT = PROJECT / "setup.sh"
BRANCH = "feature/local-rbac-organization-management"
PYTHON_SOURCE = SCRIPT.read_text().split("<<'PY_SETUP'\n", 1)[1].split("\nPY_SETUP\n", 1)[0]
HELPER = {"__name__": "installer_tests"}
exec(compile(PYTHON_SOURCE, "setup.sh:python", "exec"), HELPER)


class ConfigurationTests(unittest.TestCase):
    def test_invalid_port_can_be_retyped(self):
        answers = iter(('abc', '70000', '9100'))
        with contextlib.redirect_stdout(io.StringIO()) as output:
            result = HELPER['validated'](lambda: next(answers), HELPER['require_port'])
        self.assertEqual(result, '9100')
        self.assertEqual(output.getvalue().count('Please retype'), 2)

    def test_password_characters_stay_literal_and_duplicates_are_removed(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / ".env"
            path.write_text("# retain this\nexport SMTP_PASSWORD=old\nSMTP_PASSWORD=duplicate\nOTHER=kept\n")
            value = "a$HOME 'quoted' \"double\" \\ # $(touch /tmp/must-not-run)\nsecond line"
            HELPER["update_env"](path, {"SMTP_PASSWORD": value})
            _, parsed = HELPER["read_env"](path)
            self.assertEqual(parsed["SMTP_PASSWORD"], value)
            self.assertEqual(parsed["OTHER"], "kept")
            self.assertEqual(path.read_text().count("SMTP_PASSWORD="), 1)
            self.assertIn("# retain this", path.read_text())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_docker_rewrites_hosts_without_changing_credentials_or_queries(self):
        rewrite = HELPER["docker_mongo_uri"]
        self.assertEqual(
            rewrite("mongodb://user:p%40localhost@localhost:27017,127.0.0.1:27018/db?x=@localhost"),
            "mongodb://user:p%40localhost@host.docker.internal:27017,host.docker.internal:27018/db?x=@localhost",
        )
        self.assertEqual(rewrite("mongodb://[::1]:27017/"), "mongodb://host.docker.internal:27017/")
        uri = "mongodb+srv://user:password@cluster.example/db"
        self.assertEqual(rewrite(uri), uri)
        self.assertEqual(rewrite("mongodb://mongo.example/db?x=@localhost"), "mongodb://mongo.example/db?x=@localhost")

    def test_configuration_keeps_local_secrets_and_custom_settings(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, backup = root / "repo", root / "backup"
            (repo / "config").mkdir(parents=True)
            (backup / "config").mkdir(parents=True)
            (repo / "config/config.json").write_text(json.dumps({"mongodb": {}, "enriched": {"new_setting": 3}}))
            (backup / "config/config.json").write_text(json.dumps({"enriched": {"llm_model": "custom"}}))
            original = {
                "LOCAL_MONGO_URI": "mongodb://test-user:test-secret@mongo.example/",
                "FLASK_SECRET_KEY": "existing-session-secret",
                "WEB_AUTH_BOOTSTRAP_PASSWORD": "existing-admin-password",
                "SMTP_PASSWORD": "existing-smtp-secret",
                "NEWSLETTER_ROOT": "saved-newsletters",
                "ACCOUNT_COLLECTION": "auth",
                "RUST_SCHEDULER_ENABLED": "true",
            }
            HELPER["update_env"](backup / ".env", original)
            HELPER["update_env"](repo / ".env", {"UNRELATED": "retained"})
            original_prompt, original_hidden = HELPER["prompt"], HELPER["hidden"]
            HELPER["prompt"] = lambda label, default="": "no" if label.startswith("Configure SMTP") else default
            HELPER["hidden"] = lambda label, current="", default="": current or default
            try:
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    HELPER["configure"](repo, backup, "native")
            finally:
                HELPER["prompt"], HELPER["hidden"] = original_prompt, original_hidden
            _, configured = HELPER["read_env"](repo / ".env")
            for name in ("FLASK_SECRET_KEY", "WEB_AUTH_BOOTSTRAP_PASSWORD", "SMTP_PASSWORD"):
                self.assertEqual(configured[name], original[name])
                self.assertNotIn(original[name], output.getvalue())
            self.assertEqual(configured["ACCOUNT_COLLECTION"], "accounts")
            self.assertEqual(configured["VULNERABILITIES_COLLECTION"], "news")
            self.assertEqual(configured["RUST_SCHEDULER_ENABLED"], "false")
            self.assertEqual(configured["NEWSLETTER_ROOT"], str((repo / "saved-newsletters").resolve()))
            config = json.loads((repo / "config/config.json").read_text())
            self.assertEqual(config["enriched"], {"new_setting": 3, "llm_model": "custom"})

    def test_compose_mounts_secrets_without_embedding_them(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "compose.json"
            result = subprocess.run(
                ["bash", "-c", 'source "$1"; config_helper compose "/opt/release" "test:image" "9100" "/srv/news \\$files" "$2"',
                 "test", str(SCRIPT), str(path)], capture_output=True, text=True,
            )
            # Keep the dollar literal in the shell argument as well as Compose.
            if result.returncode:
                self.fail(result.stderr)
            data = json.loads(path.read_text())["services"]["web"]
            self.assertNotIn("env_file", data)
            self.assertNotIn("RUST_SCHEDULER_ENABLED", data["environment"])
            self.assertEqual(data["volumes"][0]["target"], "/app/.env")
            self.assertTrue(data["volumes"][0]["read_only"])
            self.assertEqual(data["ports"], ["9100:9100"])
            self.assertEqual(data["volumes"][2]["source"], "/srv/news $$files")


class RepositoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.seed, self.remote, self.server = (self.root / name for name in ("seed", "remote.git", "server"))
        self.backup = self.root / "backup"
        self.backup.mkdir(mode=0o700)
        self.env = os.environ | {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_AUTHOR_NAME": "Installer Test", "GIT_COMMITTER_NAME": "Installer Test",
            "GIT_AUTHOR_EMAIL": "installer@example.invalid", "GIT_COMMITTER_EMAIL": "installer@example.invalid",
        }
        self.git("init", "--bare", str(self.remote))
        self.git("init", "-b", "main", str(self.seed))
        (self.seed / "config").mkdir()
        (self.seed / "src").mkdir()
        (self.seed / "README.md").write_text("main version\n")
        (self.seed / "config/config.json").write_text('{"old_setting":true}\n')
        (self.seed / "src/auth.rs").write_text("main auth\n")
        (self.seed / ".gitignore").write_text(".env\n")
        self.git("-C", str(self.seed), "add", ".")
        self.git("-C", str(self.seed), "commit", "-m", "initial")
        self.git("-C", str(self.seed), "remote", "add", "origin", str(self.remote))
        self.git("-C", str(self.seed), "push", "origin", "main")
        self.git("-C", str(self.seed), "switch", "-c", BRANCH)
        (self.seed / "src/rbac.rs").write_text("new local RBAC implementation\n")
        (self.seed / "README.md").write_text("target version\n")
        self.git("-C", str(self.seed), "add", ".")
        self.git("-C", str(self.seed), "commit", "-m", "target")
        self.git("-C", str(self.seed), "push", "origin", BRANCH)
        self.git("clone", "--single-branch", "--branch", "main", str(self.remote), str(self.server))

    def git(self, *args):
        return subprocess.run(["git", *args], env=self.env, check=True, text=True, capture_output=True).stdout.strip()

    def shell(self, body, check=True):
        prefix = 'source "$1"; REPO_DIR=$2; BACKUP_DIR=$3; SETUP_ID=test-install; '
        return subprocess.run(
            ["bash", "-c", prefix + body, "test", str(SCRIPT), str(self.server), str(self.backup)],
            env=self.env, check=check, text=True, capture_output=True,
        )

    def edits(self):
        (self.server / "README.md").write_text("staged customer note\n")
        self.git("-C", str(self.server), "add", "README.md")
        (self.server / "src/auth.rs").write_text("unstaged server auth\n")
        (self.server / "local-note.txt").write_text("untracked customer notes\n")
        (self.server / ".env").write_text("SECRET=original-secret\n")

    def target_checkout(self):
        self.git("-C", str(self.server), "remote", "set-branches", "--add", "origin", BRANCH)
        self.git("-C", str(self.server), "fetch", "origin", f"refs/heads/{BRANCH}:refs/remotes/origin/{BRANCH}")
        self.git("-C", str(self.server), "switch", "--track", "origin/" + BRANCH)

    def advance_target(self):
        (self.seed / "remote-feature.txt").write_text("new remote feature\n")
        self.git("-C", str(self.seed), "add", ".")
        self.git("-C", str(self.seed), "commit", "-m", "advance target")
        self.git("-C", str(self.seed), "push", "origin", BRANCH)

    def test_dirty_divergent_main_switches_from_single_branch_clone(self):
        (self.server / "server-only.txt").write_text("server commit\n")
        self.git("-C", str(self.server), "add", ".")
        self.git("-C", str(self.server), "commit", "-m", "local main commit")
        old_head = self.git("-C", str(self.server), "rev-parse", "HEAD")
        self.edits()
        self.shell("snapshot_repository; switch_branch")
        self.assertEqual(self.git("-C", str(self.server), "branch", "--show-current"), BRANCH)
        self.assertEqual(self.git("-C", str(self.server), "rev-parse", "main"), old_head)
        self.assertEqual((self.backup / ".env").read_text(), "SECRET=original-secret\n")
        stash = (self.backup / "stash-commit").read_text().strip()
        self.assertEqual(self.git("-C", str(self.server), "show", stash + ":README.md"), "staged customer note")
        self.assertEqual(self.git("-C", str(self.server), "show", stash + "^3:local-note.txt"), "untracked customer notes")
        self.assertTrue((self.backup / "working-tree.tar.gz").exists())
        self.assertEqual((self.backup / "local-changes.patch").stat().st_mode & 0o777, 0o600)
        self.git("-C", str(self.server), "pull", "--ff-only")

    def test_failed_install_restores_staged_unstaged_untracked_and_env(self):
        self.edits()
        old_status = self.git("-C", str(self.server), "status", "--porcelain")
        old_head = self.git("-C", str(self.server), "rev-parse", "HEAD")
        self.shell('snapshot_repository; switch_branch; printf "changed=true\\n" > "$REPO_DIR/config/config.json"; printf "SECRET=new-secret\\n" > "$REPO_DIR/.env"; restore_source')
        self.assertEqual(self.git("-C", str(self.server), "rev-parse", "HEAD"), old_head)
        self.assertEqual(self.git("-C", str(self.server), "status", "--porcelain"), old_status)
        self.assertEqual((self.server / ".env").read_text(), "SECRET=original-secret\n")
        self.assertEqual((self.server / "local-note.txt").read_text(), "untracked customer notes\n")

    def test_failed_update_on_target_restores_exact_pre_update_commit(self):
        self.target_checkout()
        old_head = self.git("-C", str(self.server), "rev-parse", "HEAD")
        self.advance_target()
        self.edits()
        self.shell("snapshot_repository; switch_branch; restore_source")
        self.assertEqual(self.git("-C", str(self.server), "branch", "--show-current"), BRANCH)
        self.assertEqual(self.git("-C", str(self.server), "rev-parse", "HEAD"), old_head)
        self.assertEqual((self.server / "README.md").read_text(), "staged customer note\n")
        self.assertFalse((self.server / "remote-feature.txt").exists())

    def test_divergent_target_keeps_local_commits_and_can_restore(self):
        self.target_checkout()
        (self.server / "local-commit.txt").write_text("preserve me\n")
        self.git("-C", str(self.server), "add", ".")
        self.git("-C", str(self.server), "commit", "-m", "local target commit")
        original = self.git("-C", str(self.server), "rev-parse", "HEAD")
        self.advance_target()
        self.edits()
        self.shell('confirm() { return 0; }; snapshot_repository; switch_branch; g rev-parse HEAD > "$BACKUP_DIR/deployed-head"; restore_source')
        remote_head = self.git("-C", str(self.seed), "rev-parse", "HEAD")
        self.assertEqual((self.backup / "deployed-head").read_text().strip(), remote_head)
        self.assertEqual(self.git("-C", str(self.server), "rev-parse", "backup/target-test-install"), original)
        self.assertEqual(self.git("-C", str(self.server), "rev-parse", "HEAD"), original)
        self.assertEqual(self.git("-C", str(self.server), "branch", "--show-current"), BRANCH)

    def test_fetch_failure_triggers_source_restoration_without_dropping_stash(self):
        self.edits()
        self.git("-C", str(self.server), "remote", "set-url", "origin", str(self.root / "missing.git"))
        result = self.shell("trap 'failed $?' ERR; snapshot_repository; switch_branch", check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Installation did not complete", result.stderr)
        self.assertEqual(self.git("-C", str(self.server), "branch", "--show-current"), "main")
        self.assertEqual((self.server / "README.md").read_text(), "staged customer note\n")
        self.assertTrue(self.git("-C", str(self.server), "stash", "list"))

    def test_detached_checkout_restores_original_commit(self):
        original = self.git("-C", str(self.server), "rev-parse", "HEAD")
        self.git("-C", str(self.server), "switch", "--detach", original)
        self.edits()
        self.shell("snapshot_repository; switch_branch; restore_source")
        self.assertEqual(self.git("-C", str(self.server), "branch", "--show-current"), "")
        self.assertEqual(self.git("-C", str(self.server), "rev-parse", "HEAD"), original)
        self.assertEqual((self.server / "src/auth.rs").read_text(), "unstaged server auth\n")


class DeploymentTests(unittest.TestCase):
    def test_failed_command_retries_without_exiting(self):
        with tempfile.TemporaryDirectory() as temporary:
            self.run_shell(Path(temporary), '''
attempts=0
flaky() { attempts=$((attempts + 1)); [[ "$attempts" -eq 2 ]]; }
choose_recovery() { RETRY_ACTION=retry; }
retry_command 'Test command' flaky
[[ "$attempts" -eq 2 ]]
''')

    def test_cancel_returns_original_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            self.run_shell(Path(temporary), '''
choose_recovery() { RETRY_ACTION=cancel; }
fails() { return 42; }
if retry_command 'Test command' fails; then exit 1; else status=$?; fi
[[ "$status" -eq 42 ]]
''')

    def run_shell(self, root, body):
        return subprocess.run(
            ["bash", "-c", 'source "$1"; INSTALL_ROOT=$2; BACKUP_DIR=$2/backup; RELEASE_DIR=$2/release; UNIT_DIR=$2/units; PUBLIC_PORT=9100; TRACE=$2/trace; mkdir -p "$BACKUP_DIR" "$RELEASE_DIR" "$UNIT_DIR"; ' + body,
             "test", str(SCRIPT), str(root)], check=True, capture_output=True, text=True,
        )

    def test_native_activation_installs_unit_and_checks_http_before_enabling(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.run_shell(root, '''
systemctl() {
    printf 'systemctl %s\\n' "$*" >> "$TRACE"
    case "$1" in
        is-active|is-enabled) [[ -f "$INSTALL_ROOT/started" ]] ;;
        restart) touch "$INSTALL_ROOT/started" ;;
    esac
    return 0
}
MODE=native
systemd-analyze() { printf 'unit verified\\n' >> "$TRACE"; }
stop_legacy() { printf 'legacy stopped\\n' >> "$TRACE"; }
wait_for_login() { printf 'HTTP verified\\n' >> "$TRACE"; }
activate_native
''')
            unit = (root / "units/webserver-rust-setup.service").read_text()
            self.assertIn(f"ExecStart={root}/release/webserver-rust", unit)
            self.assertIn(f"Environment=WEBSERVER_ROOT={root}/release", unit)
            self.assertNotIn("EnvironmentFile", unit)
            commands = (root / "trace").read_text()
            self.assertLess(commands.index("legacy stopped"), commands.index("systemctl restart"))
            self.assertLess(commands.index("systemctl restart"), commands.index("HTTP verified"))
            self.assertLess(commands.index("HTTP verified"), commands.index("systemctl enable"))

    def test_docker_activation_uses_managed_project_and_preserves_prior_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.run_shell(root, '''
MODE=docker
printf 'previous manifest' > "$INSTALL_ROOT/compose.json"
printf 'new manifest' > "$BACKUP_DIR/new-compose.json"
docker() { printf 'docker %s\\n' "$*" >> "$TRACE"; }
stop_legacy() { printf 'legacy stopped\\n' >> "$TRACE"; }
wait_for_login() { printf 'HTTP verified\\n' >> "$TRACE"; }
activate_docker
''')
            self.assertEqual((root / "backup/managed-compose.json").read_text(), "previous manifest")
            self.assertEqual((root / "compose.json").read_text(), "new manifest")
            commands = (root / "trace").read_text()
            self.assertIn("-p webserver-rust-setup", commands)
            self.assertIn("up -d --force-recreate --no-deps --no-build web", commands)
            self.assertLess(commands.index("legacy stopped"), commands.index("up -d"))
            self.assertLess(commands.index("up -d"), commands.index("HTTP verified"))

    def test_runtime_restoration_keeps_legacy_stopped_when_source_restore_failed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.run_shell(root, '''
printf 'old manifest' > "$BACKUP_DIR/managed-compose.json"
printf 'new manifest' > "$INSTALL_ROOT/compose.json"
touch "$BACKUP_DIR/managed-compose-active"
COMPOSE_CHANGED=1; LEGACY_STOPPED=1; LEGACY_KIND=docker; LEGACY_NAME=old-main; LEGACY_RESTART=always
docker() { printf 'docker %s\\n' "$*" >> "$TRACE"; }
rollback_runtime 1
''')
            self.assertEqual((root / "compose.json").read_text(), "old manifest")
            commands = (root / "trace").read_text()
            self.assertIn(" down", commands)
            self.assertIn("up -d --no-deps --no-build web", commands)
            self.assertNotIn("start old-main", commands)


if __name__ == "__main__":
    unittest.main()
