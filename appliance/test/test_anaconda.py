# SPDX-FileCopyrightText: 2026 Olivares.AI
# SPDX-License-Identifier: AGPL-3.0-only
"""The native Anaconda recipe keeps destructive and identity choices with the operator."""
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parents[1]


class AnacondaRecipe(unittest.TestCase):
    def test_summary_owns_disk_and_administrator_choices(self):
        kickstart = (HERE / "images/anaconda/server.ks").read_text()
        self.assertIn("clearpart --none", kickstart)
        self.assertIn("rootpw --lock", kickstart)
        self.assertIn("console=ttyS0,115200n8", kickstart)
        self.assertIn("systemctl enable olivares-repair-console.service", kickstart)
        self.assertIn("systemctl mask getty@tty1.service", kickstart)
        self.assertIn("%post --erroronfail", kickstart)
        self.assertIn("usermod -aG olivares-admins", kickstart)
        self.assertIn('"ssh_authorized_keys": []', kickstart)
        self.assertNotIn("clearpart --all", kickstart)
        self.assertNotIn("\nuser ", kickstart)
        build = (HERE / "images/anaconda/build.sh").read_text()
        self.assertIn("mkksiso --ks", build)
        self.assertIn("sha256sum -c", build)

    def run_post(self, edition, root, passwd, groups=None, status="P", account_expires="never",
                 password_expires="never", root_key=False, user_key=False, uid_error=False, executable=True):
        etc = root / "etc"
        etc.mkdir(parents=True)
        if passwd is not None:
            (etc / "passwd").write_text(passwd.replace("/home/", str(etc / "home") + "/"))
        (etc / "hostname").write_text("olivares-server\n")
        commands = root / "bin"
        commands.mkdir()
        calls = root / "calls"
        for name in ("systemctl", "usermod", "restorecon"):
            (commands / name).write_text(f'#!/bin/sh\nprintf "{name} %s\\n" "$*" >>"$CALLS"\n')
        if groups is not None:
            (commands / "id").write_text(f'#!/bin/sh\n[ "{groups}" != error ] || exit 1\n[ "$UID_ERROR" != 1 ] || [ "$1" != -u ] || exit 1\ncase "$1" in -nG) printf "{groups}\\n" ;; -u) printf "1000\\n" ;; esac\n')
        (commands / "passwd").write_text(f'#!/bin/sh\nprintf "admin {status} 2026-01-01 0 99999 7 -1\\n"\n')
        (commands / "chage").write_text(f'#!/bin/sh\nprintf "Account expires					: {account_expires}\\nPassword expires					: {password_expires}\\n"\n')
        (commands / "ssh-keygen").write_text('#!/bin/sh\nprintf "ssh-keygen %s root=%s user=%s\\n" "$*" "$ROOT_KEY" "$USER_KEY" >>"$CALLS"\ncase "$3" in */root/*) key=$ROOT_KEY ;; */home/*) key=$USER_KEY ;; *) exit 1 ;; esac\n[ -n "$key" ] || exit 1\nprintf "256 SHA256:fixture key\\n"\n')
        if root_key:
            (etc / "root/.ssh").mkdir(parents=True)
            (etc / "root/.ssh/authorized_keys").write_text("fixture\n")
        if user_key:
            (etc / "home/admin/.ssh").mkdir(parents=True)
            (etc / "home/admin/.ssh/authorized_keys").write_text("fixture\n")
        for command in commands.iterdir():
            command.chmod(0o755 if executable else 0o644)
        # PATH holds only this directory: a stub that cannot run fails the script instead of reaching the host's command.
        for name in ("awk", "cat", "chmod", "date", "install", "mkdir"):
            (commands / name).symlink_to(shutil.which(name))
        kickstart = (HERE / f"images/anaconda/{edition}.ks").read_text()
        script = kickstart.split("%post --erroronfail", 1)[1].split("%end", 1)[0]
        script = script.replace("/etc/", str(etc) + "/").replace("/root/", str(etc / "root") + "/")
        script = script.replace("/home/", str(etc / "home") + "/")
        result = subprocess.run([shutil.which("bash"), "-x", "-c", script],
                                env=dict(os.environ, PATH=str(commands), CALLS=str(calls),
                                         ROOT_KEY="1" if root_key else "", USER_KEY="1" if user_key else "",
                                         UID_ERROR="1" if uid_error else ""),
                                capture_output=True, text=True)
        return result, etc, calls

    def test_post_keeps_machine_checks_off_guests(self):
        for edition in ("server", "desktop"):
            with self.subTest(edition=edition), tempfile.TemporaryDirectory() as tmp:
                result, etc, _ = self.run_post(
                    edition, pathlib.Path(tmp), "admin:x:1000:1000::/home/admin:/bin/bash\n", "staff wheel")
                self.assertEqual(result.returncode, 0, result.stderr)
                dropin = etc / "systemd/system/mcelog.service.d/10-virtualization.conf"
                self.assertEqual(dropin.read_text(), "[Unit]\nConditionVirtualization=no\n")

    def test_post_never_reaches_a_host_command_when_a_stub_cannot_run(self):
        # A noexec TMPDIR refuses every stub exactly as a mode 0644 file does; the host's systemctl must not run instead.
        with tempfile.TemporaryDirectory() as host, tempfile.TemporaryDirectory() as tmp:
            reached = pathlib.Path(host) / "reached"
            (pathlib.Path(host) / "systemctl").write_text(f'#!/bin/sh\nprintf "systemctl %s\\n" "$*" >>"{reached}"\n')
            (pathlib.Path(host) / "systemctl").chmod(0o755)
            with mock.patch.dict(os.environ, PATH=f"{host}:{os.environ['PATH']}"):
                result, _, _ = self.run_post("server", pathlib.Path(tmp), "admin:x:1000:1000::/home/admin:/bin/bash\n",
                                             "staff wheel", executable=False)
            self.assertNotEqual(result.returncode, 0, result.stderr)
            self.assertFalse(reached.exists(), "the host's systemctl ran: " + (reached.read_text() if reached.exists() else ""))

    def test_post_refuses_failed_administrator_discovery(self):
        cases = (("missing passwd", None, None, False), ("malformed passwd", "not-an-account\n", None, False),
                 ("NSS failure", "admin:x:1000:1000::/home/admin:/bin/bash\n", "error", False),
                 ("UID failure", "admin:x:1000:1000::/home/admin:/bin/bash\n", "staff wheel", True))
        for edition in ("server", "desktop"):
            for name, passwd, groups, uid_error in cases:
                with self.subTest(edition=edition, failure=name), tempfile.TemporaryDirectory() as tmp:
                    result, _, _ = self.run_post(edition, pathlib.Path(tmp), passwd, groups, uid_error=uid_error)
                    self.assertNotEqual(result.returncode, 0, result.stderr)
                    self.assertIn("administrator inspection failed", result.stderr)

    def test_post_counts_only_usable_administrator_credentials(self):
        cases = (("nologin", "/usr/sbin/nologin", {}), ("locked", "/bin/bash", {"status": "L"}),
                 ("account expired", "/bin/bash", {"account_expires": "2020-01-01"}),
                 ("password expired", "/bin/bash", {"password_expires": "2020-01-01", "user_key": True}))
        for edition in ("server", "desktop"):
            for name, shell, options in cases:
                with self.subTest(edition=edition, credential=name), tempfile.TemporaryDirectory() as tmp:
                    result, etc, _ = self.run_post(edition, pathlib.Path(tmp),
                                                   f"admin:x:1000:1000::/home/admin:{shell}\n", "staff wheel", **options)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("first boot will ask who becomes administrator", result.stdout)
                    self.assertFalse((etc / "userdb/olivares.user").exists())
        for edition in ("server", "desktop"):
            with self.subTest(edition=edition, credential="root authorized key"), tempfile.TemporaryDirectory() as tmp:
                result, etc, calls = self.run_post(edition, pathlib.Path(tmp),
                                               "root:x:0:0:root:/root:/bin/bash\n", root_key=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn("first boot will ask who becomes administrator", result.stdout)
                self.assertNotIn("usermod", calls.read_text())
            with self.subTest(edition=edition, credential="wheel authorized key"), tempfile.TemporaryDirectory() as tmp:
                result, etc, calls = self.run_post(edition, pathlib.Path(tmp),
                                                   "admin:x:1000:1000::/home/admin:/bin/bash\n", "staff wheel",
                                                   status="LK", user_key=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("usermod -aG olivares-admins admin", calls.read_text())
                self.assertTrue((etc / "userdb/olivares.user").exists())

    def test_post_takes_only_the_wheel_group_itself(self):
        for edition in ("server", "desktop"):
            with self.subTest(edition=edition), tempfile.TemporaryDirectory() as tmp:
                result, etc, calls = self.run_post(edition, pathlib.Path(tmp),
                                                   "admin:x:1000:1000::/home/admin:/bin/bash\n", "staff wheel-ops")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("first boot will ask who becomes administrator", result.stdout)
                self.assertFalse((etc / "userdb/olivares.user").exists())
                self.assertFalse(calls.exists() and "usermod" in calls.read_text())

    def test_desktop_defers_every_missing_administrator_to_the_tty1_console(self):
        # GNOME Initial Setup's account is wheel only, never olivares-admins: the tty1 console creates the administrator.
        nobody = "root:x:0:0:root:/root:/bin/bash\nolivares:x:999:999::/var/lib/olivares:/usr/sbin/nologin\n"
        for name, passwd, groups in (("no human account", nobody, None),
                                     ("a regular user only", "admin:x:1000:1000::/home/admin:/bin/bash\n", "staff")):
            with self.subTest(branch=name), tempfile.TemporaryDirectory() as tmp:
                result, etc, calls = self.run_post("desktop", pathlib.Path(tmp), passwd, groups)
                self.assertEqual(result.returncode, 0, result.stderr)
                marker = etc / "olivares-appliance/defer-administrator"
                self.assertTrue(marker.is_file())
                self.assertIn("systemctl enable olivares-repair-console.service", calls.read_text())
                self.assertIn("systemctl mask getty@tty1.service", calls.read_text())
                self.assertIn(f"ConditionPathExists=!{marker}\n",
                              (etc / "systemd/system/gdm.service.d/50-defer-administrator.conf").read_text())
                self.assertIn(f"ConditionPathExists={marker}\n",
                              (etc / "systemd/system/olivares-repair-console.service.d/50-defer-administrator.conf").read_text())
                self.assertEqual((etc / "systemd/system/olivares-tty1-banner.service.d/50-defer-administrator.conf").read_text(),
                                 "[Service]\nExecStartPre=-+/usr/bin/plymouth quit\n")

    def test_kiwi_desktop_ships_gnome_initial_setup(self):
        self.assertIn("gnome-initial-setup", (HERE / "images/kiwi/config.xml").read_text())

    def test_post_defers_only_a_missing_administrator(self):
        for edition in ("server", "desktop"):
            with self.subTest(edition=edition, administrator="absent"), tempfile.TemporaryDirectory() as tmp:
                result, etc, calls = self.run_post(edition, pathlib.Path(tmp),
                                                   "root:x:0:0:root:/root:/bin/bash\nolivares:x:999:999::/var/lib/olivares:/usr/sbin/nologin\n")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("first boot will ask who becomes administrator", result.stdout)
                self.assertFalse((etc / "userdb/olivares.user").exists())
                self.assertTrue((etc / "olivares-appliance/defer-administrator").is_file())
                answers = json.loads((etc / "olivares-appliance/answers.json").read_text())
                self.assertEqual(answers["schema_version"], "appliance-answers/v1")
                # No cloud-init seed on an Anaconda install: the appliance owns the host settings.
                self.assertEqual((answers["host"]["owner"], answers["host"]["ssh_authorized_keys"]), ("local", []))
                # No administrator yet: first boot creates it on the tty1 console.
                self.assertEqual(answers["host"].get("administrator"), "deferred")
                self.assertFalse(calls.exists() and "usermod" in calls.read_text())
        with tempfile.TemporaryDirectory() as tmp:
            result, etc, calls = self.run_post("server", pathlib.Path(tmp),
                                               "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000::/home/admin:/bin/bash\n",
                                               "staff wheel")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("usermod -aG olivares-admins admin", calls.read_text())
            self.assertEqual(json.loads((etc / "userdb/olivares.user").read_text()),
                             {"userName": "admin", "uid": 1000})
            self.assertEqual(json.loads((etc / "olivares-appliance/answers.json").read_text())["host"]["administrator"],
                             "installed")

    def test_every_branch_writes_answers_first_boot_accepts(self):
        go = shutil.which("go")
        self.assertIsNotNone(go, "this case builds the answers validator first boot uses: it needs go")
        human = "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000::/home/admin:/bin/bash\n"
        nobody = "root:x:0:0:root:/root:/bin/bash\nolivares:x:999:999::/var/lib/olivares:/usr/sbin/nologin\n"
        branches = (("wheel administrator with a password", human, {"groups": "staff wheel"}, "installed"),
                    ("wheel administrator with a key", human, {"groups": "staff wheel", "status": "LK", "user_key": True},
                     "installed"),
                    ("root with authorized keys", nobody, {"root_key": True}, "installed"),
                    ("a regular user only", human, {"groups": "staff"}, "deferred"),
                    ("no human account", nobody, {}, "deferred"))
        with tempfile.TemporaryDirectory() as tools:
            validator = pathlib.Path(tools) / "appliance-answers"
            subprocess.run([go, "build", "-o", str(validator), "./cmd/appliance-answers"], cwd=HERE, check=True)
            for edition in ("server", "desktop"):
                for name, passwd, options, administrator in branches:
                    with self.subTest(edition=edition, branch=name), tempfile.TemporaryDirectory() as tmp:
                        result, etc, _ = self.run_post(edition, pathlib.Path(tmp), passwd, **options)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        document = etc / "olivares-appliance/answers.json"
                        self.assertEqual(json.loads(document.read_text())["host"]["administrator"], administrator)
                        checked = subprocess.run([str(validator), "validate", "--input", str(document)],
                                                 capture_output=True, text=True)
                        self.assertEqual(checked.returncode, 0, "first boot refuses this branch's answers: " + checked.stderr)

    def test_desktop_uses_native_gnome(self):
        kickstart = (HERE / "images/anaconda/desktop.ks").read_text()
        self.assertIn("clearpart --none", kickstart)
        self.assertIn("gnome-initial-setup", kickstart)
        self.assertIn("systemctl set-default graphical.target", kickstart)
        self.assertIn("systemctl enable gdm.service sshd.service", kickstart)
        self.assertIn("ConditionPathExists=!/etc/olivares-appliance/defer-administrator", kickstart)
        self.assertNotIn("\ntext\n", kickstart)


if __name__ == "__main__":
    unittest.main()
