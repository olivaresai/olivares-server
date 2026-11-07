#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Olivares.AI
# SPDX-License-Identifier: AGPL-3.0-only
"""The image build must put the session image where the engine user's rootless Podman reads it, and refuse failures."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'appliance/layer/base/session-image.sh'


class SessionImage(unittest.TestCase):
    def run_build(self, failure='', recipe=None, mode=None):
        work = Path(self.temp.name)
        for path in ('etc', 'var/lib/olivares', 'run', 'usr/share/olivares/session-image', 'bin'):
            (work / path).mkdir(parents=True, exist_ok=True)
        (work / 'usr/share/olivares/session-image/Containerfile').write_text(
            recipe if recipe is not None else
            'FROM debian:trixie-slim@sha256:' + 'a' * 64 + '\nRUN apt-get update\n')
        script = SCRIPT.read_text().replace(' -o "$uid" -g "$gid"', '').replace('PATH=/usr/bin:/bin', 'PATH=' + str(work / 'bin') + ':/usr/bin:/bin')
        for path in ('/etc', '/var', '/run', '/usr/share', '/usr/lib'):
            script = script.replace(path, str(work) + path)
        (work / 'script').write_text(script)
        # Record what runs as root and exercise the shell's actual failure propagation. The first argument after the
        # program's own is the store, which a real build creates.
        # env -i clears the environment, so the stub carries its own log path and failure.
        (work / 'bin/podman').write_text(f'''#!/bin/sh
printf '%s\\n' "$*" >> '{work / 'effects'}'
mkdir -p "$2"
case "$*" in
  *" build "*) [ '{failure}' != build ] || exit 42 ;;
  *" image exists "*) [ '{failure}' != exists ] || exit 43 ;;
  *" save "*) : > '{work / 'usr/lib/olivares/session-image.tar'}' ;;
esac
''')
        (work / 'bin/docker').write_text(f'''#!/bin/sh
printf '%s\\n' "$*" >> '{work / 'docker-effects'}'
[ '{failure}' != save ] || exit 44
printf archive > "$3"
''')
        for command in ('gpasswd', 'systemctl', 'runuser'):
            (work / 'bin' / command).write_text(f'#!/bin/sh\nprintf "%s\\n" "$*" >> "{work / "migration-effects"}"\n')
        (work / 'bin/id').write_text('#!/bin/sh\nif [ \"$1\" = -nG ]; then echo docker; else echo 987; fi\n')
        (work / 'bin/chown').write_text('#!/bin/sh\nexit 0\n')
        for path in (work / 'bin').iterdir():
            path.chmod(0o755)
        return subprocess.run(['bash', str(work / 'script')] + ([mode] if mode else []), text=True, capture_output=True,
                              env=dict(os.environ, PATH=str(work / 'bin') + ':/usr/bin:/bin',
                                       EFFECTS=str(work / 'effects'), FAILURE=failure))

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

    def test_root_builds_and_saves_the_image_the_engine_users_service_loads(self):
        result = self.run_build()
        self.assertEqual(result.returncode, 0, result.stderr)
        work = Path(self.temp.name)
        calls = (work / 'effects').read_text().splitlines()
        self.assertEqual(len(calls), 3, calls)
        # KIWI runs the helper in a chroot, where user namespaces are refused: no runuser, no rootless podman.
        for call in calls:
            self.assertTrue(call.startswith('--root ' + str(work / 'var/tmp/olivares-session-build/storage') + ' '), call)
            self.assertNotIn('docker', call)
        self.assertIn(' build ', calls[0])
        self.assertIn('--network=host', calls[0])
        self.assertIn('/etc/apt/sources.list.d:ro', calls[0])
        self.assertIn('localhost/olivares-session:latest', calls[0])
        self.assertIn(' image exists localhost/olivares-session:latest', calls[1])
        self.assertIn(' save --format oci-archive --output ' + str(work / 'usr/lib/olivares/session-image.tar'), calls[2])
        self.assertEqual((work / 'usr/lib/olivares/session-image.tar').stat().st_mode & 0o777, 0o644)
        self.assertFalse((work / 'var/tmp/olivares-session-build').exists())
        home = work / 'var/lib/olivares/.config/systemd/user'
        for target in ('sockets.target.wants/podman.socket', 'default.target.wants/podman.service'):
            self.assertTrue((home / target).is_symlink(), target)
        dropin = (work / 'etc/systemd/system/olivares.service.d/60-session-podman.conf').read_text()
        # The appliance names its runtime: Docker is also installed, for the optional apps.
        self.assertIn('OLIVARES_SESSION_CONTAINER_RUNTIME=podman', dropin)
        self.assertIn('CONTAINER_HOST=unix://' + str(work / 'run/user/987/podman/podman.sock'), dropin)
        self.assertIn('Wants=user@987.service', dropin)
        # The engine's XDG_RUNTIME_DIR is its own bus-less directory, never the user manager's /run/user/<uid>.
        self.assertIn('XDG_RUNTIME_DIR=' + str(work / 'var/lib/olivares/podman-client'), dropin)
        self.assertNotIn('XDG_RUNTIME_DIR=' + str(work / 'run/user'), dropin)
        self.assertIn('SystemCallErrorNumber=ENOSYS', dropin)
        self.assertTrue((work / 'var/lib/olivares/podman-client').is_dir())
        self.assertIn('After=user@987.service', dropin)
        self.assertNotIn('docker', '\n'.join(l for l in dropin.lower().splitlines() if not l.startswith('#')))
        self.assertNotIn('Requires=', dropin)
        self.assertNotIn('ExecStartPre=', dropin)
        self.assertNotIn('CapabilityBoundingSet', dropin)
        self.assertNotIn('NoNewPrivileges', dropin)
        self.assertFalse((work / 'etc/systemd/system/olivares.service.d/60-session-docker.conf').exists())
        self.assertTrue((work / 'var/lib/systemd/linger/olivares').exists())

    def test_unpinned_stages_are_rejected_before_build(self):
        pinned = 'FROM debian:trixie-slim@sha256:' + 'a' * 64 + '\n'
        for recipe in (pinned + 'FROM debian:trixie-slim\n',
                       pinned + 'from debian:trixie-slim\n',
                       'RUN true\n'):
            with self.subTest(recipe=recipe):
                result = self.run_build(recipe=recipe)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('session-image: every FROM must use the pinned Debian base', result.stderr)
                self.assertFalse((Path(self.temp.name) / 'effects').exists())

    def test_existing_runtime_is_preserved_and_explained(self):
        runtime = Path(self.temp.name) / 'var/tmp/olivares-session-build'
        runtime.mkdir(parents=True)
        sentinel = runtime / 'owned-by-user-manager'
        sentinel.touch()
        result = self.run_build()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('session-image: build directory already exists:', result.stderr)
        self.assertTrue(sentinel.exists())

    def test_build_failure_stops_image_build(self):
        result = self.run_build('build')
        self.assertEqual(result.returncode, 42, result.stderr)
        self.assertEqual(len((Path(self.temp.name) / 'effects').read_text().splitlines()), 1)
        self.assertFalse((Path(self.temp.name) / 'var/tmp/olivares-session-build/storage').exists())

    def test_missing_image_stops_image_build(self):
        result = self.run_build('exists')
        self.assertEqual(result.returncode, 43, result.stderr)
        self.assertIn('session-image: built image is missing: localhost/olivares-session:latest', result.stderr)

    def test_upgrade_exports_offline_before_switching_to_vendor_podman(self):
        work = Path(self.temp.name)
        legacy = work / 'etc/systemd/system/olivares.service.d/60-session-docker.conf'
        legacy.parent.mkdir(parents=True)
        legacy.write_text('[Service]\nEnvironment=OLIVARES_SESSION_CONTAINER_RUNTIME=docker\n')
        result = self.run_build('save', mode='--migrate')
        self.assertEqual(result.returncode, 44, result.stderr)
        self.assertTrue(legacy.exists())
        self.assertFalse((legacy.parent / '60-session-podman.conf').exists())
        result = self.run_build(mode='--migrate')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(legacy.exists())
        self.assertFalse((work / 'effects').exists(), 'migration must not build or pull')
        self.assertIn('save --output ', (work / 'docker-effects').read_text())
        self.assertEqual((work / 'usr/lib/olivares/session-image.tar').read_text(), 'archive')
        home = work / 'var/lib/olivares/.config/systemd/user'
        for unit, target in (('socket', 'sockets'), ('service', 'default')):
            self.assertEqual((home / f'{target}.target.wants/podman.{unit}').readlink(),
                             work / f'usr/lib/systemd/user/podman.{unit}')
        self.assertIn('SocketMode=0600', (home / 'podman.socket.d/10-olivares.conf').read_text())
        self.assertIn('podman load --quiet --input ', (home / 'podman.service.d/10-olivares.conf').read_text())
        calls = (work / 'migration-effects').read_text()
        self.assertIn('podman load --quiet --input ', calls)
        self.assertIn('-d olivares docker', calls)
        self.assertLess(calls.index('-d olivares docker'), calls.index('restart user@987.service'))
        self.assertIn('try-restart olivares.service', calls)
        manifest = json.loads('\n'.join(l for l in (ROOT / 'packaging/nfpm/olivares-appliance-base.yaml').read_text().splitlines() if not l.startswith('#')))
        for fmt in ('rpm', 'deb'):
            self.assertIn('podman', manifest['overrides'][fmt]['depends'])
        self.assertIn('olivares >= ${VERSION}', manifest['overrides']['rpm']['depends'])
        self.assertIn('olivares (>= ${VERSION})', manifest['overrides']['deb']['depends'])
        self.assertIn('/usr/libexec/olivares/session-image --migrate',
                      (ROOT / 'appliance/layer/base/package/postinstall.sh').read_text())

    def test_recipe_runs_build_on_both_almalinux_editions(self):
        script = (ROOT / 'appliance/images/kiwi/config.sh').read_text()
        self.assertIn('/usr/libexec/olivares/session-image', script)
        manifest = json.loads('\n'.join(line for line in (ROOT / 'packaging/nfpm/olivares-appliance-base.yaml').read_text().splitlines() if not line.startswith('#')))
        dst = [x['dst'] for x in manifest['contents']]
        for path in ('/usr/libexec/olivares/session-image',):
            self.assertIn(path, dst)


class SubordinateIDs(unittest.TestCase):
    def test_rpm_recipes_require_scriptlet_command_providers(self):
        release = json.loads((ROOT / 'packaging/nfpm/packages.json').read_text())
        product = next(p for p in release['nfpms'] if p['package_name'] == 'olivares')
        dev = json.loads('\n'.join(line for line in
            (ROOT / 'appliance/images/kiwi/product-dev.nfpm.yaml').read_text().splitlines()
            if not line.startswith('#')))
        for recipe in (product, dev):
            with self.subTest(recipe=recipe.get('id', 'appliance')):
                for package in ('/bin/sh', 'gawk', 'shadow-utils', 'coreutils', 'sed', 'grep'):
                    self.assertIn(package, recipe['overrides']['rpm']['depends'])

    def test_rpm_allocates_after_existing_ranges_and_keeps_admin_assignments(self):
        script = (ROOT / 'packaging/nfpm/postinstall.sh').read_text()
        self.assertIn('# BEGIN subordinate IDs', script)
        block = script.split('# BEGIN subordinate IDs\n', 1)[1].split('# END subordinate IDs', 1)[0]
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'subuid').write_text('other:100000:65536\n')
            (root / 'subgid').write_text('other:200000:65536\n')
            usermod = root / 'usermod'
            usermod.write_text('#!/bin/sh\ncase "$1" in --add-subuids) f=subuid;; --add-subgids) f=subgid;; esac\nprintf "olivares:%s:65536\\n" "${2%-*}" >> "$TEST_ROOT/$f"\n')
            usermod.chmod(0o755)
            block = block.replace('/etc/', str(root) + '/')
            env = dict(os.environ, PATH=temp + ':/usr/bin:/bin', TEST_ROOT=temp)
            for _ in range(2):
                result = subprocess.run(['sh', '-c', 'set -eu; format=rpm; ' + block], env=env,
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((root / 'subuid').read_text(), 'other:100000:65536\nolivares:165536:65536\n')
            self.assertEqual((root / 'subgid').read_text(), 'other:200000:65536\nolivares:265536:65536\n')


if __name__ == '__main__':
    unittest.main()
