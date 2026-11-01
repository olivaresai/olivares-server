#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Olivares.AI
# SPDX-License-Identifier: AGPL-3.0-only
"""The image build must populate Docker for the engine and refuse failures."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'appliance/layer/base/session-image.sh'


class SessionImage(unittest.TestCase):
    def run_build(self, failure='', recipe=None):
        work = Path(self.temp.name)
        for path in ('etc', 'var/lib/olivares', 'run', 'usr/share/olivares/session-image', 'bin'):
            (work / path).mkdir(parents=True, exist_ok=True)
        (work / 'usr/share/olivares/session-image/Containerfile').write_text(
            recipe if recipe is not None else
            'FROM debian:trixie-slim@sha256:' + 'a' * 64 + '\nRUN apt-get update\n')
        script = SCRIPT.read_text().replace('PATH=/usr/bin:/bin', 'PATH=' + str(work / 'bin') + ':/usr/bin:/bin')
        for path in ('/etc', '/var', '/run', '/usr/share'):
            script = script.replace(path, str(work) + path)
        (work / 'script').write_text(script)
        # Record the privilege boundary and exercise the shell's actual failure propagation.
        (work / 'bin/runuser').write_text('''#!/bin/sh
printf '%s\\n' "$*" >> "$EFFECTS"
case "$*" in
  *" info")
    [ "$FAILURE" != daemon ] || exit 44
    grep -q "^dockerd " "$EFFECTS.daemons" 2>/dev/null || exit 1 ;;
  *" build "*)
    for arg do context=$arg; done
    cp "$context/Containerfile" "$EFFECTS.recipe"
    cp "$context/debian.sources" "$EFFECTS.sources"
    [ "$FAILURE" != build ] || exit 42 ;;
  *" image inspect "*) [ "$FAILURE" != exists ] || exit 43 ;;
esac
''')
        daemon = """#!/bin/sh
trap 'echo stopped-$(basename "$0") >> "EFFECT_PATH.daemons"; exit 0' TERM
printf '%s %s\\n' "$(basename "$0")" "$*" >> 'EFFECT_PATH.daemons'
while :; do sleep 0.05; done
""".replace('EFFECT_PATH', str(work / 'effects'))
        for name in ('dockerd', 'containerd'):
            (work / 'bin' / name).write_text(daemon)
        (work / 'bin/ctr').write_text('#!/bin/sh\nexit 0\n')
        (work / 'bin/mountpoint').write_text('#!/bin/sh\nexit 0\n')
        (work / 'bin/umount').write_text(
            '#!/bin/sh\nprintf "unmount %s\\n" "$*" >> "' + str(work / 'effects.daemons') + '"\n')
        for path in ('var/lib/docker/network/files/local-kv.db', 'var/lib/docker/engine-id'):
            target = work / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.touch()
        if failure == 'daemon':
            (work / 'bin/dockerd').write_text('#!/bin/sh\necho daemon-refused >&2\nexit 45\n')
        if failure == 'containerd':
            (work / 'bin/containerd').write_text('#!/bin/sh\necho containerd-refused >&2\nexit 46\n')
            (work / 'bin/ctr').write_text('#!/bin/sh\nexit 1\n')
        for path in (work / 'bin').iterdir():
            path.chmod(0o755)
        return subprocess.run(['bash', str(work / 'script')], text=True, capture_output=True,
                              env=dict(os.environ, PATH=str(work / 'bin') + ':/usr/bin:/bin',
                                       EFFECTS=str(work / 'effects'), FAILURE=failure))

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

    def test_server_uses_docker_without_a_user_manager(self):
        result = self.run_build()
        self.assertEqual(result.returncode, 0, result.stderr)
        work = Path(self.temp.name)
        calls = (work / 'effects').read_text()
        self.assertIn('docker build ', calls)
        self.assertIn('docker image inspect localhost/olivares-session:latest', calls)
        self.assertNotIn('podman', calls)
        self.assertIn('-u olivares -- env -i ', calls)
        self.assertIn('DOCKER_HOST=unix://', calls)
        self.assertIn('--network=host', calls)
        self.assertFalse((work / 'run/olivares-session-build').exists())
        staged = (work / 'effects.recipe').read_text().replace(str(work), '')
        self.assertLess(staged.index('COPY debian.sources'), staged.index('RUN apt-get update'))
        self.assertIn('rm -rf /etc/apt/sources.list.d/* /etc/apt/sources.list', staged)
        sources = (work / 'effects.sources').read_text().replace(str(work), '')
        self.assertEqual(sources.count('URIs: http://snapshot.debian.org/'), 2)
        self.assertIn('Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg', sources)
        dropin = (work / 'etc/systemd/system/olivares.service.d/60-session-docker.conf').read_text()
        self.assertIn('OLIVARES_SESSION_CONTAINER_RUNTIME=docker', dropin)
        self.assertNotIn('Requires=', dropin)
        self.assertNotIn('ExecStartPre=', dropin)
        self.assertNotIn('CapabilityBoundingSet', dropin)
        self.assertNotIn('NoNewPrivileges', dropin)
        self.assertFalse((work / 'var/lib/systemd/linger/olivares').exists())

    def test_build_uses_boot_containerd_store_and_seals_identity(self):
        result = self.run_build()
        self.assertEqual(result.returncode, 0, result.stderr)
        work = Path(self.temp.name)
        daemons = (work / 'effects.daemons').read_text().replace(str(work), '')
        self.assertIn('containerd --config=/etc/containerd/config.toml --root=/var/lib/containerd', daemons)
        self.assertIn('--containerd=/run/olivares-session-build/containerd.sock', daemons)
        self.assertIn('stopped-dockerd', daemons)
        self.assertIn('stopped-containerd', daemons)
        self.assertIn('unmount /run/olivares-session-build/exec/netns/default', daemons)
        for path in ('var/lib/docker/engine-id', 'var/lib/docker/network/files/local-kv.db'):
            self.assertFalse((work / path).exists(), path)
        calls = (work / 'effects').read_text().replace(str(work), '')
        self.assertIn('DOCKER_CONFIG=/run/olivares-session-build/client', calls)

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
        runtime = Path(self.temp.name) / 'run/olivares-session-build'
        runtime.mkdir(parents=True)
        sentinel = runtime / 'owned-by-user-manager'
        sentinel.touch()
        result = self.run_build()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('session-image: runtime directory already exists:', result.stderr)
        self.assertTrue(sentinel.exists())

    def test_daemon_failure_stops_build_with_log(self):
        result = self.run_build('daemon')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Docker build daemon is not ready', result.stderr)
        self.assertIn('daemon-refused', result.stderr)
        self.assertNotIn('docker build ', (Path(self.temp.name) / 'effects').read_text())
        self.assertFalse((Path(self.temp.name) / 'run/olivares-session-build').exists())

    def test_containerd_failure_stops_before_docker_with_log(self):
        result = self.run_build('containerd')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('containerd build daemon is not ready', result.stderr)
        self.assertIn('containerd-refused', result.stderr)
        work = Path(self.temp.name)
        self.assertFalse((work / 'effects').exists())
        self.assertFalse((work / 'run/olivares-session-build').exists())

    def test_build_failure_stops_image_build(self):
        result = self.run_build('build')
        self.assertEqual(result.returncode, 42, result.stderr)
        daemons = (Path(self.temp.name) / 'effects.daemons').read_text()
        self.assertIn('stopped-dockerd', daemons)
        self.assertIn('stopped-containerd', daemons)
        self.assertFalse((Path(self.temp.name) / 'run/olivares-session-build').exists())
        calls = (Path(self.temp.name) / 'effects').read_text()
        self.assertEqual(calls.count('docker build '), 1)
        self.assertNotIn('docker image inspect', calls)

    def test_missing_image_stops_image_build(self):
        result = self.run_build('exists')
        self.assertEqual(result.returncode, 43, result.stderr)
        self.assertIn('session-image: built image is missing: localhost/olivares-session:latest', result.stderr)

    def test_recipe_runs_build_on_both_almalinux_editions(self):
        script = (ROOT / 'appliance/images/kiwi/config.sh').read_text()
        self.assertIn('/usr/libexec/olivares/session-image', script)
        manifest = json.loads('\n'.join(line for line in (ROOT / 'packaging/nfpm/olivares-appliance-base.yaml').read_text().splitlines() if not line.startswith('#')))
        self.assertIn('/usr/libexec/olivares/session-image', [x['dst'] for x in manifest['contents']])


if __name__ == '__main__':
    unittest.main()
