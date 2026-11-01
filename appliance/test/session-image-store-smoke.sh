#!/bin/bash
# SPDX-FileCopyrightText: 2026 Olivares.AI
# SPDX-License-Identifier: AGPL-3.0-only
# Disposable privileged lab only: build with locked CE RPMs, then use boot's stores.
set -euo pipefail
cd "$(dirname "$0")/../.."
scratch=$(mktemp -d)
name=olivares-session-store-$$
base=
remove_base=false
cleanup() {
  docker rm -fv "$name" >/dev/null 2>&1 || true
  if [ "$remove_base" = true ]; then docker image rm "$base" >/dev/null; fi
  rm -rf "$scratch"
}
trap cleanup EXIT
python3 - "$scratch" <<'PY'
import hashlib, json, pathlib, subprocess, sys
lock = json.loads(pathlib.Path('appliance/images/toolchain/almalinux10/input-lock.json').read_text())
for package in lock['container_runtime']['packages'].values():
    target = pathlib.Path(sys.argv[1]) / package['href'].split('/')[-1]
    subprocess.run(['curl', '-fsSL', '--retry', '3', '--max-time', '180', '-o', str(target), package['url']], check=True)
    assert hashlib.sha256(target.read_bytes()).hexdigest() == package['sha256']
(pathlib.Path(sys.argv[1]) / 'base').write_text('almalinux@' + lock['base_image']['manifest_digest_amd64'])
PY
base=$(cat "$scratch/base")
if ! docker image inspect "$base" >/dev/null 2>&1; then remove_base=true; fi
docker run -i --rm --privileged --network=host --name "$name" --tmpfs /run \
  -v /var/lib/docker -v /var/lib/containerd \
  -v "$PWD:/src:ro" -v "$scratch:/inputs:ro" "$base" bash -s <<'INNER'
set -euo pipefail
rpm --import /src/appliance/images/kiwi/RPM-GPG-KEY-docker
rpmkeys --checksig /inputs/*.rpm
dnf install -y /inputs/*.rpm shadow-utils util-linux systemd
useradd --system --create-home --home-dir /var/lib/olivares --groups docker olivares
install -d /usr/share/olivares/session-image /etc/docker
cp /src/packaging/container/session/Containerfile /usr/share/olivares/session-image/
printf '{"selinux-enabled": true}\n' > /etc/docker/daemon.json
rpm -q docker-ce docker-ce-cli containerd.io
bash /src/appliance/layer/base/session-image.sh
test ! -e /var/lib/docker/engine-id
test ! -e /var/lib/docker/network/files/local-kv.db
test ! -e /var/lib/olivares/.docker
# The build's /run is gone. Start the RPM units' commands with their normal stores.
containerd >/run/containerd-boot.log 2>&1 &
containerd_pid=$!
boot_pid=
cleanup() {
  [ -z "$boot_pid" ] || kill "$boot_pid" 2>/dev/null || true
  kill "$containerd_pid" 2>/dev/null || true
  wait || true
}
trap cleanup EXIT
for ((i=0; i<60; i++)); do
  if ctr version >/dev/null 2>&1; then break; fi
  sleep 1
done
# Supply docker.socket's listening descriptor without requiring systemd PID 1.
systemd-socket-activate -l /run/docker.sock /usr/bin/dockerd -H fd:// \
  --containerd=/run/containerd/containerd.sock \
  --bridge=none --iptables=false --ip-forward=false --ip-masq=false >/run/docker-boot.log 2>&1 &
boot_pid=$!
for ((i=0; i<60; i++)); do
  if docker info >/dev/null 2>&1; then break; fi
  sleep 1
done
if ! docker info; then cat /run/*-boot.log; exit 1; fi
chgrp docker /run/docker.sock
chmod 660 /run/docker.sock
runuser -u olivares -- docker image inspect localhost/olivares-session:latest --format '{{.Id}}'
runuser -u olivares -- docker run --rm --pull=never --network=none --cap-drop=ALL \
  --security-opt=no-new-privileges --user "$(id -u olivares):$(id -g olivares)" \
  localhost/olivares-session:latest git --version
echo Session-image-CE-boot-store-PASS
INNER
