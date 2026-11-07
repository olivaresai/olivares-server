#!/bin/bash
# SPDX-FileCopyrightText: 2026 Olivares.AI
# SPDX-License-Identifier: AGPL-3.0-only
# Disposable privileged lab only, in the digest-pinned AlmaLinux 10 image with AlmaLinux's own podman. It does what the
# image build and the booted appliance do, in that order:
#   1. runs the real session-image.sh in a chroot, as KIWI does (the kernel refuses user namespaces there, so the helper
#      must not need one);
#   2. takes what the build left (the saved image and the engine user's files) out of the chroot, as a boot does, and runs the
#      user unit's own load line as the engine user;
#   3. starts the user's podman socket and, as a client with an empty capability bounding set and NoNewPrivileges (the
#      engine unit's), starts a container from the built image.
set -euo pipefail
cd "$(dirname "$0")/../.."
name=olivares-session-store-$$
base=
remove_base=false
cleanup() {
  docker rm -fv "$name" >/dev/null 2>&1 || true
  if [ "$remove_base" = true ]; then docker image rm "$base" >/dev/null; fi
}
trap cleanup EXIT
base=almalinux@$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["base_image"]["manifest_digest_amd64"])' \
  appliance/images/toolchain/almalinux10/input-lock.json)
if ! docker image inspect "$base" >/dev/null 2>&1; then remove_base=true; fi
# The chroot and the account home (the user's store) are anonymous volumes: overlay storage cannot sit on the lab's overlay filesystem.
docker run -i --rm --privileged --network=host --name "$name" --tmpfs /run \
  -v /sysroot -v /var/lib/olivares -v "$PWD:/src:ro" "$base" bash -s <<'INNER'
set -euo pipefail
step() { printf '== %s\n' "$*"; }
trap 'rc=$?; [ "$rc" -eq 0 ] || printf "== FAILED at line %s (rc=%s)\n" "$LINENO" "$rc"' ERR
block=$(sed -n '/^# BEGIN subordinate IDs$/,/^# END subordinate IDs$/p' /src/packaging/nfpm/postinstall.sh)
step "the image root"
dnf install -y -q --installroot=/sysroot --releasever=10 --setopt=install_weak_deps=False podman shadow-utils util-linux bash coreutils gawk grep sed
dnf install -y -q podman util-linux gawk
chroot /sysroot useradd --system --create-home --home-dir /var/lib/olivares olivares
# The product package's own allocation, not a copy of it.
chroot /sysroot env format=rpm bash -c "set -eu; $block"
install -d /sysroot/usr/share/olivares/session-image /sysroot/usr/libexec/olivares
cp /src/packaging/container/session/Containerfile /sysroot/usr/share/olivares/session-image/
install -m 0755 /src/appliance/layer/base/session-image.sh /sysroot/usr/libexec/olivares/session-image
cp /etc/resolv.conf /sysroot/etc/resolv.conf
for m in proc sys dev; do mount --rbind "/$m" "/sysroot/$m"; done
step "session-image.sh in the chroot"
chroot /sysroot /usr/libexec/olivares/session-image
for m in proc sys dev; do umount -R "/sysroot/$m"; done
grep -q "OLIVARES_SESSION_CONTAINER_RUNTIME=podman" /sysroot/etc/systemd/system/olivares.service.d/60-session-podman.conf
test -L /sysroot/var/lib/olivares/.config/systemd/user/sockets.target.wants/podman.socket
step "boot: the saved image and the engine user's files"
install -d /usr/lib/olivares
cp -a /sysroot/usr/lib/olivares/session-image.tar /usr/lib/olivares/
test -s /usr/lib/olivares/session-image.tar
useradd --system --home-dir /var/lib/olivares olivares
cp -a /sysroot/var/lib/olivares/. /var/lib/olivares/
chown -R olivares:olivares /var/lib/olivares
chmod 0750 /var/lib/olivares
format=rpm bash -c "set -eu; $block"
uid=$(id -u olivares)
install -d -m 0700 -o olivares -g olivares "/run/user/$uid" "/run/user/$uid/podman"
runuser -u olivares -- env HOME=/var/lib/olivares XDG_RUNTIME_DIR="/run/user/$uid" \
  podman system service --time=0 "unix:///run/user/$uid/podman/podman.sock" >/run/podman-service.log 2>&1 &
service_pid=$!
trap 'kill "$service_pid" 2>/dev/null || true; wait || true' EXIT
step "the user unit's own load line, as the engine user"
load=$(sed -n 's/^ExecStartPre=//p' /var/lib/olivares/.config/systemd/user/podman.service.d/10-olivares.conf)
runuser -u olivares -- env HOME=/var/lib/olivares XDG_RUNTIME_DIR="/run/user/$uid" sh -c "$load"
runuser -u olivares -- env HOME=/var/lib/olivares XDG_RUNTIME_DIR="/run/user/$uid" podman image exists localhost/olivares-session:latest
step "start the user socket"
for ((i=0; i<30; i++)); do [ -S "/run/user/$uid/podman/podman.sock" ] && break; sleep 1; done
[ -S "/run/user/$uid/podman/podman.sock" ] || { cat /run/podman-service.log; exit 1; }
step "engine side"
# The engine's side: no capabilities, no new privileges, podman as a client of the socket (CONTAINER_HOST).
engine() {
  setpriv --reuid=olivares --regid=olivares --init-groups --bounding-set=-all --no-new-privs -- \
    env -i PATH=/usr/bin:/bin HOME=/var/lib/olivares XDG_RUNTIME_DIR="/run/user/$uid" \
    CONTAINER_HOST="unix:///run/user/$uid/podman/podman.sock" "$@"
}
test "$(engine grep -c '^CapBnd:.0000000000000000$' /proc/self/status)" = 1
engine podman image exists localhost/olivares-session:latest
engine podman image inspect localhost/olivares-session:latest --format '{{.Id}}'
engine podman run --rm --pull=never --network=none --cap-drop=ALL --security-opt=no-new-privileges \
  --userns=keep-id localhost/olivares-session:latest git --version
# Docker is not in this image and the engine user has no group that opens a daemon socket.
! id -nG olivares | grep -qw docker
echo Session-image-podman-socket-PASS
INNER
