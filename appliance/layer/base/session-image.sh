#!/bin/bash
# SPDX-FileCopyrightText: 2026 Olivares.AI
# SPDX-License-Identifier: AGPL-3.0-only
# KIWI's image-root step, not a first-boot download. Every failure stops config.sh.
set -euo pipefail
uid=$(id -u olivares)
gid=$(id -g olivares)
home=/var/lib/olivares
runtime=/run/user/$uid
recipe=/usr/share/olivares/session-image
image=localhost/olivares-session:latest
# The archive the engine user's podman service loads into its own store at boot (the vendor podman.service).
archive=/usr/lib/olivares/session-image.tar
build=/var/tmp/olivares-session-build
legacy=/etc/systemd/system/olivares.service.d/60-session-docker.conf
if [ "${1:-}" = --migrate ]; then
  [ -f "$legacy" ] || exit 0
  # Preserve the installed image offline. Do not change the engine until export AND rootless load succeed.
  install -d -m 0755 /usr/lib/olivares
  trap 'rm -f "$archive.new"' EXIT
  docker save --output "$archive.new" "$image"
  chmod 0644 "$archive.new"
  install -d -m 0700 -o "$uid" -g "$gid" "$runtime"
  runuser -u olivares -- env -u CONTAINER_HOST HOME="$home" XDG_RUNTIME_DIR="$runtime" \
    podman load --quiet --input "$archive.new"
  mv -f "$archive.new" "$archive"
else
# Refuse a package that stopped pinning its base before granting network to the build.
if ! awk '
  toupper($1) == "FROM" {
    seen = 1
    if (NF != 2 || $1 != "FROM" ||
        $2 !~ /^debian:trixie-slim@sha256:[0-9a-f]+$/ ||
        length($2) != length("debian:trixie-slim@sha256:") + 64) bad = 1
  }
  END { exit (!seen || bad) }
' "$recipe/Containerfile"; then
  echo "session-image: every FROM must use the pinned Debian base" >&2
  exit 1
fi
if [ -e "$build" ]; then
  echo "session-image: build directory already exists: $build" >&2
  exit 1
fi
install -d -m 0755 "$build"
trap 'rm -rf --one-file-system "$build"' EXIT
# The build's apt sources replace ALL the base image's sources: dated, signed snapshots; no live archive is consulted.
install -d -m 0755 "$build/sources"
cat > "$build/sources/debian.sources" <<'SOURCES'
Types: deb
URIs: http://snapshot.debian.org/archive/debian/20260922T000000Z/
Suites: trixie trixie-updates
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
Check-Valid-Until: no

Types: deb
URIs: http://snapshot.debian.org/archive/debian-security/20260922T000000Z/
Suites: trixie-security
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
Check-Valid-Until: no
SOURCES
# KIWI runs this script in a chroot, where the kernel refuses user namespaces: rootless Podman cannot build or load here.
# Root builds into a throwaway store and saves the image; the engine user's service loads it at boot. env -i keeps the
# builder's credentials and container connection settings out.
as_root() {
  env -i PATH=/usr/bin:/bin HOME=/root podman --root "$build/storage" --runroot "$build/run" --storage-driver overlay \
    --cgroup-manager cgroupfs --events-backend file "$@"
}
as_root build --network=host --volume "$build/sources:/etc/apt/sources.list.d:ro" \
  -f "$recipe/Containerfile" -t "$image" "$recipe"
as_root image exists "$image" || {
  status=$?
  echo "session-image: built image is missing: $image" >&2
  exit "$status"
}
install -d -m 0755 /usr/lib/olivares
as_root save --format oci-archive --output "$archive" "$image"
chmod 0644 "$archive"

fi

# Linger starts the engine user's manager at boot without a login, and the manager starts the service that loads the image
# and serves the engine's API. The engine only ever uses the API; it never needs newuidmap's host capabilities.
install -d -m 0755 /var/lib/systemd/linger /etc/systemd/system/olivares.service.d
install -d -m 0750 -o "$uid" -g "$gid" "$home/.config" "$home/.config/systemd" "$home/.config/systemd/user" \
  "$home/.config/systemd/user/sockets.target.wants" "$home/.config/systemd/user/default.target.wants" \
  "$home/.config/systemd/user/podman.service.d" "$home/.config/systemd/user/podman.socket.d"
# The engine's own runtime directory for podman: it exists, is the user's and holds no user manager socket. The engine
# finds its user manager by those sockets (confine.UserBusDirs) and must find none; podman refuses to start when the
# directory it is given is missing or holds an unreadable bus.
install -d -m 0700 -o "$uid" -g "$gid" "$home/podman-client"
touch /var/lib/systemd/linger/olivares
ln -sfn /usr/lib/systemd/user/podman.socket \
  "$home/.config/systemd/user/sockets.target.wants/podman.socket"
ln -sfn /usr/lib/systemd/user/podman.service \
  "$home/.config/systemd/user/default.target.wants/podman.service"
# Keep the vendor's Delegate=true, KillMode=process, socket path and service lifecycle.
cat > "$home/.config/systemd/user/podman.service.d/10-olivares.conf" <<'UNIT'
[Service]
# Load the current archive even if the tag exists: an image update must replace the old tag.
ExecStartPre=/usr/bin/podman load --quiet --input /usr/lib/olivares/session-image.tar
TimeoutStartSec=infinity
UNIT
cat > "$home/.config/systemd/user/podman.socket.d/10-olivares.conf" <<'UNIT'
[Socket]
SocketMode=0600
UNIT
chown "$uid:$gid" "$home/.config/systemd/user/podman.service.d/10-olivares.conf" \
  "$home/.config/systemd/user/podman.socket.d/10-olivares.conf"
cat > /etc/systemd/system/olivares.service.d/60-session-podman.conf <<UNIT
[Unit]
Wants=user@$uid.service
After=user@$uid.service

[Service]
# Docker is installed too, for the optional apps; the engine never reaches its socket. With CONTAINER_HOST set,
# podman is a client of the user's socket and needs no newuidmap in the engine.
Environment=OLIVARES_SESSION_CONTAINER_RUNTIME=podman
Environment=CONTAINER_HOST=unix://$runtime/podman/podman.sock
Environment=XDG_RUNTIME_DIR=$home/podman-client
# The unit's filter kills a process that makes a call it does not list. podman's SELinux library probes newer calls at
# start and copes with an error, not with a kill: the calls stay refused, and fail with ENOSYS.
SystemCallErrorNumber=ENOSYS
UNIT

if [ "${1:-}" = --migrate ]; then
  # A pre-existing user manager inherited the old docker group. Recreate it after removing membership.
  if id -nG olivares | grep -qw docker; then gpasswd -d olivares docker; fi
  systemctl restart "user@$uid.service"
  runuser -u olivares -- env XDG_RUNTIME_DIR="$runtime" systemctl --user daemon-reload
  runuser -u olivares -- env XDG_RUNTIME_DIR="$runtime" systemctl --user start podman.socket podman.service
  # The old file and group access go only after the new runtime is available. Docker's own store stays intact.
  rm -f "$legacy"
  systemctl daemon-reload
  systemctl try-restart olivares.service
fi
