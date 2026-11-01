#!/bin/bash
# SPDX-FileCopyrightText: 2026 Olivares.AI
# SPDX-License-Identifier: AGPL-3.0-only
# KIWI's image-root step, not a first-boot download. Every failure stops config.sh.
set -euo pipefail
recipe=/usr/share/olivares/session-image
image=localhost/olivares-session:latest
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
# Build with a private daemon into the persistent store docker.service uses at boot.
# No bridge or firewall changes are needed: only the build uses host networking.
runtime=/run/olivares-session-build
if [ -e "$runtime" ]; then
  echo "session-image: runtime directory already exists: $runtime" >&2
  exit 1
fi
install -d -m 0755 "$runtime"
daemon_pid=
containerd_pid=
cleanup() {
  status=$?
  trap - EXIT
  if [ -n "$daemon_pid" ] && kill -0 "$daemon_pid" 2>/dev/null; then
    kill "$daemon_pid"
    wait "$daemon_pid" || true # a daemon terminated by SIGTERM may return 143
  fi
  if [ -n "$containerd_pid" ] && kill -0 "$containerd_pid" 2>/dev/null; then
    kill "$containerd_pid"
    wait "$containerd_pid" || true # a daemon terminated by SIGTERM may return 143
  fi
  # These identify the builder, not the installed appliance. Preserve image data.
  rm -f /var/lib/docker/engine-id /var/lib/docker/network/files/local-kv.db
  # Docker keeps this namespace bind mount even after its daemon exits.
  if mountpoint -q "$runtime/exec/netns/default"; then
    umount "$runtime/exec/netns/default"
  fi
  rm -rf "$runtime"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
build_sources=$runtime/context
mkdir "$build_sources"
cp -a "$recipe/." "$build_sources/"
cat > "$build_sources/debian.sources" <<'SOURCES'
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
# Docker has no build --volume. Replace all base apt sources in a staged recipe.
awk '
  !inserted && $1 == "RUN" {
    print "COPY debian.sources /tmp/olivares-debian.sources"
    print "RUN rm -rf /etc/apt/sources.list.d/* /etc/apt/sources.list && mv /tmp/olivares-debian.sources /etc/apt/sources.list.d/debian.sources"
    inserted = 1
  }
  { print }
' "$recipe/Containerfile" > "$build_sources/Containerfile"
# Docker CE 29 defaults to containerd's image store. Use the same configuration
# and persistent root as containerd.service, rather than dockerd's private store.
env -i PATH=/usr/bin:/bin HOME=/root containerd \
  --config=/etc/containerd/config.toml --root=/var/lib/containerd \
  --address="$runtime/containerd.sock" --state="$runtime/containerd" \
  > "$runtime/containerd.log" 2>&1 &
containerd_pid=$!
ready=false
for ((attempt=0; attempt<60; attempt++)); do
  if ctr --address "$runtime/containerd.sock" version >/dev/null 2>&1; then ready=true; break; fi
  if ! kill -0 "$containerd_pid" 2>/dev/null; then break; fi
  sleep 1
done
if [ "$ready" != true ]; then
  echo "session-image: containerd build daemon is not ready" >&2
  cat "$runtime/containerd.log" >&2
  exit 1
fi
# Do not inherit the builder's credentials or container connection settings.
env -i PATH=/usr/bin:/bin HOME=/root dockerd \
  --host="unix://$runtime/docker.sock" --group=docker \
  --containerd="$runtime/containerd.sock" \
  --data-root=/var/lib/docker --exec-root="$runtime/exec" --pidfile="$runtime/docker.pid" \
  --bridge=none --userland-proxy=false --iptables=false --ip-forward=false --ip-masq=false \
  > "$runtime/daemon.log" 2>&1 &
daemon_pid=$!
as_engine() {
  runuser -u olivares -- env -i HOME=/var/lib/olivares USER=olivares LOGNAME=olivares PATH=/usr/bin:/bin \
    DOCKER_HOST="unix://$runtime/docker.sock" DOCKER_CONFIG="$runtime/client" "$@"
}
ready=false
for ((attempt=0; attempt<60; attempt++)); do
  if as_engine docker info >/dev/null 2>&1; then ready=true; break; fi
  if ! kill -0 "$daemon_pid" 2>/dev/null; then break; fi
  sleep 1
done
if [ "$ready" != true ]; then
  echo "session-image: Docker build daemon is not ready" >&2
  cat "$runtime/daemon.log" >&2
  exit 1
fi
as_engine docker build --network=host -f "$build_sources/Containerfile" -t "$image" "$build_sources"
as_engine docker image inspect "$image" >/dev/null || {
  status=$?
  echo "session-image: built image is missing: $image" >&2
  exit "$status"
}
# An optional runtime failure must not stop the engine or its console.
install -d -m 0755 /etc/systemd/system/olivares.service.d
cat > /etc/systemd/system/olivares.service.d/60-session-docker.conf <<'UNIT'
[Unit]
Wants=docker.service
After=docker.service

[Service]
Environment=OLIVARES_SESSION_CONTAINER_RUNTIME=docker
UNIT
