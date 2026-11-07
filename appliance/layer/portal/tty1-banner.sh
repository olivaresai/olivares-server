#!/bin/sh
# SPDX-FileCopyrightText: 2026 Olivares.AI
# SPDX-License-Identifier: AGPL-3.0-only
# Write the banner tty1 prints: the static text, then the host's reachable IPv4 addresses and the way to the
# one-time setup token. It holds no secret and writes only OUTPUT: the repair console prints it when it starts,
# and nothing else writes to tty1 while the console may hold a prompt.
#
# tty1-banner STATIC OUTPUT [IMAGE]
set -eu
static=${1:?usage: tty1-banner STATIC OUTPUT [IMAGE]}
out=${2:?usage: tty1-banner STATIC OUTPUT [IMAGE]}
# The image's own record names its variant (config.sh writes it). An unreadable record keeps the static text.
image=${3:-/etc/olivares-appliance/image}
variant=$(cat "$image" 2>/dev/null || true)
tmp="$out.tmp.$$"
trap 'rm -f "$tmp"' EXIT HUP INT TERM
# Container bridges and their veth ends carry addresses nobody on the network can reach.
addresses=$(ip -o -4 addr show scope global | awk '$2 !~ /^(docker|br-|veth|podman)/ {sub(/\/.*/, "", $4); print $4}')
{
  if [ "$variant" = almalinux10-desktop-amd64 ]; then
    # A desktop runs a graphical desktop, so the static sentence that calls the machine headless is replaced for it.
    sed 's/^This is a headless server: it has no desktop\. Finish/This is the desktop edition, with a graphical desktop. Finish/' "$static"
  else
    cat "$static"
  fi
  if [ -n "$addresses" ]; then
    printf '%s\n' "$addresses" | while IFS= read -r address; do
      printf '  Open https://%s:8443/setup\n' "$address"
    done
  else
    printf '  Waiting for a network address (DHCP); choose q to show this screen again.\n'
  fi
  printf 'At this console, choose s to sign in, then t to show the one-time setup token.\n'
  printf 'The token is shown only after you sign in and confirm; it is never written to the journal.\n'
} >"$tmp"
chmod 0644 "$tmp"
if [ -f "$out" ] && cmp -s "$tmp" "$out"; then
  exit 0
fi
mv "$tmp" "$out"
