#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Olivares.AI
# SPDX-License-Identifier: AGPL-3.0-only
# Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.
# Build one native Anaconda installer from a signed Olivares RPM repository.
set -euo pipefail
if [ "$#" -ne 3 ]; then
  printf 'usage: %s server|desktop RPM_REPO OUTPUT.iso\n' "$0" >&2
  exit 2
fi
edition=$1
repo=$(realpath "$2")
output=$(realpath -m "$3")
case "$edition" in
  server|desktop) ;;
  *) printf 'unknown edition: %s\n' "$edition" >&2; exit 2 ;;
esac
ks=$(realpath "$(dirname "$0")/$edition.ks")
[ -f "$ks" ] || { printf 'missing Kickstart: %s\n' "$ks" >&2; exit 2; }
[ -d "$repo" ] || { printf 'missing RPM repository: %s\n' "$repo" >&2; exit 2; }
outdir=$(dirname "$output")
mkdir -p "$outdir"
image=almalinux:10@sha256:ba31c3299856068f77bc10574cad51b0a4f6a3dafb882668656e1639bee63db6
docker run --rm --privileged \
  -v "$repo:/work/olivares" -v "$ks:/work/olivares.ks:ro" -v "$outdir:/work/out" "$image" \
  bash -c 'set -euo pipefail
    dnf -y install lorax lorax-lmc-novirt xorriso isomd5sum createrepo_c
    createrepo_c /work/olivares
    curl -fsSL --retry 3 --retry-all-errors -o /work/out/boot.iso https://repo.almalinux.org/almalinux/10.2/isos/x86_64/AlmaLinux-10.2-x86_64-boot.iso
    printf "%s  %s\n" b3f865468075bcada8f208d830289302c67529789d668041d24e8d6fc697ba6a /work/out/boot.iso | sha256sum -c -
    mkksiso --ks /work/olivares.ks --add /work/olivares /work/out/boot.iso /work/out/installer.iso
    rm /work/out/boot.iso'
if [ ! -f "$outdir/installer.iso" ]; then
  printf 'mkksiso left no installer\n' >&2
  exit 1
fi
if [ "$outdir/installer.iso" != "$output" ]; then
  mv "$outdir/installer.iso" "$output"
fi
