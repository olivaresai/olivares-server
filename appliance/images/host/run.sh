#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Olivares.AI
# SPDX-License-Identifier: AGPL-3.0-only
# run.sh [--image ID] [--] COMMAND [ARG...] — run COMMAND in the image build's host toolbox (Containerfile beside this
# file), so the host needs only docker, Go and /dev/kvm. The qualification delivery, attempt.py, the formats, the boot
# battery and the NoCloud seed then take their tools from the toolbox; the AlmaLinux builder still runs on the host's
# docker, through its socket. The toolbox is privileged (KIWI and the preflight loop-mount images) and gets /dev, so a
# loop device created during the build is there too. The builder is started by the host's docker and names host paths,
# so the current directory, TMPDIR, RUNNER_TEMP and the Go caches are mounted at their own paths, and the host's Go
# toolchain read-only. When COMMAND ends, the files root wrote in the writable ones are handed back to the caller; the
# Go toolchain is never written or handed back. Without --image the toolbox
# is built first (docker's cache makes a rebuild of the same Containerfile instant).
# Exit: COMMAND's status; 2 usage; 3 docker not usable.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
image=
while [ $# -gt 0 ]; do
  case $1 in
    --image) image=${2:?run.sh: --image needs an image ID}; shift 2 ;;
    --) shift; break ;;
    *) break ;;
  esac
done
[ $# -gt 0 ] || { echo "usage: run.sh [--image ID] [--] COMMAND [ARG...]" >&2; exit 2; }
docker info >/dev/null 2>&1 || { echo "run.sh: docker is not usable by $(id -un)" >&2; exit 3; }
if [ -z "$image" ]; then
  iid=$(mktemp)
  docker build --quiet --iidfile "$iid" --file "$here/Containerfile" "$here" >/dev/null
  image=$(cat "$iid")
  rm -f "$iid"
fi
goroot=${GOROOT:-$(go env GOROOT 2>/dev/null || true)}
mounts=() dirs=()
[ -n "$goroot" ] && [ -d "$goroot" ] && mounts+=(-v "$goroot:$goroot:ro")
for dir in "$PWD" "${TMPDIR:-}" "${RUNNER_TEMP:-}" "${GOPATH:-}" "${GOCACHE:-}" "${GOMODCACHE:-}"; do
  [ -n "$dir" ] && [ -d "$dir" ] || continue
  case " ${dirs[*]-} " in *" $dir "*) continue ;; esac
  mounts+=(-v "$dir:$dir") dirs+=("$dir")
done
envs=()
for name in GITHUB_RUN_ID GITHUB_RUN_ATTEMPT GITHUB_JOB GITHUB_REF GITHUB_SHA GITHUB_REPOSITORY GITHUB_WORKSPACE \
            GITHUB_OUTPUT GITHUB_ENV GITHUB_STEP_SUMMARY RUNNER_TEMP RUNNER_NAME TMPDIR VERSION EDITION FIRMWARE \
            ACCELERATOR GOPATH GOCACHE GOMODCACHE GOFLAGS GOTOOLCHAIN PYTHONDONTWRITEBYTECODE; do
  [ -n "${!name:-}" ] && envs+=(-e "$name")
done
kvm=()
[ -c /dev/kvm ] && kvm=(--device /dev/kvm)
# The preflight records the runner image in its receipt; here that is the toolbox itself.
exec docker run --rm --privileged "${kvm[@]}" -v /dev:/dev -v /var/run/docker.sock:/var/run/docker.sock \
  "${mounts[@]}" -w "$PWD" "${envs[@]}" -e ImageOS=debian13-toolbox -e ImageVersion="$image" \
  -e PATH="${goroot:+$goroot/bin:}/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
  -e HOST_IDS="$(id -u):$(id -g)" -e HOST_DIRS="${dirs[*]}" "$image" \
  bash -c 'status=0; "$@" || status=$?; for d in $HOST_DIRS; do chown -R --from=0:0 "$HOST_IDS" "$d"; done; exit "$status"' run.sh "$@"
