#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Olivares.AI
# SPDX-License-Identifier: AGPL-3.0-only
# Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.
#
# qualification-delivery.sh OUT_DIR — the product delivery a qualification build reads, made the way the package build makes the
# release one, but with a throwaway key. Run from the pinned source root. The nfpm configurations read VERSION and ARCH
# from the environment: ARCH is amd64 here, and VERSION is X.Y or 0.0.0-dev, the qualification's, which an unset
# VERSION means; any other value is refused before anything is written.
#
#   1. go builds bin/appliance-firstboot, bin/appliance-answers and bin/olivares (static), and installs nfpm v2.47.0 into
#      a private GOBIN;
#   2. nfpm packages packaging/nfpm/olivares-appliance-base.yaml and appliance/images/kiwi/product-dev.nfpm.yaml as RPMs
#      into OUT_DIR/packages, and rpmbuild builds olivares-selinux from appliance/selinux/olivares-selinux.spec in the
#      recipe's own builder (toolchain/almalinux10: its base image by digest and its packages, the policy toolchain
#      among them, pinned by the lock), as the runner's user and without a network, into the same directory;
#   3. generate-package-repository-test-key.sh makes a throwaway key under its test-only latch, in a private
#      directory; rpm-payload-sign.py signs each RPM's header and render-rpm-repodata.py renders and signs the
#      repodata with it;
#   4. render-rpm-repodata.py render signs the repodata and writes delivery.json, the tree's only writer of it; the public key
#      the build reads is copied beside the tree before the render, so the render's checksums cover it. The key is also
#      OUT_DIR/qualification-key.asc, with its fingerprint in OUT_DIR/qualification-key.fingerprint;
#   5. delivery_check.py checks the delivery as the build will, with that fingerprint; the private directory, and with
#      it the secret key, is removed whatever happened.
# the package repository scripts come from REPO_SCRIPTS_DIR (default: scripts/ of the source root).
#   exit 0  written, and the build's own check accepts it
#   exit 1  written, and the build's own check refuses it
#   exit 2  it could not run: no new OUT_DIR, a VERSION of another form, not the source root, a missing tool or package repository script,
#           or a step
#           that failed
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
die() { printf 'qualification-delivery.sh: %s\n' "$*" >&2; exit 2; }

if [ "$#" -ne 1 ] || [ -z "${1:-}" ]; then
  die "usage: qualification-delivery.sh OUT_DIR (a new directory)"
fi
out=$1
VERSION=${VERSION-0.0.0-dev}
[[ "$VERSION" =~ ^(0\.[1-9][0-9]*|[1-9][0-9]*\.(0|[1-9][0-9]*)|0\.0\.0-dev)$ ]] || die "VERSION is X.Y or 0.0.0-dev, not '$VERSION'"
source_root=$(pwd)
builder_dir=appliance/images/toolchain/almalinux10
for config in packaging/nfpm/olivares-appliance-base.yaml packaging/nfpm/olivares-appliance-portal.yaml appliance/images/kiwi/product-dev.nfpm.yaml \
    appliance/selinux/olivares-selinux.spec "$builder_dir/Containerfile"; do
  [ -f "$source_root/$config" ] || die "run from the pinned source root: $source_root has no $config"
done
repo_scripts=${REPO_SCRIPTS_DIR:-$source_root/scripts}
missing=()
for script in generate-package-repository-test-key.sh rpm-payload-sign.py render-rpm-repodata.py; do
  [ -f "$repo_scripts/$script" ] || missing+=("$script")
done
[ ${#missing[@]} -eq 0 ] || die "the package repository scripts ${missing[*]} are not in $repo_scripts"
for tool in go docker gpg gpgconf python3; do
  command -v "$tool" >/dev/null || die "$tool is not on PATH"
done
mkdir "$out" 2>/dev/null || die "OUT_DIR must be new: $out"
out=$(cd "$out" && pwd)

# The secret key lives only here, in $private/k, with the GnuPG home in $private/k/gnupg. The names are short because
# GnuPG's socket paths below them (S.gpg-agent.browser, the longest) must fit a Unix socket name under any usual TMPDIR.
private=$(mktemp -d "${TMPDIR:-/tmp}/qXXX")
cleanup() {
  local status=$?
  if [ -d "$private/k/gnupg" ]; then
    gpgconf --homedir "$private/k/gnupg" --kill all >/dev/null 2>&1 || true
  fi
  # The workspace build rewrites the tracked go.work.sum: its copy is put back on exit, whatever the outcome, so the
  # delivery leaves the tree as it found it. A restore that fails makes the delivery fail too.
  if [ -f "$private/go.work.sum" ] && ! cp -p "$private/go.work.sum" "$source_root/go.work.sum"; then
    printf 'qualification-delivery.sh: could not restore go.work.sum\n' >&2
    status=2
  fi
  rm -rf "$private"
  exit "$status"
}
trap cleanup EXIT
if [ -f "$source_root/go.work.sum" ]; then cp -p "$source_root/go.work.sum" "$private/go.work.sum"; fi

step() {  # a step that fails means the delivery could not be made
  local status=0
  "$@" || status=$?
  [ "$status" -eq 0 ] || die "$(basename "$1") ${2:-} exited $status"
}

export ARCH=amd64 VERSION
# A development root's workspace does not list the appliance module (the release export derives that file), so the
# module's builds run under the module's own workspace, appliance/go.work; a composed root lists the module and then
# wins. The same selection as appliance/Taskfile.yml's GOWORK_FILE, and an empty value leaves go on the root's
# workspace. The product command, cmd/olivares, is in the root's workspace either way.
if grep -Eq '^[[:space:]]*(use[[:space:]]+)?\./appliance/?[[:space:]]*(//.*)?$' "$source_root/go.work" 2>/dev/null; then
  gowork=
else
  gowork=$source_root/appliance/go.work
fi
step env GOBIN="$private/gobin" go install github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.47.0
for command in appliance/cmd/appliance-firstboot appliance/cmd/appliance-answers; do
  step env GOWORK="$gowork" CGO_ENABLED=0 go build -trimpath -o "bin/$(basename "$command")" "./$command"
done
step env CGO_ENABLED=0 go build -trimpath -o bin/olivares ./cmd/olivares
step env GOWORK="$gowork" bash scripts/build-appliance-portal.sh
mkdir "$out/packages"
for config in packaging/nfpm/olivares-appliance-base.yaml packaging/nfpm/olivares-appliance-portal.yaml appliance/images/kiwi/product-dev.nfpm.yaml; do
  step "$private/gobin/nfpm" package --config "$config" --packager rpm --target "$out/packages/"
done
step docker build --iidfile "$private/builder.iid" --file "$builder_dir/Containerfile" "$builder_dir"
mkdir "$private/rpmbuild"
step docker run --rm --network none --user "$(id -u):$(id -g)" --env HOME=/rpmbuild \
  --volume "$source_root/appliance/selinux:/sources:ro" --volume "$private/rpmbuild:/rpmbuild" "$(cat "$private/builder.iid")" \
  rpmbuild -bb --define "_topdir /rpmbuild" --define "_sourcedir /sources" /sources/olivares-selinux.spec
built=("$private"/rpmbuild/RPMS/noarch/olivares-selinux-*.noarch.rpm)
if [ "${#built[@]}" -ne 1 ] || [ ! -f "${built[0]}" ]; then
  die "rpmbuild left no single olivares-selinux package"
fi
cp "${built[0]}" "$out/packages/"

step env OLIVARES_PACKAGE_REPO_TEST_ONLY=1 bash "$repo_scripts/generate-package-repository-test-key.sh" "$private/k"
key=(env OLIVARES_PACKAGE_REPO_TEST_ONLY=1 OLIVARES_PACKAGE_REPO_KEY_DESCRIPTOR_FILE="$private/k/descriptor.json"
     OLIVARES_PACKAGE_REPO_OPENPGP_SECRET_KEY_FILE="$private/k/openpgp-secret.asc" TMPDIR="$private")
rpms=()
for rpm in "$out/packages"/*.rpm; do rpms+=(--rpm "$rpm"); done
step "${key[@]}" python3 "$repo_scripts/rpm-payload-sign.py" "${rpms[@]}"
# render writes delivery.json and checksums.txt over the tree, so the key the build reads is copied in before it runs.
key_name=$(python3 -c 'import sys
sys.path.insert(0, sys.argv[1])
from delivery_check import KEY_FILE
print(KEY_FILE)' "$here") || die "the key file name cannot be read"
cp "$private/k/openpgp-public.asc" "$out/packages/$key_name" || die "could not copy the key beside the tree"
step "${key[@]}" python3 "$repo_scripts/render-rpm-repodata.py" render --repo "$out/packages"

cp "$private/k/openpgp-public.asc" "$out/qualification-key.asc"
# The fingerprint is the key's own (delivery_check.fingerprint), and must be the one the key descriptor names.
fingerprint=$(python3 -c 'import json, sys
sys.path.insert(0, sys.argv[1])
from delivery_check import fingerprint
found = fingerprint(open(sys.argv[2], "rb").read())
named = json.load(open(sys.argv[3]))["openpgp_fingerprint"]
sys.exit("the key is %s and its descriptor names %s" % (found, named)) if found != named else print(found)' \
  "$here" "$out/qualification-key.asc" "$private/k/descriptor.json") || die "the throwaway key cannot be named"
printf '%s\n' "$fingerprint" > "$out/qualification-key.fingerprint"

status=0
python3 "$here/delivery_check.py" --package-dir "$out/packages" --expected-fingerprint "$fingerprint" >/dev/null || status=$?
if [ "$status" -eq 1 ]; then
  printf 'qualification-delivery.sh: the build would refuse this delivery (key %s)\n' "$fingerprint" >&2
  exit 1
fi
[ "$status" -eq 0 ] || die "the delivery cannot be checked (delivery_check.py exited $status)"
printf 'qualification-delivery.sh: %s/packages, throwaway key %s (not a release)\n' "$out" "$fingerprint"
