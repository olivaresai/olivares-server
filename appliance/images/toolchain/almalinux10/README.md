<!-- SPDX-FileCopyrightText: 2026 Olivares.AI -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# AlmaLinux 10 appliance image build toolchain

This is the builder of the shipping `almalinux10-server-amd64` profile (and its `almalinux10-desktop-amd64` edition),
the successor of the Fedora 44 builder that never built an image. It is derived from the same
files by counted changes; the Debian builder one directory up stays for the non-shipping `debian13-server-amd64`
profile.

- `Containerfile` starts from `docker.io/library/almalinux:10`, pinned by its linux/amd64 manifest digest.
  `input-lock.json` records that digest and the digest of the image index.
- `input-lock.json` pins the AlmaLinux 10 BaseOS and AppStream trees of the current minor (10.2, `distribution.minor`), the
  AlmaLinux 10 CRB tree and the EPEL 10 tree by the sha256 of their `repomd.xml`, and the AlmaLinux 10 and EPEL 10 keys by sha256 and fingerprint.
  Every RPM the builder installs (`distribution.system_packages`) and every root the image profile names
  (`image_packages`) is locked by NEVRA and sha256 from that metadata, with its source RPM. The image roots come from the
  two AlmaLinux trees only. EPEL and CRB serve the builder alone: EPEL for `gdisk`, `python3-typer` with its closure,
  `python3-poetry-core`, `python3-simplejson` and `screen`; CRB for `python3-pygments`, which EPEL's `python3-rich` needs.
  EPEL never shadows a package AlmaLinux serves.
- `bootstrap.sh` refuses a moved lock or key, caches the four trees' metadata with dnf, checks their `repomd.xml` in the
  cache against the pins, and installs exactly the locked NEVRAs, each fetched from its pinned repository and GPG-checked. `RPM-GPG-KEY-EPEL-10` is the EPEL key,
  checked against the lock's sha256.
- `install.py` builds KIWI 11.0.4 from its verified source (the same sdist and sha256 as the Debian lock) in a venv over
  AlmaLinux's own Python packages. EPEL's `python3-kiwi` is 11.1.1 and is never installed.
- `relock-almalinux.py` writes the successor lock, bootstrap and pins after the trees moved, or with a new root, into a
  new directory for review. It never writes in place.

AlmaLinux publishes its updates into the tree of the minor it names, so a pin holds until the next push to that tree and
is then re-pinned with `relock-almalinux.py`, never loosened. AlmaLinux ends a minor when the next one is released (10.3 is in beta), so the pinned minor moves then. A new minor is a reviewed edit of the base URLs in
`appliance/images/kiwi/almalinux-repositories.json` and of `distribution.minor`, followed by a relock; the
`minor` of `appliance/images/formats/formats.json` follows.

AlmaLinux 10 is built for x86-64-v3 (AVX2); a CPU model without it does not boot the image. AlmaLinux's separate
`x86_64_v2` builds are not used here.

Nothing here has been built on a hosted runner yet. The hosted preflight (`appliance/test/runner`) still builds and
qualifies the Debian builder: its collector names `toolchain/Containerfile` and that directory as the build context.
