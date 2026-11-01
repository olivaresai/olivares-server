#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Olivares.AI
# SPDX-License-Identifier: AGPL-3.0-only
# The AlmaLinux 10 builder's bootstrap, generated from the accepted almalinux10/input-lock.json; a moved lock refuses
# before any network effect.
set -euo pipefail
cd /toolchain
printf '%s  %s\n' '603885729c29500f226fa3de6fe761b799655edf92c25d22a1c16abaa27fc3bc' input-lock.json | sha256sum -c -
# HTTPS does not grant trust: every package is checked against the AlmaLinux 10 key, whose file the base image's
# almalinux-gpg-keys installed, or against the EPEL 10 key, whose file travels beside this script; the sha256 of both is
# checked first. AlmaLinux and EPEL do not sign repomd.xml, so dnf caches the metadata of the four pinned trees, their
# repomd.xml sha256 is checked in the cache, and only then does dnf install exactly the locked NEVRAs, fetching each
# from its pinned repository and checking its signature. The base image's own repositories are removed.
printf '%s  %s\n' 'de57c3c0a2dcde88ff5b894e74335f55a0ec074815f36d472270d937c16f077b' /etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux-10 | sha256sum -c -
printf '%s  %s\n' 'de390fc168eae5ab2852e9e93d34a0b9ddf05cf9ce90ee28d97de26a4b1f6b93' RPM-GPG-KEY-EPEL-10 | sha256sum -c -
install -m 0644 RPM-GPG-KEY-EPEL-10 /etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-10
rm -f /etc/yum.repos.d/*.repo
cat > /etc/yum.repos.d/appliance-pinned.repo <<'REPO'
[almalinux-baseos]
name=almalinux-baseos
baseurl=https://repo.almalinux.org/almalinux/10.2/BaseOS/x86_64/os/
gpgcheck=1
repo_gpgcheck=0
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux-10

[almalinux-appstream]
name=almalinux-appstream
baseurl=https://repo.almalinux.org/almalinux/10.2/AppStream/x86_64/os/
gpgcheck=1
repo_gpgcheck=0
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux-10

[almalinux-crb]
name=almalinux-crb
baseurl=https://repo.almalinux.org/almalinux/10.2/CRB/x86_64/os/
gpgcheck=1
repo_gpgcheck=0
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux-10

[epel-10]
name=epel-10
baseurl=https://dl.fedoraproject.org/pub/epel/10/Everything/x86_64/
gpgcheck=1
repo_gpgcheck=0
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-10

REPO
dnf -y makecache --refresh
while read -r repo pinned; do
  cached=(/var/cache/dnf/"$repo"-*/repodata/repomd.xml)
  [ "${#cached[@]}" -eq 1 ]
  printf '%s  %s\n' "$pinned" "${cached[0]}" | sha256sum -c -
done <<'PINS'
almalinux-baseos caf34cc405ec0b63cca2520b54b13e09029647ea79ef46b974832a9fb953b8d1
almalinux-appstream 4ba3037f340eab7c94e1830dfbd5de41473945e910bf5337c86e669393459380
almalinux-crb 4a9ab6641f9297aa9534b6b93a3312b6a732f3e7a63c2929a3b4ed4f5289c9f6
epel-10 a5add31338be754e214ac67f34483cadbf16321a4df7751a39ba578ada74a9f4
PINS
dnf -y install --setopt=install_weak_deps=False \
    almalinux-gpg-keys-10.2-21.el10.x86_64 \
    bash-5.2.26-6.el10.x86_64 \
    btrfs-progs-6.12-3.el10.x86_64 \
    bzip2-1.0.8-25.el10.x86_64 \
    ca-certificates-2026.2.92_v9.0.319-100.3.el10_2.noarch \
    cpio-2.15-3.el10.x86_64 \
    createrepo_c-1.1.2-4.el10.x86_64 \
    cryptsetup-2.8.1-2.el10.x86_64 \
    curl-8.12.1-4.el10_2.7.x86_64 \
    dnf-4.20.0-22.el10_2.alma.1.noarch \
    dosfstools-4.2-12.el10.x86_64 \
    e2fsprogs-1.47.1-5.el10.x86_64 \
    erofs-utils-1.8.10-1.el10.x86_64 \
    file-5.45-9.el10.x86_64 \
    gdisk-1.0.10-2.el10_0.x86_64 \
    gnupg2-2.4.5-4.el10_1.x86_64 \
    grub2-efi-x64-modules-1:2.12-46.el10_2.alma.1.noarch \
    grub2-pc-modules-1:2.12-46.el10_2.alma.1.noarch \
    grub2-tools-1:2.12-46.el10_2.alma.1.x86_64 \
    gzip-1.13-4.el10_2.x86_64 \
    isomd5sum-1:1.2.5-3.el10.x86_64 \
    kpartx-0.9.9-18.el10.x86_64 \
    lsof-4.98.0-7.el10.x86_64 \
    lvm2-10:2.03.36-2.el10.x86_64 \
    make-1:4.4.1-9.el10.x86_64 \
    mdadm-4.4-3.el10_2.2.x86_64 \
    mtools-4.0.43-7.el10.x86_64 \
    openssl-1:3.5.8-2.el10_2.alma.1.x86_64 \
    python3-3.12.15-1.el10_2.x86_64 \
    python3-click-8.1.7-7.el10_3.noarch \
    python3-dnf-plugins-core-4.7.0-10.el10.noarch \
    python3-lxml-5.2.1-4.el10.x86_64 \
    python3-markdown-it-py-3.0.0-7.el10_0.noarch \
    python3-mdurl-0.1.2-8.el10_0.noarch \
    python3-packaging-24.2-2.el10.noarch \
    python3-pip-23.3.2-11.el10_2.noarch \
    python3-poetry-core-1.9.0-1.el10_0.noarch \
    python3-pygments-2.18.0-1.el10.noarch \
    python3-pyyaml-6.0.1-19.el10.x86_64 \
    python3-requests-2.32.4-1.el10_0.noarch \
    python3-rich-14.3.0-1.el10_3.noarch \
    python3-shellingham-1.5.4-7.el10_0.noarch \
    python3-simplejson-3.20.2-1.el10_3.x86_64 \
    python3-typer-0.20.0-1.el10_2.noarch \
    python3-typer-cli-0.20.0-1.el10_2.noarch \
    python3-typer-slim-0.20.0-1.el10_2.noarch \
    python3-typing-extensions-4.9.0-6.el10.noarch \
    qemu-img-18:10.1.0-16.el10_2.5.alma.1.x86_64 \
    rpm-4.19.1.1-23.el10.alma.1.x86_64 \
    rpm-build-4.19.1.1-23.el10.alma.1.x86_64 \
    rpm-sign-4.19.1.1-23.el10.alma.1.x86_64 \
    rsync-3.5.0-3.el10_2.x86_64 \
    screen-5.0.1-6.el10_2.x86_64 \
    sed-4.9-5.el10.x86_64 \
    selinux-policy-42.1.18-4.el10_2.4.noarch \
    selinux-policy-devel-42.1.18-4.el10_2.4.noarch \
    squashfs-tools-4.6.1-6.el10.x86_64 \
    syslinux-6.04-0.34.el10.alma.2.x86_64 \
    syslinux-nonlinux-6.04-0.34.el10.alma.2.noarch \
    tar-2:1.35-13.el10_2.x86_64 \
    util-linux-2.40.2-18.el10.x86_64 \
    xfsprogs-6.16.0-1.el10.x86_64 \
    xorriso-1.5.6-6.el10.x86_64
# Retain only the installed inventory, not the package cache; no repository stays configured.
dnf clean all
rm -f /etc/yum.repos.d/appliance-pinned.repo
