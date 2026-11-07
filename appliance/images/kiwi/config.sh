#!/bin/bash
# SPDX-FileCopyrightText: 2026 Olivares.AI
# SPDX-License-Identifier: AGPL-3.0-only
# Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.
#
# config.sh — what KIWI NG runs inside the image root once the packages are installed.
#
# It is deliberately short, and what is NOT here is the point. First boot, the console label,
# the firewall, the product's configuration and every instance identity belong to the
# appliance layer, which is installed as a package and enables itself (design 5.2). A recipe
# script that did any of that would be untestable without building 2 GB, and it would never
# reach an appliance that is already installed.
#
# What belongs here is the image's own state: a machine that has never booted. The last thing
# it does is ask the layer's own gate whether this root is still a template, and a root that
# carries an identity fails the build here rather than being cloned into every instance.
set -euxo pipefail

# KIWI NG's build environment, if this runs under KIWI (both files are KIWI's own).
test -f /.kconfig && . /.kconfig
test -f /.profile && . /.profile

# --- the base -------------------------------------------------------------------------------
# One description, one profile per base and edition (config.xml). KIWI names the profiles this
# build takes, comma-separated, in kiwi_profiles (system/profile.py :359-363); a root of no
# known profile stops here.
edition=none
case ",${kiwi_profiles:-}," in
  *,almalinux10-server-amd64,*) base=almalinux10; edition=server ;;
  *,almalinux10-desktop-amd64,*) base=almalinux10; edition=desktop ;;
  *,debian13-server-amd64,*) base=debian13; edition=server ;;
  *) printf 'config.sh: no base profile in kiwi_profiles=%s\n' "${kiwi_profiles:-}" >&2; exit 1 ;;
esac

# The neutral image declaration is independent of the service-account split
# contract. It enables appliance defaults and guarded automatic disk growth.
# Shipping profiles carry the declaration in their own overlay; normalize its
# custody here because the image owns this metadata, never an instance secret.
if [ "$base" = almalinux10 ]; then
  install -d -m 0755 -o 0 -g 0 /etc/olivares-appliance
  marker=/etc/olivares-appliance/image
  grep -qx "almalinux10-${edition}-amd64" "$marker"
  chown 0:0 "$marker"
  chmod 0644 "$marker"
fi

# The read-back of an enablement link the recipe makes (the recipe runs no service-manager command); used below.
want_link() {  # LINK TARGET
  link=$(readlink "$1" 2>/dev/null || true)
  if [ "$link" != "$2" ]; then
    printf 'config.sh: %s is not the symlink to %s the image enables\n' "$1" "$2" >&2
    exit 1
  fi
}

# --- SELinux (AlmaLinux) -------------------------------------------------------------------------
# Enforcing with the targeted policy, and no other path. selinux-policy writes
# /etc/selinux/config from a scriptlet, so the mode the appliance relies on is written here and
# checked. KIWI labels the root after this script only when the policy's file_contexts exists and
# setfiles is installed, and otherwise just warns (system/setup.py :633-645): such a root fails here.
if [ "$base" = almalinux10 ]; then
  cat > /etc/selinux/config <<'SELINUX'
# Olivares appliance: SELinux enforcing with the targeted policy (the recipe's config.sh).
SELINUX=enforcing
SELINUXTYPE=targeted
SELINUX
  grep -qx 'SELINUX=enforcing' /etc/selinux/config
  test -s /etc/selinux/targeted/contexts/files/file_contexts
  command -v setfiles
fi

# --- the update interface (AlmaLinux) ---------------------------------------------------------
# AlmaLinux security updates apply by default, with dnf-automatic's own install timer: the preset enables it and the link
# the service manager's enable operation would create is made here (the recipe runs no service-manager command) and read
# back. The other three timers stay disabled, and no enablement link may exist for any of them. The overlay's
# /etc/dnf/automatic.conf takes security advisories only, applies them and leaves the Olivares packages out (excludepkgs
# in its [base]: a product release stays the administrator's act, whatever advisory the entitled channel may carry for
# it), and its timer drop-in is the reboot window; each is read back, so a root that lost one fails the build rather than
# updating everything, nothing, the product, or at the stock 6:00. Our key and repository
# file are in place; and installonly_limit is dnf.conf's own 3, the only place DNF 4 reads it from (dnf.conf(5) has no
# drop-in directory for the main section), so the build fails if a dnf-data update ever changes it.
if [ "$base" = almalinux10 ]; then
  for unit in dnf-automatic.timer dnf-automatic-download.timer dnf-automatic-notifyonly.timer; do
    if [ -e "/etc/systemd/system/timers.target.wants/$unit" ] || [ -L "/etc/systemd/system/timers.target.wants/$unit" ]; then
      printf 'config.sh: %s is enabled; only dnf-automatic-install.timer is\n' "$unit" >&2
      exit 1
    fi
    grep -qx "disable $unit" /etc/systemd/system-preset/10-olivares-appliance.preset
  done
  grep -qx 'enable dnf-automatic-install.timer' /etc/systemd/system-preset/10-olivares-appliance.preset || {
    printf 'config.sh: the preset does not enable dnf-automatic-install.timer\n' >&2; exit 1; }
  mkdir -p /etc/systemd/system/timers.target.wants
  ln -sfn /usr/lib/systemd/system/dnf-automatic-install.timer /etc/systemd/system/timers.target.wants/dnf-automatic-install.timer
  want_link /etc/systemd/system/timers.target.wants/dnf-automatic-install.timer /usr/lib/systemd/system/dnf-automatic-install.timer
  for line in 'upgrade_type = security' 'download_updates = yes' 'apply_updates = yes' 'reboot = when-needed' 'emit_via = stdio' 'excludepkgs = olivares*'; do
    grep -Fqx "$line" /etc/dnf/automatic.conf || {
      printf 'config.sh: /etc/dnf/automatic.conf lacks the line "%s" (automatic.conf)\n' "$line" >&2; exit 1; }
  done
  # The empty OnCalendar= clears the stock 6:00, so the window is the one calendar. The stock timer is itself
  # Persistent=true (measured under the service manager: dropping the line from the drop-in leaves Persistent=yes), which
  # would make up a missed night at boot with a reboot outside the window: the drop-in says false, and never true.
  window=/etc/systemd/system/dnf-automatic-install.timer.d/10-olivares-window.conf
  for line in 'OnCalendar=' 'OnCalendar=*-*-* 03:00' 'RandomizedDelaySec=30min' 'Persistent=false'; do
    grep -Fqx "$line" "$window" || {
      printf 'config.sh: %s lacks the line "%s"\n' "$window" "$line" >&2; exit 1; }
  done
  if grep -q '^Persistent=true' "$window"; then
    printf 'config.sh: %s sets Persistent=true: a missed night would be made up at boot, outside the window\n' "$window" >&2; exit 1
  fi
  grep -qx 'installonly_limit=3' /etc/dnf/dnf.conf
  grep -qx 'gpgcheck=1' /etc/dnf/dnf.conf
  test -s /etc/pki/rpm-gpg/RPM-GPG-KEY-olivares-package-repository
  grep -qx 'gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-olivares-package-repository' /etc/yum.repos.d/olivares.repo
fi

# --- the build repository's keys (AlmaLinux) -----------------------------------------------------
# The key build.sh made for the in-build dracut RPM signs nothing else, and its secret half is gone; Docker's release key
# signs Docker's four RPMs, which the build repository holds as the lock pins them. dnf may have imported the public half of
# both into this root's rpm keyring when it installed those RPMs, and a key in that keyring is trusted for any package any
# channel offers: an old Docker-signed RPM served by the entitled channel would pass. Both leave the image here, by the
# fingerprints build.sh recorded in the overlay (one per line: per-build-key.fingerprint, vendor-keys.fingerprint), and a
# root whose keyring still lists one fails. rpm 4.19.1 names an imported key gpg-pubkey-<key ID>-<time>, the key ID being
# the last 8 hex digits of the fingerprint (%{VERSION} of that package), and rpmkeys(8) --delete takes the key ID.
if [ "$base" = almalinux10 ]; then
  records=/var/lib/olivares-appliance-build
  fingerprints=()
  for record in "$records/per-build-key.fingerprint" "$records/vendor-keys.fingerprint"; do
    if ! [ -s "$record" ]; then
      printf 'config.sh: %s does not name the build repository keys\n' "$record" >&2
      exit 1
    fi
    while IFS= read -r fingerprint || [ -n "$fingerprint" ]; do
      if ! [[ $fingerprint =~ ^[0-9A-F]{40}$ ]]; then
        printf 'config.sh: %s names a key that is not a fingerprint (%s)\n' "$record" "$fingerprint" >&2
        exit 1
      fi
      fingerprints+=("$fingerprint")
    done < "$record"
  done
  # Each rpm query is its own assignment, so a failing rpm fails the build (errexit does not reach a command
  # substitution inside a for list or a test). The AlmaLinux 10 key (key ID c2a1e572, almalinux-repositories.json) must
  # still be listed afterwards: it proves the listing worked and that only the build repository's keys left.
  installed_keys() { rpm -qa 'gpg-pubkey*' --qf '%{VERSION}\n'; }
  keys=$(installed_keys)
  for fingerprint in "${fingerprints[@]}"; do
    for key in $(awk -v key="${fingerprint: -8}" 'toupper($1) == key { print $1 }' <<<"$keys"); do
      rpmkeys --delete "$key"
    done
  done
  keys=$(installed_keys)
  for fingerprint in "${fingerprints[@]}"; do
    if [ -n "$(awk -v key="${fingerprint: -8}" 'toupper($1) == key { print $1 }' <<<"$keys")" ]; then
      printf 'config.sh: the build repository key %s is still in the rpm keyring\n' "$fingerprint" >&2
      exit 1
    fi
  done
  if ! grep -qix 'c2a1e572' <<<"$keys"; then
    printf 'config.sh: the AlmaLinux 10 key is not in the rpm keyring after the build repository keys left it\n' >&2
    exit 1
  fi
  rm -rf "$records"
fi

# --- the enabled repositories (AlmaLinux) -----------------------------------------------------
# almalinux-repos 10.2 enables baseos, appstream, crb and extras by default. The image's trust chain and its package set
# name BaseOS and AppStream alone, so crb and extras are turned off in the package's own files, %config(noreplace) files
# that an update keeps. Then the enabled repositories must be exactly those two: ours is shipped disabled, and
# olivares-entitled-repo writes the entitled channel's file at run time, once a licence is installed (dnf enables a
# section that says nothing).
if [ "$base" = almalinux10 ]; then
  for repo in crb extras; do
    file=/etc/yum.repos.d/almalinux-$repo.repo
    if [ -f "$file" ]; then
      sed -i "/^\[$repo\]\$/,/^\[/ s/^[[:space:]]*enabled[[:space:]]*=.*\$/enabled=0/" "$file"
    fi
  done
  # libdnf reads repository sections from reposdir (/etc/yum.repos.d, /etc/yum/repos.d and /etc/distro.repos.d) and from
  # dnf.conf itself, and takes 1, yes, true and enabled as true (a section that says nothing is enabled).
  repo_files=()
  for file in /etc/yum.repos.d/*.repo /etc/yum/repos.d/*.repo /etc/distro.repos.d/*.repo /etc/dnf/dnf.conf; do
    if [ -e "$file" ]; then repo_files+=("$file"); fi
  done
  enabled=$(awk '
    FNR == 1 { section = "" }
    /^[[:space:]]*\[.*\][[:space:]]*$/ {
      section = $0; gsub(/^[[:space:]]*\[|\][[:space:]]*$/, "", section)
      if (section == "main" && FILENAME ~ /dnf\.conf$/) { section = ""; next }
      on[section] = 1; next }
    section != "" && /^[[:space:]]*enabled[[:space:]]*=/ {
      value = $0; sub(/^[^=]*=[[:space:]]*/, "", value); sub(/[[:space:]]+$/, "", value)
      on[section] = (tolower(value) ~ /^(1|true|yes|enabled)$/) }
    END { for (s in on) if (on[s]) print s }' "${repo_files[@]}" | sort | tr '\n' ' ')
  if [ "$enabled" != "appstream baseos " ]; then
    printf 'config.sh: the enabled repositories are %s; the image enables appstream and baseos only\n' \
      "$enabled" >&2
    exit 1
  fi
fi

# --- the console -------------------------------------------------------------------------
# The kernel command line of the image type already carries console=ttyS0. This makes the
# boot menu itself answer on the same serial port, so an appliance with no screen can be
# recovered and the boot battery can read what the bootloader did. Debian's grub-mkconfig reads
# /etc/default/grub.d; the RHEL family's grub2-mkconfig reads /etc/default/grub only (grub2-tools
# 2.12-46.el10_2.alma.1), which KIWI writes from the AlmaLinux type's bootloader attributes, the same settings.
if [ "$base" = debian13 ]; then
  mkdir -p /etc/default/grub.d
  cat > /etc/default/grub.d/99-olivares-appliance.cfg <<'GRUB'
GRUB_TERMINAL="console serial"
GRUB_SERIAL_COMMAND="serial --unit=0 --speed=115200 --word=8 --parity=no --stop=1"
GRUB_TIMEOUT=3
GRUB_DISABLE_OS_PROBER=true
GRUB
fi

# --- the host settings' owner --------------------------------------------------------------
# cloud-init owns hostname, network, time and the authorized keys; the appliance layer waits
# for it and verifies them, and never applies them itself (design 11.2). The datasources are
# the carriers the layer documents: a NoCloud seed, the OVF environment of a hypervisor, and
# None so a machine with no seed still boots to the console label instead of stalling.
mkdir -p /etc/cloud/cloud.cfg.d
cat > /etc/cloud/cloud.cfg.d/90-olivares-appliance.cfg <<'CLOUD'
# SPDX-License-Identifier: AGPL-3.0-only
datasource_list: [ NoCloud, ConfigDrive, OVF, VMware, None ]
CLOUD

# --- a machine that has never booted --------------------------------------------------------
# systemd makes the machine ID on each instance's first boot from an EMPTY /etc/machine-id, and
# does not count that boot as a first boot (machine-id(5)), so no ConditionFirstBoot= unit runs.
# None should: Debian's systemd-firstboot.service would prompt on the console for a root
# password. The SSH host keys are made on that boot, before ssh.service: by cloud-init when it
# has a datasource (it orders itself before sshd-keygen.service), else by Debian's
# sshd-keygen.service, which the drop-in below runs whenever no host key exists instead of on a
# first boot only. AlmaLinux's sshd-keygen@.service already runs whenever its key is missing
# (ConditionFileNotEmpty=|!/etc/ssh/ssh_host_%i_key, openssh-server 9.9p1-28.el10_2.alma.1), and sshd.service
# wants it. The layer records the keys as this instance's.
: > /etc/machine-id
rm -f /etc/ssh/ssh_host_*
if [ "$base" = debian13 ]; then
  mkdir -p /etc/systemd/system/sshd-keygen.service.d
  cat > /etc/systemd/system/sshd-keygen.service.d/olivares-appliance.conf <<'UNIT'
# Olivares appliance: make the SSH host keys whenever none exists, not on a first boot only.
# An empty condition resets every condition of the unit (systemd.unit(5)); the two Debian
# conditions that still apply are restated.
[Unit]
ConditionFirstBoot=
ConditionPathIsReadWrite=/etc/ssh
ConditionPathIsSymbolicLink=!/etc/ssh
ConditionPathExistsGlob=!/etc/ssh/ssh_host_*_key
UNIT
fi
rm -f /var/lib/systemd/random-seed
rm -rf /var/lib/cloud/instance /var/lib/cloud/instances /var/lib/cloud/data
rm -f /etc/resolv.conf.bak /etc/hostname.bak

# The build's package index and downloads are not part of the appliance. On AlmaLinux, KIWI keeps
# dnf's cache in the builder, outside the root; a cache the image's own tools made is removed.
case $base in
  debian13)
    apt-get clean || true
    rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*.deb ;;
  almalinux10)
    rm -rf /var/cache/dnf ;;
esac

# --- the SELinux build checks (AlmaLinux) ------------------------------------------------------------
# After the package set, each failing the build. olivares-selinux's %post installs the appliance's policy module at
# priority 200 and records its seven ports in the policy store; with no policy loaded in the build, semanage writes the
# store without a reload, and semodule and semanage read it here. The root is labeled at build (KIWI's setfiles, after
# this script; images.sh checks the module's paths then), never by an autorelabel on boot, because the relabel
# service lowers enforcement while it runs.
if [ "$base" = almalinux10 ]; then
  if ! semodule -lfull | grep -Eq '^200 olivares[[:space:]]'; then
    printf 'config.sh: the olivares policy module is not installed at priority 200 (semodule -lfull)\n' >&2
    exit 1
  fi
  ports=$(semanage port -l -C)
  for record in 'olivares_console_port_t tcp 8443' 'olivares_grpc_port_t tcp 8444' 'olivares_portal_port_t tcp 9443' \
      'olivares_model_runtime_port_t tcp 11434' 'olivares_model_runtime_port_t tcp 1234' \
      'olivares_model_runtime_port_t tcp 8000' 'olivares_model_runtime_port_t tcp 8080'; do
    read -r type proto port <<<"$record"
    # semanage lists one line per type and protocol, its ports joined by ", ".
    if ! grep -Eq "^${type}[[:space:]]+${proto}[[:space:]]+([0-9-]+,[[:space:]]*)*${port}(,|[[:space:]]*\$)" <<<"$ports"; then
      printf 'config.sh: no port record %s in the policy store (semanage port -l -C)\n' "$record" >&2
      exit 1
    fi
  done
  if [ -e /.autorelabel ]; then
    printf 'config.sh: /.autorelabel asks for a relabel on first boot, which runs with enforcement lowered\n' >&2
    exit 1
  fi
fi

# --- the consoles (AlmaLinux) --------------------------------------------------------------------
# A booted appliance has the Appliance Console and, on the server edition, the repair console. The
# Appliance Console's socket (loopback only; remote exposure is the console's own decision, unchanged) is
# enabled by the portal package's postinstall, as the layer enables itself, and is read back here on both
# editions, so a root without it fails the build. The repair console is the image's decision, made HERE on
# the server edition as the links the service manager's enable operation would create (the recipe runs no
# service-manager command), and read back: it is wanted by multi-user.target, and getty@tty1.service is
# masked, because logind starts autovt@tty1 (the same unit) whenever the first virtual console is switched
# to, which would stop the repair console that conflicts with it. The desktop edition keeps tty1 for gdm.
# images.sh holds the units' presence in the root.
if [ "$base" = almalinux10 ]; then
  want_link /etc/systemd/system/sockets.target.wants/olivares-portal.socket /usr/lib/systemd/system/olivares-portal.socket
  if [ "$edition" = server ]; then
    mkdir -p /etc/systemd/system/multi-user.target.wants
    ln -sfn /usr/lib/systemd/system/olivares-repair-console.service /etc/systemd/system/multi-user.target.wants/olivares-repair-console.service
    ln -sfn /dev/null /etc/systemd/system/getty@tty1.service
    want_link /etc/systemd/system/multi-user.target.wants/olivares-repair-console.service /usr/lib/systemd/system/olivares-repair-console.service
    want_link /etc/systemd/system/getty@tty1.service /dev/null
  fi
fi

# --- the container runtime (AlmaLinux) ------------------------------------------------------------
# The optional apps run on Docker (appliance/layer/optionalapps), and the app's container is confined only when the
# daemon runs with SELinux support: without "selinux-enabled" it runs as spc_t, unconfined. Docker's RPMs install no
# /etc/docker/daemon.json and enable nothing (their one scriptlet makes the docker group), so the image makes both here,
# on both editions: the configuration, and the link the service manager's enable operation would create (the recipe runs
# no service-manager command), each read back. The preset line is the declared record. docker.service requires
# docker.socket and wants containerd.service, so it is the one unit enabled. images.sh holds the runtime's presence.
if [ "$base" = almalinux10 ]; then
  grep -qx 'enable docker.service' /etc/systemd/system-preset/10-olivares-appliance.preset || {
    printf 'config.sh: the preset does not enable docker.service\n' >&2; exit 1; }
  mkdir -p /etc/docker /etc/systemd/system/multi-user.target.wants
  printf '{"selinux-enabled": true}\n' > /etc/docker/daemon.json
  ln -sfn /usr/lib/systemd/system/docker.service /etc/systemd/system/multi-user.target.wants/docker.service
  grep -qx '{"selinux-enabled": true}' /etc/docker/daemon.json || {
    printf 'config.sh: /etc/docker/daemon.json does not turn on the daemon'"'"'s SELinux support\n' >&2; exit 1; }
  want_link /etc/systemd/system/multi-user.target.wants/docker.service /usr/lib/systemd/system/docker.service
  # The engine's user is NOT in the docker group: the daemon's socket is root:docker 0660, and that membership is root on the
  # host. Container sessions run under the engine user's rootless Podman (session-image.sh); Docker serves the optional apps.
fi

# --- the desktop edition (AlmaLinux) -------------------------------------------------------------
# The desktop profile's own state, each check failing the build. The enablement is made HERE,
# inside the image root, as the three links the service manager's own enable and default-target
# operations would create - the recipe still runs no service-manager command: the graphical
# target becomes the default, gdm becomes the display manager graphical.target wants (its unit
# installs only the alias), and sshd, whose stock configuration serves SFTP, joins
# multi-user.target.wants. The links are created at build time and not shipped in the overlay
# because a published copy carries the tree's files and an absolute link's target lives on the
# installed system, not in the tree. What follows the creation is the fail-closed read-back:
# each link must exist and point at its exact unit, so a root that lost an enablement - or a
# config.sh that stopped making it - fails the build here. images.sh holds the units' presence
# in the root, and the preset lines remain the declared record.
if [ "$edition" = desktop ]; then
  mkdir -p /etc/systemd/system/multi-user.target.wants
  ln -sfn /usr/lib/systemd/system/graphical.target /etc/systemd/system/default.target
  ln -sfn /usr/lib/systemd/system/gdm.service /etc/systemd/system/display-manager.service
  ln -sfn /usr/lib/systemd/system/sshd.service /etc/systemd/system/multi-user.target.wants/sshd.service
  want_link /etc/systemd/system/default.target /usr/lib/systemd/system/graphical.target
  want_link /etc/systemd/system/display-manager.service /usr/lib/systemd/system/gdm.service
  want_link /etc/systemd/system/multi-user.target.wants/sshd.service /usr/lib/systemd/system/sshd.service
  grep -qx 'enable gdm.service' /etc/systemd/system-preset/10-olivares-appliance.preset || {
    printf 'config.sh: the preset does not enable gdm.service\n' >&2; exit 1; }
  grep -qx 'enable sshd.service' /etc/systemd/system-preset/10-olivares-appliance.preset || {
    printf 'config.sh: the preset does not enable sshd.service\n' >&2; exit 1; }
fi

# --- the edition (AlmaLinux) -----------------------------------------------------------------
# An image is the Community edition and nothing else. Business is never in an image: its package comes from the
# entitled channel when a licence is activated (olivares-edition.service swaps it in on a running appliance and
# back out when the licence is removed), so a root that holds it, a product that reports another edition, or an
# installed licence fails the build here. The channel's own credential file cannot be in the root either: the
# enabled-repositories check above admits no repository but AlmaLinux's two. The product answers for its own
# edition, the way `upgrade` asks a binary it replaces; the package database answers for the packages. A name that
# merely provides olivares does not read as Community: rpm -q takes package names only.
if [ "$base" = almalinux10 ]; then
  rpm -q --quiet olivares || {
    printf 'config.sh: the Community package olivares is not installed\n' >&2; exit 1; }
  if rpm -q --quiet olivares-business; then
    printf 'config.sh: olivares-business is installed; an image ships Community and Business arrives through the entitled channel\n' >&2
    exit 1
  fi
  reported=$(/usr/bin/olivares version -o json)
  if ! grep -Eq '"edition"[[:space:]]*:[[:space:]]*"community"' <<<"$reported"; then
    printf 'config.sh: /usr/bin/olivares does not report the community edition: %s\n' "$reported" >&2
    exit 1
  fi
  if [ -e /var/lib/olivares/license.key ] || [ -L /var/lib/olivares/license.key ]; then
    printf 'config.sh: a licence is in the image; it belongs to the instance that activates it\n' >&2
    exit 1
  fi
fi

# Populate Docker's persistent store before the template gate. A missing recipe,
# failed pull/build or failed image read-back fails the image rather than first boot.
if [ "$base" = almalinux10 ]; then
  /usr/libexec/olivares/session-image
fi

# --- the gate --------------------------------------------------------------------------------
# The layer's own template check, run over the finished root. It exits 1 naming every instance
# identity it finds - SSH host keys, the machine ID, the product's TLS key, the setup token,
# the audit, catalog and policy signing keys, the store and a first-boot record - so an image
# that would clone an identity into every appliance fails HERE, not in the field.
/usr/bin/appliance-firstboot check-template /
