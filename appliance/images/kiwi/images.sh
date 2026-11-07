#!/bin/bash
# SPDX-FileCopyrightText: 2026 Olivares.AI
# SPDX-License-Identifier: AGPL-3.0-only
# Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.
#
# images.sh — what KIWI NG runs inside the image root after config.sh and after its own SELinux labeling, before it
# creates the image (KIWI 11.0.4 tasks/system_build.py: call_config_script, setup_selinux_file_contexts, then
# call_image_script). It changes nothing. On AlmaLinux it checks, each check failing the build, that the paths the
# appliance's policy module labels already carry the labels its file contexts give them (setfiles -n -v would change
# none), and that nothing asks for a relabel on first boot, which the relabel service runs with enforcement lowered.
set -euxo pipefail

# KIWI NG's build environment, if this runs under KIWI (both files are KIWI's own).
test -f /.kconfig && . /.kconfig
test -f /.profile && . /.profile

case ",${kiwi_profiles:-}," in
  *,almalinux10-server-amd64,*|*,almalinux10-desktop-amd64,*) base=almalinux10 ;;
  *,debian13-server-amd64,*) base=debian13 ;;
  *) printf 'images.sh: no base profile in kiwi_profiles=%s\n' "${kiwi_profiles:-}" >&2; exit 1 ;;
esac
# A missing or relocated Python environment fails the image build, never first use.
/usr/lib/olivares/markitdown/bin/python3 -I -c 'from markitdown import MarkItDown; MarkItDown(enable_plugins=False)'
[ "$base" = almalinux10 ] || exit 0

# The units the desktop overlay enables must be in the image, each check failing the build: gdm,
# which the overlay's display-manager.service alias points at (config.sh checks the alias), and
# sshd, which multi-user.target wants and whose stock configuration serves SFTP.
case ",${kiwi_profiles:-}," in
  *,almalinux10-desktop-amd64,*)
    for unit in gdm.service sshd.service; do
      if [ ! -e "/usr/lib/systemd/system/$unit" ]; then
        printf 'images.sh: %s, which the desktop overlay enables, is not in the image\n' "$unit" >&2
        exit 1
      fi
    done ;;
esac

# The units config.sh links must be in the image, each check failing the build: the Appliance Console's
# socket on both editions, and the repair console on the server edition. A link to a unit the packages
# did not install enables nothing, and the service manager says so only in the journal at boot.
enabled_units=(olivares-portal.socket)
case ",${kiwi_profiles:-}," in
  *,almalinux10-server-amd64,*) enabled_units+=(olivares-repair-console.service) ;;
esac
for unit in "${enabled_units[@]}"; do
  if [ ! -e "/usr/lib/systemd/system/$unit" ]; then
    printf 'images.sh: %s, which config.sh enables, is not in the image\n' "$unit" >&2
    exit 1
  fi
done

# The security-update timer config.sh links on both editions must be in the image, failing the build: dnf-automatic's own
# unit, which the link, the preset line and the window drop-in all name.
if [ ! -e /usr/lib/systemd/system/dnf-automatic-install.timer ]; then
  printf 'images.sh: dnf-automatic-install.timer, which config.sh enables, is not in the image\n' >&2
  exit 1
fi

# The container runtime must be in the image, each check failing the build: the daemon and its unit (which config.sh
# links), containerd's unit, the CLI, the Compose plugin the apps helper runs `docker compose` with, and xt_addrtype, the
# module Docker's iptables backend needs and only kernel-modules-extra carries (without it the daemon exits at start).
for path in /usr/lib/systemd/system/docker.service /usr/lib/systemd/system/containerd.service /usr/bin/docker /usr/bin/dockerd \
    /usr/libexec/docker/cli-plugins/docker-compose; do
  if [ ! -e "$path" ]; then
    printf 'images.sh: %s, which the container runtime needs, is not in the image\n' "$path" >&2
    exit 1
  fi
done
if [ -z "$(find /usr/lib/modules -name 'xt_addrtype.ko*' -print -quit 2>/dev/null)" ]; then
  printf 'images.sh: no xt_addrtype module under /usr/lib/modules: the container runtime needs kernel-modules-extra of the image kernel\n' >&2
  exit 1
fi

# The installed product, base and portal paths must exist and retain their policy labels.
labeled=(/usr/bin/olivares /usr/bin/appliance-firstboot /etc/systemd/system/olivares.service.d /var/lib/olivares
         /var/lib/olivares-appliance /usr/libexec/olivares /etc/olivares-portal)
paths=()
for path in "${labeled[@]}"; do
  if [ ! -e "$path" ]; then
    printf 'images.sh: %s, which the policy module labels, is not in the image\n' "$path" >&2
    exit 1
  fi
  paths+=("$path")
done
status=0
relabel=$(setfiles -n -v /etc/selinux/targeted/contexts/files/file_contexts "${paths[@]}" 2>&1) || status=$?
if [ "$status" -ne 0 ] || grep -qi 'relabel' <<<"$relabel"; then
  printf 'images.sh: setfiles -n -v finds labels the policy would change, or cannot check them (exit %s):\n%s\n' \
    "$status" "$relabel" >&2
  exit 1
fi
if [ -e /.autorelabel ]; then
  printf 'images.sh: /.autorelabel asks for a relabel on first boot, which runs with enforcement lowered\n' >&2
  exit 1
fi
