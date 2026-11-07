# SPDX-FileCopyrightText: 2026 Olivares.AI
# SPDX-License-Identifier: AGPL-3.0-only
# Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.
# Olivares Server: native Anaconda Installation Summary, with no disk or user answer preselected.
text
lang en_US.UTF-8
keyboard us
timezone UTC --utc
network --bootproto=dhcp --device=link --activate
rootpw --lock
firewall --disabled
bootloader --location=mbr --append="loglevel=3 console=ttyS0,115200n8"
clearpart --none
repo --name=olivares --baseurl=file:///run/install/repo/olivares

%packages
@core
olivares
olivares-appliance-base
olivares-appliance-portal
olivares-selinux
%end

%post --erroronfail
set -euo pipefail
# Machine-check logging needs physical CPU support that guests do not expose.
mkdir -p /etc/systemd/system/mcelog.service.d
cat > /etc/systemd/system/mcelog.service.d/10-virtualization.conf <<'UNIT'
[Unit]
ConditionVirtualization=no
UNIT
systemctl enable olivares-repair-console.service
systemctl mask getty@tty1.service
admin=
# The answers state the real administrator: installed by this installer, or deferred to first boot.
administrator=installed
key_usable() {
  [ -e "$1" ] || return 1
  if ! ssh-keygen -l -f "$1" >/dev/null 2>&1; then
    printf '%s\n' "administrator inspection failed: authorized keys at $1" >&2
    exit 1
  fi
}
account_usable() {
  account=$1 home=$2 shell=$3
  case "$shell" in */nologin|*/false) return 1 ;; esac
  if ! status=$(passwd -S "$account") || ! changes=$(chage -l "$account"); then
    printf '%s\n' "administrator inspection failed: credential state for $account" >&2
    exit 1
  fi
  account_expiry=$(awk -F: '$1 ~ /^Account expires[ \t]*$/ {sub(/^[ \t]+/, "", $2); print $2}' <<<"$changes")
  password_expiry=$(awk -F: '$1 ~ /^Password expires[ \t]*$/ {sub(/^[ \t]+/, "", $2); print $2}' <<<"$changes")
  if [ -z "$account_expiry" ] || [ -z "$password_expiry" ]; then
    printf '%s\n' "administrator inspection failed: credential state for $account" >&2
    exit 1
  fi
  if [ "$account_expiry" != never ] && { ! expiry=$(date -d "$account_expiry" +%s) || [ "$expiry" -le "$(date +%s)" ]; }; then
    return 1
  fi
  if [ "$password_expiry" != never ] && { ! expiry=$(date -d "$password_expiry" +%s) || [ "$expiry" -le "$(date +%s)" ]; }; then
    return 1
  fi
  if key_usable "$home/.ssh/authorized_keys"; then
    return 0
  fi
  set -- $status
  [ "$2" = P ] || return 1
}
if ! accounts=$(awk -F: 'NF != 7 || $3 !~ /^[0-9]+$/ {exit 1} $3 >= 1000 && $3 < 60000 {print $1 ":" $6 ":" $7}' /etc/passwd); then
  printf '%s\n' 'administrator inspection failed: /etc/passwd is unreadable or malformed' >&2
  exit 1
fi
for record in $accounts; do
  account=${record%%:*}
  remainder=${record#*:}
  home=${remainder%%:*}
  shell=${remainder#*:}
  if ! groups=$(id -nG "$account"); then
    printf '%s\n' "administrator inspection failed: id could not read $account" >&2
    exit 1
  fi
  if [[ " $groups " == *" wheel "* ]] && account_usable "$account" "$home" "$shell"; then
    admin=$account
    break
  fi
done
if [ -n "$admin" ]; then
  if ! uid=$(id -u "$admin") || [[ ! "$uid" =~ ^[0-9]+$ ]]; then
    printf '%s\n' "administrator inspection failed: UID for $admin" >&2
    exit 1
  fi
  usermod -aG olivares-admins "$admin"
  install -d -m 0700 /etc/userdb
  printf '{"userName":"%s","uid":%s}\n' "$admin" "$uid" >/etc/userdb/olivares.user
  chmod 0600 /etc/userdb/olivares.user
  restorecon /etc/userdb/olivares.user
elif ! key_usable /root/.ssh/authorized_keys; then
  printf '%s\n' 'No human administrator selected; first boot will ask who becomes administrator.'
  install -d -m 0700 /etc/olivares-appliance
  printf 'defer-administrator\n' >/etc/olivares-appliance/defer-administrator
  chmod 0600 /etc/olivares-appliance/defer-administrator
  administrator=deferred
fi
hostname=$(cat /etc/hostname)
install -d -m 0700 /etc/olivares-appliance
cat >/etc/olivares-appliance/answers.json <<EOF
{
  "schema_version": "appliance-answers/v1",
  "source": "file",
  "host": {
    "owner": "local",
    "administrator": "$administrator",
    "hostname": "$hostname",
    "network": {"mode": "dhcp"},
    "time": {"timezone": "UTC", "servers": ["pool.ntp.org"]},
    "ssh_authorized_keys": []
  },
  "product": {
    "storage_profile": "single-node-prod",
    "public_console_url": "https://$hostname:9443",
    "update_channel": "stable",
    "node_role": "control"
  }
}
EOF
chmod 0600 /etc/olivares-appliance/answers.json
%end
