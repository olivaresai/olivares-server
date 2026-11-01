#!/bin/sh
# SPDX-FileCopyrightText: 2026 Olivares.AI
# SPDX-License-Identifier: AGPL-3.0-only
set -eu
if command -v systemd-sysusers >/dev/null 2>&1; then
    systemd-sysusers /usr/lib/sysusers.d/olivares-appliance-portal.conf
    systemd-sysusers /usr/lib/sysusers.d/olivares-hostops.conf
fi
if command -v systemd-tmpfiles >/dev/null 2>&1; then
    systemd-tmpfiles --create /usr/lib/tmpfiles.d/olivares-hostops.conf
fi
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    systemctl enable olivares-portal-pam.socket
    # The Appliance Console's socket, loopback 9443; the repair console on tty1 is the image's decision.
    systemctl enable olivares-portal.socket
    # The management sockets of the console: made after the network is online and whenever the selection or the firewall owner's measurement is published; none unless remote access holds; the timer checks them every two minutes.
    systemctl enable olivares-portal-sockets.service olivares-portal-sockets.path olivares-portal-sockets.timer
    systemctl enable olivares-net-guard.socket olivares-net-guard.service olivares-helper-netrestore.socket olivares-helper-netprobe.socket
    # The module helpers' sockets, for the Appliance Console's services, storage, firewall, host-package and optional apps reads.
    systemctl enable olivares-helper-units.socket olivares-helper-storage.socket olivares-helper-firewall.socket olivares-helper-apt.socket olivares-helper-apps.socket
    # Online data growth uses the same native path automatically on each appliance boot.
    systemctl enable olivares-grow-data@auto.service
    # The firewall owner's boot load and its guard.
    systemctl enable olivares-firewall.service olivares-firewall-guard.service
fi
