#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Olivares.AI
# SPDX-License-Identifier: AGPL-3.0-only
# Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

# Build the payload of olivares-appliance-portal from the same checkout as the image.
set -euo pipefail
for command in \
	appliance/cmd/olivares-appliance \
	appliance/layer/portal/cmd/olivares-portal \
	appliance/layer/portal/cmd/olivares-portal-sockets \
	appliance/layer/netguard/cmd/olivares-net-guard \
	appliance/layer/helpers/olivares-portal-power \
	appliance/layer/helpers/olivares-portal-system \
	appliance/layer/helpers/olivares-portal-support-bundle \
	appliance/layer/helpers/olivares-portal-netrestore \
	appliance/layer/helpers/olivares-portal-netprobe \
	appliance/layer/helpers/olivares-portal-units \
	appliance/layer/storage/olivares-portal-storage \
	appliance/layer/updates/olivares-portal-apt \
	appliance/layer/updates/olivares-package-retain \
	appliance/layer/firewall/olivares-portal-firewall \
	appliance/layer/optionalapps/olivares-portal-apps \
	appliance/layer/firewall/olivares-portal-firewall-local \
	appliance/layer/helpers/olivares-portal-cert \
	appliance/cmd/olivares-entitled-repo; do
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "bin/$(basename "$command")" "./$command"
done

# These two host adapters use PAM; a static build selects the refusing stub.
for command in \
	appliance/layer/tui/cmd/olivares-repair-console \
	appliance/layer/portal/portalpam/cmd/olivares-portal-pam; do
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -tags olivares_pam -trimpath -o "bin/$(basename "$command")" "./$command"
done
