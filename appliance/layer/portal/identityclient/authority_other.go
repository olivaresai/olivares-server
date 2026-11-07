// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

//go:build !linux || (!amd64 && !arm64)

package identityclient

import (
	"context"
	"github.com/olivaresai/olivares/appliance/layer/hostops"
)

func (authority) Authorize(context.Context, hostops.Descriptor, string, string) (hostops.Caller, error) {
	return hostops.Caller{}, refused
}

func (a authority) ReserveExposure(ctx context.Context, d hostops.Descriptor, target, digest string) (hostops.Caller, error) {
	return hostops.Caller{}, refused
}
