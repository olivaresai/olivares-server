// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

// Package identityclient consumes current engine attribution for one exact act.
// It owns no product store, credential, mapping or cached permission.
package identityclient

import (
	"context"
	"errors"
	"github.com/olivaresai/olivares/appliance/layer/hostops"
	"github.com/olivaresai/olivares/appliance/layer/portal/localsession"
)

var refused = errors.New("mode_refused")

// NewAuthorityResolver captures only the existing trusted connection context.
// UID is checked against the original kernel peer on every Authorize call.
func NewAuthorityResolver() localsession.AuthorityResolver {
	return func(ctx context.Context, uid uint32) (hostops.Authority, error) {
		if ctx == nil || ctx.Err() != nil || uid == 0 {
			return nil, refused
		}
		return authority{held: ctx, uid: uid}, nil
	}
}

type authority struct {
	held context.Context
	uid  uint32
}
