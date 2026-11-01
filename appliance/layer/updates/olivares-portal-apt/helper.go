// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package main

import (
	"context"

	"github.com/olivaresai/olivares/appliance/layer/helpers/helperschema"
	"github.com/olivaresai/olivares/appliance/layer/helpers/invocation"
	"github.com/olivaresai/olivares/appliance/layer/updates"
)

// helper is the host-package helper over x: the status read and the two package acts, admitted by
// the seam for the Appliance Console alone and answered by the module's own PackageAnswer. A
// document that is not a package request is refused, never performed.
func helper(x updates.RPM) invocation.Helper {
	return invocation.Helper{
		Name:       updates.HelperName,
		Rules:      updates.HelperRules(),
		NewRequest: func() helperschema.Request { return &updates.PackageRequest{} },
		Perform: func(ctx context.Context, _ helperschema.Peer, request helperschema.Request) helperschema.Response {
			r, ok := request.(*updates.PackageRequest)
			if !ok {
				return helperschema.Response{Result: helperschema.ResultRefused, Code: helperschema.CodeInputRefused}
			}
			return updates.PackageAnswer(ctx, x, r)
		},
	}
}
