// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package main

import (
	"context"
	"os"

	"github.com/olivaresai/olivares/appliance/layer/helpers/helperschema"
	"github.com/olivaresai/olivares/appliance/layer/helpers/invocation"
	"github.com/olivaresai/olivares/appliance/layer/hostusers"
)

func helper() invocation.Helper {
	return invocation.Helper{
		Name:       helperschema.HelperSystem,
		Rules:      helperschema.SystemRules(),
		NewRequest: func() helperschema.Request { return &hostusers.CreateRequest{} },
		Perform: func(ctx context.Context, _ helperschema.Peer, request helperschema.Request) helperschema.Response {
			provisioner := hostusers.Provisioner{Host: hostusers.Linux{Diagnostics: os.Stderr}, Record: hostusers.UserdbRecord("/etc/userdb/olivares.user"), SupplementalGroup: "olivares-admins"}
			return hostusers.CreateAnswer(ctx, provisioner, request.(*hostusers.CreateRequest))
		},
	}
}
