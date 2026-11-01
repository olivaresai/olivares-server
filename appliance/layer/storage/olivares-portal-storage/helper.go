// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package main

import (
	"context"

	"github.com/olivaresai/olivares/appliance/layer/helpers/helperschema"
	"github.com/olivaresai/olivares/appliance/layer/helpers/invocation"
	"github.com/olivaresai/olivares/appliance/layer/storage"
)

// helper admits inventory reads and the two separately validated, identity-bound
// actions for the attested Appliance Console. An absent action owner refuses.
func helper(read storage.Reader, apply ...func(context.Context, *storage.ActionRequest) helperschema.Response) invocation.Helper {
	return invocation.Helper{
		Name:       storage.HelperName,
		Rules:      storage.HelperRules(),
		NewRequest: func() helperschema.Request { return &storage.HelperRequest{} },
		Perform: func(ctx context.Context, _ helperschema.Peer, document helperschema.Request) helperschema.Response {
			r, ok := document.(*storage.HelperRequest)
			if !ok {
				return helperschema.Response{Result: helperschema.ResultRefused, Code: storage.CodeInputRefused}
			}
			if r.Op != storage.SubcommandInventory {
				if len(apply) != 1 || apply[0] == nil {
					return helperschema.Response{Result: helperschema.ResultRefused, Code: helperschema.CodeConsumerUnavailable}
				}
				return apply[0](ctx, &storage.ActionRequest{Op: r.Op, OperationID: *r.OperationID, Identity: *r.Identity})
			}
			return storage.Answer(read(ctx))
		},
	}
}
