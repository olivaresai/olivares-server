// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

//go:build !(linux && (amd64 || arm64))

package identityengine

import (
	"context"
	"net"
)

func (*Server) Serve(context.Context, *net.UnixListener) error { return refused }
