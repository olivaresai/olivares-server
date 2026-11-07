// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

// olivares-portal-system performs the fixed host-user operation for an attested repair console.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/olivaresai/olivares/appliance/layer/helpers/invocation"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	code := invocation.Serve(ctx, helper(), invocation.Linux{}, os.Args[1:], 0, os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
