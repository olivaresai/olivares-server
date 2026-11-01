// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

// olivares-package-retain retains the host-package plan the console composes its update and
// recovery tasks from.
//
// It runs as root, started by olivares-package-retain.service, takes no argument and no path, and
// reads one fixed delivery directory: the two RPM files a trusted source (the entitled channel) put there
// and the document that names them. It fetches no package, changes no repository and no key. The
// plan is verified and left in /var/lib/olivares-package-plan, where olivares-portal-apt, the
// package helper, reads it; the unit then restarts the console so that it composes its tasks from
// the plan (it composes them once, when its local listener opens).
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/olivaresai/olivares/appliance/layer/updates"
)

// The two directories are root's and private, the units' StateDirectory: the helper's own plan
// directory, and the delivery directory the trusted source writes into.
const (
	stateDirectory    = "/var/lib/olivares-package-plan"
	deliveryDirectory = "/var/lib/olivares-package-delivery"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	code := run(ctx, stateDirectory, deliveryDirectory, updates.LinuxRun, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, state, delivery string, native func(context.Context, []string, int64) ([]byte, error), out, diagnostic io.Writer) int {
	stateRoot, err := os.OpenRoot(state)
	if err != nil {
		fmt.Fprintf(diagnostic, "package retention: the plan directory cannot be opened: %v\n", err)
		return 1
	}
	defer stateRoot.Close()
	deliveryRoot, err := os.OpenRoot(delivery)
	if err != nil {
		fmt.Fprintf(diagnostic, "package retention: the delivery directory cannot be opened: %v\n", err)
		return 1
	}
	defer deliveryRoot.Close()
	plan, err := updates.RPM{Root: stateRoot, Run: native}.Retain(ctx, deliveryRoot)
	if err != nil {
		fmt.Fprintf(diagnostic, "package retention refused: %v\n", err)
		return 1
	}
	fmt.Fprintf(out, "retained the plan %s: %s to %s\n", plan.Digest, plan.From, plan.To)
	return 0
}
