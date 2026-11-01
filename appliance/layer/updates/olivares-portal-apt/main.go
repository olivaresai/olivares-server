// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

// olivares-portal-apt answers the host-package module's retained native plan to an invoker the
// kernel attests.
//
// Its socket unit, olivares-helper-apt.socket, listens on /run/olivares-helpers/apt.sock with
// Accept=yes and starts one instance per connection, as root, with the connection as its standard
// input and output. It reads one closed package document (status, update or recover), takes no
// argument and no path, admits the Appliance Console alone from the connection, and works only on
// the plan retained in /var/lib/olivares-package-plan: it fetches no package, changes no
// repository and no key. Status verifies the retained RPMs and the plan and answers the plan's
// digest and tasks; an act re-verifies them and replays one native transaction, and waits for the
// seam's guest proof before it runs at all.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/olivaresai/olivares/appliance/layer/helpers/invocation"
	"github.com/olivaresai/olivares/appliance/layer/updates"
)

// stateDirectory is the helper's private operation directory: root's, mode 0700, the unit's
// StateDirectory. The plan is retained there by the package owner before the helper is asked.
const stateDirectory = "/var/lib/olivares-package-plan"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	code := run(ctx)
	stop()
	os.Exit(code)
}

func run(ctx context.Context) int {
	root, err := os.OpenRoot(stateDirectory)
	if err != nil {
		fmt.Fprintf(os.Stderr, "apt helper: the retained plan directory cannot be opened: %v\n", err)
		return invocation.ExitFailure
	}
	defer root.Close()
	return invocation.Serve(ctx, helper(updates.RPM{Root: root, Run: updates.LinuxRun}), invocation.Linux{}, os.Args[1:], 0, os.Stdin, os.Stdout, os.Stderr)
}
