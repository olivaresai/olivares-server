// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.
package main

import (
	"context"
	"fmt"
	"github.com/olivaresai/olivares/appliance/layer/netguard"
	"github.com/olivaresai/olivares/appliance/layer/portal"
	"net"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"
	"time"
)

func main() { os.Exit(run()) }

// selectionVerdict decides from the published selection whether the guard has interfaces to guard. With none selected it
// is done with guarding (code 0): run then serves its socket refusing every request until a selection names one. An
// unreadable or invalid selection at start is a failure (code 1) that names its reason.
func selectionVerdict(selection portal.Selection, reason string) (done bool, code int, message string) {
	if reason != "" {
		return true, 1, "network management selection unavailable: " + reason
	}
	if len(selection.ManagementInterfaces) == 0 {
		return true, 0, "no management interface is selected: nothing to guard; requests are refused as network_guard_unavailable until a selection names one"
	}
	return false, 0, ""
}

// selectionReread is how often a guard with nothing to guard reads the published selection again. First boot may
// publish it after the guard started.
const selectionReread = 2 * time.Second

// managementSelected reports whether the published selection names a management interface, and why a published one
// cannot be read.
func managementSelected() (bool, string) {
	selection, reason := portal.ReadSelection(portal.SelectionFile)
	return reason == "" && len(selection.ManagementInterfaces) > 0, reason
}

// unguarded is the edge served while nothing is selected: with no engine it refuses every admitted request as
// network_guard_unavailable, so no change is made unguarded.
var unguarded = netguard.Edge{}

// acceptedConnectionDeadline is the deadline Edge.Serve gives each connection it accepted (serve_linux.go). Serve does
// not wait for them when it returns, so the guard waits this long before it exits and each still gets its reply.
const acceptedConnectionDeadline = time.Second

// serveUntilSelected answers the guard socket through unguarded until read reports a management interface, so no
// connection waits on a stopped service; it then returns nil, and the next request starts the guard under that selection.
// A published selection that cannot be used keeps it refusing, and report names each new reason once.
func serveUntilSelected(ctx context.Context, listener net.Listener, read func() (bool, string), report func(reason string), every time.Duration) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		last := ""
		ticker := time.NewTicker(every)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				selected, reason := read()
				if selected {
					cancel()
					return
				}
				if reason != "" && reason != last {
					report(reason)
				}
				last = reason
			}
		}
	}()
	if err := unguarded.Serve(ctx, listener); err != nil && ctx.Err() == nil {
		return err
	}
	time.Sleep(acceptedConnectionDeadline)
	return nil
}
func run() int {
	if len(os.Args) == 2 && os.Args[1] == "initialize-runtime" {
		if err := netguard.InitializeRuntime(); err != nil {
			fmt.Fprintln(os.Stderr, "network runtime initialization refused:", err)
			return 2
		}
		return 0
	}
	if len(os.Args) != 1 {
		return 2
	}
	account, err := user.Lookup("olivares-net-guard")
	if err != nil || account.Uid != strconv.Itoa(os.Geteuid()) || os.Geteuid() == 0 {
		return 1
	}
	if os.Getenv("LISTEN_PID") != strconv.Itoa(os.Getpid()) || os.Getenv("LISTEN_FDS") != "1" {
		return 2
	}
	f := os.NewFile(3, "guard-socket")
	listener, err := net.FileListener(f)
	f.Close()
	if err != nil {
		return 2
	}
	defer listener.Close()
	selection, reason := portal.ReadSelection(portal.SelectionFile)
	if done, code, message := selectionVerdict(selection, reason); done {
		fmt.Fprintln(os.Stderr, message)
		if code != 0 {
			return code
		}
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
		defer stop()
		report := func(reason string) {
			fmt.Fprintln(os.Stderr, "network management selection unavailable: "+reason+"; requests stay refused")
		}
		if err := serveUntilSelected(ctx, listener, managementSelected, report, selectionReread); err != nil {
			return 2
		}
		if ctx.Err() == nil {
			fmt.Fprintln(os.Stderr, "a management interface is selected: the next request starts the guard under it")
		}
		return 0
	}
	bus, err := netguard.NewSystemTransport(selection.ManagementInterfaces)
	if err != nil {
		fmt.Fprintln(os.Stderr, "network owner identity unavailable")
		return 1
	}
	defer bus.Close()
	journal, err := netguard.OpenJournal("/var/lib/olivares-net-guard/acts")
	if err != nil {
		return 2
	}
	clock, err := netguard.NewBootClock()
	if err != nil {
		return 2
	}
	lock, err := netguard.NewFileLock()
	if err != nil {
		return 2
	}
	engine, err := netguard.NewEngine(netguard.Config{Bus: bus, Clock: clock, Journal: journal, Lock: lock, Restorer: &netguard.RootHelper{}})
	if err != nil {
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := engine.Tick(ctx); err != nil {
					fmt.Fprintln(os.Stderr, "network recovery remains unresolved")
				}
			}
		}
	}()
	if err := (netguard.Edge{Engine: engine}).Serve(ctx, listener); err != nil && ctx.Err() == nil {
		return 2
	}
	return 0
}
