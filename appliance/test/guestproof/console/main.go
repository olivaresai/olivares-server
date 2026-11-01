// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

// This executable is an unpackaged guest fixture, never shipped. It is the Appliance Console's local
// session server with the console's own composition (localsession.OpenWithPackages over the served
// catalog, the helper client of the installed helpers, the audit spool) and one stand-in: the identity
// owner, which in the product answers whether the signed-in operator may authorize an act. Here a
// fixed authority authorizes the services verb on a unit target and nothing else, so the guest proof
// measures the console's act path, the helper seam and the service manager, never the product's
// sign-in. It runs as the console's account in olivares-portal.service and takes its listening socket
// from the service manager (LISTEN_FDS), as the console does.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/olivaresai/olivares/appliance/layer/hostops"
	"github.com/olivaresai/olivares/appliance/layer/portal"
	"github.com/olivaresai/olivares/appliance/layer/portal/audit"
	"github.com/olivaresai/olivares/appliance/layer/portal/helperclient"
	"github.com/olivaresai/olivares/appliance/layer/portal/localsession"
	"github.com/olivaresai/olivares/appliance/layer/services"
)

// standIn authorizes the services verb on a unit target for the plan's digest, and refuses every other act.
type standIn struct{}

func (standIn) Authorize(_ context.Context, d hostops.Descriptor, target, digest string) (hostops.Caller, error) {
	if d.Module != services.Module || d.ActVerb != services.Module || !strings.HasPrefix(target, "unit:") || len(digest) != 64 {
		return hostops.Caller{}, errors.New("denied")
	}
	return hostops.Caller{Actor: "guest-proof", Mode: "product-up"}, nil
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: guestproof-console <operations directory> <audit directory>")
		os.Exit(2)
	}
	fds, _ := strconv.Atoi(os.Getenv("LISTEN_FDS"))
	if fds != 1 || os.Getenv("LISTEN_PID") != strconv.Itoa(os.Getpid()) {
		fmt.Fprintln(os.Stderr, "guestproof-console: the listening socket comes from the service manager")
		os.Exit(2)
	}
	listener, err := net.FileListener(os.NewFile(3, "local.sock"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "guestproof-console:", err)
		os.Exit(1)
	}
	spool, err := audit.Open(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, "guestproof-console:", err)
		os.Exit(1)
	}
	resolve := func(context.Context, uint32) (hostops.Authority, error) { return standIn{}, nil }
	server, err := localsession.OpenWithPackages(context.Background(), os.Args[1], portal.ServedDescriptors(), helperclient.Client{}, localsession.Linux{}, resolve, spool)
	if err != nil {
		fmt.Fprintln(os.Stderr, "guestproof-console:", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "guestproof-console: serving the local session")
	fmt.Fprintln(os.Stderr, "guestproof-console:", server.Serve(listener))
	os.Exit(1)
}
