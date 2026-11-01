// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

// olivares-portal-pam is the fixed, no-argument, per-connection native PAM worker.
// Its socket-activated unit supplies stdin as an accepted AF_UNIX connection.
package main

import (
	"context"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/olivaresai/olivares/core/nativepam"
)

func main() {
	if len(os.Args) != 1 || os.Geteuid() != 0 {
		os.Exit(1)
	}
	file := os.NewFile(0, "accepted-pam-connection")
	conn, err := net.FileConn(file)
	_ = file.Close()
	if err != nil {
		os.Exit(1)
	}
	c, ok := conn.(*net.UnixConn)
	if !ok {
		_ = conn.Close()
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, nativepam.WorkerLifetime)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- nativepam.ServeWorker(ctx, c, cancel) }()
	select {
	case err := <-done:
		if err != nil {
			os.Exit(1)
		}
	case <-ctx.Done():
		// Terminate even a blocked native PAM call. The unit's KillMode and
		// finite RuntimeMaxSec reap the worker and all PAM children; memory
		// belongs to this one disposable process, never the static portal.
		_ = c.Close()
		os.Exit(1)
	}
}
