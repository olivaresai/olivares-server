// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

//go:build linux && (amd64 || arm64)

package localsession

import (
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The held session's two liveness probes, the pidfd's and the socket's, poll with no timeout and no wait. A
// signal that reaches the thread inside such a call makes it return EINTR, which is not an answer about the
// peer: the Go runtime signals its own threads all the time, and a probe that reads EINTR as "gone" closes a
// live client's session in the middle of its request (measured in a guest: about 1 request in 100). Here the
// process is signaled as fast as it can be while the probes ask about a peer that is alive throughout.
func TestLiveness_ASignalNeverMakesALivePeerLookGone(t *testing.T) {
	pidfd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		t.Skipf("no pidfd here: %v", err)
	}
	defer unix.Close(pidfd)
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fds[0]), "held")
	defer file.Close()
	defer unix.Close(fds[1])
	conn, err := net.FileConn(file)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	held, ok := conn.(*net.UnixConn)
	if !ok {
		t.Fatal("not a unix connection")
	}

	var stop atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		for !stop.Load() {
			_ = syscall.Kill(os.Getpid(), syscall.SIGURG)
		}
	}()
	defer func() { stop.Store(true); <-done }()

	var asked, gonePidfd, goneSocket int
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); asked++ {
		if (Linux{}).Alive(pidfd) != nil {
			gonePidfd++
		}
		if !peerSocketAlive(held) {
			goneSocket++
		}
	}
	if gonePidfd != 0 || goneSocket != 0 {
		t.Fatalf("a live peer looked gone: the pidfd probe %d times and the socket probe %d times in %d rounds", gonePidfd, goneSocket, asked)
	}
}
