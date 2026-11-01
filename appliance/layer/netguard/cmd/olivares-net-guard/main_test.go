// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.
package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/olivaresai/olivares/appliance/layer/helpers/helperschema"
	"github.com/olivaresai/olivares/appliance/layer/netguard"
	"github.com/olivaresai/olivares/appliance/layer/portal"
)

// The journal of a refused initialization showed only "network runtime initialization refused" (#2834): the refusal
// names its cause, here the non-root one.
func TestInitializeRuntimeRefusalNamesItsCause(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the refusal measured here is the non-root one")
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr, args := os.Stderr, os.Args
	os.Stderr, os.Args = w, []string{"olivares-net-guard", "initialize-runtime"}
	code := run()
	os.Stderr, os.Args = stderr, args
	w.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if code != 2 || !strings.Contains(string(out), "network_runtime_requires_root") {
		t.Fatalf("run() = %d, stderr %q; want 2 and the refusal's cause", code, out)
	}
}

// With no management interface selected (first boot published no selection, or one that names none) the guard has
// nothing to guard: the verdict is code 0 and says so, and run serves refusals instead of exiting 1 into a restart every
// 15 s (the regression). An unreadable or invalid selection at start is still a failure, and its reason is printed.
func TestSelectionVerdict(t *testing.T) {
	for _, c := range []struct {
		name      string
		selection portal.Selection
		reason    string
		done      bool
		code      int
		says      string
	}{
		{"none published", portal.Selection{}, "", true, 0, "nothing to guard"},
		{"published without management interfaces", portal.Selection{Listen: portal.ListenLocal}, "", true, 0, "nothing to guard"},
		{"invalid", portal.Selection{}, "the published selection does not follow its schema", true, 1, "does not follow its schema"},
		{"management interfaces", portal.Selection{ManagementInterfaces: []string{"enp1s0"}}, "", false, 0, ""},
	} {
		done, code, message := selectionVerdict(c.selection, c.reason)
		if done != c.done || code != c.code || !strings.Contains(message, c.says) {
			t.Errorf("%s: selectionVerdict = %v, %d, %q; want %v, %d and a message with %q", c.name, done, code, message, c.done, c.code, c.says)
		}
	}
}

// With nothing selected the guard keeps its socket answered: a request gets a refusal, not a reset, so systemd never
// sees a queued connection on an exited service (cand8: start-limit-hit within a second). Once a selection names an
// interface, serving stops so the next request starts the guard under it (the regression).
func TestServeUntilSelected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guard.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	var selected atomic.Bool
	done := make(chan error, 1)
	read := func() (bool, string) { return selected.Load(), "" }
	go func() {
		done <- serveUntilSelected(context.Background(), listener, read, func(string) {}, 20*time.Millisecond)
	}()
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	// Frame the request as the portal's client does: write it, half-close, read the answer. The guard reads an attested
	// peer's request to its end (a CI runner started by systemd is one) and refuses an unattested peer without reading
	// it, so a write that comes after that refusal finds the connection closed. Only the answer is under test.
	_, _ = conn.Write([]byte(`{"action":"status"}` + "\n"))
	if err := conn.(*net.UnixConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	var response netguard.EdgeResponse
	if err := json.NewDecoder(conn).Decode(&response); err != nil {
		t.Fatalf("no answer while nothing is selected: %v", err)
	}
	// A well-formed request is never refused as malformed, so that code would mean it reached the guard garbled.
	if response.Code == "" || response.Code == "ok" || response.Code == "network_input_refused" {
		t.Fatalf("answer %q; want a refusal of the request", response.Code)
	}
	selectedAt := time.Now()
	selected.Store(true)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serveUntilSelected = %v; want nil once a management interface is selected", err)
		}
		// Edge.Serve does not wait for the connections it accepted; the drain wait gives each its reply.
		if waited := time.Since(selectedAt); waited < acceptedConnectionDeadline {
			t.Fatalf("returned %v after the selection; want at least the %v drain wait", waited, acceptedConnectionDeadline)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("still serving after a management interface was selected")
	}
}

// While nothing is selected, the portal (the guard's only client) is refused by name, so it cannot make an unguarded
// change and says why (the regression review).
func TestUnguardedRefusesThePortalAsGuardUnavailable(t *testing.T) {
	portalPeer := helperschema.Peer{UID: 1001, Account: "olivares-portal", Unit: "olivares-portal.service", Attested: true}
	for _, action := range []string{"status", "apply", "confirm"} {
		if got := unguarded.Handle(context.Background(), portalPeer, netguard.EdgeRequest{Action: action}).Code; got != "network_guard_unavailable" {
			t.Errorf("unguarded.Handle(portal, %q) = %q; want network_guard_unavailable", action, got)
		}
	}
}

// An unusable selection published while the guard serves keeps it refusing, and the journal names why, once per new
// reason, instead of still reading "nothing to guard" (review of the regression).
func TestServeUntilSelectedNamesAnUnusableSelectionOnce(t *testing.T) {
	// A short directory: t.TempDir() under this test's name exceeds the 108-byte Unix socket path limit.
	dir, err := os.MkdirTemp("", "ng")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	listener, err := net.Listen("unix", filepath.Join(dir, "guard.sock"))
	if err != nil {
		t.Fatal(err)
	}
	const bad = "the published selection does not follow its schema"
	var reads atomic.Int32
	read := func() (bool, string) {
		if reads.Add(1) <= 3 {
			return false, bad
		}
		return true, ""
	}
	var mu sync.Mutex
	var reported []string
	report := func(reason string) { mu.Lock(); reported = append(reported, reason); mu.Unlock() }
	done := make(chan error, 1)
	go func() { done <- serveUntilSelected(context.Background(), listener, read, report, 10*time.Millisecond) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serveUntilSelected = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("still serving after a usable selection was read")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(reported) != 1 || reported[0] != bad {
		t.Fatalf("reported %q; want the reason once", reported)
	}
}
