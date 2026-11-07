// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package netguard

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/olivaresai/olivares/appliance/layer/helpers/helperschema"
)

func TestGuardEdge_ExposureIsExactRootUnitAndStatusOnly(t *testing.T) {
	peer := helperschema.Peer{UID: 0, Account: "root", Unit: "olivares-helper-system@12-34-0.service", Attested: true}
	if err := AdmitEdge(peer, "status"); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"apply", "confirm", "revert"} {
		if err := AdmitEdge(peer, action); err == nil {
			t.Fatal("exposure may mutate")
		}
	}
	for _, change := range []func(*helperschema.Peer){func(p *helperschema.Peer) { p.UID = 1000 }, func(p *helperschema.Peer) { p.Unit = "olivares-helper-systemx@12.service" }, func(p *helperschema.Peer) { p.Attested = false }} {
		bad := peer
		change(&bad)
		if err := AdmitEdge(bad, "status"); err == nil {
			t.Fatal("unattested exposure admitted")
		}
	}
}
func TestGuardEdge_TransientDriverIsRefused(t *testing.T) {
	for _, account := range []string{"root", "olivares-portal", "olivares-net-guard"} {
		p := helperschema.Peer{UID: 1001, Account: account, Unit: "run-test-driver.service", Attested: true}
		if account == "root" {
			p.UID = 0
		}
		if err := AdmitEdge(p, "apply"); err == nil {
			t.Fatal(account, "driver admitted")
		}
	}
}
func TestGuardEdge_StrictBoundedDocumentAndEOF(t *testing.T) {
	valid := `{"action":"status","operation_id":"0123456789abcdef0123456789abcdef"}`
	if _, err := DecodeEdge(strings.NewReader(valid)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{valid + ` {}`, valid + " garbage", valid + strings.Repeat(" ", MaxEdgeBytes), `{"action":"status","action":"apply"}`, `{"Action":"status"}`, `{"action":"status","path":"/etc/shadow"}`} {
		if _, err := DecodeEdge(strings.NewReader(bad)); err == nil {
			t.Fatal("invalid or oversized document accepted")
		}
	}
}
func TestGuard_StatusDuringPendingCallDoesNotTakeNetworkLock(t *testing.T) {
	e, n, _, change := newTestEngine(t)
	n.delay = UpdateInMemory
	if _, _, err := e.Apply(t.Context(), change); err != nil {
		t.Fatal(err)
	}
	e.operation.Lock()
	defer e.operation.Unlock()
	status, err := e.Status(change.OperationID)
	if err != nil || status.PendingCalls != 1 {
		t.Fatal(status, err)
	}
}

type brokenClock struct{}

func (brokenClock) Now() (string, time.Duration, error) {
	return "", 0, errors.New("boot_identity_unavailable")
}

// While nothing is selected the guard answers status network_unselected, of this boot and with no window, and
// refuses everything else as before; a guard that cannot read its boot answers no status either.
func TestGuardEdge_UnselectedAnswersStatusOnly(t *testing.T) {
	console := helperschema.Peer{UID: 0, Account: "root", Unit: "olivares-repair-console.service", TTY: "/dev/tty1", Attested: true}
	boot := "3f1c2a8e-5b7d-4e21-9a0c-6d2f8b4e1a73"
	unselected := Edge{Unselected: &testClock{boot: boot, now: time.Second}}
	got := unselected.Handle(context.Background(), console, EdgeRequest{Action: "status"})
	if got.Code != CodeUnselected || got.BootID != boot || len(got.OpenWindows) != 0 || got.Status != nil {
		t.Fatalf("unselected status answered %+v", got)
	}
	for name, c := range map[string]struct {
		edge    Edge
		request EdgeRequest
	}{
		"apply":                  {unselected, EdgeRequest{Action: "apply"}},
		"one operation's status": {unselected, EdgeRequest{Action: "status", OperationID: "fedcba9876543210fedcba9876543210"}},
		"no clock":               {Edge{}, EdgeRequest{Action: "status"}},
		"a boot it cannot read":  {Edge{Unselected: brokenClock{}}, EdgeRequest{Action: "status"}},
	} {
		if got := c.edge.Handle(context.Background(), console, c.request); got.Code != "network_guard_unavailable" {
			t.Errorf("%s: answered %+v, not network_guard_unavailable", name, got)
		}
	}
}
