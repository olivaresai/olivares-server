// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package localsession

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/olivaresai/olivares/appliance/layer/firewall"
	"github.com/olivaresai/olivares/appliance/layer/firewall/policy"
	"github.com/olivaresai/olivares/appliance/layer/helpers/helperschema"
	"github.com/olivaresai/olivares/appliance/layer/hostops"
	"github.com/olivaresai/olivares/appliance/layer/optionalapps"
	"github.com/olivaresai/olivares/appliance/layer/portal/audit"
	"github.com/olivaresai/olivares/appliance/layer/portal/localframe"
)

// firewallHelper is the firewall helper as the console sees it: it answers the confirmed policy, takes
// one candidate as a pending window and confirms it.
type firewallHelper struct {
	confirmed policy.Document
	window    firewall.Window
	ops       []string
}

func (h *firewallHelper) Call(_ context.Context, name string, request helperschema.Request) (helperschema.Response, error) {
	r, ok := request.(*firewall.Request)
	if name != firewall.HelperName || !ok || r.Validate() != nil {
		return helperschema.Response{}, errors.New("a request the firewall helper would not take")
	}
	h.ops = append(h.ops, r.Op)
	switch r.Op {
	case firewall.OpStatus:
		status := firewall.Status{ConfirmedDigest: policy.Digest(h.confirmed), Confirmed: &h.confirmed, Windows: []firewall.Window{}}
		body, _ := json.Marshal(status)
		return helperschema.Response{Result: helperschema.ResultAnswered, Bundle: body}, nil
	case firewall.OpApply:
		h.window = firewall.Window{SchemaVersion: firewall.WindowSchema, OperationID: r.OperationID, App: r.App, CandidateDigest: policy.Digest(*r.Candidate),
			PreviousDigest: policy.Digest(h.confirmed), Candidate: *r.Candidate, State: firewall.WindowPending, Postconditions: []string{"runtime table " + policy.Digest(*r.Candidate)}}
	case firewall.OpConfirm:
		h.window.State = firewall.WindowConfirmed
		h.window.Postconditions = []string{"confirmed policy " + h.window.CandidateDigest}
		h.confirmed = h.window.Candidate
	}
	body, _ := json.Marshal(h.window)
	return helperschema.Response{Result: helperschema.ResultPerformed, Bundle: body}, nil
}

type networkIdentity struct{}

func (networkIdentity) Authorize(_ context.Context, d hostops.Descriptor, target, digest string) (hostops.Caller, error) {
	if d.Module != "firewall" || d.ActVerb != "network" || d.Audience != "appliance-helper:olivares-portal-firewall" || target != "network" || len(digest) != 64 {
		return hostops.Caller{}, errors.New("denied")
	}
	return hostops.Caller{Actor: "operator", Mode: "product-up"}, nil
}

func (a networkIdentity) ReserveExposure(ctx context.Context, d hostops.Descriptor, target, digest string) (hostops.Caller, error) {
	return a.Authorize(ctx, d, target, digest)
}

// The firewall's app-row act is an adopted act of the portal's local socket: the served catalog
// carries it, a plan reads the firewall helper's status and offers the apply, and the apply is
// confirmed by the operator's digest, recorded on the network target and not repeated on reopening.
// A catalog that does not serve it, and an absent helper, adopt nothing.
func TestLocalSession_FirewallAppRowIsAnAdoptedAct(t *testing.T) {
	f := admittedFacts(1000, true)
	own, code := admit(4, f)
	if code != "" {
		t.Fatal(code)
	}
	defer own.Close()
	auditDir := t.TempDir()
	if err := os.Chmod(auditDir, 0700); err != nil {
		t.Fatal(err)
	}
	spool, err := audit.Open(auditDir)
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(context.Context, uint32) (hostops.Authority, error) { return networkIdentity{}, nil }
	served := append([]hostops.Descriptor{hostops.StatusDescriptor()}, firewall.Descriptors()...)
	confirmed := policy.Document{SchemaVersion: policy.SchemaVersion, SSHPort: 22, Portal: policy.Portal{Listen: policy.ListenLocal},
		DHCPv6ClientInterfaces: []string{}, Apps: []policy.AppRow{}}
	dir := t.TempDir()
	open := func(helper *firewallHelper, descriptors []hostops.Descriptor) *Server {
		t.Helper()
		var caller interface {
			Call(context.Context, string, helperschema.Request) (helperschema.Response, error)
		}
		if helper != nil {
			caller = helper
		}
		s, err := OpenWithPackages(t.Context(), dir, descriptors, caller, f, resolve, spool)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	request := func(s *Server, op string, value any) localframe.Record {
		t.Helper()
		body, _ := json.Marshal(value)
		return s.handleFor(t.Context(), localframe.Record{Type: "request", Op: op, Body: body}, own)
	}
	input := json.RawMessage(`{"app":"nginx-proxy-manager","change":"add"}`)
	plan := func(s *Server) (localframe.Record, hostops.Plan) {
		r := request(s, "task.plan", taskRequest{Module: "firewall", Verb: "app-row", Surface: "cli", Inputs: input})
		var p hostops.Plan
		_ = json.Unmarshal(r.Body, &p)
		return r, p
	}

	helper := &firewallHelper{confirmed: confirmed}
	s := open(helper, served)
	r, p := plan(s)
	if r.Status != 200 || !p.Permissions.Apply {
		t.Fatalf("add with the firewall helper: %+v, want a plan that offers the apply", r)
	}
	if got := strings.Join(helper.ops, " "); got != "status" {
		t.Fatalf("a plan asked the helper for %q, want its status alone", got)
	}
	if r, _ := plan(open(helper, []hostops.Descriptor{hostops.StatusDescriptor()})); r.Status == 200 {
		t.Fatalf("add is planned although the catalog does not serve it: %+v", r)
	}
	if r, _ := plan(open(nil, served)); r.Status == 200 {
		t.Fatalf("add without the firewall helper was planned: %+v", r)
	}

	apply := hostops.ApplyRequest{Module: "firewall", Verb: "app-row", Surface: "cli", Inputs: input, OperationID: strings.Repeat("c", 32), Confirmation: p.Digest}
	var rec hostops.Record
	if r := request(s, "task.apply", apply); r.Status != 200 || json.Unmarshal(r.Body, &rec) != nil || rec.State != hostops.StateSucceeded || rec.Target != "network" {
		t.Fatalf("the act: %+v record %+v, want succeeded on the network target", r, rec)
	}
	want := confirmed
	want.Apps = optionalapps.FirewallRows()
	if policy.Digest(helper.confirmed) != policy.Digest(want) {
		t.Errorf("the helper holds the confirmed policy %s, want the policy with the app's rows %s", policy.Digest(helper.confirmed), policy.Digest(want))
	}
	effects := len(helper.ops)
	s = open(helper, served)
	if r := request(s, "task.apply", apply); r.Status != 200 || len(helper.ops) != effects {
		t.Fatalf("a reopened operation repeated its effect: %+v after %v", r, helper.ops)
	}
}

// deniedIdentity is an authority that refuses the network verb.
type deniedIdentity struct{}

func (deniedIdentity) Authorize(context.Context, hostops.Descriptor, string, string) (hostops.Caller, error) {
	return hostops.Caller{}, errors.New("denied")
}

// The firewall helper now performs what the console sends it, so the console is what stands in front of
// the table: an authority that refuses the network verb, and a confirmation that is not the digest of the
// plan the operator read, each stop the act before the helper is asked to apply anything.
func TestLocalSession_FirewallAppRowStopsBeforeTheHelperWithoutAuthorityOrTheOperatorsDigest(t *testing.T) {
	f := admittedFacts(1000, true)
	own, code := admit(4, f)
	if code != "" {
		t.Fatal(code)
	}
	defer own.Close()
	auditDir := t.TempDir()
	if err := os.Chmod(auditDir, 0700); err != nil {
		t.Fatal(err)
	}
	spool, err := audit.Open(auditDir)
	if err != nil {
		t.Fatal(err)
	}
	served := append([]hostops.Descriptor{hostops.StatusDescriptor()}, firewall.Descriptors()...)
	confirmed := policy.Document{SchemaVersion: policy.SchemaVersion, SSHPort: 22, Portal: policy.Portal{Listen: policy.ListenLocal},
		DHCPv6ClientInterfaces: []string{}, Apps: []policy.AppRow{}}
	input := json.RawMessage(`{"app":"nginx-proxy-manager","change":"add"}`)
	for name, c := range map[string]struct {
		authority hostops.Authority
		digest    func(planned string) string
	}{
		"the authority refuses the verb":   {deniedIdentity{}, func(planned string) string { return planned }},
		"a digest that is not the plan's":  {networkIdentity{}, func(string) string { return strings.Repeat("0", 64) }},
		"no digest at all":                 {networkIdentity{}, func(string) string { return "" }},
		"the digest of another act's plan": {networkIdentity{}, func(string) string { return strings.Repeat("f", 64) }},
	} {
		helper := &firewallHelper{confirmed: confirmed}
		resolve := func(context.Context, uint32) (hostops.Authority, error) { return c.authority, nil }
		s, err := OpenWithPackages(t.Context(), t.TempDir(), served, helper, f, resolve, spool)
		if err != nil {
			t.Fatal(err)
		}
		call := func(op string, value any) localframe.Record {
			body, _ := json.Marshal(value)
			return s.handleFor(t.Context(), localframe.Record{Type: "request", Op: op, Body: body}, own)
		}
		planned := call("task.plan", taskRequest{Module: "firewall", Verb: "app-row", Surface: "cli", Inputs: input})
		var p hostops.Plan
		_ = json.Unmarshal(planned.Body, &p)
		apply := hostops.ApplyRequest{Module: "firewall", Verb: "app-row", Surface: "cli", Inputs: input, OperationID: strings.Repeat("d", 32), Confirmation: c.digest(p.Digest)}
		answered := call("task.apply", apply)
		var rec hostops.Record
		succeeded := answered.Status == 200 && json.Unmarshal(answered.Body, &rec) == nil && rec.State == hostops.StateSucceeded
		if succeeded || slices.Contains(helper.ops, firewall.OpApply) || slices.Contains(helper.ops, firewall.OpConfirm) {
			t.Errorf("%s: %+v record %+v after helper ops %v, want the act stopped before the helper applied anything", name, answered, rec, helper.ops)
		}
	}
}
