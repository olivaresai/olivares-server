// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package localsession

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/olivaresai/olivares/appliance/layer/hostops"
	"github.com/olivaresai/olivares/appliance/layer/hostusers"
	"github.com/olivaresai/olivares/appliance/layer/portal/localframe"
)

type localTask struct{ effects int }

func (x *localTask) Prepare(context.Context, json.RawMessage) (string, error) { return "system", nil }
func (x *localTask) Apply(context.Context, hostops.Command, json.RawMessage) hostops.Observation {
	x.effects++
	return hostops.Observation{P1: "performed", Postconditions: []string{"account measured"}}
}

type localAuthority struct{ denied bool }

func (a localAuthority) Authorize(context.Context, hostops.Descriptor, string, string) (hostops.Caller, error) {
	c := hostops.Caller{Actor: "product-user", Mode: "product-up"}
	if a.denied {
		return c, errors.New("denied")
	}
	return c, nil
}

type localAudit struct{}

func (localAudit) Append(hostops.ActEvent) error { return nil }
func TestLocalSession_AdoptionRequiresTrustedIdentityAndHeldPeer(t *testing.T) {
	catalog, err := hostops.NewCatalog(hostusers.Descriptors())
	if err != nil {
		t.Fatal(err)
	}
	engine, err := hostops.OpenWithCatalog(t.TempDir(), catalog)
	if err != nil {
		t.Fatal(err)
	}
	task := &localTask{}
	acts := hostops.NewActs(engine, catalog, map[string]hostops.AdoptedTask{"host-user.create": task}, localAudit{})
	f := admittedFacts(1000, true)
	own, code := admit(4, f)
	if code != "" {
		t.Fatal(code)
	}
	defer own.Close()
	denied := false
	resolves := 0
	s := NewServer(engine, catalog, f).WithActs(acts, func(_ context.Context, uid uint32) (hostops.Authority, error) {
		resolves++
		if uid != 1000 {
			t.Fatal("foreign UID")
		}
		return localAuthority{denied: denied}, nil
	})
	body := json.RawMessage(`{"module":"host-user","verb":"create","surface":"cli","inputs":{"account":"alice","home":"/home/alice","group":"staff"}}`)
	response := s.handleFor(context.Background(), localframe.Record{Type: "request", Op: "task.plan", Body: body}, own)
	var plan hostops.Plan
	if response.Type != "response" || json.Unmarshal(response.Body, &plan) != nil || !plan.Permissions.Apply {
		t.Fatalf("plan: %+v", response)
	}
	req := hostops.ApplyRequest{OperationID: strings.Repeat("1a", 16), Module: "host-user", Verb: "create", Surface: "cli", Inputs: plan.Inputs, Confirmation: plan.Digest}
	encoded, _ := json.Marshal(req)
	call := localframe.Record{Type: "request", Op: "task.apply", Body: encoded}
	denied = true
	if r := s.handleFor(context.Background(), call, own); r.Code != "mode_refused" || task.effects != 0 {
		t.Fatalf("denial: %+v", r)
	}
	denied = false
	if r := s.handleFor(context.Background(), call, own); r.Type != "response" || r.Status != 200 || task.effects != 1 {
		t.Fatalf("apply: %+v", r)
	}
	f.admin = false
	before := resolves
	if r := s.handleFor(context.Background(), call, own); r.Code != "mode_refused" || resolves != before || task.effects != 1 {
		t.Fatalf("revoked peer: %+v", r)
	}
	if r := s.handle(call); r.Code != "input_refused" || task.effects != 1 {
		t.Fatalf("unbound caller: %+v", r)
	}
}

func TestLocalSession_AdoptionKeepsReadPlansAndEmptyApplyCompatibility(t *testing.T) {
	ds := append([]hostops.Descriptor{hostops.StatusDescriptor()}, hostusers.Descriptors()...)
	catalog, err := hostops.NewCatalog(ds)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := hostops.OpenWithCatalog(t.TempDir(), catalog)
	if err != nil {
		t.Fatal(err)
	}
	acts := hostops.NewActs(engine, catalog, map[string]hostops.AdoptedTask{"host-user.create": &localTask{}}, localAudit{})
	f := admittedFacts(1000, true)
	own, code := admit(4, f)
	if code != "" {
		t.Fatal(code)
	}
	defer own.Close()
	resolves := 0
	s := NewServer(engine, catalog, f).WithActs(acts, func(context.Context, uint32) (hostops.Authority, error) {
		resolves++
		return nil, errors.New("identity unavailable")
	})
	plan := localframe.Record{Type: "request", Op: "task.plan", Body: json.RawMessage(`{"module":"host","verb":"status","surface":"cli","inputs":{}}`)}
	if r := s.handleFor(context.Background(), plan, own); r.Type != "response" || resolves != 0 {
		t.Fatalf("existing read plan changed: %+v", r)
	}
	if r := s.handleFor(context.Background(), localframe.Record{Type: "request", Op: "task.apply", Body: json.RawMessage(`{}`)}, own); r.Code != "act_not_adopted" || r.Status != 503 || resolves != 0 {
		t.Fatalf("empty apply changed: %+v", r)
	}
}
