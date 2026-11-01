// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package hostops_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/olivaresai/olivares/appliance/layer/hostops"
)

type adoptedTask struct{ effects int }

func (t *adoptedTask) Prepare(context.Context, json.RawMessage) (string, error) { return "system", nil }
func (t *adoptedTask) Apply(context.Context, hostops.Command, json.RawMessage) hostops.Observation {
	t.effects++
	return hostops.Observation{P1: "performed", Postconditions: []string{"account and home measured"}}
}

type actAuthority struct {
	denied bool
	actor  string
}

func (a actAuthority) Authorize(context.Context, hostops.Descriptor, string, string) (hostops.Caller, error) {
	c := hostops.Caller{Actor: "operator-1", Mode: "product-up"}
	if a.actor != "" {
		c.Actor = a.actor
	}
	if a.denied {
		return c, errors.New("denied")
	}
	return c, nil
}

type actAudit struct {
	events            []hostops.ActEvent
	fail, failOutcome bool
}

func (a *actAudit) Append(e hostops.ActEvent) error {
	if a.fail || a.failOutcome && e.Outcome != "authorized" && e.Outcome != "refused" {
		return errors.New("audit unavailable")
	}
	a.events = append(a.events, e)
	return nil
}

func TestAdoptedTask_ConfirmationAuthorityAuditAndOnceOnly(t *testing.T) {
	d := hostops.StatusDescriptor()
	d.ID, d.Module, d.Verb = "host-user.create", "host-user", "create"
	d.Confirmation, d.ActVerb, d.Audience = "confirm", "system", "appliance-helper:olivares-portal-system"
	catalog, err := hostops.NewCatalog([]hostops.Descriptor{d})
	if err != nil {
		t.Fatal(err)
	}
	e, err := hostops.OpenWithCatalog(t.TempDir(), catalog)
	if err != nil {
		t.Fatal(err)
	}
	task, audit := &adoptedTask{}, &actAudit{}
	s := hostops.NewActs(e, catalog, map[string]hostops.AdoptedTask{d.ID: task}, audit)
	r := hostops.ApplyRequest{OperationID: strings.Repeat("a1", 16), Module: d.Module, Verb: d.Verb, Surface: "cli", Inputs: json.RawMessage(`{}`)}
	plan, err := s.Plan(context.Background(), r.Module, r.Verb, r.Surface, r.Inputs, actAuthority{})
	if err != nil || !plan.Permissions.Apply || len(plan.Digest) != 64 {
		t.Fatalf("plan: %+v %v", plan, err)
	}
	if _, _, err := s.Apply(context.Background(), r, actAuthority{}); err == nil || task.effects != 0 {
		t.Fatal("unconfirmed effect")
	}
	r.Confirmation = plan.Digest
	if _, _, err := s.Apply(context.Background(), r, actAuthority{actor: "operator-2"}); err == nil || task.effects != 0 {
		t.Fatal("another operator reused confirmation")
	}
	if _, _, err := s.Apply(context.Background(), r, actAuthority{denied: true}); err == nil || task.effects != 0 {
		t.Fatal("denied effect")
	}
	audit.fail = true
	if _, _, err := s.Apply(context.Background(), r, actAuthority{}); err == nil || task.effects != 0 {
		t.Fatal("effect without audit")
	}
	audit.fail = false
	rec, status, err := s.Apply(context.Background(), r, actAuthority{})
	if err != nil || status != 200 || rec.State != hostops.StateSucceeded || rec.Actor != "operator-1" || task.effects != 1 {
		t.Fatalf("apply: %+v %d %v", rec, status, err)
	}
	if _, _, err := s.Apply(context.Background(), r, actAuthority{}); err != nil || task.effects != 1 {
		t.Fatalf("replay: %v, effects %d", err, task.effects)
	}
	if len(audit.events) < 3 || audit.events[0].Outcome != "refused" {
		t.Fatalf("audit: %+v", audit.events)
	}
	t.Run("outcome audit failure remains unknown without repeating", func(t *testing.T) {
		engine, err := hostops.OpenWithCatalog(t.TempDir(), catalog)
		if err != nil {
			t.Fatal(err)
		}
		effect, failedAudit := &adoptedTask{}, &actAudit{failOutcome: true}
		acts := hostops.NewActs(engine, catalog, map[string]hostops.AdoptedTask{d.ID: effect}, failedAudit)
		for range 2 {
			rec, status, err := acts.Apply(context.Background(), r, actAuthority{})
			if err != nil || status != 202 || rec.State != hostops.StateRunning || rec.Outcome != hostops.OutcomeUnknown || effect.effects != 1 {
				t.Fatalf("unverified outcome: %+v status=%d err=%v effects=%d", rec, status, err, effect.effects)
			}
		}
	})
}
