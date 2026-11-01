// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package hostusers_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/olivaresai/olivares/appliance/layer/hostops"
	"github.com/olivaresai/olivares/appliance/layer/hostusers"
	"github.com/olivaresai/olivares/appliance/layer/portal/audit"
)

type authority struct{ deny bool }

func (a authority) Authorize(_ context.Context, d hostops.Descriptor, target, digest string) (hostops.Caller, error) {
	caller := hostops.Caller{Actor: "fran", Mode: "product-up"}
	if a.deny || d.ID != "host-user.create" || target != "system" || len(digest) != 64 {
		return caller, errors.New("denied")
	}
	return caller, nil
}
func TestHostUser_NativeOperationSurvivesRestartWithoutRepeatingEffect(t *testing.T) {
	catalog, err := hostops.NewCatalog(hostusers.Descriptors())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	engine, err := hostops.OpenWithCatalog(dir, catalog)
	if err != nil {
		t.Fatal(err)
	}
	auditDir := t.TempDir()
	if err := os.Chmod(auditDir, 0o700); err != nil {
		t.Fatal(err)
	}
	spool, err := audit.Open(auditDir)
	if err != nil {
		t.Fatal(err)
	}
	h := &host{}
	p := hostusers.Provisioner{Host: h}
	acts := hostops.NewActs(engine, catalog, map[string]hostops.AdoptedTask{"host-user.create": p}, hostops.SpoolAudit{Spool: spool})
	r := hostops.ApplyRequest{OperationID: strings.Repeat("12", 16), Module: "host-user", Verb: "create", Surface: "cli", Inputs: json.RawMessage(`{"account":"alice","group":"staff","home":"/home/alice"}`)}
	plan, err := acts.Plan(context.Background(), r.Module, r.Verb, r.Surface, r.Inputs, authority{})
	if err != nil {
		t.Fatal(err)
	}
	r.Confirmation = plan.Digest
	if _, _, err := acts.Apply(context.Background(), r, authority{deny: true}); err == nil || h.path != "" {
		t.Fatal("denied account creation")
	}
	rec, _, err := acts.Apply(context.Background(), r, authority{})
	if err != nil || rec.State != hostops.StateSucceeded {
		t.Fatalf("create: %+v %v", rec, err)
	}
	t.Logf("created operation=%s actor=%s state=%s command=%s args=%q", rec.OperationID, rec.Actor, rec.State, h.path, h.args)
	h.path = ""
	engine, err = hostops.OpenWithCatalog(dir, catalog)
	if err != nil {
		t.Fatal(err)
	}
	acts = hostops.NewActs(engine, catalog, map[string]hostops.AdoptedTask{"host-user.create": p}, hostops.SpoolAudit{Spool: spool})
	if again, _, err := acts.Apply(context.Background(), r, authority{}); err != nil || again.State != rec.State || h.path != "" {
		t.Fatalf("restart replay: %+v %v", again, err)
	}
	r.OperationID = strings.Repeat("34", 16)
	if _, _, err := acts.Apply(context.Background(), r, authority{}); err == nil || h.path != "" {
		t.Fatal("new operation created a duplicate")
	}
	events, err := spool.Pending()
	if err != nil || len(events) < 3 || events[0].Outcome != "refused" || events[0].OperationID != rec.OperationID || events[0].Target != "system" || events[0].PlanDigest != plan.Digest {
		t.Fatalf("audit: %+v %v", events, err)
	}
	t.Logf("restart retrieved %s without another command; durable audit events=%d, denied target=%s", rec.OperationID, len(events), events[0].Target)
}
