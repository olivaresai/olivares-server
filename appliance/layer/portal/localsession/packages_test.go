// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package localsession

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/olivaresai/olivares/appliance/layer/helpers/helperschema"
	"github.com/olivaresai/olivares/appliance/layer/hostops"
	"github.com/olivaresai/olivares/appliance/layer/portal/audit"
	"github.com/olivaresai/olivares/appliance/layer/portal/localframe"
	"github.com/olivaresai/olivares/appliance/layer/updates"
)

// This fixture is a serialized protected answer, not a public native Plan.
// Native RPM execution and installed peer admission belong to separate journeys.
type statusPackages struct {
	status  updates.PackageStatus
	effects int
	refused bool
}

func (h *statusPackages) Call(_ context.Context, name string, request helperschema.Request) (helperschema.Response, error) {
	r, ok := request.(*updates.PackageRequest)
	if !ok || name != updates.HelperName || r.Validate() != nil {
		return helperschema.Response{}, errors.New("unexpected package request")
	}
	if h.refused || r.NativePlan != "" && r.NativePlan != h.status.Digest {
		return helperschema.Response{Result: helperschema.ResultRefused}, nil
	}
	if r.Op == "status" {
		body, _ := json.Marshal(h.status)
		return helperschema.Response{Result: helperschema.ResultAnswered, Bundle: body}, nil
	}
	h.effects++
	h.status.Installed = h.status.To
	if r.Op == "recover" {
		h.status.Installed = h.status.From
	}
	facts := []string{"package=" + h.status.Name, "installed=" + h.status.Installed, "recovery_scope=package-version-only"}
	if r.Op == "update" {
		facts = append(facts, "repository="+h.status.Repository)
	}
	body, _ := json.Marshal(struct {
		OperationID string              `json:"operation_id"`
		Op          string              `json:"op"`
		Target      string              `json:"target"`
		NativePlan  string              `json:"native_plan"`
		Observation hostops.Observation `json:"observation"`
	}{r.OperationID, r.Op, "packages", h.status.Digest, hostops.Observation{P1: "performed", MeasuredChange: true, RevertDefined: true, RevertMeasured: r.Op == "recover", Postconditions: facts}})
	return helperschema.Response{Result: helperschema.ResultPerformed, Bundle: body}, nil
}

func serializedPackages() *statusPackages {
	p := updates.PackageStatus{Name: "olv-example", Repository: "appstream", PreviousRepository: "baseos", From: "olv-example-1.0-1.x86_64", To: "olv-example-1.1-1.x86_64", Installed: "olv-example-1.0-1.x86_64", RecoveryScope: "package-version-only", Digest: strings.Repeat("c", 64)}
	for _, op := range []string{"update", "recover"} {
		from, to, repository := p.From, p.To, p.Repository
		if op == "recover" {
			from, to, repository = to, from, p.PreviousRepository
		}
		p.Descriptors = append(p.Descriptors, hostops.Descriptor{ID: "host-package." + op, Module: "host-package", Verb: op, Title: "Host package " + op, Category: "Packages",
			InputSchema:   hostops.InputSchema{Type: "object", Properties: map[string]hostops.InputField{"native_plan": {Type: "string", Enum: []string{p.Digest}}}, Required: []string{"native_plan"}},
			Preconditions: []string{"Current exact-plan authority"}, Consequence: "Change " + from + " to " + to + "; repository=" + repository + "; recovery_scope=package-version-only.",
			Confirmation: "confirm", Modes: []string{"product-up"}, ActVerb: "package", Audience: "appliance-helper:olivares-portal-apt", EquivalentCommand: "olivares-appliance host-package " + op + " --plan", OutputSchema: "hostop-v1.schema.json", Surfaces: []string{"web", "cli", "tui"}})
	}
	return &statusPackages{status: p}
}

type packageIdentity struct{ denied bool }

func (a *packageIdentity) Authorize(_ context.Context, d hostops.Descriptor, target, digest string) (hostops.Caller, error) {
	c := hostops.Caller{Actor: "operator", Mode: "product-up"}
	if a.denied || d.Module != "host-package" || d.ActVerb != "package" || d.Audience != "appliance-helper:olivares-portal-apt" || target != "packages" || len(digest) != 64 {
		return c, errors.New("denied")
	}
	return c, nil
}

func TestLocalSession_PackageStatusComposesConfirmedTasksWithoutPrivatePlans(t *testing.T) {
	helper := serializedPackages()
	f := admittedFacts(1000, true)
	own, code := admit(4, f)
	if code != "" {
		t.Fatal(code)
	}
	defer own.Close()
	authority := &packageIdentity{}
	resolve := func(_ context.Context, uid uint32) (hostops.Authority, error) {
		if uid != 1000 {
			t.Fatal("caller supplied a foreign UID")
		}
		return authority, nil
	}
	auditDir := t.TempDir()
	if err := os.Chmod(auditDir, 0700); err != nil {
		t.Fatal(err)
	}
	spool, err := audit.Open(auditDir)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	open := func(h updates.HelperCaller, identity AuthorityResolver, log *audit.Spool) *Server {
		t.Helper()
		engineCatalog, native, err := CatalogWithPackages(t.Context(), []hostops.Descriptor{hostops.StatusDescriptor()}, h)
		if err != nil {
			t.Fatal(err)
		}
		s, err := OpenWithPackages(t.Context(), dir, []hostops.Descriptor{hostops.StatusDescriptor()}, h, f, identity, log)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(engineCatalog.Descriptors(), s.catalog.Descriptors()) {
			t.Fatal("engine authorization and portal tasks use different descriptors")
		}
		for _, d := range native {
			if d.Audience != "appliance-helper:olivares-portal-apt" || !slices.Equal(d.InputSchema.Properties["native_plan"].Enum, []string{helper.status.Digest}) {
				t.Fatal("engine catalog lost the native package audience or sealed digest")
			}
		}
		return s
	}
	s := open(helper, resolve, spool)
	request := func(s *Server, op string, value any) localframe.Record {
		t.Helper()
		body, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return s.handleFor(t.Context(), localframe.Record{Type: "request", Op: op, Body: body}, own)
	}
	listed := request(s, "task.list", map[string]string{"surface": "cli"})
	var tasks struct {
		Tasks []hostops.Descriptor `json:"tasks"`
	}
	if listed.Status != 200 || json.Unmarshal(listed.Body, &tasks) != nil || len(tasks.Tasks) != 3 || helper.effects != 0 {
		t.Fatalf("native status tasks missing: %+v", listed)
	}
	for i, op := range []string{"update", "recover"} {
		for _, surface := range []string{"cli", "tui"} {
			r := request(s, "task.describe", taskRequest{Module: "host-package", Verb: op, Surface: surface})
			var d hostops.Descriptor
			if r.Status != 200 || json.Unmarshal(r.Body, &d) != nil || !slices.Equal(d.InputSchema.Properties["native_plan"].Enum, []string{helper.status.Digest}) || !strings.Contains(d.Consequence, "package-version-only") || (op == "recover" && !strings.Contains(d.Consequence, "repository=baseos")) {
				t.Fatalf("%s description lost native binding: %+v", surface, r)
			}
		}
		input := json.RawMessage(`{"native_plan":"` + helper.status.Digest + `"}`)
		p := request(s, "task.plan", taskRequest{Module: "host-package", Verb: op, Surface: "cli", Inputs: input})
		var plan hostops.Plan
		if p.Status != 200 || json.Unmarshal(p.Body, &plan) != nil || !plan.Permissions.Apply || helper.effects != i {
			t.Fatalf("confirmed nonmutating plan: %+v", p)
		}
		apply := hostops.ApplyRequest{Module: "host-package", Verb: op, Surface: "cli", Inputs: input, OperationID: strings.Repeat([]string{"a", "b"}[i], 32), Confirmation: plan.Digest}
		authority.denied = true
		if r := request(s, "task.apply", apply); r.Status != 403 || helper.effects != i {
			t.Fatalf("revoked current authority reached effect: %+v", r)
		}
		authority.denied = false
		r := request(s, "task.apply", apply)
		var rec hostops.Record
		want := []string{hostops.StateSucceeded, hostops.StateRolledBack}[i]
		if r.Status != 200 || json.Unmarshal(r.Body, &rec) != nil || rec.State != want || rec.Target != "packages" || rec.OperationID != apply.OperationID || helper.effects != i+1 {
			t.Fatalf("%s effect: %+v record=%+v", op, r, rec)
		}
		s = open(helper, resolve, spool)
		if r := request(s, "task.apply", apply); r.Status != 200 || helper.effects != i+1 {
			t.Fatalf("reopened operation repeated effect: %+v", r)
		}
	}
	events, err := spool.Pending()
	if err != nil || len(events) != 8 {
		t.Fatalf("durable decisions/outcomes: %d %v", len(events), err)
	}
	for _, e := range events {
		if e.Actor != "operator" || e.Target != "packages" || len(e.PlanDigest) != 64 || len(e.OperationID) != 32 {
			t.Fatalf("audit correlation missing: %+v", e)
		}
	}
	for _, missing := range []string{"identity", "audit", "helper", "helper refusal", "descriptor digest", "repair mode", "open schema", "previous repository"} {
		t.Run(missing, func(t *testing.T) {
			h := serializedPackages()
			var caller updates.HelperCaller = h
			identity, log := AuthorityResolver(resolve), spool
			switch missing {
			case "identity":
				identity = nil
			case "audit":
				log = nil
			case "helper":
				caller = nil
			case "helper refusal":
				h.refused = true
			case "descriptor digest":
				h.status.Descriptors[0].InputSchema.Properties["native_plan"] = hostops.InputField{Type: "string", Enum: []string{strings.Repeat("e", 64)}}
			case "repair mode":
				h.status.Descriptors[0].Modes = []string{"product-down-repair"}
			case "open schema":
				h.status.Descriptors[0].InputSchema.AdditionalProperties = true
			case "previous repository":
				h.status.PreviousRepository = ""
			}
			closed := open(caller, identity, log)
			if r := request(closed, "task.apply", struct{}{}); r.Status != 503 || r.Code != "act_not_adopted" || h.effects != 0 {
				t.Fatalf("missing input opened admission: %+v", r)
			}
			if r := request(closed, "task.describe", taskRequest{Module: "host", Verb: "status", Surface: "cli"}); r.Status != 200 {
				t.Fatalf("existing read lost: %+v", r)
			}
			if missing != "identity" && missing != "audit" {
				if r := request(closed, "task.describe", taskRequest{Module: "host-package", Verb: "update", Surface: "cli"}); r.Status != 422 {
					t.Fatalf("unbound native task exposed: %+v", r)
				}
			}
		})
	}
	t.Log("serialized list/describe, two confirmed fake effects, current authority, durable ID retrieval and eight audits; no installed/native execution claim")
}

type callerFunc func(context.Context, string, helperschema.Request) (helperschema.Response, error)

func (f callerFunc) Call(ctx context.Context, name string, r helperschema.Request) (helperschema.Response, error) {
	return f(ctx, name, r)
}

// An appliance with no plan is the usual state and is quiet. A status the console cannot use (a helper that did not
// answer in its budget, an answer that is not a plan) offers no package task either, and the journal says so.
func TestPackageDescriptors_SayWhyOnlyWhenTheStatusIsUnusable(t *testing.T) {
	for _, tc := range []struct {
		name   string
		call   callerFunc
		logged string
	}{
		{"no plan the helper can load", func(context.Context, string, helperschema.Request) (helperschema.Response, error) {
			return helperschema.Response{Result: helperschema.ResultRefused, Code: helperschema.CodeInputRefused}, nil
		}, ""},
		{"a helper that cannot be reached", func(context.Context, string, helperschema.Request) (helperschema.Response, error) {
			return helperschema.Response{}, errors.New("consumer_unavailable")
		}, "the host-package status is unusable (consumer_unavailable"},
		{"a helper that failed", func(context.Context, string, helperschema.Request) (helperschema.Response, error) {
			return helperschema.Response{Result: helperschema.ResultFailed, Code: helperschema.CodeEffectFailed}, nil
		}, "result \"failed\""},
		{"an answer that is not a plan", func(context.Context, string, helperschema.Request) (helperschema.Response, error) {
			return helperschema.Response{Result: helperschema.ResultAnswered, Bundle: []byte(`{"Digest":"x"}`)}, nil
		}, "the host-package status is unusable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logged bytes.Buffer
			log.SetOutput(&logged)
			t.Cleanup(func() { log.SetOutput(os.Stderr) })
			if tasks := packageDescriptors(t.Context(), tc.call); len(tasks) != 0 {
				t.Fatalf("%d package tasks from an unusable status", len(tasks))
			}
			if tc.logged == "" && logged.Len() != 0 || !strings.Contains(logged.String(), tc.logged) {
				t.Fatalf("logged %q, want %q", logged.String(), tc.logged)
			}
		})
	}
}
