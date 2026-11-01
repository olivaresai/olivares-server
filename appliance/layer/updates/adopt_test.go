// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package updates_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/olivaresai/olivares/appliance/layer/helpers/helperschema"
	"github.com/olivaresai/olivares/appliance/layer/hostops"
	"github.com/olivaresai/olivares/appliance/layer/portal/audit"
	"github.com/olivaresai/olivares/appliance/layer/updates"
)

type packageAuthority struct {
	actor string
	deny  bool
}

func (a packageAuthority) Authorize(_ context.Context, d hostops.Descriptor, target, digest string) (hostops.Caller, error) {
	actor := a.actor
	if actor == "" {
		actor = "fran"
	}
	c := hostops.Caller{Actor: actor, Mode: "product-up"}
	if a.deny || d.Module != "host-package" || d.ActVerb != "package" || target != "packages" || len(digest) != 64 {
		return c, errors.New("denied")
	}
	return c, nil
}

type packageHelper struct {
	x     updates.RPM
	host  *packageHost
	fault string
	calls int
}

func (h *packageHelper) Call(ctx context.Context, name string, request helperschema.Request) (helperschema.Response, error) {
	r, ok := request.(*updates.PackageRequest)
	if !ok || name != updates.HelperName || r.Validate() != nil {
		return helperschema.Response{}, errors.New("unexpected package request")
	}
	if r.Op != "status" {
		h.calls++
		if h.fault == "refused" {
			return helperschema.Response{Result: helperschema.ResultRefused}, nil
		}
		if h.fault == "changed before helper" {
			h.host.installed = nextNEVRA
		}
	}
	answer := updates.PackageAnswer(ctx, h.x, r)
	if r.Op != "status" {
		if h.fault == "lost answer" {
			return helperschema.Response{}, errors.New("answer lost after effect")
		}
		if strings.HasPrefix(h.fault, "foreign ") || h.fault == "false rollback" || h.fault == "missing recovery scope" {
			var body map[string]json.RawMessage
			if json.Unmarshal(answer.Bundle, &body) != nil {
				return helperschema.Response{}, errors.New("fixture result unavailable")
			}
			switch h.fault {
			case "foreign operation":
				body["operation_id"], _ = json.Marshal(strings.Repeat("f", 32))
			case "foreign target":
				body["target"] = json.RawMessage(`"system"`)
			case "foreign native plan":
				body["native_plan"], _ = json.Marshal(strings.Repeat("e", 64))
			case "false rollback", "missing recovery scope":
				var observation hostops.Observation
				_ = json.Unmarshal(body["observation"], &observation)
				if h.fault == "false rollback" {
					observation.RevertMeasured = true
				} else {
					observation.Postconditions = []string{"package=olv-example", "installed=" + nextNEVRA}
				}
				body["observation"], _ = json.Marshal(observation)
			}
			answer.Bundle, _ = json.Marshal(body)
		}
	}
	return answer, nil
}

func preparedPackage(t *testing.T) (*packageHelper, updates.Plan) {
	t.Helper()
	h, root, previous, next := fixture(t)
	x := updates.RPM{Root: root, Run: h.run}
	p, err := x.Prepare(t.Context(), previous, next)
	if err != nil {
		t.Fatal(err)
	}
	return &packageHelper{x: x, host: h}, p
}

func packageActs(t *testing.T, dir string, helper *packageHelper, descriptors []hostops.Descriptor, spool *audit.Spool) *hostops.Acts {
	t.Helper()
	catalog, err := hostops.NewCatalog(descriptors)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := hostops.OpenWithCatalog(dir, catalog)
	if err != nil {
		t.Fatal(err)
	}
	tasks := map[string]hostops.AdoptedTask{}
	for _, d := range catalog.Descriptors() {
		tasks[d.ID] = updates.PackageTask{Op: d.Verb, Helper: helper}
	}
	return hostops.NewActs(engine, catalog, tasks, hostops.SpoolAudit{Spool: spool})
}

func packageSpool(t *testing.T) *audit.Spool {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := audit.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func packageInput(p updates.Plan) json.RawMessage {
	body, _ := json.Marshal(map[string]string{"native_plan": p.Digest})
	return body
}

func TestPackageTask_ConfirmedUpdateRecoveryAndReopenedIDsUseOneEffectEach(t *testing.T) {
	helper, p := preparedPackage(t)
	answer, err := helper.Call(t.Context(), updates.HelperName, &updates.PackageRequest{Op: "status"})
	var nativeStatus updates.PackageStatus
	if err != nil || answer.Result != helperschema.ResultAnswered || hostops.DecodeClosed(answer.Bundle, &nativeStatus) != nil || nativeStatus.Digest != p.Digest || nativeStatus.Repository != p.Repository || nativeStatus.PreviousRepository != "baseos" || len(nativeStatus.Descriptors) != 2 || len(helper.host.replays) != 0 || strings.Contains(string(answer.Bundle), helper.x.Root.Name()) {
		t.Fatalf("protected status lacks sealed-plan catalog/provenance: %+v %v", nativeStatus, err)
	}
	dir, spool := t.TempDir(), packageSpool(t)
	acts := packageActs(t, dir, helper, nativeStatus.Descriptors, spool)
	for i, op := range []string{"update", "recover"} {
		r := hostops.ApplyRequest{Module: "host-package", Verb: op, Surface: "cli", OperationID: strings.Repeat([]string{"a", "b"}[i], 32), Inputs: packageInput(p)}
		plan, err := acts.Plan(t.Context(), r.Module, r.Verb, r.Surface, r.Inputs, packageAuthority{})
		repository := p.Repository
		if op == "recover" {
			repository = "baseos"
		}
		if err != nil || !plan.Permissions.Apply || len(helper.host.replays) != i || !strings.Contains(plan.Descriptor.Consequence, previousNEVRA) || !strings.Contains(plan.Descriptor.Consequence, nextNEVRA) || !strings.Contains(plan.Descriptor.Consequence, "repository="+repository) || !strings.Contains(plan.Descriptor.Consequence, "package-version-only") {
			t.Fatalf("incomplete nonmutating preview: %+v %v", plan, err)
		}
		r.Confirmation = plan.Digest
		for _, authority := range []packageAuthority{{actor: "other-operator"}, {deny: true}} {
			if _, status, err := acts.Apply(t.Context(), r, authority); err == nil || status != 403 || helper.calls != i {
				t.Fatalf("denied operator reached helper: %d %v calls=%d", status, err, helper.calls)
			}
		}
		want := hostops.StateSucceeded
		if op == "recover" {
			want = hostops.StateRolledBack
		}
		rec, status, err := acts.Apply(t.Context(), r, packageAuthority{})
		if err != nil || status != 200 || rec.State != want || rec.Target != "packages" || helper.calls != i+1 {
			t.Fatalf("%s: %+v status=%d err=%v calls=%d", op, rec, status, err, helper.calls)
		}
		acts = packageActs(t, dir, helper, nativeStatus.Descriptors, spool)
		if got, _, err := acts.Apply(t.Context(), r, packageAuthority{}); err != nil || got.State != want || helper.calls != i+1 {
			t.Fatalf("reopened ID repeated %s: %+v %v", op, got, err)
		}
	}
	events, err := spool.Pending()
	if err != nil || len(events) != 10 || len(helper.host.replays) != 2 || helper.host.installed != previousNEVRA {
		t.Fatalf("native effects=%v audits=%d err=%v", helper.host.replays, len(events), err)
	}
	t.Logf("two confirmed helper calls, two native replays, ten durable audits; reopened IDs retrieve only; recovery scope=%s", p.RecoveryScope)
}

func TestPackageTask_ChangedRetainedPlanAndUntrustedInputsRefuseEffects(t *testing.T) {
	for _, cause := range []string{"caller digest", "caller path", "edited plan", "changed before helper", "foreign command", "caller constructed plan", "bootstrap operation", "empty update digest", "empty recovery digest", "foreign status digest"} {
		t.Run(cause, func(t *testing.T) {
			helper, p := preparedPackage(t)
			task := updates.PackageTask{Op: "update", Helper: helper}
			input := packageInput(p)
			target, err := task.Prepare(t.Context(), input)
			if err != nil {
				t.Fatal(err)
			}
			cmd := hostops.Command{OperationID: strings.Repeat("a", 32), TaskID: "host-package.update", Module: "host-package", Verb: "update", Target: target}
			switch cause {
			case "bootstrap operation", "empty update digest", "empty recovery digest", "foreign status digest":
				r := &updates.PackageRequest{Op: "status", NativePlan: p.Digest}
				switch cause {
				case "bootstrap operation":
					r.OperationID = cmd.OperationID
				case "empty update digest", "empty recovery digest":
					r.Op = "update"
					if cause == "empty recovery digest" {
						r.Op = "recover"
					}
					r.NativePlan, r.OperationID = "", cmd.OperationID
				case "foreign status digest":
					r.NativePlan = strings.Repeat("e", 64)
				}
				if answer := updates.PackageAnswer(t.Context(), helper.x, r); answer.Result != helperschema.ResultRefused || len(helper.host.replays) != 0 {
					t.Fatalf("%s: %+v native=%v", cause, answer, helper.host.replays)
				}
				return
			case "caller digest":
				input = json.RawMessage(`{"native_plan":"` + strings.Repeat("e", 64) + `"}`)
			case "caller path":
				input = json.RawMessage(`{"native_plan":"` + p.Digest + `","path":"/tmp/foreign"}`)
			case "edited plan":
				data, err := helper.x.Root.ReadFile("plan.json")
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(helper.host.dir+"/plan.json", []byte(strings.Replace(string(data), p.Repository, "foreign-repo", 1)), 0600); err != nil {
					t.Fatal(err)
				}
			case "changed before helper":
				helper.fault = cause
			case "foreign command":
				cmd.Target = "system"
			case "caller constructed plan":
				if ds := updates.Descriptors(updates.Plan{Name: p.Name, From: p.From, To: p.To, Repository: p.Repository, Digest: p.Digest, RecoveryScope: p.RecoveryScope}); len(ds) != 0 {
					t.Fatal("caller supplied a trusted native plan")
				}
				return
			}
			if got := task.Apply(t.Context(), cmd, input); got.P1 != "not-performed" || len(helper.host.replays) != 0 {
				t.Fatalf("%s: %+v native=%v", cause, got, helper.host.replays)
			}
		})
	}
}

func TestPackageTask_UncertainAnswersKeepPackagesLockedAndNeverRetry(t *testing.T) {
	for _, cause := range []string{"lost answer", "foreign operation", "foreign target", "foreign native plan", "false rollback", "missing recovery scope", "native failed", "native failed after change", "measurement lost", "refused"} {
		t.Run(cause, func(t *testing.T) {
			helper, p := preparedPackage(t)
			helper.fault = cause
			want := hostops.StateRunning
			switch cause {
			case "native failed":
				helper.host.replayError = true
				want = hostops.StateFailed
			case "native failed after change":
				helper.host.replayError = true
				helper.host.changedFailure = true
				want = hostops.StatePartial
			case "measurement lost":
				helper.host.lostMeasurement = true
			case "refused":
				want = hostops.StateFailed
			}
			dir, spool := t.TempDir(), packageSpool(t)
			acts := packageActs(t, dir, helper, updates.Descriptors(p), spool)
			r := hostops.ApplyRequest{Module: "host-package", Verb: "update", Surface: "cli", OperationID: strings.Repeat("a", 32), Inputs: packageInput(p)}
			plan, err := acts.Plan(t.Context(), r.Module, r.Verb, r.Surface, r.Inputs, packageAuthority{})
			if err != nil {
				t.Fatal(err)
			}
			r.Confirmation = plan.Digest
			for range 2 {
				got, _, err := acts.Apply(t.Context(), r, packageAuthority{})
				if err != nil || got.State != want || helper.calls != 1 {
					t.Fatalf("%s: %+v err=%v calls=%d", cause, got, err, helper.calls)
				}
				acts = packageActs(t, dir, helper, updates.Descriptors(p), spool)
			}
			if want == hostops.StateRunning && cause != "measurement lost" {
				next := hostops.ApplyRequest{Module: r.Module, Verb: "recover", Surface: "cli", OperationID: strings.Repeat("b", 32), Inputs: r.Inputs}
				plan, err := acts.Plan(t.Context(), next.Module, next.Verb, next.Surface, next.Inputs, packageAuthority{})
				if err != nil {
					t.Fatal(err)
				}
				next.Confirmation = plan.Digest
				_, status, err := acts.Apply(t.Context(), next, packageAuthority{})
				var locked *hostops.TargetLocked
				if status != 409 || !errors.As(err, &locked) || locked.OperationID != r.OperationID || helper.calls != 1 {
					t.Fatalf("unknown update lost packages lock: %d %v calls=%d", status, err, helper.calls)
				}
			}
		})
	}
}

// The helper admits the Appliance Console alone: status reads, and the two package acts are
// mutating subcommands, so the seam holds them for its guest proof.
func TestHelperRules_StatusReadsAndBothActsMutateForTheApplianceConsoleAlone(t *testing.T) {
	want := map[string]bool{"status": false, "update": true, "recover": true}
	rules := updates.HelperRules()
	if len(rules) != len(want) {
		t.Fatalf("%d rules, want %d", len(rules), len(want))
	}
	for _, rule := range rules {
		mutating, ok := want[rule.Subcommand]
		if !ok || rule.Mutating != mutating || len(rule.Invokers) != 1 || rule.Invokers[0] != helperschema.Portal {
			t.Errorf("rule %+v, want mutating=%v for the Appliance Console alone", rule, mutating)
		}
	}
}
