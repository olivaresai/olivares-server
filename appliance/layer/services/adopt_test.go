// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package services

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/olivaresai/olivares/appliance/layer/helpers/helperschema"
	"github.com/olivaresai/olivares/appliance/layer/hostops"
	"github.com/olivaresai/olivares/appliance/layer/portal/audit"
)

type restartAuthority struct {
	deny  bool
	actor string
}

type restartHelper struct{ executor Executor }

func (h restartHelper) Call(ctx context.Context, name string, request helperschema.Request) (helperschema.Response, error) {
	r, ok := request.(*Request)
	if !ok || name != HelperName || r.Validate() != nil {
		return helperschema.Response{}, errors.New("invalid helper request")
	}
	return Answer(ctx, h.executor, r), nil
}

func (a restartAuthority) Authorize(_ context.Context, d hostops.Descriptor, target, digest string) (hostops.Caller, error) {
	c := hostops.Caller{Actor: "fran", Mode: "product-up"}
	if a.actor != "" {
		c.Actor = a.actor
	}
	if a.deny || !strings.HasPrefix(d.ID, "service.") || !strings.HasPrefix(target, "unit:") || len(digest) != 64 {
		return c, errors.New("denied")
	}
	return c, nil
}

func TestUnitTask_Restart_ConfirmedRestartHasDurableOutcomeAndAudit(t *testing.T) {
	catalog, err := hostops.NewCatalog(Descriptors())
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
	bus := newFakeBus(active("olivares-app-example.service"))
	bus.finish = finishWith("done", active)
	task := UnitTask{Op: OpRestart, Helper: restartHelper{executor: Executor{Bus: bus, JobWait: time.Millisecond}}}
	acts := hostops.NewActs(engine, catalog, map[string]hostops.AdoptedTask{"service.restart": task}, hostops.SpoolAudit{Spool: spool})
	r := hostops.ApplyRequest{OperationID: strings.Repeat("12", 16), Module: "service", Verb: "restart", Surface: "cli", Inputs: json.RawMessage(`{"unit":"olivares-app-example.service"}`)}
	plan, err := acts.Plan(t.Context(), r.Module, r.Verb, r.Surface, r.Inputs, restartAuthority{})
	if err != nil || !plan.Permissions.Apply {
		t.Fatalf("plan: %+v %v", plan, err)
	}
	r.Confirmation = plan.Digest
	if _, status, err := acts.Apply(t.Context(), r, restartAuthority{deny: true}); err == nil || status != 403 || bus.jobs != 0 {
		t.Fatal("denied restart reached systemd", status, err)
	}
	rec, status, err := acts.Apply(t.Context(), r, restartAuthority{})
	if err != nil || status != 200 || rec.State != hostops.StateSucceeded || rec.Target != "unit:olivares-app-example.service" || bus.jobs != 1 {
		t.Fatalf("restart: %+v status=%d %v", rec, status, err)
	}
	if !strings.Contains(strings.Join(rec.Postconditions, " "), "job_result=done ActiveState=active") {
		t.Fatal("missing observed service state", rec.Postconditions)
	}
	engine, err = hostops.OpenWithCatalog(dir, catalog)
	if err != nil {
		t.Fatal(err)
	}
	acts = hostops.NewActs(engine, catalog, map[string]hostops.AdoptedTask{"service.restart": task}, hostops.SpoolAudit{Spool: spool})
	if again, _, err := acts.Apply(t.Context(), r, restartAuthority{}); err != nil || again.State != rec.State || bus.jobs != 1 {
		t.Fatalf("reopened operation repeated restart: %+v %v", again, err)
	}
	events, err := spool.Pending()
	if err != nil || len(events) != 4 || events[0].Outcome != "refused" || events[0].Target != rec.Target || events[0].PlanDigest != plan.Digest || events[2].Outcome != "performed" {
		t.Fatalf("durable audit: %+v %v", events, err)
	}
	t.Logf("operation=%s actor=%s unit=%s state=%s jobs=%d audit_events=%d", rec.OperationID, rec.Actor, rec.Target, rec.State, bus.jobs, len(events))
}

type restartAudit struct{ fail bool }

func (a restartAudit) Append(hostops.ActEvent) error {
	if a.fail {
		return errors.New("audit unavailable")
	}
	return nil
}

type restartHelperFunc func(context.Context, string, helperschema.Request) (helperschema.Response, error)

func (f restartHelperFunc) Call(ctx context.Context, name string, request helperschema.Request) (helperschema.Response, error) {
	return f(ctx, name, request)
}

func restartActs(t *testing.T, task UnitTask, eventAudit hostops.ActAudit) (*hostops.Acts, hostops.ApplyRequest) {
	t.Helper()
	catalog, err := hostops.NewCatalog(Descriptors())
	if err != nil {
		t.Fatal(err)
	}
	engine, err := hostops.OpenWithCatalog(t.TempDir(), catalog)
	if err != nil {
		t.Fatal(err)
	}
	acts := hostops.NewActs(engine, catalog, map[string]hostops.AdoptedTask{"service.restart": task}, eventAudit)
	r := hostops.ApplyRequest{OperationID: strings.Repeat("34", 16), Module: Module, Verb: OpRestart, Surface: "cli", Inputs: json.RawMessage(`{"unit":"olivares-app-example.service"}`)}
	plan, err := acts.Plan(t.Context(), r.Module, r.Verb, r.Surface, r.Inputs, restartAuthority{})
	if err != nil || !plan.Permissions.Apply {
		t.Fatalf("plan: %+v %v", plan, err)
	}
	r.Confirmation = plan.Digest
	return acts, r
}

func TestUnitTask_Restart_ChangedOperatorUnitAndAuditOutagePreventEffects(t *testing.T) {
	for _, cause := range []string{"operator", "unit", "audit"} {
		t.Run(cause, func(t *testing.T) {
			bus := newFakeBus(active("olivares-app-example.service"), active("olivares-app-other.service"))
			task := UnitTask{Op: OpRestart, Helper: restartHelper{executor: Executor{Bus: bus, JobWait: time.Millisecond}}}
			acts, request := restartActs(t, task, restartAudit{fail: cause == "audit"})
			authority := restartAuthority{}
			want := 403
			switch cause {
			case "operator":
				authority.actor = "other-operator"
			case "unit":
				request.Inputs = json.RawMessage(`{"unit":"olivares-app-other.service"}`)
			case "audit":
				want = 503
			}
			if _, status, err := acts.Apply(t.Context(), request, authority); err == nil || status != want || len(effects(bus.Calls())) != 0 {
				t.Fatalf("%s reached effects: status=%d err=%v calls=%v", cause, status, err, bus.Calls())
			}
		})
	}
}

func TestUnitTask_Restart_ProtectedAbsentAndUncomposedUnitsNeverReachAnEffect(t *testing.T) {
	for _, input := range []string{`{"unit":"dbus.service"}`, `{"unit":"absent.service"}`, `{"unit":"olivares-app-example.service","actor":"fran"}`, `{"unit":"olivares-app-example.service","unit":"other.service"}`} {
		bus := newFakeBus(active("olivares-app-example.service"))
		task := UnitTask{Op: OpRestart, Helper: restartHelper{executor: Executor{Bus: bus}}}
		if target, err := task.Prepare(t.Context(), json.RawMessage(input)); err == nil || target != "" || len(effects(bus.Calls())) != 0 {
			t.Fatalf("unsafe plan %s: target=%s err=%v calls=%v", input, target, err, bus.Calls())
		}
	}
	if _, err := (UnitTask{Op: OpRestart}).Prepare(t.Context(), json.RawMessage(`{"unit":"olivares-app-example.service"}`)); err == nil {
		t.Fatal("uncomposed helper offered a plan")
	}
}

func TestUnitTask_Restart_ObservedJobOutcomeSurvivesReplayWithoutAnotherJob(t *testing.T) {
	for _, c := range []struct {
		name, result, want string
		after              func(string) Unit
		queueError         bool
	}{
		{"unreported but active", "", hostops.StateRunning, active, false},
		{"done but inactive", "done", hostops.StatePartial, inactive, false},
		{"failed without change", "failed", hostops.StateFailed, active, false},
		{"failed with change", "failed", hostops.StatePartial, failed, false},
		{"queue refused", "", hostops.StateFailed, active, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			bus := newFakeBus(active("olivares-app-example.service"))
			if c.result != "" {
				bus.finish = finishWith(c.result, c.after)
			}
			if c.queueError {
				bus.queueErr = errors.New("conflicting job")
			}
			task := UnitTask{Op: OpRestart, Helper: restartHelper{executor: Executor{Bus: bus, JobWait: time.Millisecond}}}
			acts, request := restartActs(t, task, restartAudit{})
			for range 2 {
				rec, _, err := acts.Apply(t.Context(), request, restartAuthority{})
				if err != nil || rec.State != c.want || bus.jobs > 1 {
					t.Fatalf("job outcome: %+v err=%v jobs=%d", rec, err, bus.jobs)
				}
			}
			calls := effects(bus.Calls())
			if len(calls) != 2 || calls[0] != "Subscribe" || calls[1] != "RestartUnit" {
				t.Fatalf("restart was repeated: %v", calls)
			}
		})
	}
}

func TestUnitTask_Restart_UnverifiedHelperAnswerStaysUnknownAndIsNotRetried(t *testing.T) {
	for _, cause := range []string{"lost", "unit", "verb", "class", "outcome", "missing job", "unknown field", "duplicate field"} {
		t.Run(cause, func(t *testing.T) {
			bus := newFakeBus(active("olivares-app-example.service"))
			bus.finish = finishWith("done", active)
			calls := 0
			helper := restartHelperFunc(func(ctx context.Context, name string, request helperschema.Request) (helperschema.Response, error) {
				response, err := (restartHelper{executor: Executor{Bus: bus, JobWait: time.Millisecond}}).Call(ctx, name, request)
				if request.(*Request).Op != OpRestart {
					return response, err
				}
				calls++
				if cause == "lost" {
					return helperschema.Response{}, errors.New("connection lost after send")
				}
				var value map[string]any
				if err := json.Unmarshal(response.Bundle, &value); err != nil {
					t.Fatal(err)
				}
				switch cause {
				case "unit":
					value["unit"] = "olivares-app-other.service"
				case "verb":
					value["op"] = OpStop
				case "class":
					value["class"] = "other"
				case "outcome":
					value["outcome"] = hostops.StateFailed
				case "missing job":
					delete(value, "job")
				case "unknown field":
					value["actor"] = "fran"
				case "duplicate field":
					response.Bundle = append(response.Bundle[:len(response.Bundle)-1], []byte(`,"unit":"olivares-app-example.service"}`)...)
					return response, nil
				}
				response.Bundle, err = json.Marshal(value)
				return response, err
			})
			acts, request := restartActs(t, UnitTask{Op: OpRestart, Helper: helper}, restartAudit{})
			for range 2 {
				rec, status, err := acts.Apply(t.Context(), request, restartAuthority{})
				if err != nil || status != 202 || rec.State != hostops.StateRunning || calls != 1 || bus.jobs != 1 {
					t.Fatalf("unverified answer: %+v status=%d err=%v calls=%d jobs=%d", rec, status, err, calls, bus.jobs)
				}
			}
		})
	}
}
