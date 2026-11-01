// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package optionalapps

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/olivaresai/olivares/appliance/layer/helpers/helperschema"
	"github.com/olivaresai/olivares/appliance/layer/hostops"
	"github.com/olivaresai/olivares/appliance/layer/portal/audit"
)

type appAuthority struct {
	actor string
	deny  bool
}

func (a appAuthority) Authorize(_ context.Context, d hostops.Descriptor, target, digest string) (hostops.Caller, error) {
	actor := a.actor
	if actor == "" {
		actor = "fran"
	}
	caller := hostops.Caller{Actor: actor, Mode: "product-up"}
	if a.deny || d.Module != "nginx-proxy-manager" || target != appTarget() || len(digest) != 64 {
		return caller, errors.New("denied")
	}
	return caller, nil
}

type appHelper struct {
	host  *dockerHost
	fault string
	calls int
}

func (h *appHelper) Call(ctx context.Context, name string, request helperschema.Request) (helperschema.Response, error) {
	r, ok := request.(*LifecycleRequest)
	if name != HelperName || !ok || r.Validate() != nil {
		return helperschema.Response{}, errors.New("unexpected fixed app helper request")
	}
	if r.Op != "status" {
		h.calls++
		if h.fault == "refused" {
			return helperschema.Response{Result: helperschema.ResultRefused}, nil
		}
		if h.fault == "changed before helper" {
			h.host.installed, h.host.running = true, true
		}
	}
	response := LifecycleAnswer(ctx, h.host.executor(), r)
	if r.Op != "status" {
		switch h.fault {
		case "lost answer":
			return helperschema.Response{}, errors.New("helper answer lost after effect")
		case "foreign operation", "foreign target", "foreign manifest", "false rollback":
			var body lifecycleResult
			if json.Unmarshal(response.Bundle, &body) != nil {
				return helperschema.Response{}, errors.New("missing fixture result")
			}
			switch h.fault {
			case "foreign operation":
				body.OperationID = strings.Repeat("f", 32)
			case "foreign target":
				body.Target = "app:another-app"
			case "foreign manifest":
				body.Manifest = strings.Repeat("e", 64)
			case "false rollback":
				body.Observation.RevertDefined, body.Observation.RevertMeasured = true, true
			}
			response.Bundle, _ = json.Marshal(body)
		}
	}
	return response, nil
}

func appActs(t *testing.T, directory string, helper *appHelper, spool *audit.Spool) *hostops.Acts {
	t.Helper()
	catalog, err := hostops.NewCatalog(Descriptors())
	if err != nil {
		t.Fatal(err)
	}
	engine, err := hostops.OpenWithCatalog(directory, catalog)
	if err != nil {
		t.Fatal(err)
	}
	tasks := map[string]hostops.AdoptedTask{}
	for _, d := range catalog.Descriptors() {
		tasks[d.ID] = LifecycleTask{Op: d.Verb, Helper: helper}
	}
	return hostops.NewActs(engine, catalog, tasks, hostops.SpoolAudit{Spool: spool})
}

func appAudit(t *testing.T) *audit.Spool {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	spool, err := audit.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return spool
}

func TestLifecycleTask_ConfirmedLifecycleHasAuditAndReopenedIDsNeverRepeatEffects(t *testing.T) {
	helper := &appHelper{host: newDockerHost(t)}
	dir, spool := t.TempDir(), appAudit(t)
	acts := appActs(t, dir, helper, spool)
	for i, op := range []string{"install", "stop", "start", "uninstall"} {
		r := hostops.ApplyRequest{Module: "nginx-proxy-manager", Verb: op, Surface: "cli", OperationID: strings.Repeat([]string{"12", "34", "56", "78"}[i], 16), Inputs: json.RawMessage(`{}`)}
		before := len(helper.host.effects)
		plan, err := acts.Plan(t.Context(), r.Module, r.Verb, r.Surface, r.Inputs, appAuthority{})
		if err != nil || !plan.Permissions.Apply || len(helper.host.effects) != before {
			t.Fatalf("non-mutating plan: %+v %v effects=%v", plan, err, helper.host.effects)
		}
		r.Confirmation = plan.Digest
		for _, authority := range []appAuthority{{actor: "another-operator"}, {deny: true}} {
			if _, status, err := acts.Apply(t.Context(), r, authority); err == nil || status != 403 || helper.calls != i {
				t.Fatalf("denied confirmation reached helper: status=%d err=%v calls=%d", status, err, helper.calls)
			}
		}
		rec, status, err := acts.Apply(t.Context(), r, appAuthority{})
		if err != nil || status != 200 || rec.State != hostops.StateSucceeded || rec.Target != appTarget() || helper.calls != i+1 {
			t.Fatalf("%s: %+v %d %v helper_calls=%d", op, rec, status, err, helper.calls)
		}
		acts = appActs(t, dir, helper, spool)
		if again, _, err := acts.Apply(t.Context(), r, appAuthority{}); err != nil || again.State != rec.State || helper.calls != i+1 {
			t.Fatalf("replay: %+v %v helper_calls=%d", again, err, helper.calls)
		}
	}
	events, err := spool.Pending()
	if err != nil || len(events) != 20 || !slices.Equal(helper.host.effects, []string{"pull", "up", "stop", "start", "down"}) {
		t.Fatalf("audit=%d err=%v native_effects=%v", len(events), err, helper.host.effects)
	}
	t.Logf("four confirmed helper calls; native effects=%v; durable audit=%d; reopened IDs never repeat", helper.host.effects, len(events))
}

func TestLifecycleTask_ChangedNativeStateAndUntrustedIntentRefuseBeforeEffects(t *testing.T) {
	for _, cause := range []string{"foreign mount", "changed before helper", "caller image", "foreign command", "foreign expected ID"} {
		t.Run(cause, func(t *testing.T) {
			helper := &appHelper{host: newDockerHost(t)}
			task := LifecycleTask{Op: "install", Helper: helper}
			input := json.RawMessage(`{}`)
			target, err := task.Prepare(t.Context(), input)
			if err != nil {
				t.Fatal(err)
			}
			cmd := hostops.Command{OperationID: strings.Repeat("a", 32), TaskID: "nginx-proxy-manager.install", Module: "nginx-proxy-manager", Verb: "install", Target: target}
			switch cause {
			case "foreign mount":
				helper.host.installed, helper.host.running, helper.host.foreign = true, true, "other mount"
			case "changed before helper":
				helper.fault = cause
			case "caller image":
				input = json.RawMessage(`{"image":"untrusted:latest"}`)
			case "foreign command":
				cmd.Target = "app:another-app"
			case "foreign expected ID":
				helper.host.installed, helper.host.running = true, true
				r := &LifecycleRequest{Op: "stop", OperationID: cmd.OperationID, Manifest: manifestDigest(), Expected: State{Installed: true, Running: true, ContainerID: strings.Repeat("d", 64)}}
				answer := LifecycleAnswer(t.Context(), helper.host.executor(), r)
				if answer.Result != helperschema.ResultRefused || len(helper.host.effects) != 0 {
					t.Fatalf("foreign expected ID reached native effect: %+v %v", answer, helper.host.effects)
				}
				return
			}
			observation := task.Apply(t.Context(), cmd, input)
			if observation.P1 != "not-performed" || len(helper.host.effects) != 0 {
				t.Fatalf("%s: %+v native_effects=%v", cause, observation, helper.host.effects)
			}
		})
	}
}

func TestLifecycleTask_LostOrForeignAnswersRetainUnknownAndBlockNewLifecycle(t *testing.T) {
	for _, cause := range []string{"lost answer", "foreign operation", "foreign target", "foreign manifest", "false rollback", "up", "refused"} {
		t.Run(cause, func(t *testing.T) {
			helper := &appHelper{host: newDockerHost(t), fault: cause}
			helper.host.fail = cause
			dir, spool := t.TempDir(), appAudit(t)
			acts := appActs(t, dir, helper, spool)
			r := hostops.ApplyRequest{Module: "nginx-proxy-manager", Verb: "install", Surface: "cli", OperationID: strings.Repeat("a", 32), Inputs: json.RawMessage(`{}`)}
			plan, err := acts.Plan(t.Context(), r.Module, r.Verb, r.Surface, r.Inputs, appAuthority{})
			if err != nil {
				t.Fatal(err)
			}
			r.Confirmation = plan.Digest
			want := hostops.StateRunning
			if cause == "up" {
				want = hostops.StatePartial
			} else if cause == "refused" {
				want = hostops.StateFailed
			}
			for range 2 {
				rec, _, err := acts.Apply(t.Context(), r, appAuthority{})
				if err != nil || rec.State != want || helper.calls != 1 {
					t.Fatalf("%s: %+v %v helper_calls=%d", cause, rec, err, helper.calls)
				}
				acts = appActs(t, dir, helper, spool)
			}
			if want == hostops.StateRunning {
				next := hostops.ApplyRequest{Module: r.Module, Verb: "stop", Surface: "cli", OperationID: strings.Repeat("b", 32), Inputs: r.Inputs}
				plan, err := acts.Plan(t.Context(), next.Module, next.Verb, next.Surface, next.Inputs, appAuthority{})
				if err != nil {
					t.Fatal(err)
				}
				next.Confirmation = plan.Digest
				_, status, err := acts.Apply(t.Context(), next, appAuthority{})
				var locked *hostops.TargetLocked
				if status != 409 || !errors.As(err, &locked) || locked.OperationID != r.OperationID || helper.calls != 1 {
					t.Fatalf("new lifecycle bypassed unknown install's app lock: %d %v calls=%d", status, err, helper.calls)
				}
			}
		})
	}
}
