// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package hostusers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/olivaresai/olivares/appliance/layer/helpers/helperschema"
	"github.com/olivaresai/olivares/appliance/layer/hostops"
	"github.com/olivaresai/olivares/appliance/layer/hostusers"
	"github.com/olivaresai/olivares/appliance/layer/portal/audit"
)

// The existing fake OS owns the useradd behavior; this adapter adds a changing
// group identity and successful absence for a different uncreated account/home.
type userHost struct {
	host
	gid     string
	effects int
}

func (h *userHost) Group(context.Context, string) (string, error) {
	if h.gid == "" {
		return "1001", nil
	}
	return h.gid, nil
}
func (h *userHost) Account(ctx context.Context, name string) (hostusers.Account, bool, error) {
	if h.exists && name != h.account.Name {
		return hostusers.Account{}, false, nil
	}
	return h.host.Account(ctx, name)
}
func (h *userHost) Home(ctx context.Context, path string) (hostusers.Home, error) {
	if h.homeExists && path != "/home/alice" && !h.unsafe {
		return hostusers.Home{}, nil
	}
	return h.host.Home(ctx, path)
}
func (h *userHost) Run(ctx context.Context, path string, args []string) error {
	h.effects++
	return h.host.Run(ctx, path, args)
}

type userHelper struct {
	host  *userHost
	fault string
	calls int
}

func (h *userHelper) Call(ctx context.Context, name string, request helperschema.Request) (helperschema.Response, error) {
	r, ok := request.(*hostusers.CreateRequest)
	if !ok || name != hostusers.HelperName || r.Validate() != nil {
		return helperschema.Response{}, errors.New("unexpected fixed user request")
	}
	document, err := json.Marshal(r)
	if err != nil {
		return helperschema.Response{}, err
	}
	var decoded hostusers.CreateRequest
	if err := helperschema.Decode(bytes.NewReader(document), &decoded); err != nil {
		return helperschema.Response{}, err
	}
	r = &decoded
	if r.Op != "status" {
		h.calls++
		if h.fault == "refused" {
			return helperschema.Response{Result: helperschema.ResultRefused}, nil
		}
		if h.fault == "group changed" {
			h.host.gid = "2001"
		}
	}
	answer := hostusers.CreateAnswer(ctx, hostusers.Provisioner{Host: h.host}, r)
	if r.Op != "status" {
		if h.fault == "lost answer" {
			return helperschema.Response{}, errors.New("user answer lost after effect")
		}
		if strings.HasPrefix(h.fault, "foreign ") || h.fault == "false rollback" {
			var body map[string]json.RawMessage
			if json.Unmarshal(answer.Bundle, &body) != nil {
				return helperschema.Response{}, errors.New("fixture answer unavailable")
			}
			switch h.fault {
			case "foreign operation":
				body["operation_id"], _ = json.Marshal(strings.Repeat("f", 32))
			case "foreign account":
				body["request"] = json.RawMessage(`{"account":"bob","home":"/home/bob","group":"staff"}`)
			case "foreign gid":
				body["expected_gid"] = json.RawMessage(`"2001"`)
			case "false rollback":
				var observation hostops.Observation
				_ = json.Unmarshal(body["observation"], &observation)
				observation.RevertDefined, observation.RevertMeasured = true, true
				body["observation"], _ = json.Marshal(observation)
			}
			answer.Bundle, _ = json.Marshal(body)
		}
	}
	return answer, nil
}

type userAuthority struct {
	actor string
	deny  bool
}

func (a userAuthority) Authorize(_ context.Context, d hostops.Descriptor, target, digest string) (hostops.Caller, error) {
	actor := a.actor
	if actor == "" {
		actor = "fran"
	}
	c := hostops.Caller{Actor: actor, Mode: "product-up"}
	if a.deny || d.ID != "host-user.create" || target != "system" || len(digest) != 64 {
		return c, errors.New("denied")
	}
	return c, nil
}
func userActs(t *testing.T, dir string, helper *userHelper, spool *audit.Spool) *hostops.Acts {
	t.Helper()
	catalog, err := hostops.NewCatalog(hostusers.Descriptors())
	if err != nil {
		t.Fatal(err)
	}
	engine, err := hostops.OpenWithCatalog(dir, catalog)
	if err != nil {
		t.Fatal(err)
	}
	return hostops.NewActs(engine, catalog, map[string]hostops.AdoptedTask{"host-user.create": hostusers.CreateTask{Helper: helper}}, hostops.SpoolAudit{Spool: spool})
}
func userSpool(t *testing.T) *audit.Spool {
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

func TestCreateTask_ConfirmedFixedHelperHasAuditAndReopenedRetrieval(t *testing.T) {
	helper := &userHelper{host: &userHost{}}
	dir, spool := t.TempDir(), userSpool(t)
	acts := userActs(t, dir, helper, spool)
	r := hostops.ApplyRequest{Module: "host-user", Verb: "create", Surface: "cli", OperationID: strings.Repeat("a", 32), Inputs: json.RawMessage(`{"account":"alice","group":"staff"}`)}
	plan, err := acts.Plan(t.Context(), r.Module, r.Verb, r.Surface, r.Inputs, userAuthority{})
	if err != nil || !plan.Permissions.Apply || helper.host.effects != 0 {
		t.Fatal("nonmutating plan", plan, err)
	}
	r.Confirmation = plan.Digest
	for _, a := range []userAuthority{{actor: "other-operator"}, {deny: true}} {
		if _, status, err := acts.Apply(t.Context(), r, a); err == nil || status != 403 || helper.calls != 0 || helper.host.effects != 0 {
			t.Fatalf("denied actor reached helper: %d %v", status, err)
		}
	}
	got, status, err := acts.Apply(t.Context(), r, userAuthority{})
	if err != nil || status != 200 || got.State != hostops.StateSucceeded || helper.calls != 1 || helper.host.effects != 1 || helper.host.account.Home != "/home/alice" || helper.host.path != "/usr/sbin/useradd" {
		t.Fatalf("create %+v status=%d err=%v calls=%d native=%d", got, status, err, helper.calls, helper.host.effects)
	}
	acts = userActs(t, dir, helper, spool)
	if again, _, err := acts.Apply(t.Context(), r, userAuthority{}); err != nil || again.State != got.State || helper.calls != 1 || helper.host.effects != 1 {
		t.Fatalf("reopened ID repeated: %+v %v", again, err)
	}
	r.OperationID = strings.Repeat("b", 32)
	if _, _, err := acts.Apply(t.Context(), r, userAuthority{}); err == nil || helper.host.effects != 1 {
		t.Fatal("duplicate account was retried")
	}
	events, err := spool.Pending()
	if err != nil || len(events) != 5 {
		t.Fatalf("audit=%d err=%v", len(events), err)
	}
	t.Log("one confirmed attested Call/one fixed useradd; default private home measured; five durable audits; reopened retrieval only")
}

func TestCreateTask_ChangedNativeGroupAndUntrustedIntentRefuseEffects(t *testing.T) {
	for _, cause := range []string{"group changed", "foreign expected gid", "caller shell", "caller actor", "wire caller actor", "foreign target", "existing home"} {
		t.Run(cause, func(t *testing.T) {
			helper := &userHelper{host: &userHost{}}
			task := hostusers.CreateTask{Helper: helper}
			input := json.RawMessage(`{"account":"alice","group":"staff"}`)
			target, err := task.Prepare(t.Context(), input)
			if err != nil {
				t.Fatal(err)
			}
			cmd := hostops.Command{OperationID: strings.Repeat("a", 32), TaskID: "host-user.create", Module: "host-user", Verb: "create", Target: target}
			switch cause {
			case "group changed":
				helper.fault = cause
			case "foreign expected gid":
				r := &hostusers.CreateRequest{Op: "create", OperationID: cmd.OperationID, Request: hostusers.Request{Account: "alice", Home: "/home/alice", Group: "staff"}, ExpectedGID: "2001"}
				got := hostusers.CreateAnswer(t.Context(), hostusers.Provisioner{Host: helper.host}, r)
				if got.Result != helperschema.ResultRefused || helper.host.effects != 0 {
					t.Fatalf("foreign group reached useradd: %+v", got)
				}
				return
			case "caller shell":
				input = json.RawMessage(`{"account":"alice","group":"staff","shell":"/bin/sh"}`)
			case "caller actor":
				input = json.RawMessage(`{"account":"alice","group":"staff","actor":"root"}`)
			case "wire caller actor":
				var r hostusers.CreateRequest
				document := `{"op":"status","operation_id":"","request":{"account":"alice","home":"/home/alice","group":"staff","actor":"root"},"expected_gid":""}`
				if helperschema.Decode(strings.NewReader(document), &r) == nil || helper.host.effects != 0 {
					t.Fatal("caller authority crossed the fixed helper document")
				}
				return
			case "foreign target":
				cmd.Target = "packages"
			case "existing home":
				helper.host.homeExists = true
			}
			if obs := task.Apply(t.Context(), cmd, input); obs.P1 != "not-performed" || helper.host.effects != 0 {
				t.Fatalf("%s: %+v native=%d", cause, obs, helper.host.effects)
			}
		})
	}
}

func TestCreateTask_UncertainOrPartialAnswerNeverRepeatsUseradd(t *testing.T) {
	for _, cause := range []string{"lost answer", "foreign operation", "foreign account", "foreign gid", "false rollback", "native failed after creation", "unmeasured", "refused"} {
		t.Run(cause, func(t *testing.T) {
			helper := &userHelper{host: &userHost{}, fault: cause}
			want := hostops.StateRunning
			if cause == "native failed after creation" {
				helper.host.fail = true
				want = hostops.StatePartial
			}
			if cause == "unmeasured" {
				helper.host.unmeasured = true
			}
			if cause == "refused" {
				want = hostops.StateFailed
			}
			dir, spool := t.TempDir(), userSpool(t)
			acts := userActs(t, dir, helper, spool)
			r := hostops.ApplyRequest{Module: "host-user", Verb: "create", Surface: "cli", OperationID: strings.Repeat("a", 32), Inputs: json.RawMessage(`{"account":"alice","group":"staff"}`)}
			plan, err := acts.Plan(t.Context(), r.Module, r.Verb, r.Surface, r.Inputs, userAuthority{})
			if err != nil {
				t.Fatal(err)
			}
			r.Confirmation = plan.Digest
			for range 2 {
				got, _, err := acts.Apply(t.Context(), r, userAuthority{})
				if err != nil || got.State != want || helper.calls != 1 || helper.host.effects > 1 {
					t.Fatalf("%s: %+v %v calls=%d native=%d", cause, got, err, helper.calls, helper.host.effects)
				}
				acts = userActs(t, dir, helper, spool)
			}
			if want == hostops.StateRunning {
				next := hostops.ApplyRequest{Module: r.Module, Verb: r.Verb, Surface: r.Surface, OperationID: strings.Repeat("b", 32), Inputs: json.RawMessage(`{"account":"bob","group":"staff"}`)}
				plan, err := acts.Plan(t.Context(), next.Module, next.Verb, next.Surface, next.Inputs, userAuthority{})
				if err != nil {
					t.Fatal(err)
				}
				next.Confirmation = plan.Digest
				_, status, err := acts.Apply(t.Context(), next, userAuthority{})
				var locked *hostops.TargetLocked
				if status != 409 || !errors.As(err, &locked) || locked.OperationID != r.OperationID || helper.calls != 1 {
					t.Fatalf("unknown useradd lost system lock: %d %v calls=%d", status, err, helper.calls)
				}
			}
		})
	}
}
