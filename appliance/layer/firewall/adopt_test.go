// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package firewall_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/olivaresai/olivares/appliance/layer/firewall"
	"github.com/olivaresai/olivares/appliance/layer/firewall/policy"
	"github.com/olivaresai/olivares/appliance/layer/helpers/helperschema"
	"github.com/olivaresai/olivares/appliance/layer/hostops"
	"github.com/olivaresai/olivares/appliance/layer/optionalapps"
)

// ownerHelper is the firewall helper over a real owner: a document passes the helper's own schema
// and reaches the owner through Answer, as the socket's would. fault may replace an answer or
// lose it.
type ownerHelper struct {
	o     *owner
	calls []string
	fault func(op string) (*helperschema.Response, error)
}

func (h *ownerHelper) Call(ctx context.Context, name string, request helperschema.Request) (helperschema.Response, error) {
	r, ok := request.(*firewall.Request)
	if name != firewall.HelperName || !ok || r.Validate() != nil {
		return helperschema.Response{}, errors.New("a request the firewall helper would not take")
	}
	h.calls = append(h.calls, r.Op)
	if h.fault != nil {
		if response, err := h.fault(r.Op); response != nil || err != nil {
			if response == nil {
				return helperschema.Response{}, err
			}
			return *response, err
		}
	}
	return firewall.Answer(ctx, h.o.Owner, r), nil
}

func appRowTask(h firewall.HelperCaller) firewall.AppRowTask {
	return firewall.AppRowTask{Helper: h, Apps: map[string][]policy.AppRow{optionalapps.Slug: optionalapps.FirewallRows()}}
}

func appRowCommand(n byte) hostops.Command {
	return hostops.Command{OperationID: operationID(n), TaskID: "firewall.app-row", Module: firewall.Module, Verb: firewall.VerbAppRow, Target: firewall.Target}
}

const (
	addInput    = `{"app":"nginx-proxy-manager","change":"add"}`
	removeInput = `{"app":"nginx-proxy-manager","change":"remove"}`
)

// The app's firewall act, sent through the console, adds its rows, has the owner read the table back
// and confirms them in the same act, and removes exactly those rows again the same way. Nothing else of
// the policy moves.
func TestAppRowTask_AddsAndRemovesTheAppsRowsAndConfirmsThem(t *testing.T) {
	ctx := context.Background()
	o := newOwner(t)
	install(t, o, managed())
	h := &ownerHelper{o: o}
	task := appRowTask(h)

	target, err := task.Prepare(ctx, json.RawMessage(addInput))
	if err != nil || target != firewall.Target {
		t.Fatalf("the plan of add targets %q (%v), want %q", target, err, firewall.Target)
	}
	if len(o.kernel.ruleset) == 0 || o.kernel.loads != 1 {
		t.Fatalf("a plan loaded a ruleset: %d loads", o.kernel.loads)
	}
	with := managed()
	with.Apps = optionalapps.FirewallRows()
	got := task.Apply(ctx, appRowCommand(7), json.RawMessage(addInput))
	if got.P1 != "performed" || len(got.Postconditions) == 0 {
		t.Fatalf("add: %+v, want performed with its measured facts", got)
	}
	if digest := confirmedDigest(t, o); digest != policy.Digest(with) {
		t.Errorf("the confirmed policy is %s, want the policy with the app's rows %s", digest, policy.Digest(with))
	}
	if w, err := o.Window(operationID(7)); err != nil || w.State != firewall.WindowConfirmed || w.App != optionalapps.Slug {
		t.Errorf("the window is %+v (%v), want the app's, confirmed", w, err)
	}
	if !slices.Equal(h.calls, []string{"status", "status", "apply", "confirm"}) {
		t.Errorf("the helper was asked %v, want a plan's status, then status, apply and confirm", h.calls)
	}
	loaded := forwardChain(string(o.kernel.ruleset))
	for _, want := range []string{"ct original proto-dst 80 accept", "ct original proto-dst 443 accept", `iifname "olv-npm" accept`} {
		if !strings.Contains(loaded, want) {
			t.Errorf("the loaded forward chain lacks %q:\n%s", want, loaded)
		}
	}
	m, _ := o.published(t)
	for _, port := range []string{"80/tcp", "443/tcp"} {
		if r, found := rowOf(m.Rows, port); !found || !slices.Equal(r.Interfaces, []string{"*"}) {
			t.Errorf("%s is not measured on every interface: %+v", port, m.Rows)
		}
	}

	// The same plan is no longer a change, and the removal is the app's own act again.
	if _, err := task.Prepare(ctx, json.RawMessage(addInput)); err == nil {
		t.Error("add of rows that are in force was planned")
	}
	if _, err := task.Prepare(ctx, json.RawMessage(removeInput)); err != nil {
		t.Fatalf("the plan of remove: %v", err)
	}
	if got := task.Apply(ctx, appRowCommand(8), json.RawMessage(removeInput)); got.P1 != "performed" {
		t.Fatalf("remove: %+v, want performed", got)
	}
	if digest := confirmedDigest(t, o); digest != policy.Digest(managed()) {
		t.Errorf("the confirmed policy is %s after remove, want the policy without the app %s", digest, policy.Digest(managed()))
	}
	if after := forwardChain(string(o.kernel.ruleset)); strings.Contains(after, "dnat") || strings.Contains(after, "olv-npm") {
		t.Errorf("the forward chain still forwards for the app after remove:\n%s", after)
	}
	if _, err := task.Prepare(ctx, json.RawMessage(removeInput)); err == nil {
		t.Error("remove of rows that are not in force was planned")
	}
}

// A plan refuses what the act cannot do, before anything is asked of the owner but its status: an
// application that has no rows here, a change that is neither add nor remove, a window outside the
// owner's bounds, a member the act does not have, and a window another change left open.
func TestAppRowTask_PlanRefusesWhatTheActCannotDo(t *testing.T) {
	ctx := context.Background()
	o := newOwner(t)
	install(t, o, managed())
	h := &ownerHelper{o: o}
	task := appRowTask(h)
	for name, input := range map[string]string{
		"another application":     `{"app":"proxy","change":"add"}`,
		"a path as the app":       `{"app":"../nginx-proxy-manager","change":"add"}`,
		"a change that is not":    `{"app":"nginx-proxy-manager","change":"toggle"}`,
		"no change":               `{"app":"nginx-proxy-manager"}`,
		"a short window":          `{"app":"nginx-proxy-manager","change":"add","revert_after_s":59}`,
		"a long window":           `{"app":"nginx-proxy-manager","change":"add","revert_after_s":601}`,
		"a member of its own":     `{"app":"nginx-proxy-manager","change":"add","interfaces":["eth0"]}`,
		"a null":                  `{"app":"nginx-proxy-manager","change":null}`,
		"remove with nothing set": removeInput,
	} {
		if _, err := task.Prepare(ctx, json.RawMessage(input)); err == nil || err.Error() != firewall.CodeInputRefused {
			t.Errorf("%s: %s was planned or refused as %v, want %s", name, input, err, firewall.CodeInputRefused)
		}
	}
	for _, window := range []string{"60", "600"} {
		if _, err := task.Prepare(ctx, json.RawMessage(`{"app":"nginx-proxy-manager","change":"add","revert_after_s":`+window+`}`)); err != nil {
			t.Errorf("a window of %s seconds, at the owner's bound, was refused: %v", window, err)
		}
	}
	// A window another change left open is the owner's to close first. The add is a change on its own
	// (the confirmed policy still has no rows), so only the open window can refuse it.
	with := managed()
	with.Apps = optionalapps.FirewallRows()
	if _, err := o.Apply(ctx, firewall.ApplyRequest{OperationID: operationID(3), App: optionalapps.Slug, Candidate: with}); err != nil {
		t.Fatal(err)
	}
	if _, err := task.Prepare(ctx, json.RawMessage(addInput)); err == nil || err.Error() != firewall.CodeTargetLocked {
		t.Errorf("a plan while a window is open: %v, want %s", err, firewall.CodeTargetLocked)
	}
	// Without a confirmed policy there is nothing to derive a candidate from.
	if _, err := appRowTask(&ownerHelper{o: newOwner(t)}).Prepare(ctx, json.RawMessage(addInput)); err == nil || err.Error() != firewall.CodeTargetLocked {
		t.Errorf("a plan without a confirmed policy: %v, want %s", err, firewall.CodeTargetLocked)
	}
	// A port another application already holds makes the candidate outside the schema: nothing is sent.
	held := newOwner(t)
	holder := managed()
	holder.Apps = []policy.AppRow{{App: "proxy", Port: "80/tcp", Interfaces: []string{"*"}}}
	install(t, held, holder)
	heldHelper := &ownerHelper{o: held}
	if got := appRowTask(heldHelper).Apply(ctx, appRowCommand(6), json.RawMessage(addInput)); got.P1 != "not-performed" || slices.Contains(heldHelper.calls, "apply") {
		t.Errorf("add over another application's port: %+v after %v, want not-performed with no apply", got, heldHelper.calls)
	}
	// Without a helper nothing is asked and nothing is offered.
	if _, err := (firewall.AppRowTask{Apps: task.Apps}).Prepare(ctx, json.RawMessage(addInput)); err == nil {
		t.Error("a plan was offered without the firewall helper")
	}
}

// What the helper answers decides the observation, and a request that was sent and not answered is
// unknown, never performed.
func TestAppRowTask_ObservesWhatTheOwnerMeasured(t *testing.T) {
	ctx := context.Background()
	input := json.RawMessage(addInput)
	lost := errors.New("answer lost")

	// Not the act of this task, or not a command of this module: nothing is sent.
	o := newOwner(t)
	install(t, o, managed())
	h := &ownerHelper{o: o}
	task := appRowTask(h)
	for name, mutate := range map[string]func(*hostops.Command){
		"another task":   func(c *hostops.Command) { c.TaskID = "firewall.apply" },
		"another module": func(c *hostops.Command) { c.Module = "nginx-proxy-manager" },
		"another verb":   func(c *hostops.Command) { c.Verb = "apply" },
		"another target": func(c *hostops.Command) { c.Target = "app:nginx-proxy-manager" },
	} {
		cmd := appRowCommand(4)
		mutate(&cmd)
		if got := task.Apply(ctx, cmd, input); got.P1 != "not-performed" || len(h.calls) != 0 {
			t.Errorf("%s: %+v after %v, want not-performed with nothing asked", name, got, h.calls)
		}
	}

	for _, c := range []struct {
		name  string
		fault func(op string) (*helperschema.Response, error)
		kern  func(*owner)
		want  string
		calls []string
	}{
		{"the apply is refused by the owner", func(op string) (*helperschema.Response, error) {
			if op == "apply" {
				return &helperschema.Response{Result: helperschema.ResultRefused, Code: "target_locked"}, nil
			}
			return nil, nil
		}, nil, "not-performed", []string{"status", "apply"}},
		{"the apply is lost", func(op string) (*helperschema.Response, error) {
			if op == "apply" {
				return nil, lost
			}
			return nil, nil
		}, nil, "unknown", []string{"status", "apply"}},
		{"the table does not load", nil, func(o *owner) { o.kernel.failLoad = true }, "failed", []string{"status", "apply"}},
		{"the confirmation is lost", func(op string) (*helperschema.Response, error) {
			if op == "confirm" {
				return nil, lost
			}
			return nil, nil
		}, nil, "partial", []string{"status", "apply", "confirm", "status"}},
		{"the window expired before the confirmation", func(op string) (*helperschema.Response, error) {
			if op == "confirm" {
				return &helperschema.Response{Result: helperschema.ResultRefused, Code: firewall.CodeWindowExpired}, nil
			}
			return nil, nil
		}, nil, "partial", []string{"status", "apply", "confirm", "status"}},
		{"the status is lost", func(op string) (*helperschema.Response, error) { return nil, lost }, nil, "not-performed", []string{"status"}},
	} {
		o := newOwner(t)
		install(t, o, managed())
		h := &ownerHelper{o: o, fault: c.fault}
		if c.kern != nil {
			c.kern(o)
		}
		got := appRowTask(h).Apply(ctx, appRowCommand(5), input)
		if got.P1 != c.want || !slices.Equal(h.calls, c.calls) {
			t.Errorf("%s: %+v after %v, want %s after %v", c.name, got, h.calls, c.want, c.calls)
		}
		if got.P1 != "performed" && confirmedDigest(t, o) != policy.Digest(managed()) {
			t.Errorf("%s: the confirmed policy moved", c.name)
		}
	}

	// An answer that is not the window of this operation is not believed.
	o = newOwner(t)
	install(t, o, managed())
	h = &ownerHelper{o: o, fault: func(op string) (*helperschema.Response, error) {
		if op != "apply" {
			return nil, nil
		}
		w := firewall.Window{SchemaVersion: firewall.WindowSchema, OperationID: operationID(9), State: firewall.WindowConfirmed}
		data, _ := json.Marshal(w)
		return &helperschema.Response{Result: helperschema.ResultPerformed, Bundle: data}, nil
	}}
	if got := appRowTask(h).Apply(ctx, appRowCommand(5), input); got.P1 != "unknown" {
		t.Errorf("another operation's window: %+v, want unknown", got)
	}
}

// The owner confirmed the load and the answer was lost: the window is read again and the load, which
// stays, is performed. It is not reported as one that will revert.
func TestAppRowTask_AConfirmedLoadWhoseAnswerWasLostIsPerformed(t *testing.T) {
	ctx := context.Background()
	o := newOwner(t)
	install(t, o, managed())
	h := &ownerHelper{o: o}
	h.fault = func(op string) (*helperschema.Response, error) {
		if op != firewall.OpConfirm {
			return nil, nil
		}
		firewall.Answer(ctx, o.Owner, &firewall.Request{Op: firewall.OpConfirm, OperationID: operationID(5)})
		return nil, errors.New("answer lost")
	}
	got := appRowTask(h).Apply(ctx, appRowCommand(5), json.RawMessage(addInput))
	if got.P1 != "performed" || !slices.Equal(h.calls, []string{"status", "apply", "confirm", "status"}) {
		t.Errorf("a confirmation made and not answered: %+v after %v, want performed after a status read", got, h.calls)
	}
	with := managed()
	with.Apps = optionalapps.FirewallRows()
	if digest := confirmedDigest(t, o); digest != policy.Digest(with) {
		t.Errorf("the confirmed policy is %s, want the policy with the app's rows", digest)
	}
}

// forging passes every request to the owner and changes one member of the window that answers apply.
type forging struct {
	*ownerHelper
	forge func(*firewall.Window)
}

func (f forging) Call(ctx context.Context, name string, request helperschema.Request) (helperschema.Response, error) {
	response, err := f.ownerHelper.Call(ctx, name, request)
	if r, ok := request.(*firewall.Request); ok && r.Op == firewall.OpApply && err == nil {
		var w firewall.Window
		if json.Unmarshal(response.Bundle, &w) == nil {
			f.forge(&w)
			response.Bundle, _ = json.Marshal(w)
		}
	}
	return response, err
}

// A window is believed only when it is this operation's, for this application and this candidate, in
// the schema this task reads. Each variant changes the owner's own answer in the one member it names;
// the control, which changes none, is performed.
func TestAppRowTask_AWindowIsBelievedOnlyWhenEveryMemberIsThisOperations(t *testing.T) {
	ctx := context.Background()
	for name, c := range map[string]struct {
		forge func(*firewall.Window)
		want  string
	}{
		"control, nothing changed": {func(*firewall.Window) {}, "performed"},
		"another operation":        {func(w *firewall.Window) { w.OperationID = operationID(9) }, "unknown"},
		"another application":      {func(w *firewall.Window) { w.App = "proxy" }, "unknown"},
		"another candidate":        {func(w *firewall.Window) { w.CandidateDigest = "sha256:" + strings.Repeat("0", 64) }, "unknown"},
		"another schema":           {func(w *firewall.Window) { w.SchemaVersion = "other" }, "unknown"},
	} {
		o := newOwner(t)
		install(t, o, managed())
		task := appRowTask(forging{&ownerHelper{o: o}, c.forge})
		if got := task.Apply(ctx, appRowCommand(5), json.RawMessage(addInput)); got.P1 != c.want {
			t.Errorf("%s: %+v, want %s", name, got, c.want)
		}
	}
}
