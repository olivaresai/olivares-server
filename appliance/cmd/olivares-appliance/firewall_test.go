// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/olivaresai/olivares/appliance/layer/firewall"
	"github.com/olivaresai/olivares/appliance/layer/hostops"
	"github.com/olivaresai/olivares/appliance/layer/hostops/console"
	"github.com/olivaresai/olivares/appliance/layer/portal/localclient"
	"github.com/olivaresai/olivares/appliance/layer/portal/localsession"
)

// fwSession is the local API as the CLI sees it, serving the Firewall tasks; it records each
// plan asked of it.
type fwSession struct {
	plans  []string
	closed bool
}

func (s *fwSession) Descriptors(string) ([]hostops.Descriptor, error) {
	return firewall.Descriptors(), nil
}
func (s *fwSession) Operation(string, string) (hostops.View, int, error) {
	return hostops.View{}, 0, &localclient.Refused{Code: "input_refused"}
}
func (s *fwSession) Description(module, verb, surface string) (hostops.Descriptor, error) {
	catalog, _ := hostops.NewCatalog(firewall.Descriptors())
	return catalog.Describe(module, verb, surface)
}
func (s *fwSession) Plan(module, verb, surface string, inputs json.RawMessage) (hostops.Plan, error) {
	s.plans = append(s.plans, module+" "+verb+" "+surface+" "+string(inputs))
	d, err := s.Description(module, verb, surface)
	if err != nil || d.ValidateInput(inputs) != nil {
		return hostops.Plan{}, &localclient.Refused{Code: "input_refused"}
	}
	return hostops.Plan{Descriptor: d, Inputs: inputs, Permissions: hostops.Permissions{Read: true, Plan: true, Code: "act_not_adopted"}}, nil
}
func (s *fwSession) Close() error { s.closed = true; return nil }

// firewallReads is the console's firewall read of a managed host, in two pages: three measured
// ports, then an open window.
func firewallReads() *reads {
	digest := "sha256:" + strings.Repeat("1f", 32)
	head := &localsession.FirewallHead{PolicyDigest: digest, BootID: "8d8a1f0c-54c0-4b3e-9d6a-2a1f3b4c5d6e", MeasuredAt: "2026-09-27T18:59:00Z",
		InputPolicy: "drop", ConfirmedDigest: digest}
	page := func(offset, next int, rows ...localsession.FirewallRow) localsession.ModuleAnswer {
		return localsession.ModuleAnswer{Query: localsession.QueryFirewallStatus, Generation: 4, ReadAt: "2026-09-27T19:00:00Z",
			Offset: offset, Next: next, Total: 4, Firewall: head, FirewallRows: rows}
	}
	return &reads{answers: map[string]localsession.ModuleAnswer{
		readKey(localsession.QueryFirewallStatus, "", 0): page(0, 3,
			localsession.FirewallRow{Kind: localsession.FirewallPort, Port: "22/tcp", Interfaces: []string{"*"}},
			localsession.FirewallRow{Kind: localsession.FirewallPort, Port: "9443/tcp", Interfaces: []string{"eth0"}},
			localsession.FirewallRow{Kind: localsession.FirewallPort, Port: "546/udp", Interfaces: []string{"eth0", "eth1"}}),
		readKey(localsession.QueryFirewallStatus, "", 3): page(3, 0,
			localsession.FirewallRow{Kind: localsession.FirewallWindow, OperationID: strings.Repeat("cd", 16), State: "pending",
				CandidateDigest: "sha256:" + strings.Repeat("3d", 32)}),
	}, errs: map[string]error{}}
}

func TestFirewallCLI_PlansActsThroughTheLocalAPIAndRefusesThemBeforeDialing(t *testing.T) {
	run := func(s *fwSession, args ...string) (int, bool, string, string, int) {
		dials := 0
		var out, diagnostic bytes.Buffer
		code, handled := runFirewall(context.Background(), args, &out, &diagnostic, func() (console.Session, error) { dials++; return s, nil },
			func() (moduleSession, error) { dials++; return firewallReads(), nil })
		return code, handled, out.String(), diagnostic.String(), dials
	}
	id := strings.Repeat("ab", 16)

	// Plans go through the local API with the closed inputs.
	for _, c := range []struct {
		args  []string
		plan  string
		shows []string
	}{
		{[]string{"firewall", "apply", "--plan"}, `firewall apply cli {}`,
			[]string{"Apply the firewall policy", "reverts unless confirmed", "Command: olivares-appliance firewall apply", "Changes: disabled (act_not_adopted)"}},
		{[]string{"firewall", "plan", "--revert-after", "300"}, `firewall apply cli {"revert_after_s":300}`,
			[]string{"Command: olivares-appliance firewall apply --revert-after 300"}},
		{[]string{"firewall", "confirm", id, "--plan"}, `firewall confirm cli {"operation":"` + id + `"}`,
			[]string{"Confirm the firewall change", "Command: olivares-appliance firewall confirm " + id}},
		{[]string{"firewall", "revert", id, "--plan"}, `firewall revert cli {"operation":"` + id + `"}`,
			[]string{"Revert the firewall change", "Command: olivares-appliance firewall revert " + id}},
		{[]string{"firewall", "app-row", "proxy", "add", "--plan"}, `firewall app-row cli {"app":"proxy","change":"add"}`,
			[]string{"Command: olivares-appliance firewall app-row proxy add"}},
	} {
		s := &fwSession{}
		code, handled, out, diagnostic, dials := run(s, c.args...)
		if code != 0 || !handled || dials != 1 || !s.closed || len(s.plans) != 1 || s.plans[0] != c.plan || diagnostic != "" {
			t.Errorf("%v: exit %d handled %v dials %d plans %v stderr %q", c.args, code, handled, dials, s.plans, diagnostic)
		}
		for _, want := range c.shows {
			if !strings.Contains(out, want) {
				t.Errorf("%v: the plan does not show %q:\n%s", c.args, want, out)
			}
		}
	}

	// Refused before dialing: acts, which this console carries no authorization for, and every
	// command line outside the closed grammar.
	for _, c := range []struct {
		args []string
		code string
	}{
		{[]string{"firewall", "apply"}, "act_not_adopted"},
		{[]string{"firewall", "confirm", id}, "act_not_adopted"},
		{[]string{"firewall", "revert", id}, "act_not_adopted"},
		{[]string{"firewall", "app-row", "proxy", "remove"}, "input_refused"},
		{[]string{"firewall"}, "input_refused"},
		{[]string{"firewall", "flush"}, "input_refused"},
		{[]string{"firewall", "show", "--plan"}, "input_refused"},
		{[]string{"firewall", "show", "eth0"}, "input_refused"},
		{[]string{"firewall", "apply", "--revert-after", "30", "--plan"}, "input_refused"},
		{[]string{"firewall", "apply", "--revert-after", "0600", "--plan"}, "input_refused"},
		{[]string{"firewall", "apply", "--plan", "--plan"}, "input_refused"},
		{[]string{"firewall", "apply", "--plan", "--output", "json"}, "input_refused"},
		{[]string{"firewall", "confirm", strings.ToUpper(id), "--plan"}, "input_refused"},
		{[]string{"firewall", "revert", "--plan"}, "input_refused"},
		{[]string{"firewall", "app-row", "../proxy", "add", "--plan"}, "input_refused"},
		{[]string{"firewall", "app-row", "proxy", "open", "--plan"}, "input_refused"},
		{[]string{"firewall", "apply", "/etc/nftables.conf", "--plan"}, "input_refused"},
	} {
		code, handled, out, diagnostic, dials := run(&fwSession{}, c.args...)
		first := ""
		if words := strings.Fields(diagnostic); len(words) > 0 {
			first = words[0]
		}
		if code != 1 || !handled || dials != 0 || out != "" || first != c.code {
			t.Errorf("%v: exit %d handled %v dials %d stdout %q stderr %q, want %s before dialing", c.args, code, handled, dials, out, diagnostic, c.code)
		}
	}
	// Other command lines are not the firewall verbs'.
	for _, args := range [][]string{{"service", "list"}, {"op", "get", id}, {}, {"tui"}} {
		if _, handled, _, _, dials := run(&fwSession{}, args...); handled || dials != 0 {
			t.Errorf("%v was taken by the firewall verbs", args)
		}
	}
}

func TestFirewallCLI_ShowReadsThroughTheLocalAPI(t *testing.T) {
	show := func(r *reads) (int, string, string, int, int) {
		plans, dials := 0, 0
		var out, diagnostic bytes.Buffer
		code, handled := runFirewall(context.Background(), []string{"firewall", "show"}, &out, &diagnostic,
			func() (console.Session, error) { plans++; return &fwSession{}, nil },
			func() (moduleSession, error) { dials++; return r, nil })
		if !handled {
			t.Fatal("firewall show was not taken by the firewall verbs")
		}
		return code, out.String(), diagnostic.String(), plans, dials
	}
	id := strings.Repeat("cd", 16)

	// show reads firewall.status through the local API, every page of one read, and prints it.
	r := firewallReads()
	code, out, diagnostic, plans, dials := show(r)
	if code != 0 || diagnostic != "" || plans != 0 || dials != 1 || !r.closed ||
		strings.Join(r.asked, ";") != "firewall.status  0 cli;firewall.status  3 cli" {
		t.Fatalf("show: exit %d stderr %q plans %d reads %d asked %v", code, diagnostic, plans, dials, r.asked)
	}
	for _, want := range []string{"sha256:" + strings.Repeat("1f", 32), "input drop", "22/tcp on every interface", "9443/tcp on eth0",
		"546/udp on eth0, eth1", "Always kept", "Window " + id + ": pending", "reverts unless confirmed", "2026-09-27T19:00:00Z"} {
		if !strings.Contains(out, want) {
			t.Errorf("show does not print %q:\n%s", want, out)
		}
	}

	// An unmeasured firewall is read and said so: why, and that the console stays on loopback.
	r = firewallReads()
	r.answers = map[string]localsession.ModuleAnswer{readKey(localsession.QueryFirewallStatus, "", 0): {Query: localsession.QueryFirewallStatus,
		Generation: 5, ReadAt: "2026-09-27T19:00:30Z", Firewall: &localsession.FirewallHead{Unmeasured: "no measurement is published"}}}
	code, out, diagnostic, _, _ = show(r)
	if code != 0 || diagnostic != "" || !strings.Contains(out, "unmeasured (no measurement is published)") || !strings.Contains(out, "loopback") ||
		!strings.Contains(out, "No policy is confirmed") || strings.Contains(out, "every interface") {
		t.Errorf("show of an unmeasured firewall: exit %d stderr %q\n%s", code, diagnostic, out)
	}

	// Exits per the console contract: 1 for a refusal with its closed code, 2 for a read that could
	// not run, with nothing on stdout.
	for _, c := range []struct {
		err  error
		exit int
		code string
	}{
		{&localclient.Refused{Code: "mode_refused"}, 1, "mode_refused"},
		{&localclient.Refused{Code: "consumer_unavailable"}, 2, "consumer_unavailable"},
		{&localclient.Failure{Code: "response_unverified", Sent: true}, 2, "response_unverified"},
	} {
		r := firewallReads()
		r.errs[readKey(localsession.QueryFirewallStatus, "", 0)] = c.err
		if code, out, diagnostic, _, _ := show(r); code != c.exit || out != "" || firstWord(diagnostic) != c.code || !r.closed {
			t.Errorf("show with %v: exit %d stdout %q stderr %q, want %d %s", c.err, code, out, diagnostic, c.exit, c.code)
		}
	}
	r = firewallReads()
	moved := r.answers[readKey(localsession.QueryFirewallStatus, "", 3)]
	moved.Generation = 5
	r.answers[readKey(localsession.QueryFirewallStatus, "", 3)] = moved
	if code, out, diagnostic, _, _ := show(r); code != 2 || out != "" || firstWord(diagnostic) != "consumer_unavailable" || len(r.asked) != 4 {
		t.Errorf("a read that kept changing: exit %d stdout %q stderr %q asked %v", code, out, diagnostic, r.asked)
	}
	var out2, diagnostic2 bytes.Buffer
	code, _ = runFirewall(context.Background(), []string{"firewall", "show"}, &out2, &diagnostic2, nil, func() (moduleSession, error) {
		return nil, &localclient.Failure{Code: "local_unavailable", Reason: "socket_unavailable"}
	})
	if code != 2 || firstWord(diagnostic2.String()) != "local_unavailable" || out2.Len() != 0 {
		t.Errorf("no session: exit %d stderr %q", code, diagnostic2.String())
	}

	// The other firewall verbs keep their refusals, and read nothing.
	for _, args := range [][]string{{"firewall", "apply"}, {"firewall", "confirm", id}, {"firewall", "revert", id}} {
		plans, dials := 0, 0
		var out, diagnostic bytes.Buffer
		code, handled := runFirewall(context.Background(), args, &out, &diagnostic, func() (console.Session, error) { plans++; return &fwSession{}, nil },
			func() (moduleSession, error) { dials++; return firewallReads(), nil })
		if code != 1 || !handled || plans != 0 || dials != 0 || out.Len() != 0 || firstWord(diagnostic.String()) != firewall.CodeActNotAdopted {
			t.Errorf("%v: exit %d handled %v plans %d reads %d stderr %q", args, code, handled, plans, dials, diagnostic.String())
		}
	}
}

// fwApplySession is the local API of a console that carries the act authorization: it keeps the
// request it was asked to apply.
type fwApplySession struct {
	fwSession
	applied []hostops.ApplyRequest
}

func (s *fwApplySession) Plan(module, verb, surface string, inputs json.RawMessage) (hostops.Plan, error) {
	plan, err := s.fwSession.Plan(module, verb, surface, inputs)
	plan.Digest, plan.Permissions = strings.Repeat("d", 64), hostops.Permissions{Read: true, Plan: true, Apply: true}
	return plan, err
}
func (s *fwApplySession) Apply(r hostops.ApplyRequest) (hostops.Record, int, error) {
	s.applied = append(s.applied, r)
	return hostops.Record{OperationID: r.OperationID, State: hostops.StateSucceeded, Target: firewall.Target}, 200, nil
}

// The app's own act is adopted: its plan shows the digest that confirms it, and the confirmed command line
// submits it once, with the closed inputs, through the console's shared grammar. Everything else of the
// module keeps its refusal, and a slug or change outside the grammar is refused before dialing.
func TestFirewallCLI_AppRowIsPlannedAndSubmittedWithItsDigest(t *testing.T) {
	digest := strings.Repeat("d", 64)
	s := &fwApplySession{}
	var out, diagnostic bytes.Buffer
	dial := func() (console.Session, error) { return s, nil }
	read := func() (moduleSession, error) { return firewallReads(), nil }
	if code, handled := runFirewall(context.Background(), []string{"firewall", "app-row", "nginx-proxy-manager", "add", "--revert-after", "120", "--plan"}, &out, &diagnostic, dial, read); code != 0 || !handled || len(s.applied) != 0 {
		t.Fatalf("plan: exit %d handled %v applied %v stderr %q", code, handled, s.applied, diagnostic.String())
	}
	for _, want := range []string{"Plan: " + digest, "Command: olivares-appliance firewall app-row nginx-proxy-manager add --revert-after 120", "Changes: available after confirmation"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the plan does not show %q:\n%s", want, out.String())
		}
	}
	out.Reset()
	args := []string{"firewall", "app-row", "nginx-proxy-manager", "add", "--revert-after", "120", "--confirm", digest, "--output", "json"}
	if code, handled := runFirewall(context.Background(), args, &out, &diagnostic, dial, read); code != 0 || !handled || len(s.applied) != 1 {
		t.Fatalf("apply: exit %d handled %v applied %v stderr %q", code, handled, s.applied, diagnostic.String())
	}
	got := s.applied[0]
	if got.Module != "firewall" || got.Verb != "app-row" || got.Confirmation != digest || got.Surface != "cli" || string(got.Inputs) != `{"app":"nginx-proxy-manager","change":"add","revert_after_s":120}` {
		t.Errorf("the submitted request is %+v", got)
	}
	for _, args := range [][]string{
		{"firewall", "app-row", "../proxy", "add", "--confirm", digest},
		{"firewall", "app-row", "proxy", "open", "--confirm", digest},
		{"firewall", "apply", "--confirm", digest},
	} {
		dials := 0
		var out, diagnostic bytes.Buffer
		code, _ := runFirewall(context.Background(), args, &out, &diagnostic, func() (console.Session, error) { dials++; return s, nil }, read)
		if code != 1 || dials != 0 || len(s.applied) != 1 {
			t.Errorf("%v: exit %d dials %d applied %d, want a refusal before dialing", args, code, dials, len(s.applied))
		}
	}
}
