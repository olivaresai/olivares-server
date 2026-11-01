// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/olivaresai/olivares/appliance/layer/hostops"
	"github.com/olivaresai/olivares/appliance/layer/hostops/console"
	"github.com/olivaresai/olivares/appliance/layer/portal/localclient"
	"github.com/olivaresai/olivares/appliance/layer/portal/localsession"
	"github.com/olivaresai/olivares/appliance/layer/services"
)

const updateService = "olivares-appliance-update.service"

// An act with neither --plan nor --confirm shows its plan and the command that confirms it: it sends
// nothing, and what it names is what the Services and Updates pages print as the act's command.
func TestServiceCLI_ABareActShowsItsPlanAndTheCommandThatConfirmsIt(t *testing.T) {
	for _, c := range []struct{ verb, unit, command string }{
		{services.OpStart, updateService, "olivares-appliance service start " + updateService},
		{services.OpStop, "dnf-automatic-install.timer", "olivares-appliance service stop dnf-automatic-install.timer"},
		{services.OpLogs, "dnf-automatic-install.service", "olivares-appliance service logs dnf-automatic-install.service --lines 20"},
	} {
		s := &restartingSession{}
		var out, diagnostic bytes.Buffer
		args := strings.Fields(c.command)[1:]
		code, handled := runService(t.Context(), args, &out, &diagnostic, func() (console.Session, error) { return s, nil }, nil)
		confirm := "Confirm: " + c.command + " --confirm " + strings.Repeat("a", 64)
		if code != 0 || !handled || s.applied != 0 || len(s.plans) != 1 || !strings.Contains(out.String(), confirm) || diagnostic.Len() != 0 {
			t.Errorf("%s: exit %d handled %v plans %v applied %d\nstdout %q\nstderr %q\nwant %q", c.command, code, handled, s.plans, s.applied, out.String(), diagnostic.String(), confirm)
		}
	}
}

// Every verb of the services module is an act the CLI confirms through the console: the module, the
// verb and the unit reach the apply as the plan's inputs, and the operation id the operator gave is kept.
func TestServiceCLI_EveryActWithItsConfirmationReachesTheApply(t *testing.T) {
	id := strings.Repeat("1", 32)
	for _, c := range []struct {
		args  []string
		input string
	}{
		{[]string{"service", "start", updateService}, `{"unit":"` + updateService + `"}`},
		{[]string{"service", "stop", "dnf-automatic-install.timer"}, `{"unit":"dnf-automatic-install.timer"}`},
		{[]string{"service", "restart", "olivares.service"}, `{"unit":"olivares.service"}`},
		{[]string{"service", "reload", "olivares.service"}, `{"unit":"olivares.service"}`},
		{[]string{"service", "enable", "dnf-automatic-install.timer"}, `{"unit":"dnf-automatic-install.timer"}`},
		{[]string{"service", "disable", "dnf-automatic-install.timer"}, `{"unit":"dnf-automatic-install.timer"}`},
	} {
		s := &restartingSession{}
		var out, diagnostic bytes.Buffer
		args := append(append([]string{}, c.args...), "--confirm", strings.Repeat("a", 64), "--operation-id", id)
		code, handled := runService(t.Context(), args, &out, &diagnostic, func() (console.Session, error) { return s, nil }, nil)
		if code != 0 || !handled || s.applied != 1 || s.request.Module != services.Module || s.request.Verb != c.args[1] ||
			string(s.request.Inputs) != c.input || s.request.OperationID != id || s.request.Confirmation != strings.Repeat("a", 64) {
			t.Errorf("%v: exit %d handled %v applied %d request %+v stderr %q", c.args, code, handled, s.applied, s.request, diagnostic.String())
		}
	}
}

// A confirmed act the unit's class does not admit, a confirmation that is not a plan digest, a line
// count on any act but logs and a caller's own flag are refused before the session is dialed.
func TestServiceCLI_ConfirmedActsRefuseWhatTheClassTableAndTheGrammarRefuseBeforeDialing(t *testing.T) {
	digest := strings.Repeat("a", 64)
	for _, c := range []struct {
		args []string
		code string
	}{
		{[]string{"service", "stop", "dbus.service", "--confirm", digest}, "unit_protected"},
		{[]string{"service", "logs", "/etc/passwd", "--confirm", digest}, "input_refused"},
		{[]string{"service", "start", updateService, "--confirm", "not-a-digest"}, "input_refused"},
		{[]string{"service", "start", updateService, "--confirm", digest, "--lines", "5"}, "input_refused"},
		{[]string{"service", "logs", updateService, "--confirm", digest, "--lines", "0"}, "input_refused"},
		{[]string{"service", "logs", updateService, "--confirm", digest, "--lines", "501"}, "input_refused"},
		{[]string{"service", "logs", updateService, "--confirm", digest, "--lines", "05"}, "input_refused"},
		{[]string{"service", "stop", "dnf-automatic-install.timer", "--confirm", digest, "--actor", "fran"}, "input_refused"},
		{[]string{"service", "stop", "dnf-automatic-install.timer", "--confirm", digest, "--plan"}, "input_refused"},
	} {
		var out, diagnostic bytes.Buffer
		dials := 0
		code, handled := runService(t.Context(), c.args, &out, &diagnostic, func() (console.Session, error) { dials++; return &restartingSession{}, nil },
			func() (moduleSession, error) { dials++; return hostReads(), nil })
		if code != 1 || !handled || dials != 0 || out.Len() != 0 || firstWord(diagnostic.String()) != c.code {
			t.Errorf("%v: exit %d handled %v dials %d stdout %q stderr %q, want %s before dialing", c.args, code, handled, dials, out.String(), diagnostic.String(), c.code)
		}
	}
}

// logsReads is the console's hold as the CLI collects from it: the entries of the act of id, in two pages.
func logsReads(id string) *reads {
	first := []services.Entry{{Timestamp: "2026-10-23T05:00:00Z", Priority: "6", Message: "Started the run"}, {Timestamp: "2026-10-23T05:00:01Z", Priority: "4", Message: "token=hunter2 \x1b[31mred"}}
	second := []services.Entry{{Timestamp: "2026-10-23T05:00:02Z", Priority: "3", Message: "Finished"}}
	return &reads{answers: map[string]localsession.ModuleAnswer{
		readKey(localsession.QueryServicesLogs, id, 0): {Query: localsession.QueryServicesLogs, LogUnit: "dnf-automatic-install.service", Total: 3, Next: 2, Entries: first},
		readKey(localsession.QueryServicesLogs, id, 2): {Query: localsession.QueryServicesLogs, LogUnit: "dnf-automatic-install.service", Offset: 2, Total: 3, Entries: second},
	}, errs: map[string]error{}}
}

// A confirmed logs act is the console's act, and the entries it read are collected by its operation id
// from the console's hold and printed, control characters replaced, newest last. With --output json the
// receipt is the first line and the entries are the second.
func TestServiceCLI_ALogsActPrintsTheEntriesItReadByItsOperationID(t *testing.T) {
	id := strings.Repeat("2", 32)
	args := []string{"service", "logs", "dnf-automatic-install.service", "--lines", "3", "--confirm", strings.Repeat("a", 64), "--operation-id", id}
	run := func(extra ...string) (int, *restartingSession, *reads, string, string) {
		s, r := &restartingSession{}, logsReads(id)
		var out, diagnostic bytes.Buffer
		code, _ := runService(t.Context(), append(append([]string{}, args...), extra...), &out, &diagnostic,
			func() (console.Session, error) { return s, nil }, func() (moduleSession, error) { return r, nil })
		return code, s, r, out.String(), diagnostic.String()
	}
	code, s, r, out, diagnostic := run()
	if code != 0 || s.applied != 1 || s.request.Verb != services.OpLogs || string(s.request.Inputs) != `{"lines":3,"unit":"dnf-automatic-install.service"}` {
		t.Fatalf("the act: exit %d applied %d request %+v stderr %q", code, s.applied, s.request, diagnostic)
	}
	for _, want := range []string{id, "Entries of dnf-automatic-install.service, newest last:", "2026-10-23T05:00:00Z 6 Started the run", "token=hunter2 ?[31mred", "2026-10-23T05:00:02Z 3 Finished"} {
		if !strings.Contains(out, want) {
			t.Errorf("the output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b") || !r.closed || len(r.asked) != 2 {
		t.Errorf("a control character reached the terminal, or the hold was read %v with the session closed %v", r.asked, r.closed)
	}
	code, _, _, out, _ = run("--output", "json")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	var got collected
	if code != 0 || len(lines) != 2 || json.Unmarshal([]byte(lines[1]), &got) != nil || got.Unit != "dnf-automatic-install.service" || len(got.Entries) != 3 || got.Entries[2].Message != "Finished" {
		t.Errorf("json output: exit %d\n%s", code, out)
	}
}

// failingSession is a session whose apply fails with err, after a plan that offers it.
type failingSession struct {
	restartingSession
	err error
}

func (s *failingSession) Apply(hostops.ApplyRequest) (hostops.Record, int, error) {
	return hostops.Record{}, 0, s.err
}

// The entries come only from an act that happened. An act the console refused or lost is that failure
// and reads nothing; an act that ran but whose entries are gone says so and exits 2.
func TestServiceCLI_ALogsActReadsNothingUnlessItRanAndSaysWhenItsEntriesAreGone(t *testing.T) {
	id := strings.Repeat("3", 32)
	args := []string{"service", "logs", "dnf-automatic-install.service", "--confirm", strings.Repeat("a", 64), "--operation-id", id}
	var out, diagnostic bytes.Buffer
	refused := &failingSession{err: &localclient.Refused{Code: "plan_changed"}}
	r := logsReads(id)
	if code, _ := runService(t.Context(), args, &out, &diagnostic, func() (console.Session, error) { return refused, nil }, func() (moduleSession, error) { return r, nil }); code != 1 || len(r.asked) != 0 || !strings.Contains(diagnostic.String(), "plan_changed") {
		t.Errorf("a refused act: exit %d reads %v stderr %q", code, r.asked, diagnostic.String())
	}
	out.Reset()
	diagnostic.Reset()
	gone := &reads{answers: map[string]localsession.ModuleAnswer{}, errs: map[string]error{}}
	if code, _ := runService(t.Context(), args, &out, &diagnostic, func() (console.Session, error) { return &restartingSession{}, nil }, func() (moduleSession, error) { return gone, nil }); code != 2 ||
		!strings.Contains(out.String(), id) || !strings.Contains(diagnostic.String(), "its entries could not be collected") {
		t.Errorf("entries that are gone: exit %d stdout %q stderr %q", code, out.String(), diagnostic.String())
	}
	out.Reset()
	diagnostic.Reset()
	unminted := []string{"service", "logs", "dnf-automatic-install.service", "--confirm", strings.Repeat("a", 64)}
	s := &restartingSession{}
	hold := &reads{answers: map[string]localsession.ModuleAnswer{}, errs: map[string]error{}}
	_, _ = runService(t.Context(), unminted, &out, &diagnostic, func() (console.Session, error) { return s, nil }, func() (moduleSession, error) { return hold, nil })
	if len(s.request.OperationID) != 32 || len(hold.asked) != 1 || !strings.Contains(hold.asked[0], s.request.OperationID) {
		t.Errorf("a minted operation id %q was not the one the entries were collected by: %v", s.request.OperationID, hold.asked)
	}
}

// A plan whose answer the client could not verify names why, so that an operator and a log can tell a session the
// console closed from a malformed record.
func TestServiceCLI_AnUnverifiedAnswerNamesItsReason(t *testing.T) {
	s := &session{err: &localclient.Failure{Code: "response_unverified", Reason: "connection_closed", Sent: true}}
	var out, diagnostic bytes.Buffer
	code, _ := runService(t.Context(), []string{"service", "start", "dnf-automatic-install.timer"}, &out, &diagnostic, func() (console.Session, error) { return s, nil }, nil)
	if code != 2 || out.Len() != 0 || strings.TrimSpace(diagnostic.String()) != "response_unverified connection_closed" {
		t.Fatalf("exit %d stdout %q stderr %q", code, out.String(), diagnostic.String())
	}
}

// What the CLI collects must be what the act read: pages that do not add up to the total, entries of another unit,
// and a page that does not move on are not printed as the journal, and an empty journal is an empty list, never null.
func TestServiceCLI_ALogsCollectionThatDoesNotMatchTheActIsNotPrinted(t *testing.T) {
	id := strings.Repeat("4", 32)
	args := []string{"service", "logs", "dnf-automatic-install.service", "--confirm", strings.Repeat("a", 64), "--operation-id", id}
	run := func(r *reads, extra ...string) (int, string, string) {
		var out, diagnostic bytes.Buffer
		code, _ := runService(t.Context(), append(append([]string{}, args...), extra...), &out, &diagnostic,
			func() (console.Session, error) { return &restartingSession{}, nil }, func() (moduleSession, error) { return r, nil })
		return code, out.String(), diagnostic.String()
	}
	entry := []services.Entry{{Timestamp: "t", Priority: "6", Message: "m"}}
	key := func(offset int) string { return readKey(localsession.QueryServicesLogs, id, offset) }
	one := func(a localsession.ModuleAnswer) *reads {
		a.Query = localsession.QueryServicesLogs
		return &reads{answers: map[string]localsession.ModuleAnswer{key(0): a}, errs: map[string]error{}}
	}
	for name, r := range map[string]*reads{
		"a total the pages do not add up to": one(localsession.ModuleAnswer{LogUnit: "dnf-automatic-install.service", Total: 3, Entries: entry}),
		"another unit":                       one(localsession.ModuleAnswer{LogUnit: "sshd.service", Total: 1, Entries: entry}),
		"a page that does not move on":       one(localsession.ModuleAnswer{LogUnit: "dnf-automatic-install.service", Total: 2, Next: 0 + 0, Entries: entry}),
	} {
		code, out, diagnostic := run(r)
		if code != 2 || strings.Contains(out, "Entries of") || !strings.Contains(diagnostic, "its entries could not be collected") {
			t.Errorf("%s: exit %d stdout %q stderr %q", name, code, out, diagnostic)
		}
	}
	stuck := one(localsession.ModuleAnswer{LogUnit: "dnf-automatic-install.service", Total: 2, Next: 1, Entries: entry})
	stuck.answers[key(1)] = localsession.ModuleAnswer{Query: localsession.QueryServicesLogs, LogUnit: "dnf-automatic-install.service", Offset: 1, Total: 2, Next: 1, Entries: entry}
	if code, out, _ := run(stuck); code != 2 || strings.Contains(out, "Entries of") {
		t.Errorf("a page that does not move on: exit %d stdout %q", code, out)
	}
	empty := one(localsession.ModuleAnswer{LogUnit: "dnf-automatic-install.service", Total: 0})
	if code, out, _ := run(empty, "--output", "json"); code != 0 || !strings.Contains(out, `"entries":[]`) || strings.Contains(out, "null") {
		t.Errorf("an empty journal: exit %d stdout %q", code, out)
	}
}
