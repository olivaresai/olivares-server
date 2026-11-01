// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package localsession

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/olivaresai/olivares/appliance/layer/helpers/helperschema"
	"github.com/olivaresai/olivares/appliance/layer/hostops"
	"github.com/olivaresai/olivares/appliance/layer/portal/audit"
	"github.com/olivaresai/olivares/appliance/layer/portal/localframe"
	"github.com/olivaresai/olivares/appliance/layer/services"
)

const updateTimer = "dnf-automatic-install.timer"

// unitBus is one unit on a service manager: every job it queues finishes done and leaves the unit in the
// state the method asks for.
type unitBus struct {
	mu          sync.Mutex
	unit        services.Unit
	file        string
	subscribers []chan services.JobRemoved
	calls       []string
}

func (b *unitBus) record(call string) { b.mu.Lock(); b.calls = append(b.calls, call); b.mu.Unlock() }

func (b *unitBus) ListUnitsByPatterns(context.Context, []string, []string) ([]services.Unit, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return []services.Unit{b.unit}, nil
}
func (b *unitBus) GetUnitFileState(context.Context, string) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.file, nil
}
func (b *unitBus) Dependents(context.Context, string) ([]string, error) { return nil, nil }
func (b *unitBus) ServiceType(context.Context, string) (string, error) {
	return "", errors.New("not a service")
}
func (b *unitBus) Subscribe(context.Context) (<-chan services.JobRemoved, func(), error) {
	ch := make(chan services.JobRemoved, 4)
	b.mu.Lock()
	b.subscribers = append(b.subscribers, ch)
	b.mu.Unlock()
	return ch, func() {}, nil
}
func (b *unitBus) QueueJob(_ context.Context, method, unit, _ string) (string, error) {
	b.record(method)
	b.mu.Lock()
	defer b.mu.Unlock()
	b.unit.ActiveState, b.unit.SubState = "active", "running"
	if method == "StopUnit" {
		b.unit.ActiveState, b.unit.SubState = "inactive", "dead"
	}
	for _, s := range b.subscribers {
		s <- services.JobRemoved{ID: 7, Job: "/job/7", Unit: unit, Result: "done"}
	}
	return "/job/7", nil
}
func (b *unitBus) EnableUnitFiles(context.Context, []string, bool, bool) (int, error) {
	b.record("EnableUnitFiles")
	b.mu.Lock()
	b.file = "enabled"
	b.mu.Unlock()
	return 1, nil
}
func (b *unitBus) DisableUnitFiles(context.Context, []string, bool) (int, error) {
	b.record("DisableUnitFiles")
	b.mu.Lock()
	b.file = "disabled"
	b.mu.Unlock()
	return 1, nil
}

// unitsHelper is the units helper's own answer over bus and a journal of the given messages.
type unitsHelper struct {
	bus      *unitBus
	messages []string
}

func (h *unitsHelper) Call(ctx context.Context, name string, request helperschema.Request) (helperschema.Response, error) {
	req, ok := request.(*services.Request)
	if !ok || name != services.HelperName {
		return helperschema.Response{}, errors.New("a document of another helper")
	}
	journal := func(context.Context, []string, int64) ([]byte, error) {
		var out strings.Builder
		for i, m := range h.messages {
			line, _ := json.Marshal(map[string]string{"__REALTIME_TIMESTAMP": fmt.Sprintf("%d000000", 1760000000+i), "PRIORITY": "6", "MESSAGE": m})
			out.Write(line)
			out.WriteByte('\n')
		}
		return []byte(out.String()), nil
	}
	return services.Answer(ctx, services.Executor{Bus: h.bus, Journal: journal, JobWait: time.Second}, req), nil
}

// serviceIdentity authorizes the service verb on a unit target, as the identity owner does for an operator.
type serviceIdentity struct{}

func (serviceIdentity) Authorize(_ context.Context, d hostops.Descriptor, target, digest string) (hostops.Caller, error) {
	if d.Module != services.Module || d.ActVerb != services.Module || !strings.HasPrefix(target, "unit:") || len(digest) != 64 {
		return hostops.Caller{}, errors.New("denied")
	}
	return hostops.Caller{Actor: "operator", Mode: "product-up"}, nil
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// The services module's acts are adopted acts of the portal's local socket: the served catalog carries them,
// a plan reads the unit through the units helper and offers the apply, each verb is its own act with its own
// receipt, and the entries of a logs act leave through module.read by the operation id of the act, never
// through the receipt. A catalog that does not serve them, and an absent helper, adopt nothing.
func TestLocalSession_ServicesActsAreAdoptedActs(t *testing.T) {
	f := admittedFacts(1000, true)
	own, code := admit(4, f)
	if code != "" {
		t.Fatal(code)
	}
	defer own.Close()
	auditDir := t.TempDir()
	if err := os.Chmod(auditDir, 0700); err != nil {
		t.Fatal(err)
	}
	spool, err := audit.Open(auditDir)
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(context.Context, uint32) (hostops.Authority, error) { return serviceIdentity{}, nil }
	served := append([]hostops.Descriptor{hostops.StatusDescriptor()}, services.Descriptors()...)
	helper := &unitsHelper{bus: &unitBus{unit: services.Unit{Name: updateTimer, LoadState: "loaded", ActiveState: "inactive", SubState: "dead"}, file: "disabled"},
		messages: []string{"Started dnf-automatic-install.service", "token=hunter2 in the journal"}}
	open := func(caller *unitsHelper, descriptors []hostops.Descriptor) *Server {
		t.Helper()
		var h interface {
			Call(context.Context, string, helperschema.Request) (helperschema.Response, error)
		}
		if caller != nil {
			h = caller
		}
		s, err := OpenWithPackages(t.Context(), t.TempDir(), descriptors, h, f, resolve, spool)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	request := func(s *Server, op string, value any) localframe.Record {
		t.Helper()
		return s.handleFor(t.Context(), localframe.Record{Type: "request", Op: op, Body: mustJSON(value)}, own)
	}
	plan := func(s *Server, verb, input string) (localframe.Record, hostops.Plan) {
		r := request(s, "task.plan", taskRequest{Module: services.Module, Verb: verb, Surface: "cli", Inputs: json.RawMessage(input)})
		var p hostops.Plan
		_ = json.Unmarshal(r.Body, &p)
		return r, p
	}
	input := `{"unit":"` + updateTimer + `"}`
	s := open(helper, served)
	for _, verb := range []string{services.OpStart, services.OpStop, services.OpEnable, services.OpDisable, services.OpLogs} {
		if r, p := plan(s, verb, input); r.Status != 200 || !p.Permissions.Apply {
			t.Errorf("%s with the units helper: %+v, want a plan that offers the apply", verb, r)
		}
	}
	if r, p := plan(open(helper, []hostops.Descriptor{hostops.StatusDescriptor()}), services.OpStart, input); r.Status == 200 && p.Permissions.Apply {
		t.Fatalf("start is offered although the catalog does not serve it: %+v", r)
	}
	if r, p := plan(open(nil, served), services.OpStart, input); r.Status == 200 && p.Permissions.Apply {
		t.Fatalf("start without the units helper was offered: %+v", r)
	}

	act := func(verb, id string) hostops.Record {
		t.Helper()
		_, p := plan(s, verb, input)
		var rec hostops.Record
		r := request(s, "task.apply", hostops.ApplyRequest{Module: services.Module, Verb: verb, Surface: "cli", Inputs: json.RawMessage(input), OperationID: id, Confirmation: p.Digest})
		if r.Status != 200 || json.Unmarshal(r.Body, &rec) != nil || rec.State != hostops.StateSucceeded || rec.TaskID != "service."+verb || rec.Target != "unit:"+updateTimer {
			t.Fatalf("%s: %+v record %+v, want a succeeded receipt of its own task on the unit", verb, r, rec)
		}
		return rec
	}
	act(services.OpStart, strings.Repeat("a", 32))
	act(services.OpEnable, strings.Repeat("b", 32))
	if got := strings.Join(helper.bus.calls, " "); !strings.Contains(got, "StartUnit") || !strings.Contains(got, "EnableUnitFiles") {
		t.Fatalf("the service manager was asked %q, want a start and an enable", got)
	}

	logsID := strings.Repeat("c", 32)
	rec := act(services.OpLogs, logsID)
	if !strings.Contains(strings.Join(rec.Postconditions, " "), "entries_read=2") || strings.Contains(fmt.Sprint(rec), "hunter2") {
		t.Fatalf("the logs receipt is %+v, want the count of entries and none of their text", rec)
	}
	read := func(srv *Server, id string, offset int) localframe.Record {
		return request(srv, "module.read", map[string]any{"query": QueryServicesLogs, "operation_id": id, "offset": offset, "surface": "cli"})
	}
	var answer ModuleAnswer
	if r := read(s, logsID, 0); r.Status != 200 || json.Unmarshal(r.Body, &answer) != nil || len(answer.Entries) != 2 || answer.Entries[1].Message != "token=hunter2 in the journal" || answer.LogUnit != updateTimer || answer.Next != 0 {
		t.Fatalf("collecting the entries of the act: %+v %+v", r, answer)
	}
	if r := read(s, strings.Repeat("9", 32), 0); r.Status == 200 {
		t.Fatalf("another operation id collected the entries: %+v", r)
	}
	if r := read(s, "not-an-operation-id", 0); r.Status != 422 {
		t.Fatalf("a malformed operation id: %+v, want input_refused", r)
	}
	if r := read(open(helper, served), logsID, 0); r.Status == 200 {
		t.Fatalf("a console that opened later still held the entries: %+v", r)
	}
}

// logsConsole is the console of a guest with a journal of messages for the update timer, and the means to ask it as
// the session of any uid.
func logsConsole(t *testing.T, messages []string) (*Server, func(uid uint32) *owner) {
	t.Helper()
	auditDir := t.TempDir()
	if err := os.Chmod(auditDir, 0700); err != nil {
		t.Fatal(err)
	}
	spool, err := audit.Open(auditDir)
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(context.Context, uint32) (hostops.Authority, error) { return serviceIdentity{}, nil }
	served := append([]hostops.Descriptor{hostops.StatusDescriptor()}, services.Descriptors()...)
	helper := &unitsHelper{bus: &unitBus{unit: services.Unit{Name: updateTimer, LoadState: "loaded", ActiveState: "active", SubState: "running"}, file: "enabled"}, messages: messages}
	s, err := OpenWithPackages(t.Context(), t.TempDir(), served, helper, admittedFacts(1000, true), resolve, spool)
	if err != nil {
		t.Fatal(err)
	}
	return s, func(uid uint32) *owner {
		own, code := admit(4, admittedFacts(uid, true))
		if code != "" {
			t.Fatal(code)
		}
		t.Cleanup(own.Close)
		return own
	}
}

// askAs sends one request to s as the session own.
func askAs(t *testing.T, s *Server, own *owner, op string, value any) localframe.Record {
	t.Helper()
	return s.handleFor(t.Context(), localframe.Record{Type: "request", Op: op, Body: mustJSON(value)}, own)
}

// logsAct performs a confirmed logs act of lines entries as own, and returns its record.
func logsAct(t *testing.T, s *Server, own *owner, id string, lines int) hostops.Record {
	t.Helper()
	input := json.RawMessage(fmt.Sprintf(`{"unit":%q,"lines":%d}`, updateTimer, lines))
	var p hostops.Plan
	if r := askAs(t, s, own, "task.plan", taskRequest{Module: services.Module, Verb: services.OpLogs, Surface: "cli", Inputs: input}); r.Status != 200 || json.Unmarshal(r.Body, &p) != nil || !p.Permissions.Apply {
		t.Fatalf("plan: %+v", r)
	}
	var rec hostops.Record
	r := askAs(t, s, own, "task.apply", hostops.ApplyRequest{Module: services.Module, Verb: services.OpLogs, Surface: "cli", Inputs: input, OperationID: id, Confirmation: p.Digest})
	if r.Status != 200 || json.Unmarshal(r.Body, &rec) != nil || rec.State != hostops.StateSucceeded {
		t.Fatalf("apply: %+v %+v", r, rec)
	}
	return rec
}

func readLogsPage(t *testing.T, s *Server, own *owner, id string, offset int) (localframe.Record, ModuleAnswer) {
	t.Helper()
	r := askAs(t, s, own, "module.read", map[string]any{"query": QueryServicesLogs, "operation_id": id, "offset": offset, "surface": "cli"})
	var a ModuleAnswer
	if r.Status == 200 {
		if err := json.Unmarshal(r.Body, &a); err != nil {
			t.Fatal(err)
		}
	}
	return r, a
}

// A journal larger than a frame is collected whole, in pages: every entry once and in order, each page naming the same
// unit, and the entries are gone once the last page has been served.
func TestLocalSession_LogsLargerThanAFrameArePagedWholeAndDroppedAfterTheLastPage(t *testing.T) {
	messages := make([]string, 200)
	for i := range messages {
		messages[i] = fmt.Sprintf("%03d %s", i, strings.Repeat("m", 200))
	}
	s, as := logsConsole(t, messages)
	own := as(1000)
	id := strings.Repeat("5", 32)
	rec := logsAct(t, s, own, id, 200)
	if !strings.Contains(strings.Join(rec.Postconditions, " "), "entries_read=200") {
		t.Fatalf("receipt %+v", rec)
	}
	var got []string
	pages := 0
	for offset := 0; ; pages++ {
		r, a := readLogsPage(t, s, own, id, offset)
		if r.Status != 200 || a.LogUnit != updateTimer || a.Total != 200 || a.Offset != offset || len(a.Entries) == 0 {
			t.Fatalf("page at %d: %+v %+v", offset, r, a)
		}
		for _, e := range a.Entries {
			got = append(got, e.Message)
		}
		if a.Next == 0 {
			break
		}
		if a.Next <= offset {
			t.Fatalf("page at %d did not move on: next %d", offset, a.Next)
		}
		offset = a.Next
	}
	if pages < 2 || len(got) != 200 || got[0] != messages[0] || got[199] != messages[199] {
		t.Fatalf("%d pages gave %d entries", pages+1, len(got))
	}
	for i := range got {
		if got[i] != messages[i] {
			t.Fatalf("entry %d: %q", i, got[i])
		}
	}
	if r, _ := readLogsPage(t, s, own, id, 0); r.Status == 200 {
		t.Fatalf("the entries were served again after a complete collection: %+v", r)
	}
}

// The operation id names entries and is no secret: another session of the same host, or the same session before its own
// act, collects nothing of an act it did not ask for.
func TestLocalSession_LogsAreCollectedByTheSessionThatAskedForThemAlone(t *testing.T) {
	s, as := logsConsole(t, []string{"first", "second"})
	asker, other := as(1000), as(2000)
	id := strings.Repeat("6", 32)
	logsAct(t, s, asker, id, 100)
	if r, _ := readLogsPage(t, s, other, id, 0); r.Status == 200 {
		t.Fatalf("another session collected the entries: %+v", r)
	}
	if r, a := readLogsPage(t, s, asker, id, 0); r.Status != 200 || len(a.Entries) != 2 {
		t.Fatalf("the session that asked: %+v %+v", r, a)
	}
	if r := s.handleFor(t.Context(), localframe.Record{Type: "request", Op: "module.read", Body: mustJSON(map[string]any{"query": QueryServicesLogs, "operation_id": id, "surface": "cli"})}, nil); r.Status != 403 {
		t.Fatalf("a read without a session: %+v, want mode_refused", r)
	}
}
