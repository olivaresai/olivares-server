// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package services

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/olivaresai/olivares/appliance/layer/helpers/helperschema"
	"github.com/olivaresai/olivares/appliance/layer/hostops"
)

// updateUnits are the units of the Updates page: the acts on them are the reason the class table names them.
var updateUnits = []string{"olivares-appliance-update.service", "olivares-appliance-rollback.service", "dnf-automatic-install.service", "dnf-automatic-install.timer"}

func TestUnits_TheUpdateUnitsAreManagedBecauseTheirActsAreAdopted(t *testing.T) {
	for _, unit := range updateUnits {
		if got := Classify(unit); got != ClassManaged {
			t.Errorf("%s is in class %q, want managed", unit, got)
		}
		for _, op := range []string{OpStart, OpStop, OpEnable, OpDisable, OpStatus, OpLogs} {
			if refusal := Check(op, unit); refusal != nil {
				t.Errorf("%s %s: %v", op, unit, refusal)
			}
		}
	}
	// A neighbor of these names is still not managed by the shape of its name.
	for _, unit := range []string{"dnf-automatic.timer", "dnf-automatic-install.socket", "olivares-entitled-repo.service", "olivares-appliance-update.timer"} {
		if got := Classify(unit); got == ClassManaged {
			t.Errorf("%s is managed by the shape of its name", unit)
		}
	}
}

// unitActs composes the adopted task of every act of the services module over bus, as the console does.
func unitActs(t *testing.T, bus *fakeBus, hold *LogHold, journal Runner) (*hostops.Acts, string) {
	t.Helper()
	catalog, err := hostops.NewCatalog(Descriptors())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	engine, err := hostops.OpenWithCatalog(dir, catalog)
	if err != nil {
		t.Fatal(err)
	}
	helper := restartHelper{executor: Executor{Bus: bus, Journal: journal, JobWait: time.Millisecond}}
	tasks := map[string]hostops.AdoptedTask{}
	for _, d := range Descriptors() {
		if IsAct(d.Verb) {
			tasks[d.ID] = UnitTask{Op: d.Verb, Helper: helper, Hold: hold}
		}
	}
	return hostops.NewActs(engine, catalog, tasks, restartAudit{}), dir
}

func confirmed(t *testing.T, acts *hostops.Acts, id, op, inputs string) hostops.ApplyRequest {
	t.Helper()
	r := hostops.ApplyRequest{OperationID: id, Module: Module, Verb: op, Surface: "cli", Inputs: json.RawMessage(inputs)}
	plan, err := acts.Plan(t.Context(), r.Module, r.Verb, r.Surface, r.Inputs, restartAuthority{})
	if err != nil || !plan.Permissions.Apply {
		t.Fatalf("plan %s %s: %+v %v", op, inputs, plan, err)
	}
	r.Confirmation = plan.Digest
	return r
}

// Each verb is its own act: its own task id for the act authorization, its own plan digest, its own durable
// receipt with the state the service manager measured afterwards.
func TestUnitTask_EveryEffectVerbHasItsOwnPlanReceiptAndMeasuredPostcondition(t *testing.T) {
	for _, c := range []struct {
		op, unit string
		before   func(string) Unit
		file     string // the unit-file state the act leaves, for enable and disable
		fact     string
	}{
		{OpStart, "olivares-appliance-update.service", inactive, "", "ActiveState=active"},
		{OpStart, "dnf-automatic-install.service", inactive, "", "ActiveState=active"},
		{OpStart, "dnf-automatic-install.timer", inactive, "", "ActiveState=active"},
		{OpStop, "dnf-automatic-install.timer", active, "", "ActiveState=inactive"},
		{OpEnable, "dnf-automatic-install.timer", active, "enabled", "UnitFileState=enabled"},
		{OpDisable, "dnf-automatic-install.timer", active, "disabled", "UnitFileState=disabled"},
	} {
		t.Run(c.op+" "+c.unit, func(t *testing.T) {
			bus := newFakeBus(c.before(c.unit))
			bus.files[c.unit] = map[string]string{"enabled": "disabled", "disabled": "enabled", "": "enabled"}[c.file]
			if c.file != "" {
				bus.fileAfter[c.unit] = c.file
			}
			bus.finish = func(method, unit, job string) ([]JobRemoved, Unit) {
				after := active
				if method == "StopUnit" {
					after = inactive
				}
				return []JobRemoved{{ID: 7, Job: job, Unit: unit, Result: "done"}}, after(unit)
			}
			acts, _ := unitActs(t, bus, NewLogHold(), nil)
			r := confirmed(t, acts, strings.Repeat("ab", 16), c.op, `{"unit":"`+c.unit+`"}`)
			rec, status, err := acts.Apply(t.Context(), r, restartAuthority{})
			if err != nil || status != 200 || rec.State != hostops.StateSucceeded || rec.TaskID != "service."+c.op || rec.Target != "unit:"+c.unit {
				t.Fatalf("%s %s: %+v status=%d err=%v", c.op, c.unit, rec, status, err)
			}
			if !strings.Contains(strings.Join(rec.Postconditions, " "), c.fact) {
				t.Fatalf("missing %s: %v", c.fact, rec.Postconditions)
			}
			if len(effects(bus.Calls())) == 0 {
				t.Fatal("no act reached the service manager")
			}
		})
	}
}

// A confirmation is for one verb: the digest of a plan to stop a unit confirms no start of it.
func TestUnitTask_AConfirmationOfOneVerbConfirmsNoOther(t *testing.T) {
	bus := newFakeBus(active("dnf-automatic-install.timer"))
	acts, _ := unitActs(t, bus, NewLogHold(), nil)
	stop := confirmed(t, acts, strings.Repeat("cd", 16), OpStop, `{"unit":"dnf-automatic-install.timer"}`)
	start := stop
	start.Verb = OpStart
	if _, status, err := acts.Apply(t.Context(), start, restartAuthority{}); err == nil || status != 403 || len(effects(bus.Calls())) != 0 {
		t.Fatalf("the plan of a stop confirmed a start: status=%d err=%v calls=%v", status, err, bus.Calls())
	}
}

// A start whose job did not report stays running, outcome unknown, and a replay of its operation id is a read.
func TestUnitTask_AStartWithNoVerifiedJobStaysUnknownAndIsNotRepeated(t *testing.T) {
	bus := newFakeBus(inactive("dnf-automatic-install.service"))
	acts, _ := unitActs(t, bus, NewLogHold(), nil)
	r := confirmed(t, acts, strings.Repeat("ef", 16), OpStart, `{"unit":"dnf-automatic-install.service"}`)
	for range 2 {
		rec, status, err := acts.Apply(t.Context(), r, restartAuthority{})
		if err != nil || status != 202 || rec.State != hostops.StateRunning || bus.jobs != 1 {
			t.Fatalf("unreported job: %+v status=%d err=%v jobs=%d", rec, status, err, bus.jobs)
		}
	}
	if calls := effects(bus.Calls()); len(calls) != 2 || calls[1] != "StartUnit" {
		t.Fatalf("the start was repeated: %v", calls)
	}
}

func journalOf(messages ...string) Runner {
	return func(context.Context, []string, int64) ([]byte, error) {
		var out strings.Builder
		for _, m := range messages {
			line, _ := json.Marshal(map[string]string{"__REALTIME_TIMESTAMP": "1760000000000000", "PRIORITY": "6", "MESSAGE": m})
			out.Write(line)
			out.WriteByte('\n')
		}
		return []byte(out.String()), nil
	}
}

// The logs act is authorized and receipted like an effect, and its entries leave through the hold of the console
// that asked, never through the durable record.
func TestUnitTask_LogsActLeavesOnlyItsCountInTheDurableReceipt(t *testing.T) {
	const secret = "token=hunter2 in the journal"
	bus := newFakeBus(active("dnf-automatic-install.service"))
	hold := NewLogHold()
	acts, dir := unitActs(t, bus, hold, journalOf("first", secret))
	id := strings.Repeat("12", 16)
	r := confirmed(t, acts, id, OpLogs, `{"unit":"dnf-automatic-install.service","lines":2}`)
	rec, status, err := acts.Apply(t.Context(), r, restartAuthority{})
	if err != nil || status != 200 || rec.State != hostops.StateSucceeded || rec.TaskID != "service.logs" || len(effects(bus.Calls())) != 0 {
		t.Fatalf("logs act: %+v status=%d err=%v calls=%v", rec, status, err, bus.Calls())
	}
	if !strings.Contains(strings.Join(rec.Postconditions, " "), "entries_read=2") {
		t.Fatalf("receipt: %v", rec.Postconditions)
	}
	logs, ok := hold.Get(id, 0)
	if !ok || logs.Unit != "dnf-automatic-install.service" || len(logs.Entries) != 2 || logs.Entries[1].Message != secret {
		t.Fatalf("the console cannot collect what the act read: %+v %v", logs, ok)
	}
	if _, ok := hold.Get(strings.Repeat("99", 16), 0); ok {
		t.Fatal("another operation id collected the entries")
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*"))
	for _, f := range files {
		if data, err := os.ReadFile(f); err == nil && strings.Contains(string(data), "hunter2") {
			t.Fatalf("the journal text reached the durable record %s", f)
		}
	}
}

func TestUnitTask_LogsActRefusesWhatTheClassTableOrTheHoldCannotServe(t *testing.T) {
	bus := newFakeBus(active("dnf-automatic-install.service"))
	if _, err := (UnitTask{Op: OpLogs, Helper: restartHelper{executor: Executor{Bus: bus, Journal: journalOf("x")}}}).Prepare(t.Context(), json.RawMessage(`{"unit":"dnf-automatic-install.service"}`)); err == nil {
		t.Fatal("a logs act with no hold to collect from reads the journal for nothing")
	}
	task := UnitTask{Op: OpLogs, Helper: restartHelper{executor: Executor{Bus: bus, Journal: journalOf("x")}}, Hold: NewLogHold()}
	for _, input := range []string{`{"unit":"dnf-automatic-install.service","lines":0}`, `{"unit":"dnf-automatic-install.service","lines":501}`, `{"unit":"dnf-automatic-install.service","lines":"5"}`, `{"unit":"absent.service"}`, `{"unit":"dnf-automatic-install.service","path":"/etc"}`} {
		if target, err := task.Prepare(t.Context(), json.RawMessage(input)); err == nil || target != "" {
			t.Errorf("logs input %s was planned: %q", input, target)
		}
	}
	if target, err := task.Prepare(t.Context(), json.RawMessage(`{"unit":"dnf-automatic-install.service"}`)); err != nil || target != "unit:dnf-automatic-install.service" {
		t.Fatalf("a logs act with the default line count: %q %v", target, err)
	}
}

func TestLogHold_KeepsAFewOperationsForAShortTime(t *testing.T) {
	now := time.Unix(1_760_000_000, 0)
	hold := NewLogHold()
	hold.now = func() time.Time { return now }
	for i := range holdCapacity + 1 {
		hold.Put(strings.Repeat(string(rune('a'+i)), 32), 0, Logs{Unit: "x.service", Lines: 1, Entries: []Entry{{Message: "m"}}})
	}
	if _, ok := hold.Get(strings.Repeat("a", 32), 0); ok {
		t.Error("the oldest hold survived the capacity")
	}
	newest := strings.Repeat(string(rune('a'+holdCapacity)), 32)
	if _, ok := hold.Get(newest, 0); !ok {
		t.Error("the newest hold was dropped")
	}
	now = now.Add(holdTTL + time.Second)
	if _, ok := hold.Get(newest, 0); ok {
		t.Error("a hold outlived its time")
	}
}

// A oneshot service that ran to completion is inactive afterwards, so its start is reached when its job
// finished done and it exited cleanly; no other unit gets that reading. A simple service, a unit that is not
// a service and a oneshot that failed or whose job did not report keep the plan's strict postcondition.
func TestExecutor_AStartOfAOneshotThatRanToCompletionIsReachedAndNothingElseIs(t *testing.T) {
	const unit = "olivares-appliance-update.service"
	for _, c := range []struct {
		name, op, serviceType, result string
		after                         func(string) Unit
		want                          string
	}{
		{"oneshot ran to completion", OpStart, "oneshot", "done", inactive, hostops.StateSucceeded},
		{"oneshot restarted to completion", OpRestart, "oneshot", "done", inactive, hostops.StateSucceeded},
		{"oneshot that stays active", OpStart, "oneshot", "done", active, hostops.StateSucceeded},
		{"oneshot that failed", OpStart, "oneshot", "done", failed, hostops.StatePartial},
		{"oneshot whose job failed, state unchanged", OpStart, "oneshot", "failed", inactive, hostops.StateFailed},
		{"oneshot whose job did not report", OpStart, "oneshot", "", inactive, hostops.StateRunning},
		{"simple service done but inactive", OpStart, "simple", "done", inactive, hostops.StatePartial},
		{"unit that is not a service done but inactive", OpStart, "", "done", inactive, hostops.StatePartial},
		{"oneshot reloaded", OpReload, "oneshot", "done", inactive, hostops.StatePartial},
	} {
		t.Run(c.name, func(t *testing.T) {
			bus := newFakeBus(inactive(unit))
			if c.serviceType != "" {
				bus.types = map[string]string{unit: c.serviceType}
			}
			if c.result != "" {
				bus.finish = finishWith(c.result, c.after)
			} else {
				bus.finish = func(_, unit, _ string) ([]JobRemoved, Unit) { return nil, c.after(unit) }
			}
			res := Executor{Bus: bus, JobWait: time.Millisecond}.Apply(t.Context(), c.op, unit)
			if got := outcome(res.Observation()); got != c.want {
				t.Fatalf("%s %s: outcome %s with %v, want %s", c.op, unit, got, res.Observation().Postconditions, c.want)
			}
		})
	}
}

// The helper's logs answer may carry up to MaxAnswerBytes of entries, and a default read of 100 ordinary journal lines
// is already larger than the 16 KiB the closed decoder takes for a request. The console takes the whole answer, holds
// every entry and records how many it read; a bound meant for requests must not turn a real journal into `unknown`.
func TestUnitTask_ALogsAnswerAsLargeAsTheHelperSendsIsHeldWhole(t *testing.T) {
	messages := make([]string, 100)
	for i := range messages {
		messages[i] = strings.Repeat("x", 280) + " line " + strings.Repeat("y", i%10)
	}
	bus := newFakeBus(active("dnf-automatic-install.service"))
	hold := NewLogHold()
	acts, _ := unitActs(t, bus, hold, journalOf(messages...))
	id := strings.Repeat("34", 16)
	r := confirmed(t, acts, id, OpLogs, `{"unit":"dnf-automatic-install.service"}`)
	rec, status, err := acts.Apply(t.Context(), r, restartAuthority{})
	if err != nil || status != 200 || rec.State != hostops.StateSucceeded || !strings.Contains(strings.Join(rec.Postconditions, " "), "entries_read=100") {
		t.Fatalf("a 100-line read of %d bytes: %+v status=%d err=%v", 100*290, rec, status, err)
	}
	logs, ok := hold.Get(id, 0)
	if !ok || len(logs.Entries) != 100 || logs.Entries[99].Message != messages[99] {
		t.Fatalf("the entries held: %d, %v", len(logs.Entries), ok)
	}
}

// The answer to a logs act is verified before anything is held: an answer for another unit or another count, more
// entries than asked for, a member the schema does not name, a repeated member or no data at all stays unknown and
// holds nothing; a journal reader that failed changed nothing.
func TestUnitTask_ALogsAnswerThatIsNotExactlyWhatWasAskedForIsUnknownAndHoldsNothing(t *testing.T) {
	const unit = "dnf-automatic-install.service"
	entries := `[{"timestamp":"t","priority":"6","message":"m"}]`
	performed := func(bundle string) helperschema.Response {
		return helperschema.Response{Result: helperschema.ResultPerformed, Bundle: json.RawMessage(bundle)}
	}
	for _, c := range []struct {
		name     string
		response helperschema.Response
		want     string
	}{
		{"the exact answer", performed(`{"unit":"` + unit + `","lines":100,"entries":` + entries + `,"truncated":false}`), "performed"},
		{"another unit", performed(`{"unit":"sshd.service","lines":100,"entries":` + entries + `,"truncated":false}`), "unknown"},
		{"another count", performed(`{"unit":"` + unit + `","lines":50,"entries":` + entries + `,"truncated":false}`), "unknown"},
		{"more entries than asked", performed(`{"unit":"` + unit + `","lines":1,"entries":[` + entries[1:len(entries)-1] + `,` + entries[1:len(entries)-1] + `],"truncated":false}`), "unknown"},
		{"a member the schema does not name", performed(`{"unit":"` + unit + `","lines":100,"entries":` + entries + `,"truncated":false,"extra":1}`), "unknown"},
		{"a repeated member", performed(`{"unit":"` + unit + `","unit":"` + unit + `","lines":100,"entries":` + entries + `,"truncated":false}`), "unknown"},
		{"no data", helperschema.Response{Result: helperschema.ResultPerformed}, "unknown"},
		{"answered, not performed", helperschema.Response{Result: helperschema.ResultAnswered, Bundle: json.RawMessage(`{"unit":"` + unit + `","lines":100,"entries":[],"truncated":false}`)}, "unknown"},
		{"a journal reader that failed", helperschema.Response{Result: helperschema.ResultFailed, Code: CodeEffectFailed}, "not-performed"},
	} {
		t.Run(c.name, func(t *testing.T) {
			hold := NewLogHold()
			task := UnitTask{Op: OpLogs, Hold: hold, Helper: restartHelperFunc(func(context.Context, string, helperschema.Request) (helperschema.Response, error) {
				return c.response, nil
			})}
			id := strings.Repeat("78", 16)
			cmd := hostops.Command{OperationID: id, TaskID: "service.logs", Module: Module, Verb: OpLogs, Target: "unit:" + unit}
			got := task.Apply(t.Context(), cmd, json.RawMessage(`{"unit":"`+unit+`"}`))
			if got.P1 != c.want {
				t.Fatalf("observation %q, want %q", got.P1, c.want)
			}
			if _, held := hold.Get(id, 0); held != (c.want == "performed") {
				t.Fatalf("held %v after %s", held, c.want)
			}
		})
	}
}

// A oneshot unit that is not loaded after its run, because the manager unloads a finished unit nothing refers to,
// is read from the unit file's state alone and is still reached; a unit that settled in another dead-looking state is not.
func TestExecutor_AStartOfAOneshotIsReachedWhenTheManagerUnloadedItAndNotWhenItSettledElsewhere(t *testing.T) {
	const unit = "olivares-appliance-update.service"
	exited := func(name string) Unit { u := inactive(name); u.SubState = "exited"; return u }
	for _, c := range []struct {
		name  string
		after func(string) Unit
		want  string
	}{
		{"unloaded after the run", func(string) Unit { return Unit{} }, hostops.StateSucceeded},
		{"inactive and exited", exited, hostops.StatePartial},
	} {
		t.Run(c.name, func(t *testing.T) {
			bus := newFakeBus()
			bus.files[unit] = "static"
			bus.types = map[string]string{unit: "oneshot"}
			bus.finish = finishWith("done", c.after)
			res := Executor{Bus: bus, JobWait: time.Millisecond}.Apply(t.Context(), OpStart, unit)
			if got := outcome(res.Observation()); got != c.want {
				t.Fatalf("outcome %s with %v, want %s", got, res.Observation().Postconditions, c.want)
			}
			if c.want == hostops.StateSucceeded && !slices.Contains(res.Observation().Postconditions, "ServiceType=oneshot") {
				t.Fatalf("the receipt does not say why an inactive unit is a reached start: %v", res.Observation().Postconditions)
			}
		})
	}
}
