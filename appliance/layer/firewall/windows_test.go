// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package firewall_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/olivaresai/olivares/appliance/layer/firewall"
	"github.com/olivaresai/olivares/appliance/layer/hostops"
	"github.com/olivaresai/olivares/appliance/layer/optionalapps"
)

// keptClosed is how many closed windows the owner keeps beside the open ones, as the owner's choice
// fixes it: small and fixed.
const keptClosed = 8

// idBase makes the operation ids fall as the acts rise. A production operation id is random, so the
// owner must order its windows by when they were written, never by their ids.
const idBase = 1_000_000

// actID is the nth act's operation id: 32 lowercase hexadecimal digits, a new one for each n.
func actID(n int) string { return fmt.Sprintf("%032x", idBase-n) }

// actNumber is the number n of an operation id actID made.
func actNumber(t *testing.T, id string) int {
	t.Helper()
	var v int
	if _, err := fmt.Sscanf(id, "%032x", &v); err != nil {
		t.Fatalf("%q is not an act's operation id: %v", id, err)
	}
	return idBase - v
}

// longAgo is when the nth window was written, as far as the owner can tell: a file's modification time
// is how it orders the closed windows, and acts that follow each other inside one clock tick would
// otherwise tie. It is long before the window the owner is closing, which is written now.
func longAgo(n int) time.Time { return time.Unix(1_000_000_000+int64(n), 0) }

// settle gives a window's file its place in time.
func settle(t *testing.T, o *owner, id string, at time.Time) {
	t.Helper()
	if err := os.Chtimes(windowFile(o, id), at, at); err != nil {
		t.Fatal(err)
	}
}

func windowFile(o *owner, id string) string { return filepath.Join(o.StateDir, "pending", id+".json") }

// runActs runs acts first to last of the app-row act, add on the odd ones and remove on the even
// ones, and requires every one to be performed and its window to be there when it is done.
func runActs(t *testing.T, o *owner, task firewall.AppRowTask, first, last int) {
	t.Helper()
	for n := first; n <= last; n++ {
		input := addInput
		if n%2 == 0 {
			input = removeInput
		}
		cmd := hostops.Command{OperationID: actID(n), TaskID: "firewall.app-row", Module: firewall.Module, Verb: firewall.VerbAppRow, Target: firewall.Target}
		if got := task.Apply(context.Background(), cmd, json.RawMessage(input)); got.P1 != "performed" {
			t.Fatalf("act %d (%s): %+v, want performed", n, input, got)
		}
		if _, err := o.Window(actID(n)); err != nil {
			t.Fatalf("act %d's window was dropped as it closed: %v", n, err)
		}
		settle(t, o, actID(n), longAgo(n))
	}
}

// windowNumbers are the numbers of the acts whose windows the owner holds, in ascending order.
func windowNumbers(t *testing.T, o *owner) []int {
	t.Helper()
	windows, err := o.Windows()
	if err != nil {
		t.Fatal(err)
	}
	var numbers []int
	for _, w := range windows {
		numbers = append(numbers, actNumber(t, w.OperationID))
	}
	slices.Sort(numbers)
	return numbers
}

// rangeOf is the numbers first to last.
func rangeOf(first, last int) []int {
	var numbers []int
	for n := first; n <= last; n++ {
		numbers = append(numbers, n)
	}
	return numbers
}

// statusSize is the size of the status answer the console reads back.
func statusSize(t *testing.T, o *owner) int {
	t.Helper()
	answer := firewall.Answer(context.Background(), o.Owner, &firewall.Request{Op: firewall.OpStatus})
	if answer.Result != "answered" {
		t.Fatalf("the status read: %+v, want answered", answer)
	}
	return len(answer.Bundle)
}

// An application can be added and removed as often as its operator likes: each act leaves a window, and
// the owner drops the older closed ones, so the status answer the console reads back within 64 KiB
// stays small however many acts there were (measured before the owner dropped any: 66,333 bytes
// after 73 acts, and the 74th act was not performed).
func TestAppRowTask_TwoHundredActsAreAllPerformedAndTheStatusStaysSmall(t *testing.T) {
	o := newOwner(t)
	install(t, o, managed())
	runActs(t, o, appRowTask(&ownerHelper{o: o}), 1, 200)

	if size := statusSize(t, o); size >= 16<<10 {
		t.Errorf("the status answer after 200 acts is %d bytes, want under %d", size, 16<<10)
	}
	if got, want := windowNumbers(t, o), rangeOf(200-keptClosed+1, 200); !slices.Equal(got, want) {
		t.Errorf("the owner holds the windows of acts %v, want the newest written: %v", got, want)
	}
}

// A window is also the record that answers a reopened operation without repeating its effect, so the
// recent closed ones stay: an operation sent again with the plan it had gets its own window back and
// the kernel is not loaded a second time. One older than the kept ones is gone.
func TestOwner_AnOperationRetriedInsideTheKeptRangeIsAnsweredFromItsWindow(t *testing.T) {
	ctx := context.Background()
	o := newOwner(t)
	install(t, o, managed())
	runActs(t, o, appRowTask(&ownerHelper{o: o}), 1, 40)

	with := managed()
	with.Apps = optionalapps.FirewallRows()
	loads := o.kernel.loads
	for n := 40; n > 40-keptClosed; n-- {
		candidate := managed()
		if n%2 == 1 {
			candidate = with
		}
		before, err := o.Window(actID(n))
		if err != nil {
			t.Fatalf("act %d's window was dropped: %v", n, err)
		}
		got, err := o.Apply(ctx, firewall.ApplyRequest{OperationID: actID(n), App: optionalapps.Slug, Candidate: candidate})
		if err != nil || fmt.Sprint(got) != fmt.Sprint(before) || got.State != firewall.WindowConfirmed {
			t.Errorf("act %d sent again: %+v (%v), want the window it has, confirmed", n, got, err)
		}
	}
	if o.kernel.loads != loads {
		t.Errorf("the kernel was loaded %d more times by operations that were sent again", o.kernel.loads-loads)
	}
	if _, err := o.Window(actID(40 - keptClosed)); code(err) != firewall.CodeNoSuchWindow {
		t.Errorf("the window of act %d, older than the kept ones: %v, want it dropped", 40-keptClosed, err)
	}
}

// The newest window is the one just written, whatever the file's time says: after the wall clock stepped
// back (a boot without a clock, an RTC corrected), every older window looks newer, and the window an
// act has just closed must still be there to answer a retry.
func TestOwner_TheWindowJustClosedStaysAfterTheClockSteppedBack(t *testing.T) {
	o := newOwner(t)
	install(t, o, managed())
	task := appRowTask(&ownerHelper{o: o})
	runActs(t, o, task, 1, 12)
	for _, n := range windowNumbers(t, o) {
		settle(t, o, actID(n), time.Unix(4_000_000_000+int64(n), 0))
	}
	runActs(t, o, task, 13, 13)
	if numbers := windowNumbers(t, o); !slices.Contains(numbers, 13) || len(numbers) != keptClosed {
		t.Errorf("the owner holds the windows of acts %v, want %d with act 13's", numbers, keptClosed)
	}
}

// Every way a window closes drops the older ones: the operator's revert, the guard at a deadline, and a
// boot that closes the window a reboot ended.
func TestOwner_EveryWayAWindowClosesDropsTheOlderOnes(t *testing.T) {
	with := managed()
	with.Apps = optionalapps.FirewallRows()
	for name, closeIt := range map[string]func(*testing.T, *owner, string){
		"operator's revert": func(t *testing.T, o *owner, id string) {
			if _, err := o.Revert(context.Background(), id); err != nil {
				t.Fatal(err)
			}
		},
		"guard at the deadline": func(t *testing.T, o *owner, id string) {
			o.clock.now += pastEveryWindow
			if closed, err := o.Sweep(context.Background()); err != nil || len(closed) != 1 {
				t.Fatalf("the sweep closed %+v (%v), want the one window", closed, err)
			}
		},
		"boot after a reboot": func(t *testing.T, o *owner, id string) {
			o.reboot()
			if _, err := o.BootLoad(context.Background()); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			o := newOwner(t)
			install(t, o, managed())
			for n := 1; n <= 20; n++ {
				if _, err := o.Apply(context.Background(), firewall.ApplyRequest{OperationID: actID(n), App: optionalapps.Slug, Candidate: with}); err != nil {
					t.Fatalf("act %d: %v", n, err)
				}
				closeIt(t, o, actID(n))
				settle(t, o, actID(n), longAgo(n))
			}
			if got, want := windowNumbers(t, o), rangeOf(20-keptClosed+1, 20); !slices.Equal(got, want) {
				t.Errorf("the owner holds the windows of acts %v, want the newest closed: %v", got, want)
			}
		})
	}
}

// pastEveryWindow is longer than any revert window, so a sweep after it finds the open window due.
const pastEveryWindow = 11 * time.Minute

// An owner that already holds more windows than it can read, or than the console can, is not stuck: the
// boot load drops the older ones, and nothing but the owner's own boot has to run for it.
func TestOwner_AnOwnerPastTheLimitRecoversAtBoot(t *testing.T) {
	ctx := context.Background()
	o := newOwner(t)
	install(t, o, managed())
	runActs(t, o, appRowTask(&ownerHelper{o: o}), 1, 1)
	first, err := o.Window(actID(1))
	if err != nil {
		t.Fatal(err)
	}
	for n := 2; n <= 300; n++ {
		copied := first
		copied.OperationID = actID(n)
		data, err := json.Marshal(copied)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(windowFile(o, actID(n)), append(data, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		settle(t, o, actID(n), longAgo(n))
	}
	if _, err := o.Windows(); code(err) != firewall.CodeStateUnreadable {
		t.Fatalf("300 windows: %v, want the owner to refuse to read them", err)
	}

	if _, err := o.BootLoad(ctx); err != nil {
		t.Fatal(err)
	}
	if got, want := windowNumbers(t, o), rangeOf(300-keptClosed+1, 300); !slices.Equal(got, want) {
		t.Errorf("after the boot the owner holds the windows of acts %v, want the newest written: %v", got, want)
	}
}

// A candidate policy can be as large as the schema allows, and the status answer carries every window
// kept, so the owner keeps the newest closed windows only up to a number of bytes, and always the newest.
func TestOwner_LargeWindowsAreKeptByTheirBytesAndTheNewestAlways(t *testing.T) {
	o := newOwner(t)
	install(t, o, managed())
	runActs(t, o, appRowTask(&ownerHelper{o: o}), 1, 1)
	first, err := o.Window(actID(1))
	if err != nil {
		t.Fatal(err)
	}
	for n := 2; n <= 7; n++ {
		large := first
		large.OperationID, large.Postconditions = actID(n), []string{strings.Repeat("x", 6000)}
		data, err := json.Marshal(large)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(windowFile(o, actID(n)), append(data, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		settle(t, o, actID(n), longAgo(n))
	}
	if _, err := o.BootLoad(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, want := windowNumbers(t, o), []int{6, 7}; !slices.Equal(got, want) {
		t.Errorf("the owner holds the windows of acts %v, want only the two newest 6 KB ones that fit 16 KiB: %v", got, want)
	}
}

// Only closed windows go. A window that is still open is the guard's to revert and is never dropped,
// however old its file is.
func TestOwner_AnOpenWindowIsNeverDropped(t *testing.T) {
	ctx := context.Background()
	o := newOwner(t)
	install(t, o, managed())
	task := appRowTask(&ownerHelper{o: o})
	runActs(t, o, task, 1, 20)

	// Act 21 stays open, and a second open window, due an hour later, is written beside it.
	with := managed()
	with.Apps = optionalapps.FirewallRows()
	first, err := o.Apply(ctx, firewall.ApplyRequest{OperationID: actID(21), App: optionalapps.Slug, Candidate: with})
	if err != nil {
		t.Fatal(err)
	}
	second := first
	second.OperationID, second.DeadlineNS = actID(99), first.DeadlineNS+int64(time.Hour)
	data, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(windowFile(o, actID(99)), append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	settle(t, o, actID(99), longAgo(0))

	// The first one's deadline passes; the guard reverts it, which closes one more window.
	o.clock.now = time.Duration(first.DeadlineNS) + time.Second
	closed, err := o.Sweep(ctx)
	if err != nil || len(closed) != 1 || closed[0].OperationID != actID(21) {
		t.Fatalf("the sweep closed %+v (%v), want act 21's window only", closed, err)
	}
	if w, err := o.Window(actID(99)); err != nil || w.State != firewall.WindowPending {
		t.Errorf("the second open window is %+v (%v), want it kept and still open", w, err)
	}
	if w, err := o.Window(actID(21)); err != nil || w.State != firewall.WindowReverted {
		t.Errorf("the window the guard just closed is %+v (%v), want it kept, reverted", w, err)
	}
	if _, err := o.Window(actID(13)); code(err) != firewall.CodeNoSuchWindow {
		t.Errorf("the oldest closed window left: %v, want it dropped by that close", err)
	}
}

// What the owner does not recognize as a window is not its to remove: a file that does not follow the
// window schema, a temporary file, a file with another name and a directory named like a window.
func TestOwner_LeavesWhatItDoesNotRecognizeAsAWindow(t *testing.T) {
	ctx := context.Background()
	o := newOwner(t)
	install(t, o, managed())
	runActs(t, o, appRowTask(&ownerHelper{o: o}), 1, 12)

	with := managed()
	with.Apps = optionalapps.FirewallRows()
	if _, err := o.Apply(ctx, firewall.ApplyRequest{OperationID: actID(13), App: optionalapps.Slug, Candidate: with}); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(o.StateDir, "pending")
	strangers := []string{actID(500) + ".json", "." + actID(13) + ".json.123456", "notes.json", actID(501) + ".json"}
	for _, name := range strangers[:3] {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{not a window"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, strangers[3]), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Confirm(ctx, actID(13)); err != nil {
		t.Fatal(err)
	}
	for _, name := range strangers {
		if _, err := os.Lstat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s was removed: %v", name, err)
		}
	}
	if _, err := o.Window(actID(5)); code(err) != firewall.CodeNoSuchWindow {
		t.Errorf("the oldest closed window left: %v, want it dropped though strangers lie beside it", err)
	}
}
