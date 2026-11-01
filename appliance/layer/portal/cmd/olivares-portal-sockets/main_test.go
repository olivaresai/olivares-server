// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/olivaresai/olivares/appliance/layer/portal"
)

const eth0Unit = "olivares-portal-mgmt-eth0.socket"

func ptr(v bool) *bool { return &v }

// remote is a decision that exposes the console on the named interfaces.
func remote(ifaces ...string) portal.Decision {
	return portal.Decide(
		portal.Selection{Enabled: ptr(true), Listen: portal.ListenManagement, ManagementInterfaces: ifaces},
		portal.Custody{Verified: true},
		portal.FirewallMeasurement{Holds: true, Policy: portal.Measured("held")},
	)
}

func local() portal.Decision {
	return portal.Decide(portal.Selection{}, portal.Custody{Verified: true}, portal.FirewallMeasurement{})
}

// fixture is a generator over a temporary unit directory and a model of the service manager: it
// records every systemctl call, knows which sockets are active, and refuses to start a socket
// while the console runs, as the service manager does.
type fixture struct {
	t      *testing.T
	dir    string
	calls  []string
	fail   map[string]bool
	held   map[string][]string
	active map[string]bool
	// console is whether olivares-portal.service runs; consoleBack is how many of the next stops are
	// undone at once by a connection to a socket that is listening.
	console     bool
	consoleBack int
	out         bytes.Buffer
}

func newFixture(t *testing.T) *fixture {
	return &fixture{t: t, dir: t.TempDir(), fail: map[string]bool{}, active: map[string]bool{}, console: true,
		held: map[string][]string{"eth0": {"192.0.2.10"}}}
}

func (f *fixture) generator() generator {
	return generator{
		dir: f.dir,
		addresses: func(iface string) ([]netip.Addr, error) {
			var out []netip.Addr
			for _, text := range f.held[iface] {
				out = append(out, netip.MustParseAddr(text))
			}
			return out, nil
		},
		run: func(_ context.Context, args ...string) ([]byte, error) {
			call := "systemctl " + strings.Join(args, " ")
			if args[0] != "is-active" {
				f.calls = append(f.calls, call)
			}
			if f.fail[call] {
				return []byte("Failed to start: boom\n"), errors.New("exit status 1")
			}
			switch {
			case args[0] == "is-active" && args[len(args)-1] == consoleUnit:
				if !f.console {
					return nil, errors.New("exit status 3")
				}
			case args[0] == "is-active" && !f.active[args[len(args)-1]]:
				return nil, errors.New("exit status 3")
			case args[0] == "stop" && args[1] == consoleUnit:
				if f.consoleBack > 0 {
					f.consoleBack--
				} else {
					f.console = false
				}
			case args[0] == "stop":
				f.active[args[1]] = false
			case args[0] == "start" && f.console:
				return []byte("Socket service " + consoleUnit + " already active, refusing.\n"), errors.New("exit status 1")
			case args[0] == "start":
				f.active[args[1]] = true
			}
			return nil, nil
		},
		out: &f.out,
	}
}

func (f *fixture) apply(d portal.Decision) error {
	f.t.Helper()
	f.calls = nil
	return f.generator().apply(context.Background(), d)
}

func (f *fixture) read(name string) string {
	f.t.Helper()
	data, err := os.ReadFile(filepath.Join(f.dir, name))
	if err != nil {
		f.t.Fatal(err)
	}
	return string(data)
}

func (f *fixture) exists(name string) bool {
	_, err := os.Lstat(filepath.Join(f.dir, name))
	return err == nil
}

func equal(t *testing.T, what string, got, want []string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Errorf("%s:\n got %q\nwant %q", what, got, want)
	}
}

const (
	startEth0   = "systemctl start " + eth0Unit
	stopEth0    = "systemctl stop " + eth0Unit
	stopConsole = "systemctl stop olivares-portal.service"
	reload      = "systemctl daemon-reload"
)

func TestApply_StartsANewSocketAndStopsTheConsoleOnlyBecauseTheManagerRefuses(t *testing.T) {
	f := newFixture(t)
	if err := f.apply(remote("eth0")); err != nil {
		t.Fatal(err)
	}
	if got := f.read(eth0Unit); !strings.Contains(got, "ListenStream=192.0.2.10:9443\n") || !strings.Contains(got, "BindToDevice=eth0\n") {
		t.Errorf("the unit is\n%s", got)
	}
	info, err := os.Stat(filepath.Join(f.dir, eth0Unit))
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Errorf("the unit's mode is %v (%v), want 0644", info.Mode().Perm(), err)
	}
	// The service manager refuses to start a socket while its service runs: the console stops, then it starts.
	equal(t, "systemctl calls", f.calls, []string{reload, startEth0, stopConsole, startEth0})
	if !f.active[eth0Unit] || f.console {
		t.Errorf("socket active = %v, console running = %v; want an active socket and a stopped console", f.active[eth0Unit], f.console)
	}
	if leftovers, _ := filepath.Glob(filepath.Join(f.dir, ".*")); len(leftovers) != 0 {
		t.Errorf("temporary files or a marker are left: %v", leftovers)
	}
	if !strings.Contains(f.out.String(), "console on eth0") {
		t.Errorf("the journal line is %q", f.out.String())
	}
}

func TestApply_AConsoleThatIsNotRunningIsNotStoppedToAddASocket(t *testing.T) {
	f := newFixture(t)
	f.console = false
	if err := f.apply(remote("eth0")); err != nil {
		t.Fatal(err)
	}
	equal(t, "systemctl calls", f.calls, []string{reload, startEth0})
}

func TestApply_AnUnchangedHostRunsNothingAndTheConsoleKeepsRunning(t *testing.T) {
	f := newFixture(t)
	if err := f.apply(remote("eth0")); err != nil {
		t.Fatal(err)
	}
	f.console = true // a connection started it again
	if err := f.apply(remote("eth0")); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 0 || !f.console {
		t.Errorf("an unchanged host ran %q, console running = %v", f.calls, f.console)
	}
}

func TestApply_ASocketThatIsNotActiveIsStartedAgainEvenIfNothingChanged(t *testing.T) {
	f := newFixture(t)
	if err := f.apply(remote("eth0")); err != nil {
		t.Fatal(err)
	}
	f.active[eth0Unit] = false // it failed, or was stopped by hand
	f.console = true
	if err := f.apply(remote("eth0")); err != nil {
		t.Fatal(err)
	}
	equal(t, "systemctl calls", f.calls, []string{startEth0, stopConsole, startEth0})
}

func TestApply_ADefaultHostRunsNothingPrivileged(t *testing.T) {
	f := newFixture(t)
	if err := f.apply(local()); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 0 {
		t.Errorf("a local-only host ran %q", f.calls)
	}
	if entries, _ := os.ReadDir(f.dir); len(entries) != 0 {
		t.Errorf("a local-only host wrote %d files", len(entries))
	}
}

func TestApply_ANewAddressReplacesTheUnit(t *testing.T) {
	f := newFixture(t)
	if err := f.apply(remote("eth0")); err != nil {
		t.Fatal(err)
	}
	f.held["eth0"] = []string{"192.0.2.77"}
	f.console = true
	if err := f.apply(remote("eth0")); err != nil {
		t.Fatal(err)
	}
	if got := f.read(eth0Unit); !strings.Contains(got, "192.0.2.77:9443") || strings.Contains(got, "192.0.2.10") {
		t.Errorf("the unit still names the old address:\n%s", got)
	}
	equal(t, "systemctl calls", f.calls, []string{stopEth0, reload, stopConsole, startEth0})
}

func TestApply_APrerequisiteThatNoLongerHoldsStopsAndRemovesTheUnit(t *testing.T) {
	selected := []string{"eth0"}
	for name, d := range map[string]portal.Decision{
		"the firewall measurement is gone": portal.Decide(portal.Selection{Enabled: ptr(true), Listen: portal.ListenManagement, ManagementInterfaces: selected}, portal.Custody{Verified: true}, portal.FirewallMeasurement{}),
		"portal.listen is local":           portal.Decide(portal.Selection{Enabled: ptr(true), Listen: portal.ListenLocal, ManagementInterfaces: selected}, portal.Custody{Verified: true}, portal.FirewallMeasurement{Holds: true}),
		"portal.enabled is false":          portal.Decide(portal.Selection{Enabled: ptr(false), Listen: portal.ListenManagement, ManagementInterfaces: selected}, portal.Custody{Verified: true}, portal.FirewallMeasurement{Holds: true}),
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			if err := f.apply(remote("eth0")); err != nil {
				t.Fatal(err)
			}
			f.console = true
			if err := f.apply(d); err != nil {
				t.Fatal(err)
			}
			if f.exists(eth0Unit) || f.active[eth0Unit] {
				t.Error("the unit is still there or active")
			}
			// The console is stopped too: it holds the closed socket's listener until it exits.
			equal(t, "systemctl calls", f.calls, []string{stopEth0, reload, stopConsole})
			if f.console {
				t.Error("the console still runs, holding the removed listener")
			}
		})
	}
}

func TestApply_AnInterfaceNoLongerSelectedLosesItsUnitAndTheOtherKeepsIt(t *testing.T) {
	f := newFixture(t)
	f.held["eth1"] = []string{"198.51.100.5"}
	if err := f.apply(remote("eth0", "eth1")); err != nil {
		t.Fatal(err)
	}
	f.console = true
	if err := f.apply(remote("eth1")); err != nil {
		t.Fatal(err)
	}
	if f.exists(eth0Unit) || !f.exists("olivares-portal-mgmt-eth1.socket") || !f.active["olivares-portal-mgmt-eth1.socket"] {
		t.Errorf("eth0 exists=%v, eth1 exists=%v active=%v", f.exists(eth0Unit), f.exists("olivares-portal-mgmt-eth1.socket"), f.active["olivares-portal-mgmt-eth1.socket"])
	}
	equal(t, "systemctl calls", f.calls, []string{stopEth0, reload, stopConsole})
}

func TestApply_TouchesNoUnitItDidNotWrite(t *testing.T) {
	f := newFixture(t)
	foreign := map[string]string{
		"olivares-portal-local.socket":        "package unit",
		"olivares-portal-mgmt-eth0.service":   "wrong suffix",
		"other-olivares-portal-mgmt-x.socket": "wrong prefix",
		".olivares-portal-mgmt-eth0.socket.1": "another writer's temporary",
	}
	for name, text := range foreign {
		if err := os.WriteFile(filepath.Join(f.dir, name), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(f.dir, "olivares-portal-mgmt-dir.socket"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := f.apply(local()); err != nil {
		t.Fatal(err)
	}
	for name, text := range foreign {
		if f.read(name) != text {
			t.Errorf("%s changed", name)
		}
	}
	if !f.exists("olivares-portal-mgmt-dir.socket") || len(f.calls) != 0 {
		t.Errorf("a directory named like a unit was touched or systemctl ran: %q", f.calls)
	}
}

func TestApply_ReplacesOrRemovesAnEntryThatIsNotAGeneratedUnit(t *testing.T) {
	f := newFixture(t)
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(f.dir, eth0Unit)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(f.dir, "olivares-portal-mgmt-eth9.socket")); err != nil {
		t.Fatal(err)
	}
	if err := f.apply(remote("eth0")); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Lstat(filepath.Join(f.dir, eth0Unit)); info == nil || !info.Mode().IsRegular() {
		t.Error("the symbolic link was not replaced by the generated unit")
	}
	if f.exists("olivares-portal-mgmt-eth9.socket") {
		t.Error("a symbolic link named like a management unit nobody asked for was left")
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != "keep" {
		t.Errorf("the link target was followed and changed: %q, %v", got, err)
	}
}

func TestApply_AFailureNeverLeavesAListenerTheDecisionDidNotAllow(t *testing.T) {
	t.Run("an address lookup that fails removes the units", func(t *testing.T) {
		f := newFixture(t)
		if err := f.apply(remote("eth0")); err != nil {
			t.Fatal(err)
		}
		g := f.generator()
		g.addresses = func(string) ([]netip.Addr, error) { return nil, errors.New("netlink") }
		f.console = true
		err := g.apply(context.Background(), remote("eth0"))
		if err == nil || !strings.Contains(err.Error(), "eth0") {
			t.Fatalf("err = %v, want the lookup failure", err)
		}
		if f.exists(eth0Unit) || f.active[eth0Unit] || f.console {
			t.Errorf("the unit exists=%v, its socket is active=%v, the console runs=%v although the address could not be read", f.exists(eth0Unit), f.active[eth0Unit], f.console)
		}
	})
	t.Run("more addresses than the console takes are skipped and said so", func(t *testing.T) {
		f := newFixture(t)
		f.held["eth0"] = nil
		for i := 1; i <= portal.MaxListenFDs; i++ {
			f.held["eth0"] = append(f.held["eth0"], netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}).String())
		}
		if err := f.apply(remote("eth0")); err != nil {
			t.Fatal(err)
		}
		// The addresses past the console's room are not served; the ones that fit still are.
		if !f.active[eth0Unit] || strings.Contains(f.read(eth0Unit), "192.0.2."+fmt.Sprint(portal.MaxListenFDs)+":") {
			t.Errorf("the socket is active=%v or the unit lists an address beyond the room:\n%s", f.active[eth0Unit], f.read(eth0Unit))
		}
		if !strings.Contains(f.out.String(), "not served") {
			t.Errorf("the journal line does not say addresses were skipped: %q", f.out.String())
		}
	})
	t.Run("a start that keeps failing is reported with systemctl's own words after the rest was tried", func(t *testing.T) {
		f := newFixture(t)
		f.held["eth1"] = []string{"198.51.100.5"}
		f.fail[startEth0] = true
		err := f.apply(remote("eth0", "eth1"))
		if err == nil || !strings.Contains(err.Error(), startEth0) || !strings.Contains(err.Error(), "Failed to start: boom") {
			t.Fatalf("err = %v, want the failed start named with systemctl's output", err)
		}
		// The console is stopped once for the refusal; the second failure has no console to blame.
		equal(t, "systemctl calls", f.calls, []string{
			reload, startEth0, stopConsole, startEth0, "systemctl start olivares-portal-mgmt-eth1.socket",
		})
		// The marker is for the destructive steps; a socket that will not start is looked at again through
		// is-active, and must not make every later run stop the console.
		if f.exists(unfinishedMarker) {
			t.Error("a start that keeps failing left the change marked unfinished")
		}
	})
}

// A connection to a socket that is already listening starts the console between the generator's
// stop and its start, and the service manager then refuses the start.
func TestApply_AConsoleStartedAgainInBetweenIsStoppedAgainAndTheStartRetried(t *testing.T) {
	f := newFixture(t)
	f.consoleBack = 1
	if err := f.apply(remote("eth0")); err != nil {
		t.Fatal(err)
	}
	equal(t, "systemctl calls", f.calls, []string{reload, startEth0, stopConsole, startEth0, stopConsole, startEth0})
	if !f.active[eth0Unit] {
		t.Error("the socket is not active")
	}
}

func TestApply_AStopThatFailsKeepsTheUnitFileSoTheNextRunStopsItAgain(t *testing.T) {
	f := newFixture(t)
	if err := f.apply(remote("eth0")); err != nil {
		t.Fatal(err)
	}
	f.console = true
	f.fail[stopEth0] = true
	err := f.apply(local())
	if err == nil || !strings.Contains(err.Error(), stopEth0) {
		t.Fatalf("err = %v, want the failed stop named", err)
	}
	if !f.exists(eth0Unit) || !f.active[eth0Unit] {
		t.Fatalf("exists=%v active=%v: the file was removed although the socket still listens, so no later run could find it", f.exists(eth0Unit), f.active[eth0Unit])
	}
	delete(f.fail, stopEth0)
	if err := f.apply(local()); err != nil {
		t.Fatal(err)
	}
	if f.exists(eth0Unit) || f.active[eth0Unit] || f.exists(unfinishedMarker) {
		t.Errorf("the next run did not finish the job: exists=%v active=%v marker=%v", f.exists(eth0Unit), f.active[eth0Unit], f.exists(unfinishedMarker))
	}
}

func TestApply_AReplacedUnitWhoseOldSocketWillNotStopKeepsItsOldTextUntilItStops(t *testing.T) {
	f := newFixture(t)
	if err := f.apply(remote("eth0")); err != nil {
		t.Fatal(err)
	}
	f.held["eth0"] = []string{"192.0.2.77"}
	f.fail[stopEth0] = true
	if err := f.apply(remote("eth0")); err == nil {
		t.Fatal("a stop that failed was not reported")
	}
	if got := f.read(eth0Unit); !strings.Contains(got, "192.0.2.10") {
		t.Fatalf("the unit was rewritten under a socket that still listens on the old address:\n%s", got)
	}
	delete(f.fail, stopEth0)
	f.console = true
	if err := f.apply(remote("eth0")); err != nil {
		t.Fatal(err)
	}
	if got := f.read(eth0Unit); !strings.Contains(got, "192.0.2.77") || !f.active[eth0Unit] {
		t.Errorf("the next run did not move the socket to the new address (active=%v):\n%s", f.active[eth0Unit], got)
	}
}

func TestApply_AConsoleStopThatFailsIsRedoneByTheNextRun(t *testing.T) {
	f := newFixture(t)
	if err := f.apply(remote("eth0")); err != nil {
		t.Fatal(err)
	}
	// The measurement is withdrawn; the unit goes, but the console will not stop.
	f.console = true
	f.fail[stopConsole] = true
	err := f.apply(local())
	if err == nil || !strings.Contains(err.Error(), stopConsole) {
		t.Fatalf("err = %v, want the failed console stop named", err)
	}
	if !f.console || f.exists(eth0Unit) {
		t.Fatalf("console running=%v, unit exists=%v: the scenario did not arise", f.console, f.exists(eth0Unit))
	}
	// Nothing is left to remove, so only the marker tells the next run the console still holds the listener.
	delete(f.fail, stopConsole)
	if err := f.apply(local()); err != nil {
		t.Fatal(err)
	}
	equal(t, "systemctl calls", f.calls, []string{reload, stopConsole})
	if f.console || f.exists(unfinishedMarker) {
		t.Errorf("console running=%v marker=%v after the next run", f.console, f.exists(unfinishedMarker))
	}
}

func TestApply_ARunKilledBeforeTheReloadIsRedoneEvenThoughTheFilesAreRight(t *testing.T) {
	f := newFixture(t)
	if err := f.apply(remote("eth0")); err != nil {
		t.Fatal(err)
	}
	// The previous run wrote the unit and was killed before the reload: the marker is all that is left of it.
	if err := os.WriteFile(filepath.Join(f.dir, unfinishedMarker), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	f.console = true
	if err := f.apply(remote("eth0")); err != nil {
		t.Fatal(err)
	}
	equal(t, "systemctl calls", f.calls, []string{reload, stopConsole})
	if f.exists(unfinishedMarker) {
		t.Error("the marker outlived the run that finished the change")
	}
}

func TestApply_AnUnstartableSocketDoesNotStopAConsoleThatIsNotRunning(t *testing.T) {
	f := newFixture(t)
	f.console = false
	f.fail[startEth0] = true
	if err := f.apply(remote("eth0")); err == nil {
		t.Fatal("a start that failed was not reported")
	}
	// With no console running the refusal is not the cause, so a stop cannot cure it and is not tried.
	equal(t, "systemctl calls", f.calls, []string{reload, startEth0})
}

func TestApply_AnUnchangedRunSaysNothingInTheJournal(t *testing.T) {
	f := newFixture(t)
	if err := f.apply(remote("eth0")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.out.String(), "changed") {
		t.Fatalf("a run that changed something said %q", f.out.String())
	}
	// The cases share one fixture and the second removes the unit the first keeps, so their order is fixed.
	for _, c := range []struct {
		name string
		d    portal.Decision
	}{{"with a socket", remote("eth0")}, {"on a default host", local()}} {
		t.Run(c.name, func(t *testing.T) {
			if c.name == "on a default host" {
				if err := f.apply(local()); err != nil { // the removal says its piece
					t.Fatal(err)
				}
			}
			f.out.Reset()
			if err := f.apply(c.d); err != nil {
				t.Fatal(err)
			}
			if f.out.Len() != 0 {
				t.Errorf("a run every two minutes that changed nothing wrote %q", f.out.String())
			}
		})
	}
}

func TestApply_AMarkerThatCannotBeWrittenBeginsNoChange(t *testing.T) {
	f := newFixture(t)
	if err := os.Mkdir(filepath.Join(f.dir, unfinishedMarker), 0o755); err != nil { // writing a file there fails
		t.Fatal(err)
	}
	err := f.apply(remote("eth0"))
	if err == nil || !strings.Contains(err.Error(), "unfinished marker") {
		t.Fatalf("err = %v, want the marker named", err)
	}
	if f.exists(eth0Unit) || len(f.calls) != 0 {
		t.Errorf("a change was begun without the marker that would let the next run finish it: unit=%v calls=%q", f.exists(eth0Unit), f.calls)
	}
}

func TestApply_ALastingLookupFailureDoesNotKeepStoppingTheConsole(t *testing.T) {
	f := newFixture(t)
	if err := f.apply(remote("eth0")); err != nil {
		t.Fatal(err)
	}
	g := f.generator()
	g.addresses = func(string) ([]netip.Addr, error) { return nil, errors.New("netlink") }
	if err := g.apply(context.Background(), remote("eth0")); err == nil {
		t.Fatal("the lookup failure was not reported")
	}
	// The units are gone and the console stopped; the failure goes on, and the change is finished.
	f.calls, f.console = nil, true
	if err := g.apply(context.Background(), remote("eth0")); err == nil {
		t.Fatal("the lookup failure was not reported again")
	}
	if len(f.calls) != 0 || !f.console || f.exists(unfinishedMarker) {
		t.Errorf("a failure that lasts re-ran the change: calls=%q console=%v marker=%v", f.calls, f.console, f.exists(unfinishedMarker))
	}
}

func TestApply_ASelectedInterfaceWithoutAnAddressIsAnUnfinishedRunButNotAChange(t *testing.T) {
	f := newFixture(t)
	f.held["eth0"] = nil
	err := f.apply(remote("eth0"))
	if err == nil || !strings.Contains(err.Error(), "no address yet on eth0") {
		t.Fatalf("err = %v, want the pending address named so that the service runs again", err)
	}
	if f.exists(eth0Unit) || len(f.calls) != 0 || f.exists(unfinishedMarker) {
		t.Errorf("a unit or a marker was written or systemctl ran (%q) with no address to listen on", f.calls)
	}
}

func TestApply_AnInterfaceWithAnAddressIsServedWhileAnotherWaits(t *testing.T) {
	f := newFixture(t)
	f.held["eth1"] = nil
	err := f.apply(remote("eth0", "eth1"))
	if err == nil || !strings.Contains(err.Error(), "no address yet on eth1") {
		t.Fatalf("err = %v, want the pending interface named", err)
	}
	if !f.active[eth0Unit] || f.exists(unfinishedMarker) {
		t.Errorf("eth0 active=%v marker=%v: the pending interface held up the other, or left its change unfinished", f.active[eth0Unit], f.exists(unfinishedMarker))
	}
}

func TestApply_AnAddressLostWhileTheSocketRunsRemovesTheSocket(t *testing.T) {
	f := newFixture(t)
	if err := f.apply(remote("eth0")); err != nil {
		t.Fatal(err)
	}
	f.held["eth0"] = nil
	f.console = true
	if err := f.apply(remote("eth0")); err == nil {
		t.Fatal("a lease that is gone was not reported")
	}
	if f.exists(eth0Unit) || f.active[eth0Unit] || f.console {
		t.Errorf("exists=%v active=%v console=%v: the socket of a gone address stayed", f.exists(eth0Unit), f.active[eth0Unit], f.console)
	}
}

func TestApply_AUnitThatCannotBeReadIsStillStoppedAndRemoved(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every file")
	}
	f := newFixture(t)
	if err := f.apply(remote("eth0")); err != nil {
		t.Fatal(err)
	}
	f.held["eth1"] = []string{"198.51.100.5"}
	if err := f.apply(remote("eth0", "eth1")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(f.dir, eth0Unit), 0); err != nil {
		t.Fatal(err)
	}
	f.console = true
	if err := f.apply(local()); err != nil {
		t.Fatal(err)
	}
	if f.exists(eth0Unit) || f.exists("olivares-portal-mgmt-eth1.socket") || f.active[eth0Unit] || f.active["olivares-portal-mgmt-eth1.socket"] {
		t.Error("one unreadable unit kept every socket up")
	}
}

func TestApply_AUnitDirectoryThatCannotBeListedIsAnError(t *testing.T) {
	f := newFixture(t)
	file := filepath.Join(f.dir, "not-a-directory")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	g := f.generator()
	g.dir = file
	if err := g.apply(context.Background(), remote("eth0")); err == nil {
		t.Fatal("a unit directory that is a file was accepted")
	}
}

func TestRunWith_AppliesAgainWhileTheFilesChangeUnderIt(t *testing.T) {
	f := newFixture(t)
	g := f.generator()
	// The measurement is withdrawn during the first run: the decision read after it is not the one applied.
	reads := []portal.Decision{remote("eth0"), local(), local(), local()}
	decide := func() (portal.Decision, string) {
		d := reads[0]
		if len(reads) > 1 {
			reads = reads[1:]
		}
		return d, ""
	}
	var stderr bytes.Buffer
	if code := runWith(context.Background(), decide, g, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if f.exists(eth0Unit) || f.active[eth0Unit] {
		t.Errorf("the withdrawal that landed mid-run was lost: exists=%v active=%v", f.exists(eth0Unit), f.active[eth0Unit])
	}
}

func TestRunWith_FilesThatKeepChangingAreAFailureTheServiceRunsAgain(t *testing.T) {
	f := newFixture(t)
	next := 0
	decide := func() (portal.Decision, string) {
		next++
		if next%2 == 1 {
			return remote("eth0"), ""
		}
		return local(), ""
	}
	var stderr bytes.Buffer
	code := runWith(context.Background(), decide, f.generator(), &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "<3>the selection or the firewall measurement kept changing") {
		t.Errorf("exit %d, stderr %q: a change that landed after the last attempt was dropped with exit 0", code, stderr.String())
	}
}

func TestRunWith_ExitCodesAndJournalPriorities(t *testing.T) {
	t.Run("a finished run exits 0 and prints no error line", func(t *testing.T) {
		f := newFixture(t)
		var stderr bytes.Buffer
		code := runWith(context.Background(), func() (portal.Decision, string) { return remote("eth0"), "" }, f.generator(), &stderr)
		if code != 0 || stderr.Len() != 0 {
			t.Errorf("exit %d, stderr %q", code, stderr.String())
		}
	})
	t.Run("an unfinished run exits 1 with every line at error priority", func(t *testing.T) {
		f := newFixture(t)
		f.held["eth0"] = nil
		var stderr bytes.Buffer
		code := runWith(context.Background(), func() (portal.Decision, string) { return remote("eth0"), "" }, f.generator(), &stderr)
		if code != 1 || !strings.HasPrefix(stderr.String(), "<3>no address yet on eth0") {
			t.Errorf("exit %d, stderr %q", code, stderr.String())
		}
	})
	t.Run("a refused selection is a warning, not a failure", func(t *testing.T) {
		f := newFixture(t)
		var stderr bytes.Buffer
		code := runWith(context.Background(), func() (portal.Decision, string) { return local(), "the published selection is not one" }, f.generator(), &stderr)
		if code != 0 || !strings.HasPrefix(stderr.String(), "<4>the published selection") {
			t.Errorf("exit %d, stderr %q", code, stderr.String())
		}
	})
}

func TestRun_TakesNoArguments(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--help"}, &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "usage") {
		t.Errorf("run with an argument = %d, %q", code, stderr.String())
	}
}

func TestInterfaceAddresses_AnInterfaceThatIsNotThereHoldsNone(t *testing.T) {
	addrs, err := interfaceAddresses("olv-no-such-if")
	if err != nil || len(addrs) != 0 {
		t.Errorf("addresses = %v, err = %v", addrs, err)
	}
	lo, err := net.InterfaceByName("lo")
	if err != nil || lo.Flags&net.FlagUp == 0 {
		t.Skip("this namespace has no loopback that is up")
	}
	got, err := interfaceAddresses("lo")
	if err != nil || len(got) == 0 || !got[0].IsLoopback() {
		t.Errorf("lo addresses = %v, err = %v", got, err)
	}
}
