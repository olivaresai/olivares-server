// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

// olivares-portal-sockets makes the socket units that expose the Appliance Console on the
// management interfaces, and removes them when a prerequisite no longer holds.
//
// The console binds no socket, so a remote listener is a socket unit per management interface
// (portal.ManagementSockets). This program is the one place that writes them. It runs as root
// when the host may have changed what they depend on: after the network is online at boot, and
// whenever the selection or the firewall owner's measurement is published. It decides as the
// console does, from the published selection and the owner's measurement, then makes
// /run/systemd/system match: it writes a unit only while portal.enabled is true, portal.listen is
// management, an interface is selected and the firewall measurement holds, and stops and removes
// every unit it wrote otherwise. The addresses come from the kernel now, because a DHCP lease is
// not known at first boot.
//
// The console holds the sockets it was passed until it exits, and the service manager refuses to
// start a socket while the service it triggers is running. So the program stops the console
// before it starts a socket, and again when it removes one; the next connection to a socket that
// is listening starts a console that is passed the current set.
//
// Whatever it cannot do it reports with a non-zero exit: a selected interface that holds no
// address yet, a socket that would not stop or start. Its timer runs it again every two minutes,
// which also picks up what no file change announces (a lease that moved, a socket that failed by
// itself, a publication that landed while it ran). A unit file stays until its socket has
// stopped, so a run that follows finds it again. A marker beside the units says a change was
// begun and not finished (a run killed in the middle, a reload or a console stop that failed);
// the next run then reloads and stops the console again whatever the files say.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/olivaresai/olivares/appliance/layer/portal"
)

const (
	usage = "usage: olivares-portal-sockets"
	// unitDirectory is where the service manager reads runtime units; /run is empty after a reboot.
	unitDirectory = "/run/systemd/system"
	consoleUnit   = "olivares-portal.service"
	runTimeout    = 4 * time.Minute
	// startAttempts bounds how often a socket start is tried when a connection to a socket that
	// is already listening has started the console again in between.
	startAttempts = 3
	// decisionAttempts bounds how often the program applies a decision again because the files it
	// decided from changed while it ran.
	decisionAttempts = 3
	// maxUnitBytes bounds a unit read back; a generated unit is far smaller.
	maxUnitBytes = 16 << 10
	// unfinishedMarker names the file, beside the units and ending in no unit suffix, that exists
	// from the first change of a run until the run has finished it.
	unfinishedMarker = ".olivares-portal-mgmt.unfinished"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		_, _ = fmt.Fprintln(stderr, usage)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), runTimeout)
	defer cancel()
	g := generator{dir: unitDirectory, addresses: interfaceAddresses, run: systemctl, out: stdout}
	return runWith(ctx, portal.DecideHost, g, stderr)
}

// runWith applies the decision the host's files give, and again while those files changed during
// the run: the path unit starts no second run of a service that is still running, so a
// publication that lands mid-run would otherwise be lost.
func runWith(ctx context.Context, decide func() (portal.Decision, string), g generator, stderr io.Writer) int {
	var failure error
	settled := false
	for attempt := 0; attempt < decisionAttempts && !settled; attempt++ {
		d, reason := decide()
		if reason != "" {
			_, _ = fmt.Fprintln(stderr, "<4>"+reason+"; serving as if none were published")
		}
		failure = g.apply(ctx, d)
		later, _ := decide()
		settled = reflect.DeepEqual(later, d)
	}
	if !settled {
		failure = errors.Join(failure, errors.New("the selection or the firewall measurement kept changing while the sockets were made"))
	}
	if failure == nil {
		return 0
	}
	// "<3>" is the journal's error priority, so `journalctl -p err` shows the failure.
	for _, line := range strings.Split(failure.Error(), "\n") {
		_, _ = fmt.Fprintln(stderr, "<3>"+line)
	}
	return 1
}

// generator makes a directory of runtime units match a decision.
type generator struct {
	dir       string
	addresses func(iface string) ([]netip.Addr, error)
	// run runs systemctl with the arguments and returns its output.
	run func(ctx context.Context, args ...string) ([]byte, error)
	out io.Writer
}

// apply stops and removes the units the decision no longer asks for, writes the ones it does, and
// starts them. Whatever cannot be done is reported after the rest was tried; a decision whose
// units cannot be made asks for none, so a failure never leaves a listener the decision did not
// allow.
func (g generator) apply(ctx context.Context, d portal.Decision) error {
	plan, planErr := portal.ManagementSockets(d, g.addresses)
	present, err := g.present()
	if err != nil {
		return errors.Join(planErr, err)
	}
	wanted := map[string]string{}
	for _, u := range plan.Units {
		wanted[u.Name] = u.Text
	}
	var errs []error
	if planErr != nil {
		errs = append(errs, planErr)
	}
	// What the destructive steps below report is counted from here; planErr is a lasting condition of
	// the host and must not keep a finished change marked unfinished.
	steps := len(errs)
	marker := filepath.Join(g.dir, unfinishedMarker)
	// A marker that cannot be inspected is not a marker that is absent.
	_, markerErr := os.Lstat(marker)
	unfinished := !errors.Is(markerErr, os.ErrNotExist)

	// What the files say is stale: units that are no longer wanted or whose text differs.
	var stale, fresh []string
	for _, name := range slices.Sorted(maps.Keys(present)) {
		if text, keep := wanted[name]; !keep || text != present[name] {
			stale = append(stale, name)
		}
	}
	for _, u := range plan.Units {
		if present[u.Name] != u.Text {
			fresh = append(fresh, u.Name)
		}
	}
	changed := unfinished || len(stale) > 0 || len(fresh) > 0
	if changed {
		// Without the marker a change that fails half way could not be told to the next run, so no
		// effect is begun.
		if err := markUnfinished(g.dir, marker); err != nil {
			g.report(d, plan, changed, true)
			return errors.Join(append(errs, err)...)
		}
	}

	stopFailed := map[string]bool{}
	for _, name := range stale {
		_, keep := wanted[name]
		stopErr := g.systemctl(ctx, "stop", name)
		if stopErr != nil {
			errs = append(errs, stopErr)
			stopFailed[name] = true
		}
		// The file stays while its socket may still run, so that the next run finds it and stops it.
		if !keep && stopErr == nil {
			if err := os.Remove(filepath.Join(g.dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, fmt.Errorf("%s cannot be removed: %w", name, err))
			}
		}
	}
	for _, u := range plan.Units {
		if present[u.Name] == u.Text {
			continue
		}
		// A unit whose old socket would not stop keeps its old text, so the next run stops it again.
		if stopFailed[u.Name] {
			delete(wanted, u.Name)
			continue
		}
		if err := writeAtomic(g.dir, u.Name, u.Text); err != nil {
			errs = append(errs, fmt.Errorf("%s cannot be written: %w", u.Name, err))
			delete(wanted, u.Name)
		}
	}
	if changed {
		if err := g.systemctl(ctx, "daemon-reload"); err != nil {
			errs = append(errs, err)
		}
	}
	// A console that was passed a socket this run removed or replaced still listens on it, and one
	// that an earlier run left half done may hold any set: stop it, so the next connection starts one
	// with the current sockets. A socket only added needs no stop unless the manager refuses its start.
	if len(stale) > 0 || unfinished {
		if err := g.systemctl(ctx, "stop", consoleUnit); err != nil {
			errs = append(errs, err)
		}
	}
	// The marker is for the steps above. A socket that will not start is looked at again by the next
	// run through its is-active check, and must not make that run stop the console each time.
	if changed && len(errs) == steps {
		if err := os.Remove(marker); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("the unfinished marker cannot be removed: %w", err))
		}
	}
	for _, u := range plan.Units {
		if _, ok := wanted[u.Name]; !ok || g.systemctl(ctx, "is-active", "--quiet", u.Name) == nil {
			continue
		}
		if err := g.start(ctx, u.Name); err != nil {
			errs = append(errs, err)
		}
	}
	// An address still to come is not a failed change: the marker stays clear, and the timer runs
	// this again to look.
	if len(plan.Waiting) > 0 {
		errs = append(errs, fmt.Errorf("no address yet on %s", strings.Join(plan.Waiting, ", ")))
	}
	g.report(d, plan, changed, len(errs) > 0)
	return errors.Join(errs...)
}

// report writes one line to the journal.
func (g generator) report(d portal.Decision, plan portal.SocketPlan, changed, incomplete bool) {
	// The timer runs this every two minutes: say nothing when nothing changed and nothing is wrong.
	if !changed && !incomplete {
		return
	}
	names := make([]string, 0, len(plan.Units))
	for _, u := range plan.Units {
		names = append(names, strings.TrimSuffix(strings.TrimPrefix(u.Name, portal.ManagementSocketPrefix), portal.ManagementSocketSuffix))
	}
	state := "changed"
	if incomplete {
		state = "incomplete"
	}
	if len(names) > 0 {
		_, _ = fmt.Fprintf(g.out, "management sockets %s: console on %s", state, strings.Join(names, ", "))
	} else {
		_, _ = fmt.Fprintf(g.out, "management sockets %s: none", state)
		if len(d.Reasons) > 0 {
			_, _ = fmt.Fprintf(g.out, " (%s)", strings.Join(d.Reasons, "; "))
		}
	}
	if plan.Skipped > 0 {
		_, _ = fmt.Fprintf(g.out, "; %d addresses beyond the console's %d passed sockets are not served", plan.Skipped, portal.MaxListenFDs)
	}
	_, _ = fmt.Fprintln(g.out)
}

// markUnfinished records that a change was begun, before its first effect.
func markUnfinished(dir, marker string) error {
	// #nosec G301 -- the service manager's own runtime unit directory is 0755.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("%s cannot be made: %w", dir, err)
	}
	if err := os.WriteFile(marker, nil, 0o600); err != nil {
		return fmt.Errorf("the unfinished marker cannot be written: %w", err)
	}
	return nil
}

// start starts a socket. The service manager refuses while the service the socket triggers runs,
// so when a start fails and the console runs, the console is stopped and the start tried again, as
// often as startAttempts: a connection to a socket that is already listening can start the console
// again in between. A start that fails with the console stopped is not one a stop cures, and a
// console that is not running is not stopped in vain.
func (g generator) start(ctx context.Context, name string) error {
	var errs []error
	for attempt := 0; attempt < startAttempts; attempt++ {
		err := g.systemctl(ctx, "start", name)
		if err == nil {
			return nil
		}
		errs = append(errs, err)
		if g.systemctl(ctx, "is-active", "--quiet", consoleUnit) != nil {
			break
		}
		if err := g.systemctl(ctx, "stop", consoleUnit); err != nil {
			errs = append(errs, err)
			break
		}
	}
	return errors.Join(errs...)
}

// systemctl runs systemctl with fixed arguments and names the failed command.
func (g generator) systemctl(ctx context.Context, args ...string) error {
	if out, err := g.run(ctx, args...); err != nil {
		return fmt.Errorf("systemctl %s failed: %w%s", strings.Join(args, " "), err, outputOf(out))
	}
	return nil
}

func outputOf(out []byte) string {
	if text := strings.TrimSpace(string(out)); text != "" {
		return ": " + text
	}
	return ""
}

// systemctl runs the service manager's own client with arguments this program fixes, never ones
// it reads from a file or the network.
func systemctl(ctx context.Context, args ...string) ([]byte, error) {
	// #nosec G204 -- the program is the literal /usr/bin/systemctl and every caller passes constant arguments and a unit name this program generated.
	return exec.CommandContext(ctx, "/usr/bin/systemctl", args...).CombinedOutput()
}

// present returns the units this program wrote earlier in this boot, by name with their text. An
// entry that is not a regular file, or cannot be read, has no text of a generated unit and so
// never matches one: it is replaced if the decision asks for it and stopped and removed if not.
func (g generator) present() (map[string]string, error) {
	entries, err := os.ReadDir(g.dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%s cannot be listed: %w", g.dir, err)
	}
	present := map[string]string{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, portal.ManagementSocketPrefix) || !strings.HasSuffix(name, portal.ManagementSocketSuffix) || e.IsDir() {
			continue
		}
		present[name] = "\x00not a generated unit"
		if !e.Type().IsRegular() {
			continue
		}
		if text, err := readBounded(filepath.Join(g.dir, name)); err == nil {
			present[name] = text
		}
	}
	return present, nil
}

func readBounded(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxUnitBytes+1))
	if err != nil {
		return "", err
	}
	if len(data) > maxUnitBytes {
		return "\x00too large", nil
	}
	return string(data), nil
}

// writeAtomic makes dir/name hold text, mode 0644, all at once: the service manager never reads a
// half-written unit. The temporary name ends in no unit suffix, so it is never a unit.
func writeAtomic(dir, name, text string) error {
	// #nosec G301 -- the service manager's own runtime unit directory is 0755.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+name+".")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if _, err := f.WriteString(text); err != nil {
		_ = f.Close()
		return err
	}
	// #nosec G302 -- a unit is world-readable by convention; the directory is root's and 0755 so the manager and tools can read it.
	if err := f.Chmod(0o644); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, name))
}

// interfaceAddresses returns the addresses the kernel reports on the named interface now; an
// interface that is not there holds none.
func interfaceAddresses(name string) ([]netip.Addr, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range interfaces {
		if iface.Name != name {
			continue
		}
		held, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		var addrs []netip.Addr
		for _, a := range held {
			if ipNet, ok := a.(*net.IPNet); ok {
				if addr, ok := netip.AddrFromSlice(ipNet.IP); ok {
					addrs = append(addrs, addr)
				}
			}
		}
		return addrs, nil
	}
	return nil, nil
}
