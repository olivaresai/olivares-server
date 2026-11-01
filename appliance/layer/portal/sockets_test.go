// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package portal

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// held maps an interface to the addresses it holds, as the kernel would report them.
func held(byInterface map[string][]string) func(string) ([]netip.Addr, error) {
	return func(iface string) ([]netip.Addr, error) {
		var out []netip.Addr
		for _, text := range byInterface[iface] {
			out = append(out, netip.MustParseAddr(text))
		}
		return out, nil
	}
}

// neverLooksUp fails the test if the generator asks the kernel for an address.
func neverLooksUp(t *testing.T) func(string) ([]netip.Addr, error) {
	return func(iface string) ([]netip.Addr, error) {
		t.Errorf("the generator looked up the addresses of %s although the console may not listen remotely", iface)
		return nil, nil
	}
}

func TestManagementSockets_OneUnitPerInterfaceBoundToItsDevice(t *testing.T) {
	d := Decide(remoteSelection(), Custody{Verified: true}, measuredFirewall())
	plan, err := ManagementSockets(d, held(map[string][]string{"eth0": {
		"2001:db8::10", "192.0.2.10", "fe80::1", "192.0.2.10", "::ffff:192.0.2.10", "::ffff:192.0.2.11", "127.0.0.1", "0.0.0.0", "::", "ff02::1",
	}}))
	if err != nil || len(plan.Units) != 1 || len(plan.Waiting) != 0 {
		t.Fatalf("plan = %+v, err = %v; want one unit and nothing waiting", plan, err)
	}
	unit := plan.Units[0]
	if unit.Name != "olivares-portal-mgmt-eth0.socket" {
		t.Errorf("unit name = %q", unit.Name)
	}
	parsed := parseUnit(t, unit.Name, unit.Text)
	socket := func(key string) []string { return parsed.values("Socket", key) }
	if got, want := socket("ListenStream"), []string{"192.0.2.10:9443", "192.0.2.11:9443", "[2001:db8::10]:9443"}; !slices.Equal(got, want) {
		t.Errorf("ListenStream = %v, want %v (global unicast only, sorted, one each, 4-in-6 unmapped)", got, want)
	}
	for key, want := range map[string]string{"BindToDevice": "eth0", "Service": "olivares-portal.service", "FreeBind": "yes"} {
		if got := socket(key); !slices.Equal(got, []string{want}) {
			t.Errorf("%s = %v, want %q", key, got, want)
		}
	}
	for _, stream := range socket("ListenStream") {
		if addr := netip.MustParseAddrPort(stream).Addr(); addr.IsUnspecified() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
			t.Errorf("ListenStream=%s is not a served address", stream)
		}
	}
	if len(parsed["Install"]) != 0 {
		t.Errorf("the generated unit has an [Install] section: %v", parsed["Install"])
	}
}

func TestManagementSockets_WriteNothingUnlessEveryPrerequisiteHolds(t *testing.T) {
	selection := func(mutate func(*Selection)) Selection {
		s := remoteSelection()
		mutate(&s)
		return s
	}
	unmeasured, notHeld := FirewallMeasurement{}, FirewallMeasurement{Policy: Measured("input drop; 9443/tcp on every interface")}
	for name, c := range map[string]struct {
		selection Selection
		firewall  FirewallMeasurement
	}{
		"portal.enabled is false":     {selection(func(s *Selection) { s.Enabled = enabled(false) }), measuredFirewall()},
		"portal.enabled is absent":    {selection(func(s *Selection) { s.Enabled = nil }), measuredFirewall()},
		"portal.listen is local":      {selection(func(s *Selection) { s.Listen = ListenLocal }), measuredFirewall()},
		"portal.listen is absent":     {selection(func(s *Selection) { s.Listen = "" }), measuredFirewall()},
		"no management interface":     {selection(func(s *Selection) { s.ManagementInterfaces = nil }), measuredFirewall()},
		"no firewall measurement":     {remoteSelection(), unmeasured},
		"the firewall does not admit": {remoteSelection(), notHeld},
	} {
		t.Run(name, func(t *testing.T) {
			d := Decide(c.selection, Custody{Verified: true}, c.firewall)
			// With no interface the plan is empty whatever the decision, so the decision itself is checked.
			if d.Mode == Remote {
				t.Fatalf("Decide = %+v, want a decision short of Remote", d)
			}
			plan, err := ManagementSockets(d, neverLooksUp(t))
			if err != nil || len(plan.Units) != 0 || len(plan.Waiting) != 0 {
				t.Fatalf("plan = %+v, err = %v; want no unit", plan, err)
			}
		})
	}

	// Only Decide's Remote mode asks for units, whatever interfaces a decision lists.
	for _, mode := range []Mode{Disabled, LocalOnly} {
		t.Run("a "+string(mode)+" decision that lists an interface", func(t *testing.T) {
			plan, err := ManagementSockets(Decision{Mode: mode, Interfaces: []string{"eth0"}}, neverLooksUp(t))
			if err != nil || len(plan.Units) != 0 || len(plan.Waiting) != 0 {
				t.Fatalf("plan = %+v, err = %v; want no unit", plan, err)
			}
		})
	}

	t.Run("control: all four hold", func(t *testing.T) {
		d := Decide(remoteSelection(), Custody{Verified: true}, measuredFirewall())
		plan, err := ManagementSockets(d, held(map[string][]string{"eth0": {"192.0.2.10"}}))
		if err != nil || len(plan.Units) != 1 {
			t.Fatalf("plan = %+v, err = %v; want one unit", plan, err)
		}
	})
}

func TestManagementSockets_AnInterfaceWithoutAUsableAddressWaits(t *testing.T) {
	s := remoteSelection()
	s.ManagementInterfaces = []string{"eth1", "eth0", "eth2"}
	d := Decide(s, Custody{Verified: true}, measuredFirewall())
	plan, err := ManagementSockets(d, held(map[string][]string{
		"eth0": {"192.0.2.10"},
		"eth1": {"fe80::1", "127.0.0.1"}, // no global address yet
	}))
	if err != nil {
		t.Fatal(err)
	}
	if names := unitNames(plan); !slices.Equal(names, []string{"olivares-portal-mgmt-eth0.socket"}) {
		t.Errorf("units = %v, want eth0 only", names)
	}
	if !slices.Equal(plan.Waiting, []string{"eth1", "eth2"}) {
		t.Errorf("waiting = %v, want [eth1 eth2]", plan.Waiting)
	}
}

func unitNames(plan SocketPlan) []string {
	var names []string
	for _, u := range plan.Units {
		names = append(names, u.Name)
	}
	return names
}

func TestManagementSockets_ListenOnWhatTheConsoleCanHoldAndNeverFewer(t *testing.T) {
	remote := func(ifaces ...string) Decision {
		s := remoteSelection()
		s.ManagementInterfaces = ifaces
		return Decide(s, Custody{Verified: true}, measuredFirewall())
	}
	room := MaxListenFDs - fixedListenFDs
	v4 := func(n int) []string {
		var out []string
		for i := 1; i <= n; i++ {
			out = append(out, netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}).String())
		}
		return out
	}
	streams := func(plan SocketPlan) (count int) {
		for _, u := range plan.Units {
			count += len(parseUnit(t, u.Name, u.Text).values("Socket", "ListenStream"))
		}
		return count
	}

	t.Run("addresses past the room are skipped, not the whole interface", func(t *testing.T) {
		held := append([]string{"2001:db8::1"}, v4(room)...) // room+1 usable; IPv4 sorts first
		plan, err := ManagementSockets(remote("eth0"), held2("eth0", held))
		if err != nil || len(plan.Units) != 1 || streams(plan) != room || plan.Skipped != 1 {
			t.Fatalf("plan = %+v (streams %d), err = %v; want one unit with %d streams and 1 skipped", plan, streams(plan), err, room)
		}
		if strings.Contains(plan.Units[0].Text, "2001:db8::1") {
			t.Error("the IPv6 address was kept and an IPv4 one dropped")
		}
	})
	t.Run("an interface that fits skips nothing, whatever else it holds", func(t *testing.T) {
		held := append(v4(room), "fe80::1", "fe80::2", "fe80::3", "127.0.0.1", "ff02::1")
		plan, err := ManagementSockets(remote("eth0"), held2("eth0", held))
		if err != nil || streams(plan) != room || plan.Skipped != 0 {
			t.Fatalf("plan = %+v, err = %v; want %d streams, none skipped", plan, err, room)
		}
	})
	t.Run("the room is shared round-robin, so one interface cannot starve another", func(t *testing.T) {
		both := map[string][]string{"eth0": v4(room + 3), "eth1": {"198.51.100.1", "198.51.100.2"}}
		plan, err := ManagementSockets(remote("eth0", "eth1"), held(both))
		if err != nil || len(plan.Units) != 2 || streams(plan) != room {
			t.Fatalf("plan = %+v (streams %d), err = %v; want both interfaces served within %d streams", plan, streams(plan), err, room)
		}
		for _, u := range plan.Units {
			n := len(parseUnit(t, u.Name, u.Text).values("Socket", "ListenStream"))
			if u.Name == "olivares-portal-mgmt-eth1.socket" && n != 2 {
				t.Errorf("eth1 got %d streams, want the 2 it holds", n)
			}
		}
		if plan.Skipped != 5 {
			t.Errorf("skipped = %d, want 5 (the %d of eth0 that do not fit, less the room eth1 does not use)", plan.Skipped, room+3)
		}
	})
	t.Run("more interfaces than the room give each of the first ones an address", func(t *testing.T) {
		many := map[string][]string{}
		var names []string
		for i := 0; i < room+2; i++ {
			name := fmt.Sprintf("eth%d", i)
			names = append(names, name)
			many[name] = []string{fmt.Sprintf("198.51.100.%d", i+1)}
		}
		plan, err := ManagementSockets(remote(names...), held(many))
		if err != nil || len(plan.Units) != room || plan.Skipped != 2 || len(plan.Waiting) != 0 {
			t.Fatalf("plan has %d units, %d skipped, waiting %v, err %v; want %d units and 2 skipped", len(plan.Units), plan.Skipped, plan.Waiting, err, room)
		}
	})
	t.Run("an address lookup that fails", func(t *testing.T) {
		plan, err := ManagementSockets(remote("eth0"), func(string) ([]netip.Addr, error) { return nil, errors.New("netlink") })
		if err == nil || len(plan.Units) != 0 {
			t.Fatalf("plan = %+v, err = %v; want an error and no unit", plan, err)
		}
	})
	t.Run("a name that is not an interface name", func(t *testing.T) {
		for _, name := range []string{"eth0\nExecStart=/bin/sh", "eth 0", "../x", "", "a-name-longer-than-fifteen"} {
			d := Decision{Mode: Remote, Interfaces: []string{name}}
			if plan, err := ManagementSockets(d, held(map[string][]string{name: {"192.0.2.10"}})); err == nil || len(plan.Units) != 0 {
				t.Errorf("name %q: plan = %+v, err = %v; want an error and no unit", name, plan, err)
			}
		}
	})
	t.Run("units come out sorted whatever the order of the decision", func(t *testing.T) {
		d := Decision{Mode: Remote, Interfaces: []string{"eth1", "eth0"}}
		plan, err := ManagementSockets(d, held(map[string][]string{"eth0": {"192.0.2.1"}, "eth1": {"198.51.100.1"}}))
		if err != nil || !slices.Equal(unitNames(plan), []string{"olivares-portal-mgmt-eth0.socket", "olivares-portal-mgmt-eth1.socket"}) {
			t.Fatalf("units = %v, err = %v", unitNames(plan), err)
		}
	})
}

// held2 is held for one interface.
func held2(iface string, addresses []string) func(string) ([]netip.Addr, error) {
	return held(map[string][]string{iface: addresses})
}

// The generated unit keeps the limit envelope of olivares-portal.socket, so a connection storm on a
// management address is bounded as it is on loopback.
func TestManagementSockets_KeepTheLoopbackSocketsLimitEnvelope(t *testing.T) {
	d := Decide(remoteSelection(), Custody{Verified: true}, measuredFirewall())
	plan, err := ManagementSockets(d, held(map[string][]string{"eth0": {"192.0.2.10"}}))
	if err != nil || len(plan.Units) != 1 {
		t.Fatalf("plan = %+v, err = %v", plan, err)
	}
	generated := parseUnit(t, "generated", plan.Units[0].Text)
	limits := readUnit(t, "units/olivares-portal.socket.d/30-host-operations.conf")
	if len(limits["Socket"]) == 0 {
		t.Fatal("the drop-in sets no limit")
	}
	for key, want := range limits["Socket"] {
		if got := generated.values("Socket", key); !slices.Equal(got, want) {
			t.Errorf("%s = %v, want the loopback socket's %v", key, got, want)
		}
	}
}

// The console refuses to start with more than MaxListenFDs passed sockets, so the generator keeps
// room by the number of sockets the package's own units pass: one for every Listen* line of the
// units that start the console.
func TestManagementSockets_RoomIsWhatThePackagesOwnSocketsLeave(t *testing.T) {
	units, err := filepath.Glob("units/*.socket")
	if err != nil || len(units) == 0 {
		t.Fatalf("no socket units: %v", err)
	}
	passed := 0
	for _, path := range units {
		u := readUnit(t, path)
		service := u.values("Socket", "Service")
		starts := slices.Equal(service, []string{"olivares-portal.service"}) ||
			(len(service) == 0 && filepath.Base(path) == "olivares-portal.socket") // named after the service, it starts it by default
		if !starts {
			continue
		}
		for key, values := range u["Socket"] {
			if strings.HasPrefix(key, "Listen") {
				passed += len(values)
			}
		}
	}
	if passed != fixedListenFDs {
		t.Errorf("the package's sockets pass %d descriptors to the console, fixedListenFDs is %d", passed, fixedListenFDs)
	}
}

func TestDecideHost_ReadsTheFilesTheConsoleReads(t *testing.T) {
	dir := t.TempDir()
	files := hostFiles{
		selection:   publish(t, dir, publishedSelection), // management on eth0 and eth1
		measurement: filepath.Join(dir, "measured.json"),
		bootID:      writeBootID(t, dir),
	}
	ownedByRoot(t, files.selection)

	if d, _ := files.decide(); d.Mode != LocalOnly {
		t.Fatalf("with no measurement the decision is %+v, want local-only", d)
	}
	writeMeasurement(t, files.measurement, measurement(testBootID, "drop", row("9443/tcp", "eth0", "eth1")))
	ownedByRoot(t, files.measurement)
	d, reason := files.decide()
	if d.Mode != Remote || !slices.Equal(d.Interfaces, []string{"eth0", "eth1"}) || reason != "" {
		t.Fatalf("with the owner's measurement the decision is %+v (%q), want remote on eth0 and eth1", d, reason)
	}
	// The firewall stops admitting eth1: the decision follows the file at once.
	writeMeasurement(t, files.measurement, measurement(testBootID, "drop", row("9443/tcp", "eth0")))
	if d, _ := files.decide(); d.Mode != LocalOnly {
		t.Fatalf("a measurement that admits only eth0 for a selection of eth0 and eth1: %+v", d)
	}
	// A refused selection is served as none and the reason is returned for the log.
	if err := os.WriteFile(files.selection, []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if d, reason := files.decide(); d.Mode != LocalOnly || !strings.Contains(reason, "published selection") {
		t.Fatalf("a refused selection gave %+v (%q)", d, reason)
	}
}
