// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package portal

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

const socketsProgram = "/usr/libexec/olivares/olivares-portal-sockets"

func TestPortalSocketsUnits_RunTheGeneratorAfterTheNetworkIsOnlineAndOnEveryMeasurement(t *testing.T) {
	service := readUnit(t, "units/olivares-portal-sockets.service")
	if got := service.values("Service", "ExecStart"); !slices.Equal(got, []string{socketsProgram}) {
		t.Errorf("ExecStart = %v, want %s alone, with no argument", got, socketsProgram)
	}
	for section, want := range map[string]map[string][]string{
		"Unit": {
			"After": {"network-online.target olivares-firewall.service"},
			"Wants": {"network-online.target"},
			// A tripped start limit would fail the path unit and leave a socket the measurement no longer allows.
			"StartLimitIntervalSec": {"0"},
		},
		"Service": {
			"Type":                    {"oneshot"},
			"User":                    {"root"},
			"ReadWritePaths":          {"/run/systemd/system"},
			"ProtectSystem":           {"strict"},
			"NoNewPrivileges":         {"yes"},
			"CapabilityBoundingSet":   {""},
			"AmbientCapabilities":     {""},
			"RestrictAddressFamilies": {"AF_UNIX AF_NETLINK"},
			"IPAddressDeny":           {"any"},
			"PrivateDevices":          {"yes"},
			"MemoryDenyWriteExecute":  {"yes"},
			"TimeoutStartSec":         {"270"},
		},
		"Install": {"WantedBy": {"multi-user.target"}},
	} {
		for key, values := range want {
			if got := service.values(section, key); !slices.Equal(got, values) {
				t.Errorf("[%s] %s = %q, want %q", section, key, got, values)
			}
		}
	}
	// It is not the Appliance Console: it requires nothing and orders nothing before it.
	for _, key := range []string{"Requires", "BindsTo", "PartOf", "Before"} {
		if got := service.values("Unit", key); len(got) != 0 {
			t.Errorf("the generator declares %s=%v", key, got)
		}
	}

	// The timer is the backstop for what no file announces: a lease that moved, a socket that failed by
	// itself, a selected interface still waiting for its address, a publication that landed mid-run.
	timer := readUnit(t, "units/olivares-portal-sockets.timer")
	for key, want := range map[string]string{"OnBootSec": "2min", "OnUnitInactiveSec": "2min", "Unit": "olivares-portal-sockets.service"} {
		if got := timer.values("Timer", key); !slices.Equal(got, []string{want}) {
			t.Errorf("[Timer] %s = %v, want %q", key, got, want)
		}
	}
	if got := timer.values("Install", "WantedBy"); !slices.Equal(got, []string{"timers.target"}) {
		t.Errorf("the timer's WantedBy = %v", got)
	}

	path := readUnit(t, "units/olivares-portal-sockets.path")
	if got := path.values("Path", "PathChanged"); !slices.Equal(got, []string{MeasurementFile, SelectionFile}) {
		t.Errorf("PathChanged = %v, want the firewall owner's measurement %s and the selection %s", got, MeasurementFile, SelectionFile)
	}
	if got := path.values("Path", "Unit"); !slices.Equal(got, []string{"olivares-portal-sockets.service"}) {
		t.Errorf("Unit = %v", got)
	}
	if got := path.values("Install", "WantedBy"); !slices.Equal(got, []string{"multi-user.target"}) {
		t.Errorf("WantedBy = %v", got)
	}
}

// Nothing the generator may write is a unit the package ships, whatever an interface is called.
func TestPortalSocketsUnits_TheGeneratedNamesCannotCollideWithAPackagedUnit(t *testing.T) {
	entries, err := os.ReadDir("units")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ManagementSocketPrefix) {
			t.Errorf("the package ships %s, which the generator would overwrite or remove", e.Name())
		}
	}
	// The one name pattern reaches no other unit: prefix, a valid interface name, suffix.
	longest := ManagementSocketPrefix + strings.Repeat("a", 15) + ManagementSocketSuffix
	if !regexp.MustCompile(`^olivares-portal-mgmt-[A-Za-z0-9][A-Za-z0-9._-]{0,14}\.socket$`).MatchString(longest) {
		t.Errorf("%s is not a unit name of the generated form", longest)
	}
}

func TestPortalPackage_ShipsTheSocketGeneratorBuildsItAndEnablesItsThreeUnits(t *testing.T) {
	p := readPortalPackage(t)
	shipped := p.shipped()
	for dst, src := range map[string]string{
		socketsProgram: "bin/olivares-portal-sockets",
		"/usr/lib/systemd/system/olivares-portal-sockets.service": "appliance/layer/portal/units/olivares-portal-sockets.service",
		"/usr/lib/systemd/system/olivares-portal-sockets.path":    "appliance/layer/portal/units/olivares-portal-sockets.path",
		"/usr/lib/systemd/system/olivares-portal-sockets.timer":   "appliance/layer/portal/units/olivares-portal-sockets.timer",
	} {
		if shipped[dst] != src {
			t.Errorf("the package ships %s from %q, want %s", dst, shipped[dst], src)
		}
	}

	script, err := os.ReadFile(filepath.Join("..", "..", "..", "scripts", "build-appliance-portal.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(script), "\tappliance/layer/portal/cmd/olivares-portal-sockets \\\n") {
		t.Error("the portal build does not make olivares-portal-sockets")
	}

	enabled := postinstallEnables(t, p)
	for _, unit := range []string{"olivares-portal-sockets.service", "olivares-portal-sockets.path", "olivares-portal-sockets.timer"} {
		if !slices.Contains(enabled, unit) {
			t.Errorf("the postinstall does not enable %s", unit)
		}
	}
}

// A running systemd always has /run/systemd/system, and `[ -d /run/systemd/system ]` is how the
// package scripts ask whether one runs. A tmpfiles line that created it would answer yes in an image
// root being built, so none of the package's tmpfiles files may.
func TestPortalPackage_NoTmpfilesLineCreatesTheRunningSystemdMarker(t *testing.T) {
	files, err := filepath.Glob("units/tmpfiles.d/*.conf")
	if err != nil || len(files) == 0 {
		t.Fatalf("no tmpfiles files: %v", err)
	}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "/run/systemd") {
			t.Errorf("%s creates something under /run/systemd, which only the service manager owns", file)
		}
	}
}
