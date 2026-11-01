// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

const (
	program = "/usr/libexec/olivares/olivares-package-retain"
	unitDst = "/usr/lib/systemd/system/olivares-package-retain.service"
)

// directives returns each key of a unit file with its values; a section is kept with the key as "Section.Key".
func directives(t *testing.T, file string) map[string][]string {
	t.Helper()
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	section := ""
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = strings.Trim(line, "[]")
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("%s: %q is not a directive", file, line)
		}
		out[section+"."+key] = append(out[section+"."+key], value)
	}
	return out
}

func TestUnit_CreatesTheTwoDirectoriesTheProgramOpensAndTheHelperReads(t *testing.T) {
	unit := directives(t, "../units/olivares-package-retain.service")
	names := []string{filepath.Base(stateDirectory), filepath.Base(deliveryDirectory)}
	if got := strings.Fields(strings.Join(unit["Service.StateDirectory"], " ")); !slices.Equal(got, names) || filepath.Dir(stateDirectory) != "/var/lib" || filepath.Dir(deliveryDirectory) != "/var/lib" {
		t.Errorf("StateDirectory=%v, the program opens %v", got, names)
	}
	if !slices.Equal(unit["Service.StateDirectoryMode"], []string{"0700"}) {
		t.Errorf("StateDirectoryMode=%v", unit["Service.StateDirectoryMode"])
	}
	helper := directives(t, "../units/olivares-helper-apt@.service")
	if !slices.Equal(helper["Service.StateDirectory"], []string{filepath.Base(stateDirectory)}) {
		t.Errorf("the helper reads %v, the program writes %s", helper["Service.StateDirectory"], stateDirectory)
	}
}

func TestUnit_RunsOnceAsRootWithoutNetworkOrCapabilityAndRestartsTheConsole(t *testing.T) {
	unit := directives(t, "../units/olivares-package-retain.service")
	for key, want := range map[string]string{
		"Service.Type":                    "oneshot",
		"Service.ExecStart":               program,
		"Service.ExecStartPost":           "/usr/bin/systemctl try-restart olivares-portal.service",
		"Service.User":                    "root",
		"Service.NoNewPrivileges":         "yes",
		"Service.ProtectSystem":           "strict",
		"Service.PrivateNetwork":          "yes",
		"Service.RestrictAddressFamilies": "AF_UNIX",
		"Service.CapabilityBoundingSet":   "",
		"Service.AmbientCapabilities":     "",
		"Service.ProtectHome":             "yes",
		"Service.PrivateTmp":              "yes",
		"Service.PrivateDevices":          "yes",
		"Service.IPAddressDeny":           "any",
		"Service.MemoryDenyWriteExecute":  "yes",
		"Service.RestrictSUIDSGID":        "yes",
		"Service.UMask":                   "0077",
	} {
		if !slices.Equal(unit[key], []string{want}) {
			t.Errorf("%s=%q, want %q", key, unit[key], want)
		}
	}
	// Only the package database is writable besides the state directories, and nothing starts the unit.
	if got := strings.Fields(strings.Join(unit["Service.ReadWritePaths"], " ")); !slices.Equal(got, []string{"-/var/lib/rpm", "-/usr/lib/sysimage/rpm"}) {
		t.Errorf("ReadWritePaths=%v", got)
	}
	for key := range unit {
		if strings.HasPrefix(key, "Install.") {
			t.Errorf("the unit has an [Install] section (%s): nothing starts it by itself", key)
		}
	}
}

func TestPackage_ShipsAndBuildsTheProgramAndItsUnit(t *testing.T) {
	data, err := os.ReadFile("../../../../packaging/nfpm/olivares-appliance-portal.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	var pkg struct {
		Contents []struct {
			Src, Dst string
			FileInfo struct {
				Mode         uint32
				Owner, Group string
			} `json:"file_info"`
		}
	}
	if err := json.Unmarshal([]byte(strings.Join(lines, "\n")), &pkg); err != nil {
		t.Fatal(err)
	}
	for dst, want := range map[string]struct {
		src  string
		mode uint32
	}{
		program: {"bin/olivares-package-retain", 0o755},
		unitDst: {"appliance/layer/updates/units/olivares-package-retain.service", 0o644},
	} {
		found := false
		for _, c := range pkg.Contents {
			if c.Dst == dst {
				found = true
				if c.Src != want.src || c.FileInfo.Mode != want.mode || c.FileInfo.Owner != "root" || c.FileInfo.Group != "root" {
					t.Errorf("%s: %+v, want %s mode %o root:root", dst, c, want.src, want.mode)
				}
			}
		}
		if !found {
			t.Errorf("the package does not ship %s", dst)
		}
	}
	build, err := os.ReadFile("../../../../scripts/build-appliance-portal.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`(?m)^\tappliance/layer/updates/olivares-package-retain( \\|; do)$`).Match(build) {
		t.Error("the portal payload build does not build bin/olivares-package-retain, which the package ships")
	}
}
