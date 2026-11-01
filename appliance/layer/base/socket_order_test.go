// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only

package base

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A socket unit with default dependencies is ordered before sockets.target, and basic.target after sockets.target
// (systemd.socket(5), bootup(7)). A service with default dependencies is ordered after basic.target
// (systemd.service(5)). So a socket ordered after one of our services is on an ordering cycle unless that service sets
// DefaultDependencies=no; systemd then skips a job at boot, and which one varies (lab run 10, 2026-10-21:
// "Ordering cycle found, skipping olivares-net-guard.socket", olivares-network-runtime.service failed, and
// multi-user.target was reached in one boot case of four).
func TestUnits_AServiceASocketWaitsForSetsDefaultDependenciesNo(t *testing.T) {
	sockets, err := filepath.Glob(filepath.Join(repoRoot, "appliance/layer/*/units/*.socket"))
	if err != nil || len(sockets) == 0 {
		t.Fatalf("no socket units under appliance/layer (%v)", err)
	}
	services := map[string]string{}
	paths, _ := filepath.Glob(filepath.Join(repoRoot, "appliance/layer/*/units/*.service"))
	for _, path := range paths {
		services[filepath.Base(path)] = path
	}
	checked := 0
	for _, path := range sockets {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		socket := parseUnit(string(data))
		if dd, _ := socket.last("DefaultDependencies"); dd == "no" {
			continue
		}
		for _, after := range socket["After"] {
			servicePath, ours := services[after]
			if !ours || !strings.HasSuffix(after, ".service") {
				continue
			}
			checked++
			text, err := os.ReadFile(servicePath)
			if err != nil {
				t.Fatal(err)
			}
			if dd, _ := parseUnit(string(text)).last("DefaultDependencies"); dd != "no" {
				t.Errorf("%s is ordered after %s, which keeps its default dependencies: an ordering cycle through "+
					"sockets.target and basic.target; set DefaultDependencies=no on %s", filepath.Base(path), after, after)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no socket is ordered after one of our services: the check saw nothing")
	}
}
