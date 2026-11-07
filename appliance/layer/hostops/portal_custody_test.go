// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package hostops_test

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/olivaresai/olivares/appliance/layer/portal/localsession"
)

var portalSandboxLines = []string{
	"DynamicUser=no", "User=olivares-portal", "Group=olivares-operations",
	"SupplementaryGroups=olivares-portal olivares-appliance olivares-lifecycle",
	"RemoveIPC=yes", "PrivateTmp=yes", "ProtectSystem=strict", "ProtectHome=yes", "RestrictSUIDSGID=yes", "NoNewPrivileges=yes",
	"RuntimeDirectory=olivares-portal-receipts", "RuntimeDirectoryMode=0700", "RuntimeDirectoryPreserve=no",
	"StateDirectory=olivares-portal/operations", "StateDirectoryMode=0750",
}

const portalParentDeclaration = "d /var/lib/olivares-portal 0755 root root - -"

func portalCustodyContract(unit, tmpfiles string) error {
	lines := strings.Split(unit, "\n")
	for _, want := range portalSandboxLines {
		found := false
		for _, line := range lines {
			if line == want {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("missing %s", want)
		}
	}
	if !strings.Contains("\n"+tmpfiles, "\n"+portalParentDeclaration+"\n") {
		return fmt.Errorf("missing root-owned parent")
	}
	if strings.Contains(unit, "/var/lib/private") || strings.Contains(tmpfiles, "/var/lib/private") {
		return fmt.Errorf("private backing is forbidden")
	}
	return nil
}

func TestPortal_StaticAccountAndProtectedOperationLeaf(t *testing.T) {
	unit, err := os.ReadFile("../portal/units/olivares-portal.service.d/30-host-operations.conf")
	if err != nil {
		t.Fatal(err)
	}
	tmpfiles, err := os.ReadFile("../portal/units/tmpfiles.d/olivares-hostops.conf")
	if err != nil {
		t.Fatal(err)
	}
	if err := portalCustodyContract(string(unit), string(tmpfiles)); err != nil {
		t.Fatal(err)
	}
	if localsession.OperationDirectory != "/var/lib/olivares-portal/operations" {
		t.Fatal("operation path changed")
	}
}

func TestPortal_StaticCustodyControlsRejectEachMissingSandboxSetting(t *testing.T) {
	unit := "[Service]\n" + strings.Join(portalSandboxLines, "\n") + "\n"
	tmpfiles := portalParentDeclaration + "\n"
	if err := portalCustodyContract(unit, tmpfiles); err != nil {
		t.Fatal(err)
	}
	for _, line := range portalSandboxLines {
		mutant := strings.Replace(unit, line+"\n", "", 1)
		if err := portalCustodyContract(mutant, tmpfiles); err == nil {
			t.Fatalf("missing setting accepted: %s", line)
		}
	}
	if err := portalCustodyContract(strings.Replace(unit, "DynamicUser=no", "DynamicUser=yes", 1), tmpfiles); err == nil {
		t.Fatal("dynamic identity accepted")
	}
	if err := portalCustodyContract(unit, strings.Replace(tmpfiles, "root root", "olivares-portal olivares-portal", 1)); err == nil {
		t.Fatal("portal-owned parent accepted")
	}
}

func TestPortal_StaticAccountAndSupplementaryGroupsAreDeclared(t *testing.T) {
	var data []byte
	for _, name := range []string{"olivares-appliance-portal", "olivares-hostops"} {
		b, err := os.ReadFile("../portal/units/sysusers.d/" + name + ".conf")
		if err != nil {
			t.Fatal(err)
		}
		data = append(data, b...)
	}
	for _, want := range []string{
		`u olivares-portal - "Appliance Console" /nonexistent /usr/sbin/nologin`,
		"g olivares-appliance -", "g olivares-lifecycle -", "g olivares-operations -",
	} {
		if !strings.Contains("\n"+string(data), "\n"+want+"\n") {
			t.Fatalf("missing identity declaration: %s", want)
		}
	}
}

// The repair console holds the host-operations group and no other, so its power verb reaches the
// operation store's lock through the 0750 leaf; it never holds the portal's own group.
func TestRepairConsole_HoldsTheOperationsGroupOnly(t *testing.T) {
	unit, err := os.ReadFile("../portal/units/olivares-repair-console.service")
	if err != nil {
		t.Fatal(err)
	}
	var groups []string
	for _, line := range strings.Split(string(unit), "\n") {
		if value, ok := strings.CutPrefix(line, "SupplementaryGroups="); ok {
			groups = append(groups, strings.Fields(value)...)
		}
	}
	if len(groups) != 1 || groups[0] != "olivares-operations" {
		t.Fatalf("the repair console's supplementary groups are %q, not only olivares-operations", groups)
	}
}

// The portal's StateDirectory= makes the operation store, so the repair console wants the portal
// started at boot (without it, on an enforcing desktop's first boot, the store never existed and the
// power verb was refused). It never waits for the portal nor fails with it: no ordering and no
// requirement names the portal.
func TestRepairConsole_WantsThePortalWithoutWaitingForIt(t *testing.T) {
	unit, err := os.ReadFile("../portal/units/olivares-repair-console.service")
	if err != nil {
		t.Fatal(err)
	}
	named := map[string][]string{}
	for _, line := range strings.Split(string(unit), "\n") {
		if key, value, ok := strings.Cut(line, "="); ok && !strings.HasPrefix(key, "#") {
			named[key] = append(named[key], strings.Fields(value)...)
		}
	}
	if !slices.Contains(named["Wants"], "olivares-portal.service") {
		t.Errorf("the repair console does not want olivares-portal.service, so nothing makes the operation store at boot: Wants=%q", named["Wants"])
	}
	for _, key := range []string{"After", "Before", "Requires", "Requisite", "BindsTo", "PartOf", "Upholds"} {
		for _, portal := range []string{"olivares-portal.service", "olivares-portal.socket"} {
			if slices.Contains(named[key], portal) {
				t.Errorf("%s=%s ties the last door to the console on 9443", key, portal)
			}
		}
	}
}

// The portal's unit filters the privileged system calls, chown among them: any chown the portal's code
// makes is killed with SIGSYS, so the portal would die at every start. Its code must call none.
func TestPortal_CodeCallsNoChownItsSystemCallFilterForbids(t *testing.T) {
	unit, err := os.ReadFile("../portal/units/olivares-portal.service")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains("\n"+string(unit), "\nSystemCallFilter=~@privileged") {
		t.Skip("the portal no longer filters @privileged")
	}
	chown := regexp.MustCompile(`\b(Chown|Lchown|Fchown|Fchownat)\(`)
	for _, root := range []string{".", "../portal"} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for i, line := range strings.Split(string(data), "\n") {
				if chown.MatchString(line) && !strings.HasPrefix(strings.TrimSpace(line), "//") {
					t.Errorf("%s:%d calls chown, which the portal's SystemCallFilter forbids: %s", path, i+1, strings.TrimSpace(line))
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
