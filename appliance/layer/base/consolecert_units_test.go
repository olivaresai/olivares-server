// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package base

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const (
	consoleCertificateUnitPath = "appliance/layer/base/units/olivares-console-certificate.service"
	consoleCertificateDropIn   = "appliance/layer/base/units/olivares.service.d/50-console-certificate.conf"
)

// The product pulls the unit in at each start, so the certificate is made at first boot's start of the
// product and re-issued at every later start; the product never depends on it.
func TestConsoleCertificateUnit_RunsAtEachStartOfTheProductWithoutBlockingIt(t *testing.T) {
	drop, _ := readUnit(t, consoleCertificateDropIn)
	if got := drop["Wants"]; !slices.Equal(got, []string{"olivares-console-certificate.service"}) {
		t.Fatalf("the drop-in on olivares.service wants %q", got)
	}
	if len(drop["Requires"]) != 0 || len(drop["Before"]) != 0 || len(drop["After"]) != 0 {
		t.Fatalf("the drop-in orders or requires beyond Wants=: %v", drop)
	}
	unit, _ := readUnit(t, consoleCertificateUnitPath)
	if got := unit["After"]; !slices.Contains(got, "olivares.service") {
		t.Fatalf("After=%q: the engine's CA is made after the product starts", got)
	}
	if got := unit["Before"]; !slices.Contains(got, "olivares-portal.service") {
		t.Fatalf("Before=%q: a console started with it must find its pair", got)
	}
	// Nothing enables it: the product's start pulls it in. A WantedBy= would run it before the product.
	if len(unit["WantedBy"]) != 0 || len(unit["Requires"]) != 0 {
		t.Fatalf("the unit is enabled or required by something: %v", unit)
	}
	if got, _ := unit.last("Type"); got != "oneshot" {
		t.Fatalf("Type=%q", got)
	}
	if got, _ := unit.last("ExecStart"); got != "/usr/bin/appliance-firstboot console-certificate" {
		t.Fatalf("ExecStart=%q", got)
	}
	// An active unit is not started again, so a kept RemainAfterExit= would never re-issue for a changed address.
	if got, ok := unit.last("RemainAfterExit"); ok && got != "no" {
		t.Fatalf("RemainAfterExit=%q: the unit would not run at the product's next start", got)
	}
	if got := unit["ConditionPathExists"]; !slices.Contains(got, ConsoleTLSDir) {
		t.Fatalf("ConditionPathExists=%q: a host without the console's directory skips the unit", got)
	}
}

// The unit runs in the first-boot domain, the one whose rows read the CA key and write the console's
// pair; a unit without the context would run in init's domain, where neither is granted.
func TestConsoleCertificateUnit_RunsInTheFirstBootDomainWithTheNarrowestWrite(t *testing.T) {
	unit, _ := readUnit(t, consoleCertificateUnitPath)
	if got, _ := unit.last("SELinuxContext"); got != "system_u:system_r:olivares_firstboot_t:s0" {
		t.Fatalf("SELinuxContext=%q", got)
	}
	if got, _ := unit.last("ReadWritePaths"); got != "-/etc/olivares-portal" {
		t.Fatalf("ReadWritePaths=%q: the Appliance Console's directory only", got)
	}
	// The host's addresses come over netlink (net.Interfaces); the unit connects to no peer.
	families, _ := unit.last("RestrictAddressFamilies")
	if families != "AF_NETLINK" {
		t.Fatalf("RestrictAddressFamilies=%q", families)
	}
	// FBOOT-104's reason names this unit and its families: the first-boot unit shares the domain and sets none.
	access, err := os.ReadFile(filepath.Join(repoRoot, "appliance/selinux/access.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	_, row, _ := strings.Cut(string(access), "\nFBOOT-104\t")
	row, _, _ = strings.Cut(row, "\n")
	if !strings.Contains(row, "olivares-console-certificate.service") || !strings.Contains(row, "RestrictAddressFamilies="+families+" ") {
		t.Fatalf("FBOOT-104's reason does not name this unit's RestrictAddressFamilies=%s: %q", families, row)
	}
	if got, _ := unit.last("IPAddressDeny"); got != "any" {
		t.Fatalf("IPAddressDeny=%q", got)
	}
	if got, _ := unit.last("PrivateNetwork"); got == "true" || got == "yes" {
		t.Fatal("PrivateNetwork hides the LAN addresses the certificate names")
	}
	caps, _ := unit.last("CapabilityBoundingSet")
	if !slices.Equal(strings.Fields(caps), []string{"CAP_DAC_READ_SEARCH", "CAP_DAC_OVERRIDE"}) {
		t.Fatalf("CapabilityBoundingSet=%q: it reads one account's 0600 key and writes root's directory, and chowns nothing", caps)
	}
	// The command's own deadline is 4 minutes; systemd's ends after it.
	if got, _ := unit.last("TimeoutStartSec"); got != "5min" {
		t.Fatalf("TimeoutStartSec=%q", got)
	}
}

func TestConsoleCertificateUnit_CarriesTheProductHardeningByLastValueOrStatesWhy(t *testing.T) {
	keys, product := hardening(t)
	unit, text := readUnit(t, consoleCertificateUnitPath)
	for _, key := range keys {
		justified := strings.Contains(text, "\n# "+key+": ")
		if key == "SystemCallFilter" {
			if !slices.Equal(unit[key], product[key]) && !justified {
				t.Fatalf("SystemCallFilter %q, the product's %q, and no stated reason", unit[key], product[key])
			}
			continue
		}
		got, present := unit.last(key)
		want, _ := product.last(key)
		if (!present || got != want) && !justified {
			t.Fatalf("%s=%q (present %v), the product's %q, and no stated reason", key, got, present, want)
		}
	}
}

// On first boot the product, and with it the console's certificate, start only at first boot's
// start-services, but the repair console wants the portal at once, and the portal's LoadCredential=
// sources do not exist yet, so it failed twice at CREDENTIALS. The certificate's Before= orders the
// portal only when both are queued, so the portal orders after first boot, which queues them. It never
// pulls first boot in, and nothing enables the portal, so multi-user.target never orders after it: no
// cycle through first boot's After=multi-user.target.
func TestPortal_StartsAfterFirstBootSoItsCertificateExists(t *testing.T) {
	portal, _ := readUnit(t, "appliance/layer/portal/units/olivares-portal.service")
	if !slices.Contains(portal["After"], "olivares-appliance-firstboot.service") {
		t.Fatalf("After=%q: on first boot the portal starts before its certificate exists", portal["After"])
	}
	for _, key := range []string{"Wants", "Requires", "Requisite", "BindsTo", "WantedBy", "RequiredBy"} {
		if slices.Contains(portal[key], "olivares-appliance-firstboot.service") || strings.HasSuffix(key, "By") && len(portal[key]) != 0 {
			t.Fatalf("%s=%q: the portal pulls first boot in or is enabled, which would order multi-user.target after it", key, portal[key])
		}
	}
	certificate, _ := readUnit(t, consoleCertificateUnitPath)
	if !slices.Contains(certificate["Before"], "olivares-portal.service") {
		t.Fatalf("Before=%q: the portal no longer waits for a certificate started with it", certificate["Before"])
	}
}
