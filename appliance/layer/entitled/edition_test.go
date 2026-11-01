// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package entitled

import (
	"strings"
	"testing"
	"time"
)

// The feature suite is what Render writes for a current licence and for no other class, so the repository file is
// the one record of what the licence earns now.
func TestHasFeatureSuiteReadsWhatRenderWrote(t *testing.T) {
	cases := []struct {
		name   string
		class  string
		suites []string
		want   bool
	}{
		{"current", "current", allSuites, true},
		{"security-only", "security-only", secSuites, false},
		{"security-unresolved", "security-unresolved", secSuites, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			text, err := Render("https://licenses.example.test", issuedDoc(t, tc.class, tc.suites, testNow.Add(time.Hour)), testNow)
			if err != nil {
				t.Fatal(err)
			}
			if got := HasFeatureSuite(text); got != tc.want {
				t.Errorf("HasFeatureSuite = %v, want %v for:\n%s", got, tc.want, text)
			}
		})
	}
}

// A name that merely contains the suite's, or a key that carries it as a value, is not the section.
func TestHasFeatureSuiteReadsSectionHeadersOnly(t *testing.T) {
	for name, text := range map[string]string{
		"empty":            "",
		"other section":    "[olivares-entitled-security]\nname=Olivares entitled security\n",
		"suite as a value": "[olivares-entitled-security]\nname=[olivares-entitled-stable]\n",
		"comment":          "# [olivares-entitled-stable]\n[olivares-entitled-security]\n",
		"longer id":        "[olivares-entitled-stable-extra]\n",
		"indented":         "  [olivares-entitled-stable]\n",
	} {
		if HasFeatureSuite([]byte(text)) {
			t.Errorf("%s: read as granting the feature suite:\n%s", name, text)
		}
	}
}

type held struct{ community, business bool }

func TestWantedSwapsOnlyWhenTheLicenceAndTheInstalledEditionDisagree(t *testing.T) {
	community, business := held{community: true}, held{business: true}
	cases := []struct {
		name     string
		licensed bool
		feature  bool
		held     held
		want     Swap
		swap     bool
	}{
		{"activation: a current licence on Community", true, true, community, Swap{CommunityPackage, BusinessPackage}, true},
		{"deactivation: no licence on Business", false, false, business, Swap{BusinessPackage, CommunityPackage}, true},
		// The repository file is a leftover when there is no licence; it never keeps Business.
		{"deactivation with a stale feature repository", false, true, business, Swap{BusinessPackage, CommunityPackage}, true},
		{"already Business on a current licence", true, true, business, Swap{}, false},
		{"already Community without a licence", false, false, community, Swap{}, false},
		// An expired licence keeps what is installed and gets security updates only: it neither installs nor removes Business.
		{"expired licence on Business", true, false, business, Swap{}, false},
		{"expired licence on Community", true, false, community, Swap{}, false},
		// Licence installed, channel not refreshed yet (or refresh failed): nothing changes.
		{"licence but no repository on Community", true, false, community, Swap{}, false},
		{"licence but no repository on Business", true, false, business, Swap{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, swap, err := Wanted(tc.licensed, tc.feature, tc.held.community, tc.held.business)
			if err != nil {
				t.Fatal(err)
			}
			if swap != tc.swap || got != tc.want {
				t.Errorf("Wanted = %+v, %v; want %+v, %v", got, swap, tc.want, tc.swap)
			}
		})
	}
}

// A host that holds both editions (the packages conflict) or neither is not one this path may reason about.
func TestWantedRefusesAHostThatHoldsBothEditionsOrNeither(t *testing.T) {
	for _, h := range []held{{true, true}, {false, false}} {
		for _, licensed := range []bool{true, false} {
			if _, swap, err := Wanted(licensed, licensed, h.community, h.business); err == nil || swap {
				t.Errorf("held %+v, licensed %v: Wanted = swap %v, err %v; want a refusal", h, licensed, swap, err)
			}
		}
	}
}

// A line of any length before the header does not hide it.
func TestHasFeatureSuiteReadsPastALongLine(t *testing.T) {
	text := "# " + strings.Repeat("x", 200<<10) + "\n[olivares-entitled-stable]\n"
	if !HasFeatureSuite([]byte(text)) {
		t.Error("a long comment line hid the feature suite")
	}
}
