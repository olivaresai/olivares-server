// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package storage

import "testing"

func TestNeutralImageProfilesNeverSelectTheServiceAccountContract(t *testing.T) {
	for _, profile := range []string{"almalinux10-server-amd64\n", "almalinux10-desktop-amd64\n", "debian13-server-amd64\n"} {
		if !knownImageProfile(profile) {
			t.Fatalf("current image profile refused: %q", profile)
		}
	}
	for _, profile := range []string{"", "service_account=olivares-svc\n", "almalinux10-server-amd64", "almalinux10-server-amd64\nextra\n", "almalinux10-server-amd64\r\n"} {
		if knownImageProfile(profile) {
			t.Fatalf("untrusted or unrelated declaration accepted: %q", profile)
		}
	}
}
