// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package portal

import (
	"net/http"
	"strings"
	"testing"
)

func TestPortalNetwork_AnonymousCannotReadHostStatus(t *testing.T) {
	status := Status{Custody: Custody{CertificateSHA256: "private-host-fingerprint"}}
	handler := networkHandler(status, networkAccess{})
	for _, path := range []string{"/", "/status", "/network", "/firewall", "/services", "/storage"} {
		for _, peer := range []string{localPeer, "192.0.2.10:42000"} {
			t.Run(path+peer, func(t *testing.T) {
				response := serve(t, handler, http.MethodGet, path, peer)
				if response.Code != http.StatusUnauthorized {
					t.Fatalf("anonymous %s returned %d, want 401", path, response.Code)
				}
				if strings.Contains(response.Body.String(), "private-host-fingerprint") {
					t.Fatal("anonymous response disclosed host status")
				}
			})
		}
	}
}
