// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package portal

import (
	"crypto/tls"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestProductTransport_VerifiedHTTPSWithoutProxyRedirectOrSessionStore(t *testing.T) {
	calls := 0
	native := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Host != "appliance.test:9443" {
			t.Error("portal origin host was lost")
		}
		_, _ = io.WriteString(w, nativeClaims(true))
	}))
	defer native.Close()
	public := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: native.Certificate().Raw})
	client, err := newProductClient(public)
	if err != nil {
		t.Fatal(err)
	}
	defer client.http.CloseIdleConnections()
	if client.endpoint != "https://127.0.0.1:8443" || client.http.Timeout != 5*time.Second || client.http.Jar != nil {
		t.Fatal("native endpoint, timeout or session-store contract changed")
	}
	transport, ok := client.http.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || transport.TLSClientConfig.InsecureSkipVerify || transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatal("product transport bypasses verified, proxy-free TLS")
	}
	if err := client.http.CheckRedirect(nil, nil); err != http.ErrUseLastResponse {
		t.Fatal("native redirects may escape the fixed endpoint")
	}
	// The test supplies its own loopback engine; production has no endpoint setting.
	client.endpoint = native.URL
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	source := httptest.NewRequest(http.MethodGet, "https://appliance.test:9443/status", nil)
	reply, err := client.request(source, http.MethodGet, "/v1/auth/whoami", nil)
	if err != nil || reply.status != 200 || calls != 1 {
		t.Fatalf("verified native transport failed: status=%d calls=%d err=%v", reply.status, calls, err)
	}
	if _, err := newProductClient([]byte("not a certificate")); err == nil {
		t.Fatal("missing trust certificate opened a product client")
	}
}

func TestPortalNetwork_AnonymousAndEngineOutageAreAuditedRefusals(t *testing.T) {
	calls := 0
	handler, access := networkFixture(t, func(w http.ResponseWriter, r *http.Request) { calls++; _, _ = io.WriteString(w, nativeClaims(true)) })
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://appliance.test:9443/status", nil))
	if w.Code != 401 || calls != 0 {
		t.Fatal("anonymous request was authenticated or served")
	}
	access.product.endpoint = "https://127.0.0.1:0"
	w = nativeRequest(handler, http.MethodGet, "/status", "", true)
	if w.Code != 503 || calls != 0 {
		t.Fatal("engine outage opened a different network authority")
	}
	records, err := access.records.Pending()
	if err != nil || len(records) != 2 || records[0].Outcome != "refused" || records[1].Outcome != "refused" {
		t.Fatalf("anonymous/outage audit: %+v %v", records, err)
	}
}
