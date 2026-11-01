// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package portal

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/olivaresai/olivares/appliance/layer/portal/audit"
)

const nativeActor = "user:01234567-89ab-cdef-0123-456789abcdef"

// nativeClaims is whoami for a session that meets the deployment's step-up policy.
func nativeClaims(super bool) string { return sessionClaims(super, "true") }

func networkFixture(t *testing.T, native http.HandlerFunc) (http.Handler, networkAccess) {
	t.Helper()
	server := httptest.NewTLSServer(native)
	t.Cleanup(server.Close)
	client := server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	dir := filepath.Join(t.TempDir(), "audit")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	spool, err := audit.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	access := networkAccess{product: &productClient{endpoint: server.URL, http: client}, records: spool}
	return networkHandler(Status{Custody: Custody{CertificateSHA256: "protected-fingerprint"}}, access), access
}

func nativeRequest(handler http.Handler, method, path, body string, cookie bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://appliance.test:9443"+path, strings.NewReader(body))
	r.RemoteAddr = localPeer
	if cookie {
		r.AddCookie(&http.Cookie{Name: "__Host-olivares-session", Value: "fixture-session"})
		r.AddCookie(&http.Cookie{Name: "unrelated", Value: "do-not-forward"})
	} else {
		r.Header.Set("Authorization", "Bearer fixture-session")
	}
	r.Header.Set("X-Actor", "forged-user")
	r.Header.Set("X-Forwarded-For", "forged-peer")
	r.Header.Set("Origin", "https://appliance.test:9443")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func TestPortalNetwork_CurrentHumanSuperadminRecheckedForEveryRead(t *testing.T) {
	for _, cookie := range []bool{false, true} {
		t.Run(fmt.Sprint(cookie), func(t *testing.T) {
			calls, revoked := 0, false
			handler, access := networkFixture(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.URL.Path != "/v1/auth/whoami" || r.Method != http.MethodGet {
					t.Errorf("wrong native authority request: %s %s", r.Method, r.URL.Path)
				}
				if r.Host != "appliance.test:9443" || r.Header.Get("Origin") != "https://"+r.Host {
					t.Error("native same-origin contract was changed")
				}
				if r.Header.Get("X-Actor") != "" || r.Header.Get("X-Forwarded-For") != "" || strings.Contains(r.Header.Get("Cookie"), "unrelated") {
					t.Error("client asserted identity/proxy/unrelated cookie was forwarded")
				}
				if cookie {
					if c, err := r.Cookie("__Host-olivares-session"); err != nil || c.Value != "fixture-session" {
						t.Error("native cookie not forwarded")
					}
				} else if r.Header.Get("Authorization") != "Bearer fixture-session" {
					t.Error("native bearer not forwarded")
				}
				if revoked {
					w.WriteHeader(401)
					return
				}
				_, _ = io.WriteString(w, nativeClaims(true))
			})
			for _, path := range []string{"/", "/status", "/network", "/firewall", "/services", "/storage"} {
				if w := nativeRequest(handler, http.MethodGet, path, "", cookie); w.Code != 200 {
					t.Fatalf("native admin %s returned %d: %s", path, w.Code, w.Body.String())
				}
			}
			revoked = true
			if w := nativeRequest(handler, http.MethodGet, "/status", "", cookie); w.Code != 401 || strings.Contains(w.Body.String(), "protected-fingerprint") {
				t.Fatalf("revoked session returned status: %d %s", w.Code, w.Body.String())
			}
			if calls != 7 {
				t.Fatalf("authority calls=%d, want one for each of seven reads", calls)
			}
			records, err := access.records.Pending()
			if err != nil || len(records) != 7 {
				t.Fatalf("read audit: %d records, %v", len(records), err)
			}
			verbs := []string{"host-status.read", "host-status.read", "host-network.read", "host-firewall.read", "host-services.read", "host-storage.read"}
			for i, record := range records[:6] {
				if record.Actor != nativeActor || record.Mode != "product-up" || record.Outcome != "performed" || record.Surface != "web" || record.Verb != verbs[i] {
					t.Fatalf("audit did not use native authority: %+v", record)
				}
			}
			if records[6].Outcome != "refused" {
				t.Fatal("revocation was not audited")
			}
		})
	}
}

func TestPortalNetwork_RefusesTenantAdminServiceAndMalformedIdentity(t *testing.T) {
	for _, claims := range []string{nativeClaims(false), strings.Replace(nativeClaims(true), `"user"`, `"token"`, 1), strings.Replace(nativeClaims(true), nativeActor, "forged", 1), `{"kind":"user","superadmin":true}`} {
		t.Run(claims, func(t *testing.T) {
			handler, _ := networkFixture(t, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, claims) })
			for _, path := range []string{"/status", "/services", "/storage"} {
				w := nativeRequest(handler, http.MethodGet, path, "", false)
				if w.Code != 403 || strings.Contains(w.Body.String(), "protected-fingerprint") || strings.Contains(w.Body.String(), "<h1>") {
					t.Fatalf("non-host administrator read %s: %d %s", path, w.Code, w.Body.String())
				}
			}
		})
	}
}

func TestPortalNetwork_NativeLoginSessionLogoutAndCSRF(t *testing.T) {
	loginBody := `{"email":"fixture@example.test","password":"fixture-only"}`
	calls := 0
	handler, access := networkFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Host != "appliance.test:9443" || r.Header.Get("Origin") != "https://"+r.Host {
			t.Error("portal origin was not preserved for native CSRF")
		}
		switch r.URL.Path {
		case "/v1/auth/login":
			body, _ := io.ReadAll(r.Body)
			if string(body) != loginBody || r.Header.Get("X-Olivares-Session") != "cookie" {
				t.Error("native login envelope changed")
			}
			http.SetCookie(w, &http.Cookie{Name: "__Host-olivares-session", Value: "fixture-session", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
			_, _ = io.WriteString(w, `{"csrf_token":"fixture-csrf"}`)
		case "/v1/auth/browser-session":
			_, _ = io.WriteString(w, `{"csrf_token":"fixture-csrf"}`)
		case "/v1/auth/logout":
			if r.Header.Get("X-CSRF-Token") != "fixture-csrf" {
				w.WriteHeader(403)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "__Host-olivares-session", Path: "/", Secure: true, HttpOnly: true, MaxAge: -1})
			w.WriteHeader(204)
		default:
			t.Errorf("unexpected forwarded route %s", r.URL.Path)
			w.WriteHeader(500)
		}
	})
	r := httptest.NewRequest(http.MethodPost, "https://appliance.test:9443/v1/auth/login", strings.NewReader(loginBody))
	r.Header.Set("Origin", "https://appliance.test:9443")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.Header.Set("X-Olivares-Session", "cookie")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "fixture-csrf") {
		t.Fatalf("native login not relayed: %d %s", w.Code, w.Body.String())
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatal("native protected cookie changed")
	}
	if w := nativeRequest(handler, http.MethodGet, "/v1/auth/browser-session", "", true); w.Code != 200 {
		t.Fatalf("browser session: %d", w.Code)
	}
	if w := nativeRequest(handler, http.MethodPost, "/v1/auth/logout", "", true); w.Code != 403 {
		t.Fatalf("logout bypassed native CSRF: %d", w.Code)
	}
	r = httptest.NewRequest(http.MethodPost, "https://appliance.test:9443/v1/auth/logout", nil)
	r.AddCookie(cookies[0])
	r.Header.Set("X-CSRF-Token", "fixture-csrf")
	r.Header.Set("Origin", "https://appliance.test:9443")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 204 || len(w.Result().Cookies()) != 1 || w.Result().Cookies()[0].MaxAge != -1 {
		t.Fatalf("native logout not relayed: %d", w.Code)
	}
	if calls != 4 {
		t.Fatalf("unexpected native calls: %d", calls)
	}
	records, err := access.records.Pending()
	if err != nil || len(records) != 8 {
		t.Fatalf("native action intent/result audit: %d, %v", len(records), err)
	}
	for _, record := range records {
		raw := fmt.Sprint(record)
		if strings.Contains(raw, "fixture-session") || strings.Contains(raw, "fixture-only") || strings.Contains(raw, "fixture-csrf") {
			t.Fatal("audit contains native secret material")
		}
	}
}

func TestPortalNetwork_OriginMutationAndArbitraryProxyRefused(t *testing.T) {
	calls := 0
	handler, access := networkFixture(t, func(w http.ResponseWriter, r *http.Request) { calls++; _, _ = io.WriteString(w, nativeClaims(true)) })
	for _, tc := range []struct {
		method, path, origin string
		code                 int
	}{
		{http.MethodPost, "/network", "", 405},
		{http.MethodPost, "/firewall", "", 405},
		{http.MethodPost, "/v1/system/reboot", "", 404},
		{http.MethodPost, "/v1/auth/login", "https://evil.example", 403},
		{http.MethodGet, "/status", "https://evil.example", 403},
		{http.MethodPost, storageActionPath, "null", 403},
		{http.MethodPost, storageActionPath, "https://evil.example", 403},
	} {
		r := httptest.NewRequest(tc.method, "https://appliance.test:9443"+tc.path, nil)
		r.Header.Set("Authorization", "Bearer fixture-session")
		r.Header.Set("Origin", tc.origin)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != tc.code {
			t.Fatalf("%s %s returned %d, want %d", tc.method, tc.path, w.Code, tc.code)
		}
	}
	if calls != 0 {
		t.Fatalf("refused request reached native engine: %d", calls)
	}
	records, err := access.records.Pending()
	if err != nil || len(records) != 7 {
		t.Fatalf("refusals not audited: %d %v", len(records), err)
	}
}

type failedAuditRandom struct{}

func (failedAuditRandom) Read([]byte) (int, error) { return 0, errors.New("audit unavailable") }

func TestPortalNetwork_AuditFailureDisclosesNothingAndForwardsNoAction(t *testing.T) {
	calls := 0
	handler, access := networkFixture(t, func(w http.ResponseWriter, r *http.Request) { calls++; _, _ = io.WriteString(w, nativeClaims(true)) })
	access.records.Random = failedAuditRandom{}
	w := nativeRequest(handler, http.MethodGet, "/status", "", false)
	if w.Code != 503 || strings.Contains(w.Body.String(), "protected-fingerprint") {
		t.Fatalf("read survived audit failure: %d", w.Code)
	}
	before := calls
	w = nativeRequest(handler, http.MethodPost, "/v1/auth/login", "{}", false)
	if w.Code != 503 || calls != before {
		t.Fatal("authentication action executed without durable audit")
	}
}

func TestPortalNetwork_TLSFailureRedirectAndBoundsRefuseStatus(t *testing.T) {
	for _, scenario := range []string{"bad-trust", "redirect", "large-reply"} {
		t.Run(scenario, func(t *testing.T) {
			calls := 0
			handler, access := networkFixture(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				switch scenario {
				case "redirect":
					w.Header().Set("Location", "https://evil.example/")
					w.WriteHeader(302)
				case "large-reply":
					_, _ = io.WriteString(w, strings.Repeat("x", 65537))
				default:
					_, _ = io.WriteString(w, nativeClaims(true))
				}
			})
			if scenario == "bad-trust" {
				access.product.http.Transport.(*http.Transport).TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
			}
			w := nativeRequest(handler, http.MethodGet, "/status", "", false)
			if w.Code != 503 || w.Header().Get("Location") != "" || strings.Contains(w.Body.String(), "protected-fingerprint") {
				t.Fatalf("untrusted native response disclosed status or redirect: %d", w.Code)
			}
			if scenario == "bad-trust" && calls != 0 {
				t.Fatal("client skipped TLS verification")
			}
		})
	}
	handler, _ := networkFixture(t, func(w http.ResponseWriter, r *http.Request) { t.Error("oversized login body was forwarded") })
	if w := nativeRequest(handler, http.MethodPost, "/v1/auth/login", strings.Repeat("x", 65537), false); w.Code != 413 {
		t.Fatalf("body bound: %d", w.Code)
	}
}

// The pages that name interfaces, units, disks and mount points answer 404 to a caller on another
// host, whoever signed in, and the audit says the read was not served; from this host they are read.
func TestPortalNetwork_HostPagesAreNotServedOrRecordedAsReadToAnotherHost(t *testing.T) {
	handler, access := networkFixture(t, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, nativeClaims(true)) })
	read := func(path, peer string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "https://appliance.test:9443"+path, nil)
		r.RemoteAddr = peer
		r.Header.Set("Authorization", "Bearer fixture-session")
		r.Header.Set("Origin", "https://appliance.test:9443")
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	paths := []string{"/firewall", "/services", "/storage"}
	for _, path := range paths {
		if w := read(path, "192.0.2.50:5555"); w.Code != http.StatusNotFound || strings.Contains(w.Body.String(), "<h1>") {
			t.Errorf("a signed-in superadministrator on another host read %s: %d %s", path, w.Code, w.Body.String())
		}
		if w := read(path, localPeer); w.Code != http.StatusOK {
			t.Errorf("the same superadministrator on this host read %s: %d", path, w.Code)
		}
	}
	records, err := access.records.Pending()
	if err != nil || len(records) != 2*len(paths) {
		t.Fatalf("audit: %d records, %v", len(records), err)
	}
	for i, record := range records {
		want := "refused"
		if i%2 == 1 {
			want = "performed"
		}
		if record.Outcome != want || record.Actor != nativeActor {
			t.Errorf("record %d: %+v, want %s by the signed-in actor", i, record, want)
		}
	}
}

// sessionClaims is whoami for a signed-in session; stepUp is the raw step_up_satisfied member
// ("" leaves it out, as an engine that predates it would).
func sessionClaims(super bool, stepUp string) string {
	extra := ""
	if stepUp != "" {
		extra = `,"step_up_satisfied":` + stepUp
	}
	return fmt.Sprintf(`{"kind":"user","user_id":"01234567-89ab-cdef-0123-456789abcdef","actor":%q,"superadmin":%t%s}`, nativeActor, super, extra)
}

// The console asks the product once and obeys: a superadministrator whose session does not meet the
// deployment's step-up policy is refused, with the remedy, and every other caller is refused without it
// whatever the step-up answer says, so the answer is never an oracle for who is a superadministrator.
func TestPortalNetwork_HostAdministrationNeedsTheProductsStepUpAnswer(t *testing.T) {
	const stepUpSentence = "Step-up required"
	const superadminSentence = "A product superadministrator is required"
	forged := strings.Replace(sessionClaims(true, "false"), nativeActor, "forged", 1)
	token := strings.Replace(sessionClaims(true, "false"), `"user"`, `"token"`, 1)
	for name, tc := range map[string]struct {
		claims   string
		code     int
		sentence string
		actor    string
	}{
		"superadministrator, step-up met":      {sessionClaims(true, "true"), 200, "", nativeActor},
		"superadministrator, step-up not met":  {sessionClaims(true, "false"), 403, stepUpSentence, nativeActor},
		"superadministrator, step-up not said": {sessionClaims(true, ""), 403, stepUpSentence, nativeActor},
		"superadministrator, step-up null":     {sessionClaims(true, "null"), 403, stepUpSentence, nativeActor},
		"editor, step-up met":                  {sessionClaims(false, "true"), 403, superadminSentence, nativeActor},
		"editor, step-up not met":              {sessionClaims(false, "false"), 403, superadminSentence, nativeActor},
		"forged actor, step-up not met":        {forged, 403, superadminSentence, "anonymous"},
		"token, step-up not met":               {token, 403, superadminSentence, "anonymous"},
		"no identity, superadmin, not met":     {`{"kind":"user","superadmin":true,"step_up_satisfied":false}`, 403, superadminSentence, "anonymous"},
	} {
		t.Run(name, func(t *testing.T) {
			handler, access := networkFixture(t, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, tc.claims) })
			for _, path := range []string{"/", "/status", "/network", "/updates"} {
				w := nativeRequest(handler, http.MethodGet, path, "", true)
				if w.Code != tc.code {
					t.Fatalf("GET %s returned %d, want %d: %s", path, w.Code, tc.code, w.Body.String())
				}
				served := strings.Contains(w.Body.String(), "protected-fingerprint")
				switch {
				case tc.code == 200 && (path == "/" || path == "/status") && !served:
					t.Fatalf("GET %s allowed without the host status: %s", path, w.Body.String())
				case tc.code != 200 && (served || !strings.Contains(w.Body.String(), tc.sentence)):
					t.Fatalf("GET %s refusal = %q, want the %q sentence and no status", path, w.Body.String(), tc.sentence)
				case tc.sentence == superadminSentence && strings.Contains(w.Body.String(), "Step-up"):
					t.Fatalf("GET %s told a caller who is not a superadministrator about step-up: %s", path, w.Body.String())
				}
			}
			records, err := access.records.Pending()
			if err != nil || len(records) != 4 {
				t.Fatalf("audit: %d records, %v", len(records), err)
			}
			for _, record := range records {
				if wantRefused := tc.code != 200; (record.Outcome == "refused") != wantRefused || record.Actor != tc.actor {
					t.Fatalf("audit record %+v, want refused=%t by %s", record, wantRefused, tc.actor)
				}
			}
		})
	}
}

// A member that is not a boolean is not an answer: the console cannot say who the caller is, serves nothing and says why.
func TestPortalNetwork_AMalformedStepUpAnswerServesNothing(t *testing.T) {
	for _, member := range []string{`"true"`, `1`, `{}`} {
		handler, _ := networkFixture(t, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, sessionClaims(true, member)) })
		w := nativeRequest(handler, http.MethodGet, "/status", "", true)
		if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "protected-fingerprint") {
			t.Fatalf("step_up_satisfied=%s returned %d: %s", member, w.Code, w.Body.String())
		}
	}
}

func TestPortalUpdates_LicenceActivationNeedsTheProductsStepUpAnswer(t *testing.T) {
	for name, tc := range map[string]struct{ claims, sentence, forbidden string }{
		"step-up not met":  {sessionClaims(true, "false"), "Step-up required", ""},
		"step-up not said": {sessionClaims(true, ""), "Step-up required", ""},
		"editor":           {sessionClaims(false, "false"), "A product superadministrator is required to activate a licence.", "Step-up"},
	} {
		t.Run(name, func(t *testing.T) {
			product := &productCalls{claims: tc.claims}
			handler, access := networkFixture(t, product.handler(t))
			w := updatesRequest(handler, http.MethodPost, "/updates/licence", activation(updatesBlob), nil)
			records, err := access.records.Pending()
			if err != nil {
				t.Fatal(err)
			}
			if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), tc.sentence) || (tc.forbidden != "" && strings.Contains(w.Body.String(), tc.forbidden)) || len(records) != 1 || records[0].Outcome != "refused" {
				t.Fatalf("%d %q, records %+v", w.Code, w.Body.String(), records)
			}
			if product.count("POST /v1/console/license") != 0 {
				t.Errorf("the product was asked to install: %v", product.paths())
			}
		})
	}
}
