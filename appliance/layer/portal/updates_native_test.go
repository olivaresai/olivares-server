// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package portal

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/olivaresai/olivares/core/api"
	coreaudit "github.com/olivaresai/olivares/core/audit"
	coreauth "github.com/olivaresai/olivares/core/auth"
	"github.com/olivaresai/olivares/core/engine"
	"github.com/olivaresai/olivares/core/secure"
	"github.com/olivaresai/olivares/core/store"
)

// memoryLicence is the engine's live licence surface with the verification replaced: one blob
// verifies. The routes, the session, the CSRF check, the superadministrator gate and the step-up
// are the engine's own; what is under test is the console's relay of them, not the signature.
type memoryLicence struct {
	mu     sync.Mutex
	status api.LicenseStatus
}

const goodLicence = "GOOD-LICENCE-fixture"

func (m *memoryLicence) LicenseStatus(context.Context) (api.LicenseStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status, nil
}

func (m *memoryLicence) InstallLicense(_ context.Context, blob string, _ bool) (api.LicenseStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if strings.TrimSpace(blob) != goodLicence {
		return api.LicenseStatus{}, api.ErrLicenseInvalid
	}
	expires := time.Date(2027, 3, 1, 0, 0, 0, 0, time.UTC)
	m.status = api.LicenseStatus{Edition: "community", Status: "valid", Source: "data-dir", Licensee: "Acme", Plan: "business", ExpiresAt: &expires, HotApply: true}
	return m.status, nil
}

func (m *memoryLicence) UninstallLicense(context.Context, bool) (api.LicenseStatus, error) {
	return m.status, nil
}
func (m *memoryLicence) LicenseDisplay() api.LicenseDisplayInfo { return api.LicenseDisplayInfo{} }
func (m *memoryLicence) Reconcile(context.Context)              {}

// The Updates page and its activation form against the product's real routes: the page offers the
// form with the product's own CSRF token, the relayed install reaches the licence surface, the
// product's own CSRF check refuses a token it did not issue, and a signed-out session installs nothing.
func TestPortalUpdates_NativeEngineActivation(t *testing.T) {
	ctx := context.Background()
	coreauth.SetTestHashParams(coreauth.TestArgonMemKiB, coreauth.TestArgonTime, coreauth.TestArgonThreads)
	t.Cleanup(func() {
		coreauth.SetTestHashParams(coreauth.DefaultArgonMemKiB, coreauth.DefaultArgonTime, coreauth.DefaultArgonThreads)
	})
	st, err := engine.Open(ctx, store.Config{Engine: store.EngineSQLite, DSN: ":memory:", Debug: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.System(ctx, func(sys store.SystemScope) error { _, err := sys.EnsureSystemTenant(ctx); return err }); err != nil {
		t.Fatal(err)
	}
	authenticator := coreauth.NewAuthenticator(st, nil)
	secret := make([]byte, 24)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	credential := hex.EncodeToString(secret)
	root, err := authenticator.BootstrapSuperadmin(ctx, "portal-root@example.test", credential)
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := coreaudit.NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	licence := &memoryLicence{status: api.LicenseStatus{Edition: "community", Status: "none", Source: "none", HotApply: true}}
	native, err := api.New(api.Options{
		Store: st, Authenticator: authenticator, Authorizer: coreauth.NewAuthorizer(nil), License: licence,
		Signer: signer, SetupToken: secure.NewSetupToken(filepath.Join(t.TempDir(), "setup.token")),
	})
	if err != nil {
		t.Fatal(err)
	}
	handler, _ := networkFixture(t, native.Handler().ServeHTTP)

	login := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "https://appliance.test:9443/v1/auth/login",
		strings.NewReader(`{"email":"`+root.Email+`","password":"`+credential+`"}`))
	r.Header.Set("Origin", "https://appliance.test:9443")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Olivares-Session", "cookie")
	handler.ServeHTTP(login, r)
	cookies := login.Result().Cookies()
	if login.Code != http.StatusOK || len(cookies) != 1 {
		t.Fatalf("login: %d", login.Code)
	}
	session := func(method, path string, form url.Values) *httptest.ResponseRecorder {
		return updatesRequest(handler, method, path, form, func(r *http.Request) {
			r.Header.Del("Cookie")
			r.AddCookie(cookies[0])
		})
	}

	page := session(http.MethodGet, "/updates", nil)
	token := regexp.MustCompile(`name="csrf_token" value="([A-Za-z0-9_-]+)"`).FindStringSubmatch(page.Body.String())
	if page.Code != http.StatusOK || token == nil || !strings.Contains(page.Body.String(), "No licence is installed") {
		t.Fatalf("GET /updates: %d\n%s", page.Code, page.Body.String())
	}
	post := func(blob, csrf string) *httptest.ResponseRecorder {
		return session(http.MethodPost, "/updates/licence", url.Values{"license": {blob}, "csrf_token": {csrf}})
	}
	if w := post(goodLicence, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "token is stale") {
		t.Errorf("a token the product did not issue: %d %s", w.Code, w.Body.String())
	}
	if w := post("not a licence", token[1]); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "did not accept") {
		t.Errorf("an invalid licence: %d %s", w.Code, w.Body.String())
	}
	if s, _ := licence.LicenseStatus(ctx); s.Status != "none" {
		t.Fatalf("a refused request installed a licence: %+v", s)
	}
	w := post(goodLicence, token[1])
	for _, want := range []string{"The licence is installed", "Acme", "2027-03-01", "Apply the product update"} {
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), want) {
			t.Errorf("activation: %d, lacks %q\n%s", w.Code, want, w.Body.String())
		}
	}
	if s, _ := licence.LicenseStatus(ctx); s.Status != "valid" {
		t.Errorf("the product holds %+v", s)
	}
	if again := session(http.MethodGet, "/updates", nil); !strings.Contains(again.Body.String(), "Acme") {
		t.Errorf("the page does not show the product's licence after the install:\n%s", again.Body.String())
	}

	out := session(http.MethodPost, "/v1/auth/logout", nil)
	if out.Code != http.StatusForbidden {
		t.Fatalf("logout without a token: %d", out.Code)
	}
	logout := httptest.NewRecorder()
	lr := httptest.NewRequest(http.MethodPost, "https://appliance.test:9443/v1/auth/logout", nil)
	lr.AddCookie(cookies[0])
	lr.Header.Set("Origin", "https://appliance.test:9443")
	lr.Header.Set("X-CSRF-Token", token[1])
	handler.ServeHTTP(logout, lr)
	if logout.Code != http.StatusNoContent {
		t.Fatalf("logout: %d", logout.Code)
	}
	if w := post(goodLicence, token[1]); w.Code != http.StatusUnauthorized {
		t.Errorf("a signed-out session installed: %d", w.Code)
	}
}
