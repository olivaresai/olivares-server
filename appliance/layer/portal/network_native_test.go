// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package portal

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/olivaresai/olivares/core/api"
	coreaudit "github.com/olivaresai/olivares/core/audit"
	coreauth "github.com/olivaresai/olivares/core/auth"
	"github.com/olivaresai/olivares/core/engine"
	"github.com/olivaresai/olivares/core/model"
	"github.com/olivaresai/olivares/core/secure"
	"github.com/olivaresai/olivares/core/store"
)

// TestPortalNetwork_NativeSQLiteSessionLifecycle exercises the engine's actual
// authentication routes and store through the same portal handler as production.
// Protocol fixtures cannot prove that native cookies, claims and revocation agree.
func TestPortalNetwork_NativeSQLiteSessionLifecycle(t *testing.T) {
	testNativeSessionLifecycle(t, store.Config{Engine: store.EngineSQLite, DSN: ":memory:", Debug: true})
}

func TestPortalNetwork_NativePostgresSessionLifecycle(t *testing.T) {
	dsn := os.Getenv("OLIVARES_PORTAL_TEST_POSTGRES_SUPERUSER_DSN")
	if dsn == "" {
		t.Skip("requires a disposable portal PostgreSQL fixture")
	}
	parsed, err := url.Parse(dsn)
	if err != nil || parsed.Hostname() != "127.0.0.1" {
		t.Fatal("portal PostgreSQL fixture must use loopback")
	}
	secret := make([]byte, 24)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	password := hex.EncodeToString(secret)
	var tag [6]byte
	if _, err := rand.Read(tag[:]); err != nil {
		t.Fatal(err)
	}
	prefix := "portal_" + hex.EncodeToString(tag[:])
	result, err := engine.ProvisionPostgres(context.Background(), dsn, store.PgProvisionSpec{
		Database: prefix,
		App:      store.PgRole{Name: prefix + "_app", Password: password},
		Owner:    store.PgRole{Name: prefix + "_owner", Password: password},
		Admin:    &store.PgRole{Name: prefix + "_admin", Password: password},
		SSLMode:  "disable",
	}, true)
	if err != nil {
		t.Fatal("portal PostgreSQL fixture provisioning failed")
	}
	withPassword := func(hint string) string {
		u, err := url.Parse(hint)
		if err != nil || u.User == nil {
			t.Fatal("portal PostgreSQL fixture returned no role DSN")
		}
		u.User = url.UserPassword(u.User.Username(), password)
		return u.String()
	}
	testNativeSessionLifecycle(t, store.Config{
		Engine: store.EnginePostgres, DSN: withPassword(result.AppDSNHint),
		OwnerDSN: withPassword(result.OwnerDSNHint), AdminDSN: withPassword(result.AdminDSNHint),
		MaxConns: 2, Debug: true,
	})
}

// nativeConsole is the portal's production network handler over the engine's real routes and store.
type nativeConsole struct {
	authenticator *coreauth.Authenticator
	credential    string
	root          model.User
	access        networkAccess
	call          func(method, path string, body []byte, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder
	login         func(email string) *httptest.ResponseRecorder
}

func newNativeConsole(t *testing.T, config store.Config) *nativeConsole {
	t.Helper()
	ctx := context.Background()
	coreauth.SetTestHashParams(coreauth.TestArgonMemKiB, coreauth.TestArgonTime, coreauth.TestArgonThreads)
	t.Cleanup(func() {
		coreauth.SetTestHashParams(coreauth.DefaultArgonMemKiB, coreauth.DefaultArgonTime, coreauth.DefaultArgonThreads)
	})
	st, err := engine.Open(ctx, config, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.System(ctx, func(sys store.SystemScope) error {
		_, err := sys.EnsureSystemTenant(ctx)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	authenticator := coreauth.NewAuthenticator(st, nil)
	password := make([]byte, 24)
	if _, err := rand.Read(password); err != nil {
		t.Fatal(err)
	}
	credential := hex.EncodeToString(password)
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
	native, err := api.New(api.Options{
		Store: st, Authenticator: authenticator, Authorizer: coreauth.NewAuthorizer(nil),
		Signer: signer, SetupToken: secure.NewSetupToken(filepath.Join(t.TempDir(), "setup.token")),
	})
	if err != nil {
		t.Fatal(err)
	}
	handler, access := networkFixture(t, native.Handler().ServeHTTP)
	call := func(method, path string, body []byte, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "https://appliance.test:9443"+path, bytes.NewReader(body))
		r.Header.Set("Origin", "https://appliance.test:9443")
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Olivares-Session", "cookie")
		if cookie != nil {
			r.AddCookie(cookie)
		}
		if csrf != "" {
			r.Header.Set("X-CSRF-Token", csrf)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	login := func(email string) *httptest.ResponseRecorder {
		body, err := json.Marshal(map[string]string{"email": email, "password": credential})
		if err != nil {
			t.Fatal(err)
		}
		return call(http.MethodPost, "/v1/auth/login", body, nil, "")
	}
	return &nativeConsole{authenticator: authenticator, credential: credential, root: root, access: access, call: call, login: login}
}

func testNativeSessionLifecycle(t *testing.T, config store.Config) {
	t.Helper()
	ctx := context.Background()
	console := newNativeConsole(t, config)
	authenticator, credential, root, access, call, login := console.authenticator, console.credential, console.root, console.access, console.call, console.login
	rootLogin := login(root.Email)
	if rootLogin.Code != http.StatusOK {
		t.Fatalf("native login status = %d", rootLogin.Code)
	}
	rootCookies := rootLogin.Result().Cookies()
	if len(rootCookies) != 1 || rootCookies[0].Name != productSessionCookie || !rootCookies[0].Secure || !rootCookies[0].HttpOnly {
		t.Fatal("native login did not deliver the protected session cookie")
	}
	var envelope struct {
		CSRF  string `json:"csrf_token"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rootLogin.Body.Bytes(), &envelope); err != nil || envelope.CSRF == "" || envelope.Token != "" {
		t.Fatal("native cookie login changed the credential-free envelope")
	}
	for _, path := range []string{"/", "/status", "/network", "/firewall"} {
		w := call(http.MethodGet, path, nil, rootCookies[0], "")
		want := http.StatusOK
		// Authentication preserves the renderer's existing restriction: firewall
		// details are served only to loopback peers, even for a product superadmin.
		if path == "/firewall" {
			want = http.StatusNotFound
		}
		if w.Code != want {
			t.Fatalf("native root read %s = %d, want %d", path, w.Code, want)
		}
		if (path == "/" || path == "/status") && !strings.Contains(w.Body.String(), "protected-fingerprint") {
			t.Fatalf("native root read %s omitted host status", path)
		}
	}
	if w := call(http.MethodGet, "/v1/auth/browser-session", nil, rootCookies[0], ""); w.Code != http.StatusOK {
		t.Fatalf("native browser session restore = %d", w.Code)
	}
	rootPrincipal, err := authenticator.Authenticate(ctx, rootCookies[0].Value)
	if err != nil {
		t.Fatal("native session cookie does not authenticate")
	}
	target, err := authenticator.CreateUser(ctx, rootPrincipal, coreauth.NewUser{
		Email: "portal-target@example.test", Password: credential, Superadmin: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	targetLogin := login(target.Email)
	targetCookies := targetLogin.Result().Cookies()
	if targetLogin.Code != http.StatusOK || len(targetCookies) != 1 {
		t.Fatalf("native target login = %d", targetLogin.Code)
	}
	if w := call(http.MethodGet, "/status", nil, targetCookies[0], ""); w.Code != http.StatusOK {
		t.Fatalf("native target read before disabling = %d", w.Code)
	}
	if _, err := authenticator.SetSuperadminActive(ctx, rootPrincipal, target.ID, false); err != nil {
		t.Fatal(err)
	}
	if w := call(http.MethodGet, "/status", nil, targetCookies[0], ""); w.Code != http.StatusUnauthorized || strings.Contains(w.Body.String(), "protected-fingerprint") {
		t.Fatalf("disabled native identity read = %d", w.Code)
	}
	if w := login(target.Email); w.Code != http.StatusUnauthorized || len(w.Result().Cookies()) != 0 {
		t.Fatalf("disabled native identity login = %d", w.Code)
	}
	if w := call(http.MethodPost, "/v1/auth/logout", nil, rootCookies[0], ""); w.Code != http.StatusForbidden {
		t.Fatalf("native logout without CSRF = %d", w.Code)
	}
	if w := call(http.MethodPost, "/v1/auth/logout", nil, rootCookies[0], envelope.CSRF); w.Code != http.StatusNoContent {
		t.Fatalf("native logout = %d", w.Code)
	}
	if w := call(http.MethodGet, "/status", nil, rootCookies[0], ""); w.Code != http.StatusUnauthorized || strings.Contains(w.Body.String(), "protected-fingerprint") {
		t.Fatalf("native logged-out cookie read = %d", w.Code)
	}
	records, err := access.records.Pending()
	if err != nil {
		t.Fatal(err)
	}
	rootReads, targetReads, refusals := 0, 0, 0
	for _, record := range records {
		if record.Outcome == "refused" {
			refusals++
		}
		if record.Outcome != "performed" || record.Verb == "authentication.whoami" {
			continue
		}
		if record.Actor == rootPrincipal.Actor() {
			rootReads++
		}
		if record.Actor == "user:"+target.ID.String() {
			targetReads++
		}
	}
	// The root's /firewall read came from another host and was answered 404, so it is recorded as
	// refused: the reads served are /, /status and /network.
	if rootReads != 3 || targetReads != 1 || refusals < 5 {
		t.Fatalf("native audit attribution: root reads=%d, target reads=%d, refusals=%d", rootReads, targetReads, refusals)
	}
}

// The product's own step-up policy decides, through the engine's real whoami: a plain session is refused
// with the remedy once the deployment asks for a passkey, an editor is refused without it, and the
// answer follows the policy the moment it is lowered.
func TestPortalNetwork_NativeStepUpPolicyDecidesHostAdministration(t *testing.T) {
	console := newNativeConsole(t, store.Config{Engine: store.EngineSQLite, DSN: ":memory:", Debug: true})
	ctx := context.Background()
	rootLogin := console.login(console.root.Email)
	cookies := rootLogin.Result().Cookies()
	if rootLogin.Code != http.StatusOK || len(cookies) != 1 {
		t.Fatalf("native login = %d", rootLogin.Code)
	}
	session, err := console.authenticator.Authenticate(ctx, cookies[0].Value)
	if err != nil {
		t.Fatal(err)
	}
	read := func(cookie *http.Cookie) *httptest.ResponseRecorder {
		return console.call(http.MethodGet, "/status", nil, cookie, "")
	}
	if w := read(cookies[0]); w.Code != http.StatusOK {
		t.Fatalf("default policy read = %d: %s", w.Code, w.Body.String())
	}

	// A session that has just used a passkey (AAL3) may raise the policy; this one has not.
	passkey := session
	passkey.AAL = coreauth.AAL3
	if err := console.authenticator.SetAdminStepUp(ctx, passkey, coreauth.StepUpPasskey); err != nil {
		t.Fatal(err)
	}
	if w := read(cookies[0]); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "Step-up required") || strings.Contains(w.Body.String(), "protected-fingerprint") {
		t.Fatalf("passkey policy, plain session = %d: %s", w.Code, w.Body.String())
	}

	if _, err := console.authenticator.CreateUser(ctx, session, coreauth.NewUser{Email: "portal-editor@example.test", Password: console.credential}); err != nil {
		t.Fatal(err)
	}
	editor := console.login("portal-editor@example.test")
	editorCookies := editor.Result().Cookies()
	if editor.Code != http.StatusOK || len(editorCookies) != 1 {
		t.Fatalf("editor login = %d", editor.Code)
	}
	if w := read(editorCookies[0]); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "A product superadministrator is required") || strings.Contains(w.Body.String(), "Step-up") {
		t.Fatalf("editor = %d: %s", w.Code, w.Body.String())
	}

	if err := console.authenticator.SetAdminStepUp(ctx, passkey, coreauth.StepUpNone); err != nil {
		t.Fatal(err)
	}
	if w := read(cookies[0]); w.Code != http.StatusOK {
		t.Fatalf("policy lowered, plain session = %d: %s", w.Code, w.Body.String())
	}
}
