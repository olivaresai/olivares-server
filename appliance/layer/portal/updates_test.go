// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package portal

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/olivaresai/olivares/appliance/layer/helpers/helperschema"
)

const (
	updatesBlob    = "LICENCE-BLOB-fixture.AbCd0123"
	updatesStatus  = `{"edition":"community","status":"none","source":"none","managed_externally":false,"hot_apply":true,"max_users":0,"seat_limit":0,"seat_limited":false,"active_users":1}`
	updatesStatus2 = `{"edition":"community","status":"valid","source":"data-dir","managed_externally":false,"licensee":"Acme","plan":"business","hot_apply":true,"max_users":0,"seat_limit":0,"seat_limited":false,"active_users":1}`
)

// productCalls is a product stand-in that records what the console asked of it.
type productCalls struct {
	mu       sync.Mutex
	requests []string
	bodies   []string
	headers  []http.Header
	claims   string
	licence  func(w http.ResponseWriter, r *http.Request)
	// read overrides the answer of GET /v1/console/license and browser-session by path.
	read      map[string]func(w http.ResponseWriter, r *http.Request)
	installed bool
}

func (p *productCalls) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		p.mu.Lock()
		p.requests = append(p.requests, r.Method+" "+r.URL.Path)
		p.bodies = append(p.bodies, string(body))
		p.headers = append(p.headers, r.Header.Clone())
		p.mu.Unlock()
		if override := p.read[r.Method+" "+r.URL.Path]; override != nil {
			override(w, r)
			return
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /v1/auth/whoami":
			claims := p.claims
			if claims == "" {
				claims = nativeClaims(true)
			}
			_, _ = io.WriteString(w, claims)
		case "GET /v1/auth/browser-session":
			if _, err := r.Cookie("__Host-olivares-session"); err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = io.WriteString(w, `{"session_id":"s","expires_at":"2027-01-01T00:00:00Z","csrf_token":"fixture-csrf"}`)
		case "GET /v1/console/license":
			p.mu.Lock()
			installed := p.installed
			p.mu.Unlock()
			if installed {
				_, _ = io.WriteString(w, updatesStatus2)
				return
			}
			_, _ = io.WriteString(w, updatesStatus)
		case "POST /v1/console/license":
			if p.licence != nil {
				p.licence(w, r)
				return
			}
			p.mu.Lock()
			p.installed = true
			p.mu.Unlock()
			_, _ = io.WriteString(w, updatesStatus2)
		default:
			t.Errorf("unexpected product request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}
}

func (p *productCalls) paths() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.requests...)
}

func (p *productCalls) count(request string) int {
	n := 0
	for _, r := range p.paths() {
		if r == request {
			n++
		}
	}
	return n
}

func updatesRequest(handler http.Handler, method, path string, form url.Values, mutate func(*http.Request)) *httptest.ResponseRecorder {
	body := ""
	if form != nil {
		body = form.Encode()
	}
	r := httptest.NewRequest(method, "https://appliance.test:9443"+path, strings.NewReader(body))
	r.RemoteAddr = "192.0.2.50:5555"
	r.AddCookie(&http.Cookie{Name: "__Host-olivares-session", Value: "fixture-session"})
	r.AddCookie(&http.Cookie{Name: "unrelated", Value: "do-not-forward"})
	r.Header.Set("Origin", "https://appliance.test:9443")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if mutate != nil {
		mutate(r)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func activation(license string) url.Values {
	return url.Values{"license": {license}, "csrf_token": {"fixture-csrf"}}
}

func TestPortalUpdates_ServedToASignedInSuperadministratorOnAnyHostWithTheProductsLicence(t *testing.T) {
	product := &productCalls{}
	handler, access := networkFixture(t, product.handler(t))
	for _, peer := range []string{"192.0.2.50:5555", localPeer} {
		w := updatesRequest(handler, http.MethodGet, "/updates", nil, func(r *http.Request) { r.RemoteAddr = peer })
		body := w.Body.String()
		if w.Code != http.StatusOK || !strings.Contains(body, "<h1>Updates and activation</h1>") {
			t.Fatalf("peer %s: %d %s", peer, w.Code, body)
		}
		for _, want := range []string{"No licence is installed", "Community build", `action="/updates/licence"`, `name="csrf_token" value="fixture-csrf"`} {
			if !strings.Contains(body, want) {
				t.Errorf("peer %s: page lacks %q:\n%s", peer, want, body)
			}
		}
		if w.Header().Get("Cache-Control") != "no-store" || !strings.Contains(w.Header().Get("Content-Security-Policy"), "default-src 'none'") {
			t.Errorf("headers: %v", w.Header())
		}
	}
	// A bearer caller has no browser session: the page names the command line and offers no form.
	w := updatesRequest(handler, http.MethodGet, "/updates", nil, func(r *http.Request) {
		r.Header.Del("Cookie")
		r.Header.Set("Authorization", "Bearer fixture-session")
	})
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "<form") || !strings.Contains(w.Body.String(), "olivares license install") {
		t.Errorf("bearer caller: %d\n%s", w.Code, w.Body.String())
	}
	records, err := access.records.Pending()
	if err != nil || len(records) != 3 {
		t.Fatalf("audit: %d records, %v", len(records), err)
	}
	for _, record := range records {
		if record.Verb != "host-updates.read" || record.Outcome != "performed" || record.Actor != nativeActor || record.Surface != "web" {
			t.Errorf("record %+v", record)
		}
	}
	for i, headers := range product.headers {
		if strings.Contains(headers.Get("Cookie"), "unrelated") {
			t.Errorf("request %d forwarded an unrelated cookie", i)
		}
	}
}

func TestPortalUpdates_RefusesWhoIsNotAHumanSuperadministratorBeforeAskingForTheLicence(t *testing.T) {
	for _, claims := range []string{nativeClaims(false), strings.Replace(nativeClaims(true), `"user"`, `"token"`, 1), `{"kind":"user","superadmin":true}`} {
		product := &productCalls{claims: claims}
		handler, _ := networkFixture(t, product.handler(t))
		for _, tc := range []struct{ method, path string }{{http.MethodGet, "/updates"}, {http.MethodPost, "/updates/licence"}} {
			var form url.Values
			if tc.method == http.MethodPost {
				form = activation(updatesBlob)
			}
			w := updatesRequest(handler, tc.method, tc.path, form, nil)
			if w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "<h1>") {
				t.Errorf("%s %s with %s: %d %s", tc.method, tc.path, claims, w.Code, w.Body.String())
			}
		}
		for _, r := range product.paths() {
			if r != "GET /v1/auth/whoami" {
				t.Errorf("a refused caller reached %s", r)
			}
		}
	}
	product := &productCalls{}
	handler, _ := networkFixture(t, product.handler(t))
	for _, tc := range []struct{ method, path string }{{http.MethodGet, "/updates"}, {http.MethodPost, "/updates/licence"}} {
		w := updatesRequest(handler, tc.method, tc.path, nil, func(r *http.Request) { r.Header.Del("Cookie") })
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s with no session: %d", tc.method, tc.path, w.Code)
		}
	}
	if len(product.paths()) != 0 {
		t.Errorf("a request with no session reached the product: %v", product.paths())
	}
}

func TestPortalUpdates_RelaysTheLicenceToTheProductsOwnAPIUnderTheCallersSession(t *testing.T) {
	product := &productCalls{}
	handler, access := networkFixture(t, product.handler(t))
	w := updatesRequest(handler, http.MethodPost, "/updates/licence", activation(updatesBlob), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("activation: %d %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, want := range []string{"The licence is installed", "Acme", "business", "Apply the product update"} {
		if !strings.Contains(body, want) {
			t.Errorf("the answer lacks %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, updatesBlob) {
		t.Errorf("the answer echoes the licence:\n%s", body)
	}
	if got := product.count("POST /v1/console/license"); got != 1 {
		t.Fatalf("the product saw %d installs: %v", got, product.paths())
	}
	for i, request := range product.paths() {
		if request != "POST /v1/console/license" {
			continue
		}
		if product.bodies[i] != `{"license":"`+updatesBlob+`"}` {
			t.Errorf("the product received %q", product.bodies[i])
		}
		h := product.headers[i]
		if h.Get("Content-Type") != "application/json" || h.Get("X-CSRF-Token") != "fixture-csrf" || h.Get("Origin") != "https://appliance.test:9443" {
			t.Errorf("relayed headers: %v", h)
		}
		if c := h.Get("Cookie"); !strings.Contains(c, "__Host-olivares-session=fixture-session") || strings.Contains(c, "unrelated") {
			t.Errorf("relayed cookie %q", c)
		}
	}
	records, err := access.records.Pending()
	if err != nil || len(records) != 2 {
		t.Fatalf("audit: %d records, %v", len(records), err)
	}
	// The intent before the product is asked, then its outcome.
	want := []struct{ verb, outcome string }{{"host-updates.activate", "unknown"}, {"host-updates.activate", "performed"}}
	for i, tc := range want {
		if r := records[i]; r.Verb != tc.verb || r.Outcome != tc.outcome || r.Actor != nativeActor || r.Surface != "web" {
			t.Errorf("record %d: %+v, want %+v", i, r, tc)
		}
	}
	for _, record := range records {
		if raw := fmt.Sprint(record); strings.Contains(raw, updatesBlob) || strings.Contains(raw, "fixture-csrf") || strings.Contains(raw, "fixture-session") {
			t.Errorf("audit carries the licence, the token or the session: %s", raw)
		}
	}
}

func TestPortalUpdates_TheProductsRefusalIsShownByItsStatusAndNeverByItsText(t *testing.T) {
	for _, tc := range []struct {
		status int
		want   string
	}{{http.StatusForbidden, "step-up"}, {http.StatusConflict, "managed outside this console"}, {http.StatusBadRequest, "did not accept"}, {http.StatusNotImplemented, "not available"}} {
		product := &productCalls{licence: func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = io.WriteString(w, `{"error":{"code":"x","message":"<script>alert(1)</script> `+updatesBlob+`"}}`)
		}}
		handler, access := networkFixture(t, product.handler(t))
		w := updatesRequest(handler, http.MethodPost, "/updates/licence", activation(updatesBlob), nil)
		if w.Code != tc.status || !strings.Contains(w.Body.String(), tc.want) || strings.Contains(w.Body.String(), "<script>") || strings.Contains(w.Body.String(), updatesBlob) {
			t.Errorf("product %d: portal %d\n%s", tc.status, w.Code, w.Body.String())
		}
		records, _ := access.records.Pending()
		wantOutcome := "refused"
		if tc.status == http.StatusNotImplemented {
			wantOutcome = "failed"
		}
		if len(records) != 2 || records[0].Outcome != "unknown" || records[1].Outcome != wantOutcome {
			t.Errorf("product %d: records %+v", tc.status, records)
		}
	}
}

// A product that fails after it was asked may have written the licence first, so the outcome is unknown,
// never "failed", and the page says the licence may or may not have been installed.
func TestPortalUpdates_AProductFailureAfterTheAskIsRecordedUnknownAndSaysSo(t *testing.T) {
	for _, status := range []int{http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout} {
		product := &productCalls{licence: func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }}
		handler, access := networkFixture(t, product.handler(t))
		w := updatesRequest(handler, http.MethodPost, "/updates/licence", activation(updatesBlob), nil)
		if w.Code != status || !strings.Contains(w.Body.String(), "may or may not have been installed") || strings.Contains(w.Body.String(), "not available") {
			t.Errorf("product %d: portal %d\n%s", status, w.Code, w.Body.String())
		}
		if records, _ := access.records.Pending(); len(records) != 2 || records[0].Outcome != "unknown" || records[1].Outcome != "unknown" {
			t.Errorf("product %d: records %+v", status, records)
		}
	}
}

// The banner says the licence is installed only when the licence read back after the install shows one.
func TestPortalUpdates_TheInstalledBannerNeedsTheReadBackToShowALicence(t *testing.T) {
	product := &productCalls{licence: func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, updatesStatus) }}
	handler, access := networkFixture(t, product.handler(t))
	w := updatesRequest(handler, http.MethodPost, "/updates/licence", activation(updatesBlob), nil)
	body := w.Body.String()
	if w.Code != http.StatusOK || strings.Contains(body, "The licence is installed") || !strings.Contains(body, "does not show it") {
		t.Errorf("%d\n%s", w.Code, body)
	}
	if records, _ := access.records.Pending(); len(records) != 2 || records[1].Outcome != "performed" {
		t.Errorf("the product answered 200, so the record says so: %+v", records)
	}
}

// A request the console refuses itself is audited with the activation verb, by the caller who made it.
func TestPortalUpdates_ARefusalOfTheConsoleIsAuditedWithItsVerb(t *testing.T) {
	for name, tc := range map[string]struct {
		claims string
		form   url.Values
	}{
		"a caller who is not a superadministrator": {nativeClaims(false), activation(updatesBlob)},
		"a form without a token":                   {"", url.Values{"license": {updatesBlob}}},
	} {
		t.Run(name, func(t *testing.T) {
			product := &productCalls{claims: tc.claims}
			handler, access := networkFixture(t, product.handler(t))
			w := updatesRequest(handler, http.MethodPost, "/updates/licence", tc.form, nil)
			records, _ := access.records.Pending()
			if w.Code != http.StatusForbidden || len(records) != 1 {
				t.Fatalf("%d, records %+v", w.Code, records)
			}
			if r := records[0]; r.Verb != "host-updates.activate" || r.Outcome != "refused" || r.Actor != nativeActor || r.Surface != "web" {
				t.Errorf("record %+v", r)
			}
			if product.count("POST /v1/console/license") != 0 {
				t.Errorf("the product was asked: %v", product.paths())
			}
		})
	}
}

// failAfterRandom serves n reads and then fails, so a later audit write fails after an earlier one was durable.
type failAfterRandom struct {
	mu   sync.Mutex
	left int
}

func (f *failAfterRandom) Read(b []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.left <= 0 {
		return 0, errors.New("audit unavailable")
	}
	f.left--
	return rand.Read(b)
}

// The intent is durable and the product installed the licence, but its outcome cannot be recorded: the
// caller is told the licence may be installed, and the record that stays says unknown.
func TestPortalUpdates_AnOutcomeThatCannotBeRecordedSaysTheLicenceMayBeInstalled(t *testing.T) {
	product := &productCalls{}
	handler, access := networkFixture(t, product.handler(t))
	access.records.Random = &failAfterRandom{left: 1}
	w := updatesRequest(handler, http.MethodPost, "/updates/licence", activation(updatesBlob), nil)
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "may have been installed") || product.count("POST /v1/console/license") != 1 {
		t.Errorf("%d, product %v\n%s", w.Code, product.paths(), w.Body.String())
	}
	if records, _ := access.records.Pending(); len(records) != 1 || records[0].Outcome != "unknown" {
		t.Errorf("records %+v", records)
	}
}

// A licence may hold lines and tabs and is trimmed; its bound is what the form body can carry when every
// byte of it is escaped, so no licence the console accepts by length is refused for its size.
func TestPortalUpdates_ALicenceMayHoldLinesIsTrimmedAndIsBoundedByWhatTheBodyCanCarry(t *testing.T) {
	product := &productCalls{}
	handler, _ := networkFixture(t, product.handler(t))
	w := updatesRequest(handler, http.MethodPost, "/updates/licence", activation("  line one\r\nline two\tend\n  "), nil)
	want, _ := json.Marshal(struct {
		License string `json:"license"`
	}{"line one\r\nline two\tend"})
	if w.Code != http.StatusOK {
		t.Fatalf("a licence of several lines: %d %s", w.Code, w.Body.String())
	}
	var sent []string
	for i, request := range product.paths() {
		if request == "POST /v1/console/license" {
			sent = append(sent, product.bodies[i])
		}
	}
	if len(sent) != 1 || sent[0] != string(want) {
		t.Errorf("the product received %q, want %q", sent, want)
	}
	for name, tc := range map[string]struct {
		blob string
		code int
	}{
		"the largest licence":                         {strings.Repeat("x", maxLicenceBlob), http.StatusOK},
		"the largest licence with every byte escaped": {strings.Repeat("+", maxLicenceBlob), http.StatusOK},
		"one byte more than the largest":              {strings.Repeat("x", maxLicenceBlob+1), http.StatusBadRequest},
	} {
		t.Run(name, func(t *testing.T) {
			product := &productCalls{}
			handler, _ := networkFixture(t, product.handler(t))
			w := updatesRequest(handler, http.MethodPost, "/updates/licence", activation(tc.blob), nil)
			if w.Code != tc.code {
				t.Errorf("%d, want %d", w.Code, tc.code)
			}
			if wantInstalls := map[bool]int{true: 1, false: 0}[tc.code == http.StatusOK]; product.count("POST /v1/console/license") != wantInstalls {
				t.Errorf("the product saw %d installs", product.count("POST /v1/console/license"))
			}
		})
	}
}

func TestPortalUpdates_ARelayedInstallIsRefusedBeforeTheProductIsAskedWhen(t *testing.T) {
	for name, tc := range map[string]struct {
		form   url.Values
		mutate func(*http.Request)
		code   int
	}{
		"the origin is another site":         {activation(updatesBlob), func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }, http.StatusForbidden},
		"the browser says cross-site":        {activation(updatesBlob), func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, http.StatusForbidden},
		"there is no csrf token":             {url.Values{"license": {updatesBlob}}, nil, http.StatusForbidden},
		"the csrf token is empty":            {url.Values{"license": {updatesBlob}, "csrf_token": {""}}, nil, http.StatusForbidden},
		"the licence is empty":               {url.Values{"license": {"  "}, "csrf_token": {"fixture-csrf"}}, nil, http.StatusBadRequest},
		"the licence is missing":             {url.Values{"csrf_token": {"fixture-csrf"}}, nil, http.StatusBadRequest},
		"the body is JSON":                   {activation(updatesBlob), func(r *http.Request) { r.Header.Set("Content-Type", "application/json") }, http.StatusUnsupportedMediaType},
		"the body is larger than the bound":  {activation(strings.Repeat("x", 70<<10)), nil, http.StatusRequestEntityTooLarge},
		"the licence holds a control byte":   {activation("abc\x00def"), nil, http.StatusBadRequest},
		"the licence is not UTF-8":           {activation("abc\xffdef"), nil, http.StatusBadRequest},
		"the licence field is sent twice":    {url.Values{"license": {updatesBlob, updatesBlob}, "csrf_token": {"fixture-csrf"}}, nil, http.StatusBadRequest},
		"the csrf token is sent twice":       {url.Values{"license": {updatesBlob}, "csrf_token": {"a", "b"}}, nil, http.StatusBadRequest},
		"the query string carries the token": {nil, func(r *http.Request) { r.URL.RawQuery = "license=" + updatesBlob + "&csrf_token=fixture-csrf" }, http.StatusUnsupportedMediaType},
	} {
		t.Run(name, func(t *testing.T) {
			product := &productCalls{}
			handler, _ := networkFixture(t, product.handler(t))
			w := updatesRequest(handler, http.MethodPost, "/updates/licence", tc.form, tc.mutate)
			if w.Code != tc.code {
				t.Errorf("%d, want %d: %s", w.Code, tc.code, w.Body.String())
			}
			if product.count("POST /v1/console/license") != 0 {
				t.Errorf("the product was asked to install: %v", product.paths())
			}
		})
	}
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		product := &productCalls{}
		handler, _ := networkFixture(t, product.handler(t))
		if w := updatesRequest(handler, method, "/updates/licence", nil, nil); w.Code != http.StatusMethodNotAllowed || product.count("POST /v1/console/license") != 0 {
			t.Errorf("%s /updates/licence: %d", method, w.Code)
		}
	}
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		product := &productCalls{}
		handler, _ := networkFixture(t, product.handler(t))
		if w := updatesRequest(handler, method, "/updates", nil, nil); w.Code != http.StatusMethodNotAllowed || product.count("POST /v1/console/license") != 0 {
			t.Errorf("%s /updates: %d", method, w.Code)
		}
	}
}

func TestPortalUpdates_NoInstallWithoutADurableIntent(t *testing.T) {
	product := &productCalls{}
	handler, access := networkFixture(t, product.handler(t))
	access.records.Random = failedAuditRandom{}
	w := updatesRequest(handler, http.MethodPost, "/updates/licence", activation(updatesBlob), nil)
	if w.Code != http.StatusServiceUnavailable || product.count("POST /v1/console/license") != 0 {
		t.Errorf("audit failure: %d, product asked %v", w.Code, product.paths())
	}
}

func TestPortalUpdates_AProductThatCannotBeUnderstoodIsRecordedUnknownAndSaysSo(t *testing.T) {
	product := &productCalls{licence: func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, strings.Repeat("x", 65537)) }}
	handler, access := networkFixture(t, product.handler(t))
	w := updatesRequest(handler, http.MethodPost, "/updates/licence", activation(updatesBlob), nil)
	if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), updatesBlob) {
		t.Errorf("oversized product answer: %d %s", w.Code, w.Body.String())
	}
	records, _ := access.records.Pending()
	if len(records) != 2 || records[0].Outcome != "unknown" || records[1].Outcome != "unknown" || !strings.Contains(w.Body.String(), "may or may not have been installed") {
		t.Errorf("records %+v", records)
	}
}

// The local handler, which the console serves on loopback before anyone has signed in, shows the
// page with the units it has read and the licence unread, and no form.
func TestPortalUpdates_TheLocalPageHasNoSessionSoItHasNoLicenceAndNoForm(t *testing.T) {
	handler := NewHandler(Status{Pages: readConsole()})
	rec := serve(t, handler, http.MethodGet, "/updates", localPeer)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "licence is unread") || strings.Contains(body, "<form") || !strings.Contains(body, "dnf-automatic-install.timer") {
		t.Fatalf("local /updates: %d\n%s", rec.Code, body)
	}
	if rec := serve(t, NewHandler(Status{}), http.MethodGet, "/updates", localPeer); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "unmeasured") {
		t.Errorf("local /updates with no reads: %d", rec.Code)
	}
	if rec := serve(t, handler, http.MethodPost, "/updates/licence", localPeer); rec.Code == http.StatusOK {
		t.Errorf("the local handler took a licence: %d", rec.Code)
	}
}

func TestPortalUpdates_UnitStatesComeFromTheConsolesLastRead(t *testing.T) {
	reads := newModuleReads(func() time.Time { return time.Date(2026, 10, 16, 20, 0, 0, 0, time.UTC) })
	reads.refresh(t.Context(), func(ctx context.Context, name string, _ helperschema.Request) (helperschema.Response, error) {
		if name != helperschema.HelperUnits {
			return helperschema.Response{Result: helperschema.ResultFailed}, nil
		}
		return helperschema.Response{Result: helperschema.ResultAnswered, Bundle: json.RawMessage(`{"units":[
{"name":"dnf-automatic-install.timer","load_state":"loaded","active_state":"active","sub_state":"waiting"},
{"name":"dnf-automatic-install.service","load_state":"loaded","active_state":"failed","sub_state":"failed"},
{"name":"sshd.service","load_state":"loaded","active_state":"active","sub_state":"running"}],"truncated":false}`)}, nil
	})
	body := serve(t, NewHandler(Status{Pages: reads}), http.MethodGet, "/updates", localPeer).Body.String()
	for _, want := range []string{"active (waiting)", "failed (failed)", "olivares-appliance-update.service</td><td>not loaded"} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "sshd.service") {
		t.Errorf("the page names a unit it does not report:\n%s", body)
	}
}

// The relay acts for the browser session alone: a bearer credential sent with it is never passed to the product.
func TestPortalUpdates_TheRelayForwardsTheSessionCookieAndNoBearerCredential(t *testing.T) {
	product := &productCalls{}
	handler, _ := networkFixture(t, product.handler(t))
	w := updatesRequest(handler, http.MethodPost, "/updates/licence", activation(updatesBlob), func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer someone-elses-token")
		r.Header.Set("X-Olivares-Session", "cookie")
	})
	if w.Code != http.StatusOK {
		t.Fatalf("activation: %d %s", w.Code, w.Body.String())
	}
	for i, h := range product.headers {
		if h.Get("Authorization") != "" || h.Get("X-Olivares-Session") != "" {
			t.Errorf("request %d (%s) carried a credential or transport the client chose: %v", i, product.requests[i], h)
		}
	}
	w = updatesRequest(handler, http.MethodPost, "/updates/licence", activation(updatesBlob), func(r *http.Request) {
		r.Header.Del("Cookie")
		r.Header.Set("Authorization", "Bearer someone-elses-token")
	})
	if w.Code != http.StatusUnauthorized {
		t.Errorf("a bearer credential alone: %d", w.Code)
	}
}

// What the page cannot read from the product it says, and never offers a form on a token it cannot vouch for.
func TestPortalUpdates_AReadTheProductDoesNotAnswerLeavesTheLicenceUnreadAndTheFormOut(t *testing.T) {
	status := func(code int, body string) func(http.ResponseWriter, *http.Request) {
		return func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code); _, _ = io.WriteString(w, body) }
	}
	for name, tc := range map[string]struct {
		read     map[string]func(http.ResponseWriter, *http.Request)
		unread   bool
		withForm bool
	}{
		"licence 401":          {map[string]func(http.ResponseWriter, *http.Request){"GET /v1/console/license": status(401, `{}`)}, true, true},
		"licence 500":          {map[string]func(http.ResponseWriter, *http.Request){"GET /v1/console/license": status(500, `{}`)}, true, true},
		"licence foreign body": {map[string]func(http.ResponseWriter, *http.Request){"GET /v1/console/license": status(200, `<html>`)}, true, true},
		"session 401":          {map[string]func(http.ResponseWriter, *http.Request){"GET /v1/auth/browser-session": status(401, `{}`)}, false, false},
		"session 500":          {map[string]func(http.ResponseWriter, *http.Request){"GET /v1/auth/browser-session": status(500, `{}`)}, false, false},
		"session bad token":    {map[string]func(http.ResponseWriter, *http.Request){"GET /v1/auth/browser-session": status(200, `{"csrf_token":"a\"><script>"}`)}, false, false},
		"session no token":     {map[string]func(http.ResponseWriter, *http.Request){"GET /v1/auth/browser-session": status(200, `{}`)}, false, false},
	} {
		t.Run(name, func(t *testing.T) {
			product := &productCalls{read: tc.read}
			handler, _ := networkFixture(t, product.handler(t))
			w := updatesRequest(handler, http.MethodGet, "/updates", nil, nil)
			body := w.Body.String()
			if w.Code != http.StatusOK || strings.Contains(body, "<script>") {
				t.Fatalf("%d\n%s", w.Code, body)
			}
			if got := strings.Contains(body, "The licence is unread"); got != tc.unread {
				t.Errorf("licence unread = %v, want %v:\n%s", got, tc.unread, body)
			}
			if got := strings.Contains(body, "<form"); got != tc.withForm {
				t.Errorf("form offered = %v, want %v:\n%s", got, tc.withForm, body)
			}
		})
	}
}

// A product that gives an install an answer the page cannot read is still read afterwards: the page
// shows what the product holds, not what the answer said.
func TestPortalUpdates_AnInstallAnsweredWithAnUnreadableBodyShowsWhatTheProductHolds(t *testing.T) {
	product := &productCalls{licence: func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `<html>`)
	}}
	handler, _ := networkFixture(t, product.handler(t))
	product.mu.Lock()
	product.installed = true // the product has the licence the next read returns
	product.mu.Unlock()
	w := updatesRequest(handler, http.MethodPost, "/updates/licence", activation(updatesBlob), nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Acme") || strings.Contains(w.Body.String(), "The licence is unread") {
		t.Errorf("%d\n%s", w.Code, w.Body.String())
	}
}

// An inventory cut at its bound does not say a unit beyond the cut is idle or off.
func TestPortalUpdates_ATruncatedInventoryLeavesTheUnitsUnmeasured(t *testing.T) {
	reads := newModuleReads(time.Now)
	reads.refresh(t.Context(), func(ctx context.Context, name string, _ helperschema.Request) (helperschema.Response, error) {
		if name != helperschema.HelperUnits {
			return helperschema.Response{Result: helperschema.ResultFailed}, nil
		}
		return helperschema.Response{Result: helperschema.ResultAnswered, Bundle: json.RawMessage(`{"units":[{"name":"sshd.service","load_state":"loaded","active_state":"active","sub_state":"running"}],"truncated":true}`)}, nil
	})
	body := serve(t, NewHandler(Status{Pages: reads}), http.MethodGet, "/updates", localPeer).Body.String()
	if strings.Contains(body, "not loaded: off") || !strings.Contains(body, "dnf-automatic-install.timer</td><td>unmeasured") {
		t.Errorf("a truncated inventory is read as units that are off or idle:\n%s", body)
	}
}
