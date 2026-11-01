// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package portal

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/olivaresai/olivares/appliance/layer/portal/audit"
	"github.com/olivaresai/olivares/appliance/layer/portal/auth"
)

type signInStack struct {
	ready, readonly, denied, accountDenied, groupDenied, notMember bool
	password                                                       []byte
	starts, authenticates, accounts, closes                        int
}

func (s *signInStack) Measure() auth.PAMMeasurement { return auth.PAMMeasurement{Usable: s.ready} }
func (s *signInStack) LocalGroups(string) ([]string, error) {
	if s.readonly || s.groupDenied {
		return nil, auth.ErrNotAdmitted
	}
	if s.notMember {
		return []string{"users"}, nil
	}
	return []string{auth.AdministratorsGroup}, nil
}
func (s *signInStack) Start(string) (auth.Transaction, error) {
	s.starts++
	clear(s.password)
	if s.readonly {
		return nil, auth.ErrNotAdmitted
	}
	return s, nil
}
func (s *signInStack) Authenticate() error {
	s.authenticates++
	if s.denied {
		return auth.ErrNotAdmitted
	}
	return nil
}
func (s *signInStack) Account() error {
	s.accounts++
	if s.accountDenied {
		return auth.ErrNotAdmitted
	}
	return nil
}
func (s *signInStack) Close() error { s.closes++; return nil }

func repairSignInFixture(t *testing.T) (*protectedNetwork, *signInStack) {
	t.Helper()
	// A real refused connection is the product probe's only measured-down case.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := "https://" + l.Addr().String()
	_ = l.Close()
	dir := filepath.Join(t.TempDir(), "audit")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	records, err := audit.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: time.Second}
	t.Cleanup(client.CloseIdleConnections)
	h := networkHandler(Status{}, networkAccess{product: &productClient{endpoint: endpoint, http: client}, records: records}).(*protectedNetwork)
	measure := &signInStack{ready: true, readonly: true}
	h.measurePAM = func(context.Context) auth.Stack { return measure }
	return h, measure
}

func repairSignInRequest(handler http.Handler, method string, body []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://appliance.test:9443/sign-in", bytes.NewReader(body))
	r.Header.Set("Origin", "https://appliance.test:9443")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func TestPortalSignIn_RequestBoundNativeConversation(t *testing.T) {
	t.Run("verified product refusal keeps the product route", func(t *testing.T) {
		handler, _ := networkFixture(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/livez" {
				t.Error("unexpected product path")
			}
			w.WriteHeader(http.StatusForbidden)
		})
		w := nativeRequest(handler, http.MethodGet, "/sign-in", "", false)
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "8443") || strings.Contains(w.Body.String(), `type="password"`) {
			t.Fatalf("product sign-in page status=%d", w.Code)
		}
		calls := 0
		handler.(*protectedNetwork).requestPAM = func(context.Context, string, []byte) (auth.Stack, error) { calls++; return nil, nil }
		if w := repairSignInRequest(handler, http.MethodPost, []byte("login=operator&password=fixture")); w.Code != http.StatusConflict || calls != 0 {
			t.Fatal("answering product offered native PAM")
		}
	})
	t.Run("fresh repair conversation and separate Account", func(t *testing.T) {
		h, measure := repairSignInFixture(t)
		const secret = "fixture +&=% λ"
		requests := 0
		var conversations []*signInStack
		h.requestPAM = func(ctx context.Context, login string, password []byte) (auth.Stack, error) {
			requests++
			if ctx.Err() != nil || login != "operator" || string(password) != secret {
				return nil, errors.New("bad request binding")
			}
			s := &signInStack{ready: true, password: password}
			conversations = append(conversations, s)
			return s, nil
		}
		if w := repairSignInRequest(h, http.MethodGet, nil); w.Code != 200 || !strings.Contains(w.Body.String(), `type="password"`) || measure.starts != 0 {
			t.Fatalf("repair form status=%d", w.Code)
		}
		body := []byte(url.Values{"login": {"operator"}, "password": {secret}}.Encode())
		for range 2 {
			w := repairSignInRequest(h, http.MethodPost, body)
			if w.Code != 200 || !strings.Contains(w.Body.String(), "OS sign-in verified") || strings.Contains(w.Body.String(), secret) || len(w.Result().Cookies()) != 0 {
				t.Fatalf("repair sign-in status=%d", w.Code)
			}
		}
		if requests != 2 || len(conversations) != 2 || measure.starts != 0 {
			t.Fatal("conversation reused or measurement stack started")
		}
		for _, s := range conversations {
			if s.starts != 1 || s.authenticates != 1 || s.accounts != 1 || s.closes != 1 || bytes.Count(s.password, []byte{0}) != len(s.password) {
				t.Fatal("request secret or transaction lifetime retained")
			}
		}
		records, err := h.access.records.Pending()
		if err != nil || len(records) != 4 {
			t.Fatal("missing sign-in audit")
		}
		for i, r := range records {
			if r.Mode != "product-down-repair" || r.Verb != "repair.sign-in" || (i%2 == 0 && (r.Actor != "anonymous" || r.Outcome != "unknown")) || (i%2 == 1 && (r.Actor != "os-account:operator" || r.Outcome != "performed")) {
				t.Fatal("audit did not bind the verified account and mode")
			}
		}
	})
	t.Run("auth account and group refusals dispose credentials", func(t *testing.T) {
		for _, reason := range []string{"authenticate", "account", "group", "non-member"} {
			t.Run(reason, func(t *testing.T) {
				h, _ := repairSignInFixture(t)
				s := &signInStack{ready: true, denied: reason == "authenticate", accountDenied: reason == "account", groupDenied: reason == "group", notMember: reason == "non-member"}
				h.requestPAM = func(_ context.Context, _ string, password []byte) (auth.Stack, error) {
					s.password = password
					return s, nil
				}
				w := repairSignInRequest(h, http.MethodPost, []byte("login=operator&password=fixture"))
				if w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "verified") || bytes.Count(s.password, []byte{0}) != len(s.password) {
					t.Fatal("refused sign-in accepted or credential retained")
				}
				// A login outside olivares-admins reaches no transaction at all: the group is read, the stack never started.
				outside := reason == "group" || reason == "non-member"
				if (outside && (s.starts != 0 || s.authenticates != 0 || s.accounts != 0)) || (!outside && (s.starts != 1 || s.closes != 1)) || (reason == "authenticate" && s.accounts != 0) {
					t.Fatal("refused transaction lifetime or separate Account check changed")
				}
				records, err := h.access.records.Pending()
				if err != nil || len(records) != 2 || records[1].Actor != "anonymous" || records[1].Outcome != "refused" {
					t.Fatal("refusal not durably audited")
				}
			})
		}
	})
	t.Run("closed ingress refuses before requesting PAM", func(t *testing.T) {
		for _, body := range []string{
			"login=operator&password=fixture&actor=root", "login=operator&login=root", "login=operator&password=", "login=operator&password=%xy", "login=operator&password=" + strings.Repeat("x", 8<<10),
		} {
			h, _ := repairSignInFixture(t)
			calls := 0
			h.requestPAM = func(context.Context, string, []byte) (auth.Stack, error) { calls++; return nil, nil }
			if w := repairSignInRequest(h, http.MethodPost, []byte(body)); w.Code != http.StatusForbidden || calls != 0 {
				t.Fatal("malformed ingress reached PAM")
			}
		}
		for _, boundary := range []string{"origin", "tls", "query", "media", "audit", "unmeasured", "unusable"} {
			t.Run(boundary, func(t *testing.T) {
				h, measure := repairSignInFixture(t)
				calls := 0
				h.requestPAM = func(context.Context, string, []byte) (auth.Stack, error) { calls++; return nil, nil }
				r := httptest.NewRequest(http.MethodPost, "https://appliance.test/sign-in", strings.NewReader("login=operator&password=fixture"))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				want := http.StatusServiceUnavailable
				switch boundary {
				case "origin":
					r.Header.Set("Origin", "https://foreign.test")
					want = http.StatusForbidden
				case "tls":
					r.TLS = nil
					want = http.StatusBadRequest
				case "query":
					r.URL.RawQuery = "password=fixture"
					want = http.StatusBadRequest
				case "media":
					r.Header.Set("Content-Type", "application/json")
					want = http.StatusUnsupportedMediaType
				case "audit":
					h.access.records = nil
				case "unmeasured":
					h.access.product = nil
				case "unusable":
					measure.ready = false
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				if w.Code != want || calls != 0 || measure.starts != 0 {
					t.Fatalf("ingress boundary %s status=%d PAM calls=%d", boundary, w.Code, calls)
				}
			})
		}
	})
	t.Run("product recovery and cancellation prevent Start", func(t *testing.T) {
		for _, boundary := range []string{"product recovered", "canceled"} {
			t.Run(boundary, func(t *testing.T) {
				h, _ := repairSignInFixture(t)
				up, _ := networkFixture(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) })
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				s := &signInStack{ready: true}
				h.requestPAM = func(_ context.Context, _ string, password []byte) (auth.Stack, error) {
					s.password = password
					if boundary == "canceled" {
						cancel()
					} else {
						h.access.product = up.(*protectedNetwork).access.product
					}
					return s, nil
				}
				r := httptest.NewRequest(http.MethodPost, "https://appliance.test/sign-in", strings.NewReader("login=operator&password=fixture")).WithContext(ctx)
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				want := http.StatusConflict
				if boundary == "canceled" {
					want = http.StatusServiceUnavailable
				}
				if w.Code != want || s.starts != 0 || bytes.Count(s.password, []byte{0}) != len(s.password) {
					t.Fatal("recovered or canceled request reached PAM or retained credentials")
				}
			})
		}
	})
	t.Run("lost audit refuses before and after authentication", func(t *testing.T) {
		for _, intent := range []bool{false, true} {
			h, _ := repairSignInFixture(t)
			var entropy []byte
			if intent {
				entropy = make([]byte, 16)
			}
			h.access.records.Random = bytes.NewReader(entropy)
			s := &signInStack{ready: true}
			h.requestPAM = func(_ context.Context, _ string, password []byte) (auth.Stack, error) {
				s.password = password
				return s, nil
			}
			w := repairSignInRequest(h, http.MethodPost, []byte("login=operator&password=fixture"))
			if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "verified") || (!intent && s.starts != 0) || (intent && s.starts != 1) || bytes.Count(s.password, []byte{0}) != len(s.password) {
				t.Fatal("audit failure accepted sign-in or retained credentials")
			}
			records, err := h.access.records.Pending()
			if err != nil || (!intent && len(records) != 0) || (intent && (len(records) != 1 || records[0].Outcome != "unknown")) {
				t.Fatal("unknown intent did not survive lost result audit")
			}
		}
	})
	t.Run("cancellation during final audit refuses the offer", func(t *testing.T) {
		h, _ := repairSignInFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		s := &signInStack{ready: true}
		h.requestPAM = func(_ context.Context, _ string, password []byte) (auth.Stack, error) {
			s.password = password
			return s, nil
		}
		h.access.records.Now = func() time.Time {
			if s.authenticates != 0 {
				cancel()
			}
			return time.Now()
		}
		r := httptest.NewRequest(http.MethodPost, "https://appliance.test/sign-in", strings.NewReader("login=operator&password=fixture")).WithContext(ctx)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "verified") || s.starts != 1 || s.closes != 1 || bytes.Count(s.password, []byte{0}) != len(s.password) {
			t.Fatal("expired request returned a verified offer or retained credentials")
		}
	})
}
