// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package updatepage

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/olivaresai/olivares/appliance/layer/services"
)

func serve(t *testing.T, s Snapshot, method string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	Page(s).ServeHTTP(w, httptest.NewRequest(method, "https://appliance.test:9443/updates", nil))
	return w
}

func TestPage_ReadsOnlyAndNamesNoActOfItsOwn(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		w := serve(t, Snapshot{}, method)
		if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET, HEAD" {
			t.Errorf("%s: %d allow %q, want 405 with GET, HEAD", method, w.Code, w.Header().Get("Allow"))
		}
	}
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		if w := serve(t, Snapshot{}, method); w.Code != http.StatusOK {
			t.Errorf("%s: %d", method, w.Code)
		}
	}
}

func TestPage_LicenceStatesSayWhatTheNextStepIs(t *testing.T) {
	expires := time.Date(2027, 3, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		l    Licence
		want []string
		not  []string
	}{
		{"unread", Licence{}, []string{"The licence is unread"}, []string{"Business build"}},
		{"none", Licence{Read: true, Edition: "community", Status: "none"}, []string{"No licence is installed", "Community build"}, nil},
		{"valid on community", Licence{Read: true, Edition: "community", Status: "valid", Licensee: "Acme", Plan: "business", ExpiresAt: &expires},
			[]string{"Acme", "business", "2027-03-01", "Community build", "Apply the product update"}, []string{"Business build is running"}},
		{"valid on business", Licence{Read: true, Edition: "enterprise", Status: "valid", Licensee: "Acme"},
			[]string{"Business build is running"}, []string{"Apply the product update"}},
		{"expired", Licence{Read: true, Edition: "enterprise", Status: "expired"}, []string{"expired", "security updates only"}, nil},
		{"invalid", Licence{Read: true, Edition: "community", Status: "invalid"}, []string{"does not verify"}, nil},
		{"managed outside", Licence{Read: true, Edition: "community", Status: "valid", ManagedExternally: true}, []string{"managed outside this console"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := serve(t, Snapshot{Licence: tc.l}, http.MethodGet).Body.String()
			for _, want := range tc.want {
				if !strings.Contains(body, want) {
					t.Errorf("page lacks %q:\n%s", want, body)
				}
			}
			for _, not := range tc.not {
				if strings.Contains(body, not) {
					t.Errorf("page says %q:\n%s", not, body)
				}
			}
		})
	}
}

func TestPage_TheActivationFormExistsOnlyWithAProductCSRFToken(t *testing.T) {
	without := serve(t, Snapshot{Licence: Licence{Read: true, Edition: "community", Status: "none"}}, http.MethodGet).Body.String()
	if strings.Contains(without, "<form") {
		t.Errorf("a page with no CSRF token offers a form:\n%s", without)
	}
	if !strings.Contains(without, "olivares license install") {
		t.Errorf("a page with no form does not name the command line route:\n%s", without)
	}
	with := serve(t, Snapshot{CSRF: "tok_en-1", Licence: Licence{Read: true, Edition: "community", Status: "none"}}, http.MethodGet).Body.String()
	for _, want := range []string{`<form method="post" action="/updates/licence"`, `name="license"`, `name="csrf_token" value="tok_en-1"`, `enctype="application/x-www-form-urlencoded"`} {
		if !strings.Contains(with, want) {
			t.Errorf("page lacks %q:\n%s", want, with)
		}
	}
}

func TestPage_ValuesAreEscaped(t *testing.T) {
	body := serve(t, Snapshot{CSRF: `"><script>x()</script>`, Result: `<b>done</b>`,
		Licence: Licence{Read: true, Edition: "community", Status: "valid", Licensee: `<img src=x onerror=y()>`}}, http.MethodGet).Body.String()
	for _, raw := range []string{"<script>", "<b>done", "<img src"} {
		if strings.Contains(body, raw) {
			t.Errorf("unescaped %q in the page:\n%s", raw, body)
		}
	}
}

func TestPage_UpdateUnitsShowTheirMeasuredStateAndTheirEquivalentCommands(t *testing.T) {
	s := Snapshot{UnitsMeasured: true, Units: []Unit{
		{Name: "dnf-automatic-install.timer", Active: "active", Sub: "waiting"},
		{Name: "dnf-automatic-install.service", Active: "failed", Sub: "failed"},
		{Name: "olivares-appliance-update.service", Active: "inactive", Sub: "dead"},
	}}
	body := serve(t, s, http.MethodGet).Body.String()
	for _, want := range []string{
		"dnf-automatic-install.timer", "active (waiting)", "failed (failed)", "inactive (dead)",
		"olivares-appliance service start olivares-appliance-update.service",
		"olivares-appliance service start dnf-automatic-install.service",
		"olivares-appliance service disable dnf-automatic-install.timer",
		"olivares-appliance service logs dnf-automatic-install.service --lines &lt;n&gt;",
		"security updates only", "03:00", "reboots the host about a minute after the run", "replace <code>&lt;n&gt;</code> with the number of lines",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q:\n%s", want, body)
		}
	}
	unmeasured := serve(t, Snapshot{}, http.MethodGet).Body.String()
	if !strings.Contains(unmeasured, "unmeasured") || strings.Contains(unmeasured, "active (") {
		t.Errorf("an unread inventory is not stated as unmeasured:\n%s", unmeasured)
	}
}

// The inventory lists loaded units only: an absent service is idle, an absent timer is off, and with a
// truncated inventory an absent unit is unknown.
func TestPage_AUnitTheInventoryDoesNotListIsSaidToBeIdleOrOffNeverActive(t *testing.T) {
	s := Snapshot{UnitsMeasured: true, Units: []Unit{{Name: "dnf-automatic-install.service", Active: "inactive", Sub: "dead"}}}
	body := serve(t, s, http.MethodGet).Body.String()
	for _, want := range []string{
		"olivares-appliance-update.service</td><td>not loaded: idle, or not installed",
		"dnf-automatic-install.timer</td><td>not loaded: off, or not installed",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q:\n%s", want, body)
		}
	}
	s.UnitsTruncated = true
	body = serve(t, s, http.MethodGet).Body.String()
	if strings.Contains(body, "not loaded: off") || !strings.Contains(body, "dnf-automatic-install.timer</td><td>unmeasured") {
		t.Errorf("a truncated inventory is read as a timer that is off:\n%s", body)
	}
}

func TestDecodeLicence_TakesTheProductsAnswerAndRefusesWhatIsNotOne(t *testing.T) {
	good := `{"edition":"enterprise","status":"valid","source":"data-dir","managed_externally":false,"licensee":"Acme","plan":"business","expires_at":"2027-03-01T00:00:00Z","max_users":0,"hot_apply":true}`
	l, ok := DecodeLicence([]byte(good))
	if !ok || !l.Read || l.Edition != "enterprise" || l.Status != "valid" || l.Licensee != "Acme" || l.Plan != "business" || l.ExpiresAt == nil || l.ExpiresAt.Year() != 2027 {
		t.Fatalf("decoded %+v ok=%v", l, ok)
	}
	for name, body := range map[string]string{
		"empty":           ``,
		"not json":        `<html>`,
		"unknown edition": `{"edition":"pirate","status":"valid"}`,
		"unknown status":  `{"edition":"community","status":"wonderful"}`,
		"no status":       `{"edition":"community"}`,
		"huge":            `{"edition":"community","status":"valid","licensee":"` + strings.Repeat("x", 1<<17) + `"}`,
	} {
		if l, ok := DecodeLicence([]byte(body)); ok || l.Read {
			t.Errorf("%s: accepted %+v", name, l)
		}
	}
	long, _ := DecodeLicence([]byte(`{"edition":"community","status":"valid","licensee":"` + strings.Repeat("é", 300) + `\u0007","plan":"p\nq\u202e"}`))
	if len([]rune(long.Licensee)) > 128 || strings.ContainsAny(long.Plan, "\n\a\u202e") {
		t.Errorf("a long or control-character value passed through: %q %q", long.Licensee, long.Plan)
	}
}

func TestOutcome_NamesTheProductsRefusalWithoutEchoingItsText(t *testing.T) {
	for _, tc := range []struct {
		status int
		want   string
	}{
		{http.StatusOK, "The licence is installed"},
		{http.StatusBadRequest, "did not accept"},
		{http.StatusUnauthorized, "Sign in again"},
		{http.StatusForbidden, "step-up"}, {http.StatusForbidden, "token is stale"},
		{http.StatusConflict, "managed outside this console"},
		{http.StatusNotImplemented, "not available"},
		// A product that failed after it was asked may have written the licence first.
		{http.StatusInternalServerError, "may or may not have been installed"},
		{http.StatusServiceUnavailable, "may or may not have been installed"},
	} {
		if got := Outcome(tc.status, false); !strings.Contains(got, tc.want) {
			t.Errorf("Outcome(%d) = %q, want it to say %q", tc.status, got, tc.want)
		}
	}
	if got := Outcome(http.StatusServiceUnavailable, true); !strings.Contains(got, "may or may not have been installed") {
		t.Errorf("an unanswered install is not said to be unknown: %q", got)
	}
}

// The services module's enable and disable only change whether a unit starts at boot; they never stop or
// start it. So the page cannot offer one of them as "turn it off": stopping the timer tonight is its own act
// (stop), and so is starting it now.
func TestPage_TheTimersActsSayWhatEachVerbDoes(t *testing.T) {
	byOp := map[string]string{}
	for _, a := range acts() {
		if a.Unit == "dnf-automatic-install.timer" {
			byOp[a.Op] = a.Title
		}
	}
	for _, op := range []string{"stop", "start", "disable", "enable"} {
		if byOp[op] == "" {
			t.Errorf("the timer has no %s act: %v", op, byOp)
		}
	}
	for _, op := range []string{"disable", "enable"} {
		if !strings.Contains(strings.ToLower(byOp[op]), "boot") {
			t.Errorf("the %s act is titled %q, which does not say that it concerns the boot", op, byOp[op])
		}
	}
	for op, title := range byOp {
		if strings.Contains(strings.ToLower(title), "turn ") {
			t.Errorf("the %s act is titled %q: no verb here turns the timer on or off by itself", op, title)
		}
	}
}

// Every act the page names has a command that names that act's verb and unit. That none is a command the
// console refuses is TestUpdatesPage_NoCommandItNamesIsOneTheConsoleRefuses's (cmd/olivares-appliance).
func TestPage_EveryActsCommandNamesItsVerbAndItsUnit(t *testing.T) {
	acts := acts()
	if len(acts) == 0 {
		t.Fatal("the page names no act")
	}
	for _, a := range acts {
		words := strings.Fields(a.Command)
		if !slices.Contains(words, a.Unit) || (a.Op != "logs" && !slices.Contains(words, a.Op)) {
			t.Errorf("%s %s: the command %q names another verb or unit", a.Op, a.Unit, a.Command)
		}
	}
	for _, name := range WatchedUnits() {
		if services.Classify(name) == services.ClassProtected {
			t.Errorf("%s is protected and cannot be an update unit", name)
		}
	}
}
