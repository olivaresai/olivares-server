// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package portal

import (
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/olivaresai/olivares/appliance/layer/portal/auth"
	"github.com/olivaresai/olivares/appliance/layer/updatepage"
)

const (
	updatesPath         = "/updates"
	updatesLicencePath  = "/updates/licence"
	hostUpdatesRead     = "host-updates.read"
	hostUpdatesActivate = auth.Verb("host-updates.activate")
	// maxLicenceBlob bounds the licence a form carries; a licence is a few kilobytes. A form escapes a byte
	// to three, so this is the most the body bound (maxProductBody, 64 KiB) can carry with the token.
	maxLicenceBlob = 16 << 10
)

// UpdatesRead is what the network handler reads from the product for the Updates page after it has
// authorized the caller: the product's licence answer and the CSRF token the product derives for the
// caller's browser session.
type UpdatesRead struct {
	Licence updatepage.Licence
	CSRF    string
}

// csrfToken is the shape of the product's derived token (base64url, no padding); nothing else is put
// into a page.
var csrfToken = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// updatesSnapshot is what the Updates page renders from s: the last completed read of the units the
// page reports, and the product's licence answer when the network handler read one.
func updatesSnapshot(s Status) updatepage.Snapshot {
	snapshot := updatepage.Snapshot{SignInStatement: s.SignIn.Statement(), Licence: s.Updates.Licence, CSRF: s.Updates.CSRF}
	if s.Pages == nil {
		return snapshot
	}
	inventory, _, measured := s.Pages.Units()
	snapshot.UnitsMeasured = measured
	snapshot.UnitsTruncated = inventory.Truncated
	watched := updatepage.WatchedUnits()
	for _, listed := range inventory.Units {
		if slices.Contains(watched, listed.Name) {
			snapshot.Units = append(snapshot.Units, updatepage.Unit{Name: listed.Name, Active: listed.ActiveState, Sub: listed.SubState})
		}
	}
	return snapshot
}

// serveUpdates serves the Updates page, GET and HEAD only. It names the update units and the state of the
// licence, which are state words, so it answers a caller on any host that the console let in.
func serveUpdates(s Status) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		updatepage.Page(updatesSnapshot(s)).ServeHTTP(w, r)
	}
}

// readUpdates asks the product for what the Updates page shows under the caller's own session: the
// licence status and the browser session's CSRF token. A refusal or an answer it does not know leaves
// the licence unread and the page without its form; nothing is guessed.
func (h *protectedNetwork) readUpdates(source *http.Request) UpdatesRead {
	var read UpdatesRead
	if reply, err := h.access.product.request(source, http.MethodGet, "/v1/console/license", nil); err == nil && reply.status == http.StatusOK {
		read.Licence, _ = updatepage.DecodeLicence(reply.body)
	}
	if cookie, err := source.Cookie(productSessionCookie); err == nil && cookie.Value != "" {
		if reply, err := h.access.product.request(source, http.MethodGet, "/v1/auth/browser-session", nil); err == nil && reply.status == http.StatusOK {
			var session struct {
				CSRF string `json:"csrf_token"`
			}
			if json.Unmarshal(reply.body, &session) == nil && csrfToken.MatchString(session.CSRF) {
				read.CSRF = session.CSRF
			}
		}
	}
	return read
}

// activateLicence relays one licence from the Updates page's form to the product's own licence API,
// POST /v1/console/license, under the caller's browser session. It is the one product operation the
// console carries and it is not a proxy: the route, the method, the body's one field and the
// answer's reading are fixed here, the caller must be a signed-in human superadministrator, the
// form must carry the CSRF token the product derived for that session (which the product checks
// again), and the product decides, including the step-up it asks of an administrative change.
// The licence is a signed public attestation, never a credential, and still appears in no
// record: the audit holds the verb, the actor and the outcome.
func (h *protectedNetwork) activateLicence(w http.ResponseWriter, r *http.Request) {
	const verb = string(hostUpdatesActivate)
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		h.refuse(w, http.StatusMethodNotAllowed, verb)
		return
	}
	// The relay acts for a browser session alone; a bearer credential names the product's own API.
	if cookie, err := r.Cookie(productSessionCookie); err != nil || cookie.Value == "" {
		h.refuse(w, http.StatusUnauthorized, verb)
		return
	}
	source := r.Clone(r.Context())
	// The relay acts for the cookie alone: nothing else the client sent names a credential or a transport.
	source.Header.Del("Authorization")
	source.Header.Del("X-Olivares-Session")
	principal, ok := h.signedIn(w, source, verb)
	if !ok {
		return
	}
	actor := "anonymous"
	if principal.human() {
		actor = principal.Actor
	}
	if answer := auth.NewProductIdentity(principal).Ask(r.Context(), principal.Actor, hostUpdatesActivate); !answer.Allows() {
		h.recordAnswer(w, actor, verb, "refused", http.StatusForbidden, refusalSentence(answer, "to activate a licence"))
		return
	}
	blob, csrf, status := activationForm(r)
	if status != 0 {
		h.recordAnswer(w, actor, verb, "refused", status, "request refused")
		return
	}
	// The intent is durable before the product is asked: an install whose result cannot be
	// recorded leaves the unknown intent, never an unrecorded change.
	if !h.record(actor, verb, "unknown", auth.ProductUp) {
		http.Error(w, "audit unavailable", http.StatusServiceUnavailable)
		return
	}
	body, _ := json.Marshal(struct {
		License string `json:"license"`
	}{blob})
	source.Header.Set("Content-Type", "application/json")
	source.Header.Set("X-CSRF-Token", csrf)
	reply, err := h.access.product.request(source, http.MethodPost, "/v1/console/license", body)
	// A product that did not answer in time may have installed the licence: the outcome stays
	// unknown, and the page below reads what the product holds now.
	outcome, code := "unknown", http.StatusServiceUnavailable
	switch {
	case err != nil:
	case reply.status == http.StatusNotImplemented:
		// The product has no licence service: nothing was installed.
		outcome, code = "failed", reply.status
	case reply.status >= 500:
		// A product that failed after it was asked may have written the licence first.
		outcome, code = "unknown", reply.status
	case reply.status >= 400:
		outcome, code = "refused", reply.status
	default:
		outcome, code = "performed", http.StatusOK
	}
	if !h.record(actor, verb, outcome, auth.ProductUp) {
		http.Error(w, "The audit record of the outcome could not be written; the licence may have been installed. Read the licence on this page before trying again.", http.StatusServiceUnavailable)
		return
	}
	signedIn := h.status
	signedIn.SignIn = auth.State{Mode: auth.ProductUp}
	signedIn.Updates = UpdatesRead{CSRF: csrf}
	signedIn.Updates.Licence = h.readUpdates(source).Licence
	snapshot := updatesSnapshot(signedIn)
	snapshot.Result = updatepage.Outcome(code, err != nil)
	if outcome == "performed" && !snapshot.Licence.Installed() {
		// The page says "installed" only for a licence the product reports now.
		snapshot.Result = updatepage.Unconfirmed
	}
	updatepage.Write(w, code, snapshot)
}

// recordAnswer records the outcome of a request the console refuses itself, and answers it.
func (h *protectedNetwork) recordAnswer(w http.ResponseWriter, actor, verb, outcome string, code int, message string) {
	if !h.record(actor, verb, outcome, auth.ProductUp) {
		http.Error(w, "audit unavailable", http.StatusServiceUnavailable)
		return
	}
	http.Error(w, message, code)
}

// activationForm reads the licence and the CSRF token from the request's body, which must be one
// form of at most maxProductBody bytes with each field once. It returns the HTTP status that refuses
// it, or 0.
func activationForm(r *http.Request) (blob, csrf string, status int) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/x-www-form-urlencoded" {
		return "", "", http.StatusUnsupportedMediaType
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxProductBody+1))
	switch {
	case err != nil:
		return "", "", http.StatusBadRequest
	case len(raw) > maxProductBody:
		return "", "", http.StatusRequestEntityTooLarge
	}
	form, err := url.ParseQuery(string(raw))
	if err != nil || len(form["license"]) > 1 || len(form["csrf_token"]) > 1 {
		return "", "", http.StatusBadRequest
	}
	csrf = form.Get("csrf_token")
	blob = strings.TrimSpace(form.Get("license"))
	switch {
	case !utf8.ValidString(blob):
		return "", "", http.StatusBadRequest
	case !csrfToken.MatchString(csrf):
		return "", "", http.StatusForbidden
	case blob == "" || len(blob) > maxLicenceBlob || strings.ContainsFunc(blob, func(c rune) bool {
		return (c < 0x20 && c != '\n' && c != '\r' && c != '\t') || c == 0x7f
	}):
		return "", "", http.StatusBadRequest
	}
	return blob, csrf, 0
}
