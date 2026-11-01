// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package portal

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/olivaresai/olivares/appliance/layer/hostops"
	"github.com/olivaresai/olivares/appliance/layer/portal/audit"
	"github.com/olivaresai/olivares/appliance/layer/portal/auth"
	"github.com/olivaresai/olivares/appliance/layer/portal/portalpam"
	"github.com/olivaresai/olivares/appliance/layer/storage"
)

type networkAccess struct {
	product *productClient
	records *audit.Spool
}

// networkHandler is the handler composed on the passed TLS network sockets.
func networkHandler(status Status, access networkAccess) http.Handler {
	h := &protectedNetwork{status: status, access: access, measurePAM: portalpam.NewMeasurementStack, requestPAM: portalpam.NewRequestStack}
	h.openStorageActions()
	return h
}

type protectedNetwork struct {
	storageActs *hostops.Acts
	status      Status
	access      networkAccess
	measurePAM  func(context.Context) auth.Stack
	requestPAM  func(context.Context, string, []byte) (auth.Stack, error)
	mu          sync.Mutex // The existing spool's crash-line repair must be serialized.
}

func (h *protectedNetwork) record(actor, verb, outcome string, mode auth.Mode) bool {
	if h.access.records == nil {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := h.access.records.Append(audit.Record{Actor: actor, Verb: verb, Outcome: outcome, Mode: mode.String(), Surface: "web"})
	return err == nil
}

func (h *protectedNetwork) refuse(w http.ResponseWriter, code int, verb string) {
	if !h.record("anonymous", verb, "refused", auth.Unavailable) && code != http.StatusUnauthorized {
		code = http.StatusServiceUnavailable
	}
	message := "request refused"
	if code == http.StatusUnauthorized {
		message = "Sign in through the product console on port 8443."
	}
	if code == http.StatusServiceUnavailable {
		message = "Product authentication or audit is unavailable. The repair console remains on tty1."
	}
	http.Error(w, message, code)
}

func (h *protectedNetwork) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	// Native form POSTs retain their Origin; cross-origin referrers stay suppressed.
	w.Header().Set("Referrer-Policy", "same-origin")
	if r.URL.Path == "/storage" || r.URL.Path == storageActionPath {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
	}
	if !portalSameOrigin(r) {
		h.refuse(w, 403, "origin.refused")
		return
	}
	if r.URL.Path == storageActionPath {
		h.storageAction(w, r)
		return
	}
	if r.URL.Path == "/sign-in" {
		h.signIn(w, r)
		return
	}
	if methods, ok := nativeAuthMethods[r.URL.Path]; ok {
		if !strings.Contains(" "+methods+" ", " "+r.Method+" ") {
			h.refuse(w, 405, "authentication.refused")
			return
		}
		h.nativeAuthentication(w, r)
		return
	}
	if r.URL.Path == updatesLicencePath {
		h.activateLicence(w, r)
		return
	}
	verb, ok := protectedReadVerbs[r.URL.Path]
	if !ok {
		h.refuse(w, 404, "unsupported.request")
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		h.refuse(w, 405, verb)
		return
	}
	if r.Header.Get("Authorization") == "" {
		cookie, err := r.Cookie(productSessionCookie)
		if err != nil || cookie.Value == "" {
			h.refuse(w, 401, verb)
			return
		}
	}
	principal, ok := h.signedIn(w, r, verb)
	if !ok {
		return
	}
	// This adapter is deliberately a read answer only. ID/APPLY owns exact act,
	// target and confirmed-intent authorization; no host task is composed here.
	answer := auth.NewProductIdentity(principal).Ask(r.Context(), principal.Actor, hostStatusRead)
	actor := "anonymous"
	if principal.human() {
		actor = principal.Actor
	}
	outcome, code := "performed", 200
	switch {
	case !answer.Allows():
		outcome, code = "refused", 403
	case hostPages[r.URL.Path] && !loopbackPeer(r.RemoteAddr):
		// The page answers 404 to a caller on another host; the record says it was not served.
		outcome, code = "refused", 404
	}
	if !h.record(actor, verb, outcome, auth.ProductUp) {
		http.Error(w, "audit unavailable", 503)
		return
	}
	if code == http.StatusNotFound {
		http.NotFound(w, r)
		return
	}
	if code != 200 {
		http.Error(w, refusalSentence(answer, "for host status"), code)
		return
	}
	status := h.status
	status.SignIn = auth.State{Mode: auth.ProductUp}
	status.Product = Measured("available")
	if r.URL.Path == updatesPath {
		status.Updates = h.readUpdates(r)
	}
	if r.URL.Path == "/storage" && h.storageActs != nil {
		h.renderStorage(w, r, storage.ActionsView{CSRF: h.storageCSRF(r)}, 200, false)
		return
	}
	NewHandler(status).ServeHTTP(w, r)
}

// signedIn asks the product who the caller is and refuses the request, through h.refuse, when it
// cannot say or the caller is not signed in. It is the one authority read of every protected path.
func (h *protectedNetwork) signedIn(w http.ResponseWriter, r *http.Request, verb string) (productReadAuthority, bool) {
	if h.access.product == nil || h.access.records == nil {
		h.refuse(w, 503, verb)
		return productReadAuthority{}, false
	}
	reply, err := h.access.product.request(r, http.MethodGet, "/v1/auth/whoami", nil)
	if err != nil || (reply.status != 200 && reply.status != 401 && reply.status != 403) {
		h.refuse(w, 503, verb)
		return productReadAuthority{}, false
	}
	if reply.status != 200 {
		h.refuse(w, reply.status, verb)
		return productReadAuthority{}, false
	}
	var principal productReadAuthority
	if json.Unmarshal(reply.body, &principal) != nil {
		h.refuse(w, 503, verb)
		return productReadAuthority{}, false
	}
	return principal, true
}

// hostPages are the pages that name interfaces, units, disks or mount points, which only a caller
// on this host reads: they answer 404 to any other, whoever signed in.
var hostPages = map[string]bool{"/firewall": true, "/services": true, "/storage": true}

var protectedReadVerbs = map[string]string{
	"/": "host-status.read", "/status": "host-status.read", "/network": "host-network.read", "/firewall": "host-firewall.read",
	"/services": "host-services.read", "/storage": "host-storage.read", updatesPath: hostUpdatesRead,
}

// Only the engine's existing authentication routes are relayed, and one product operation: the
// licence install of the Updates page (updates.go), whose route, method and body are fixed there.
// This is never a proxy for product operations or an alternative host mutation surface.
var nativeAuthMethods = map[string]string{
	"/v1/auth/login":           "POST",
	"/v1/auth/browser-session": "GET POST",
	"/v1/auth/logout":          "POST",
	"/v1/auth/totp/challenge":  "POST",
	"/v1/auth/whoami":          "GET",
}

func portalSameOrigin(r *http.Request) bool {
	site := r.Header.Get("Sec-Fetch-Site")
	if site != "" && site != "same-origin" && site != "none" {
		return false
	}
	origin := r.Header.Get("Origin")
	return origin == "" || origin == "https://"+r.Host
}

func (h *protectedNetwork) nativeAuthentication(w http.ResponseWriter, r *http.Request) {
	verb := "authentication." + strings.TrimPrefix(r.URL.Path, "/v1/auth/")
	if h.access.product == nil || h.access.records == nil {
		h.refuse(w, 503, verb)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxProductBody+1))
	if err != nil {
		h.refuse(w, 400, verb)
		return
	}
	if len(body) > maxProductBody {
		h.refuse(w, 413, verb)
		return
	}
	// Persist intent before a native session action; a failed result append
	// leaves the unknown intent, rather than an unrecorded action.
	if !h.record("anonymous", verb, "unknown", auth.Unavailable) {
		http.Error(w, "audit unavailable", 503)
		return
	}
	reply, err := h.access.product.request(r, r.Method, r.URL.Path, body)
	outcome, mode := "failed", auth.Unavailable
	if err == nil {
		mode = auth.ProductUp
		outcome = "performed"
		if reply.status >= 400 {
			outcome = "refused"
		}
	}
	if !h.record("anonymous", verb, outcome, mode) {
		http.Error(w, "audit unavailable", 503)
		return
	}
	if err != nil {
		http.Error(w, "product authentication unavailable", 503)
		return
	}
	for _, key := range []string{"Content-Type", "Set-Cookie", "Retry-After", "WWW-Authenticate"} {
		for _, value := range reply.headers.Values(key) {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(reply.status)
	_, _ = w.Write(reply.body)
}

const hostStatusRead auth.Verb = "host-status.read"

// productReadAuthority is the product's own answer to whoami, read once and obeyed: who the caller is,
// whether they administer the product, and whether this session meets the deployment's step-up policy.
// The console keeps no policy of its own: StepUpSatisfied is the product's StepUpSatisfied for the
// session, and an answer that does not say is not a step-up met.
type productReadAuthority struct {
	Kind            string `json:"kind"`
	UserID          string `json:"user_id"`
	Actor           string `json:"actor"`
	Superadmin      bool   `json:"superadmin"`
	StepUpSatisfied *bool  `json:"step_up_satisfied"`
}

func (p productReadAuthority) human() bool {
	if p.Kind != "user" || len(p.UserID) != 36 || p.Actor != "user:"+p.UserID {
		return false
	}
	for i, c := range p.UserID {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}

// AuthorizeVerb allows host administration to a signed-in human product superadministrator whose
// session meets the step-up policy. The superadministrator check comes first, so a caller who is not
// one is refused without learning anything about step-up; one who is, and has not stepped up, is told
// the product asks for a step-up.
func (p productReadAuthority) AuthorizeVerb(_ context.Context, identity string, verb auth.Verb) auth.Answer {
	if (verb != hostStatusRead && verb != hostUpdatesActivate) || identity != p.Actor || !p.human() || !p.Superadmin {
		return auth.AnswerRefused
	}
	if p.StepUpSatisfied == nil || !*p.StepUpSatisfied {
		return auth.AnswerStepUpRequired
	}
	return auth.AnswerAllowed
}

// refusalSentence is what a refused caller reads: the remedy when the product asked for a step-up, and
// otherwise one fixed phrase that names no check.
func refusalSentence(answer auth.Answer, need string) string {
	if answer == auth.AnswerStepUpRequired {
		return "Step-up required: complete it in the product console on port 8443, then reload."
	}
	return "A product superadministrator is required " + need + "."
}
