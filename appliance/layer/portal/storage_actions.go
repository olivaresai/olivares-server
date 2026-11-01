// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package portal

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"mime"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/olivaresai/olivares/appliance/layer/hostops"
	"github.com/olivaresai/olivares/appliance/layer/portal/audit"
	"github.com/olivaresai/olivares/appliance/layer/portal/auth"
	"github.com/olivaresai/olivares/appliance/layer/portal/localsession"
	"github.com/olivaresai/olivares/appliance/layer/storage"
)

const storageActionPath = "/storage/action"

var storageHex = regexp.MustCompile(`^[0-9a-f]{64}$`)
var storageOperationID = regexp.MustCompile(`^[0-9a-f]{32}$`)
var managedBackupTarget = regexp.MustCompile(`^/mnt/olivares-backups/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type storageSubmission struct{ Stage, Op, DiskDigest, OperationID, Confirmation, CSRF string }

func storageForm(w http.ResponseWriter, r *http.Request) (storageSubmission, bool) {
	var value storageSubmission
	kind, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || kind != "application/x-www-form-urlencoded" || r.URL.RawQuery != "" {
		return value, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2048)
	if r.ParseForm() != nil {
		return value, false
	}
	allowed := map[string]bool{"stage": true, "op": true, "disk_digest": true, "operation_id": true, "confirmation": true, "csrf_token": true}
	for k, v := range r.PostForm {
		if !allowed[k] || len(v) != 1 {
			return value, false
		}
	}
	value = storageSubmission{r.PostForm.Get("stage"), r.PostForm.Get("op"), r.PostForm.Get("disk_digest"), r.PostForm.Get("operation_id"), r.PostForm.Get("confirmation"), r.PostForm.Get("csrf_token")}
	if (value.Op != "backup" && value.Op != "grow") || !storageHex.MatchString(value.DiskDigest) || !csrfToken.MatchString(value.CSRF) {
		return value, false
	}
	switch value.Stage {
	case "plan":
		return value, value.OperationID == "" && value.Confirmation == ""
	case "apply":
		return value, storageOperationID.MatchString(value.OperationID) && storageHex.MatchString(value.Confirmation)
	}
	return value, false
}

func (h *protectedNetwork) openStorageActions() {
	if h.status.StorageCall == nil || h.access.records == nil {
		return
	}
	descriptors := storage.ActionDescriptors()
	catalog, err := hostops.NewCatalog(descriptors)
	if err != nil {
		log.Printf("storage actions unavailable: task catalog: %v", err)
		return
	}
	dir := h.status.StorageDirectory
	if dir == "" {
		dir = localsession.OperationDirectory
	}
	engine, err := hostops.OpenWithCatalog(dir, catalog)
	if err != nil {
		log.Printf("storage actions unavailable: records directory %s: %v", dir, err)
		return
	}
	tasks := map[string]hostops.AdoptedTask{}
	for _, d := range descriptors {
		tasks[d.ID] = storage.ActionTask{Op: d.Verb, Call: h.status.StorageCall}
	}
	h.storageActs = hostops.NewActs(engine, catalog, tasks, storageAudit{h})
}

type storageAudit struct{ h *protectedNetwork }

func (a storageAudit) Append(event hostops.ActEvent) error {
	a.h.mu.Lock()
	defer a.h.mu.Unlock()
	return (hostops.SpoolAudit{Spool: a.h.access.records}).Append(event)
}

func (h *protectedNetwork) storageCSRF(source *http.Request) string {
	if _, err := source.Cookie(productSessionCookie); err != nil || h.access.product == nil {
		return ""
	}
	reply, err := h.access.product.request(source, http.MethodGet, "/v1/auth/browser-session", nil)
	var session struct {
		CSRF string `json:"csrf_token"`
	}
	if err != nil || reply.status != 200 || json.Unmarshal(reply.body, &session) != nil || !csrfToken.MatchString(session.CSRF) {
		return ""
	}
	return session.CSRF
}

type storageAuthority struct {
	h      *protectedNetwork
	source *http.Request
	actor  string
}

func (a storageAuthority) Authorize(ctx context.Context, d hostops.Descriptor, target, digest string) (hostops.Caller, error) {
	refused := errors.New("mode_refused")
	if d.ID != "storage.backup" && d.ID != "storage.grow" {
		return hostops.Caller{}, refused
	}
	body, _ := json.Marshal(map[string]string{"task": d.ID, "target": target, "intent_digest": digest})
	reply, err := a.h.access.product.request(a.source.WithContext(ctx), http.MethodPost, "/v1/console/appliance/storage/authorize", body)
	var answer struct {
		Allowed    bool      `json:"allowed"`
		Actor      string    `json:"actor"`
		ValidUntil time.Time `json:"valid_until"`
	}
	now := time.Now()
	if err != nil || reply.status != 200 || json.Unmarshal(reply.body, &answer) != nil || !answer.Allowed || answer.Actor != a.actor || !answer.ValidUntil.After(now) || answer.ValidUntil.After(now.Add(5*time.Second)) {
		return hostops.Caller{}, refused
	}
	return hostops.Caller{Actor: answer.Actor, Mode: "product-up"}, nil
}

func (h *protectedNetwork) renderStorage(w http.ResponseWriter, r *http.Request, view storage.ActionsView, code int, fresh bool) {
	var inv storage.Inventory
	var stamp localsession.Stamp
	var have bool
	if h.status.Pages != nil {
		inv, stamp, have = h.status.Pages.Storage()
	}
	if fresh && h.status.StorageCall != nil {
		if measured, err := storage.HelperReader(h.status.StorageCall)(r.Context()); err == nil {
			inv, stamp.ReadAt, have = measured, time.Now(), true
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if code != 200 {
		w.WriteHeader(code)
	}
	pageRequest := r.Clone(r.Context())
	pageRequest.Method = http.MethodGet
	storage.ActionPage((auth.State{Mode: auth.ProductUp}).Statement(), inv, stamp.ReadAt, have, view).ServeHTTP(w, pageRequest)
}

func (h *protectedNetwork) storageTargetRecord(rec hostops.Record, outcome string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := h.access.records.Append(audit.Record{Actor: rec.Actor, Verb: "storage.backup-target", Outcome: outcome, Mode: rec.Mode, Surface: "web", OperationID: rec.OperationID, Target: rec.Target, PlanDigest: rec.PlanDigest})
	return err == nil
}

// Registration is retriable independently of the durable disk effect. Omit the
// restore gate on write: its effective GET value must never re-arm a pending disarm.
func (h *protectedNetwork) registerStorageTarget(source *http.Request, rec hostops.Record, target string) (success bool) {
	if !managedBackupTarget.MatchString(target) || !h.storageTargetRecord(rec, "unknown") {
		return false
	}
	defer func() {
		outcome := "unknown"
		if success {
			outcome = "performed"
		}
		if !h.storageTargetRecord(rec, outcome) {
			success = false
		}
	}()
	reply, err := h.access.product.request(source, http.MethodGet, "/v1/console/dr/schedule", nil)
	var current map[string]json.RawMessage
	if err != nil || reply.status != 200 || json.Unmarshal(reply.body, &current) != nil {
		return false
	}
	var configured string
	_ = json.Unmarshal(current["local_target"], &configured)
	if configured == target && len(current["target_free_bytes"]) > 0 && string(current["target_free_bytes"]) != "null" {
		success = true
		return true
	}
	update := map[string]json.RawMessage{}
	for _, key := range []string{"enabled", "cron", "retain_days", "verify_cron", "rpo_hours", "offsite"} {
		if value, ok := current[key]; ok {
			update[key] = value
		}
	}
	update["local_target"], _ = json.Marshal(target)
	body, err := json.Marshal(update)
	if err != nil {
		return false
	}
	reply, err = h.access.product.request(source, http.MethodPut, "/v1/console/dr/schedule", body)
	var after struct {
		LocalTarget string `json:"local_target"`
	}
	success = err == nil && reply.status == 200 && json.Unmarshal(reply.body, &after) == nil && after.LocalTarget == target
	return success
}

// growResult says what the measured postconditions show about the data volume.
func growResult(facts []string) string {
	if slices.Contains(facts, "resized=no") {
		return "The data volume already uses all the available space."
	}
	return "The data volume now uses the available space."
}

func (h *protectedNetwork) storageAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		h.refuse(w, 405, "storage.action")
		return
	}
	if !loopbackPeer(r.RemoteAddr) {
		h.refuse(w, 404, "storage.action")
		return
	}
	if _, err := r.Cookie(productSessionCookie); err != nil {
		h.refuse(w, 401, "storage.action")
		return
	}
	source := r.Clone(r.Context())
	source.Header.Del("Authorization")
	source.Header.Del("X-Olivares-Session")
	principal, ok := h.signedIn(w, source, "storage.action")
	if !ok {
		return
	}
	if answer := auth.NewProductIdentity(principal).Ask(r.Context(), principal.Actor, hostStatusRead); !answer.Allows() {
		h.recordAnswer(w, principal.Actor, "storage.action", "refused", 403, refusalSentence(answer, "to manage storage"))
		return
	}
	form, ok := storageForm(w, r)
	if !ok {
		h.recordAnswer(w, principal.Actor, "storage.action", "refused", 422, "Invalid storage request.")
		return
	}
	expected := h.storageCSRF(source)
	if expected == "" || subtle.ConstantTimeCompare([]byte(form.CSRF), []byte(expected)) != 1 {
		h.recordAnswer(w, principal.Actor, "storage.action", "refused", 403, "Request refused. Reload Storage and try again.")
		return
	}
	if h.storageActs == nil {
		h.recordAnswer(w, principal.Actor, "storage.action", "refused", 503, "Storage changes are unavailable.")
		return
	}
	if err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(185 * time.Second)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		h.recordAnswer(w, principal.Actor, "storage.action", "refused", 503, "Storage changes are unavailable.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 180*time.Second)
	defer cancel()
	source = source.WithContext(ctx)
	source.Header.Set("Content-Type", "application/json")
	source.Header.Set("X-CSRF-Token", expected)
	authority := storageAuthority{h, source, principal.Actor}
	inputs, _ := json.Marshal(map[string]string{"disk_digest": form.DiskDigest})
	view := storage.ActionsView{CSRF: expected}
	if form.Stage == "plan" {
		plan, err := h.storageActs.Plan(ctx, "storage", form.Op, "web", inputs, authority)
		if err != nil || !plan.Permissions.Apply {
			h.recordAnswer(w, principal.Actor, "storage."+form.Op, "refused", 403, "The disk changed or the current policy refuses this change. Reload Storage.")
			return
		}
		inv, err := storage.HelperReader(h.status.StorageCall)(ctx)
		disk, selectErr := storage.SelectAction(inv, form.Op, form.DiskDigest)
		if err != nil || selectErr != nil {
			h.recordAnswer(w, principal.Actor, "storage."+form.Op, "refused", 409, "The disk changed. Reload Storage.")
			return
		}
		var raw [16]byte
		if _, err := rand.Read(raw[:]); err != nil {
			h.recordAnswer(w, principal.Actor, "storage.action", "refused", 503, "Storage changes are unavailable.")
			return
		}
		view.Plan = &storage.ActionPlanView{Op: form.Op, DiskDigest: form.DiskDigest, DiskName: disk.Device, OperationID: hex.EncodeToString(raw[:]), Confirmation: plan.Digest}
		h.renderStorage(w, source, view, 200, true)
		return
	}
	record, status, err := h.storageActs.Apply(ctx, hostops.ApplyRequest{OperationID: form.OperationID, Module: "storage", Verb: form.Op, Surface: "web", Inputs: inputs, Confirmation: form.Confirmation}, authority)
	if err != nil {
		if status < 400 || status > 599 {
			status = http.StatusServiceUnavailable
		}
		log.Printf("storage action refused: op=%s operation_id=%s status=%d error=%q", form.Op, form.OperationID, status, err)
		h.recordAnswer(w, principal.Actor, "storage."+form.Op, "refused", status, "Storage change refused. Reload Storage and review a new plan.")
		return
	}
	switch record.State {
	case hostops.StateSucceeded:
		view.Result = growResult(record.Postconditions)
		if form.Op == "backup" {
			target := ""
			for _, fact := range record.Postconditions {
				if value, ok := strings.CutPrefix(fact, "backup_target="); ok {
					target = value
				}
			}
			if target == "" || !h.registerStorageTarget(source, record, target) {
				view.Result = "The disk was prepared, but backup setup is incomplete. Retry setup to save this disk as the backup target."
				view.Plan = &storage.ActionPlanView{Op: form.Op, DiskDigest: form.DiskDigest, DiskName: "the prepared disk", OperationID: form.OperationID, Confirmation: form.Confirmation, RegistrationOnly: true}
				h.renderStorage(w, source, view, 503, true)
				return
			}
			view.Result = "The disk is configured as the backup target. Your existing backup schedule is preserved."
		}
	case hostops.StateFailed:
		view.Result = "The storage change failed. Review the current disk state before trying again."
	default:
		view.Result = "The storage outcome is unconfirmed. Refresh Storage and check the disk before another change."
	}
	h.renderStorage(w, source, view, status, true)
}
