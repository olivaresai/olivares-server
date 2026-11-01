// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package portal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/olivaresai/olivares/appliance/layer/helpers/helperschema"
	"github.com/olivaresai/olivares/appliance/layer/storage"
)

func TestPortalStorage_RefusesMutationWithoutCurrentBrowserAuthorityAndCSRF(t *testing.T) {
	for _, tc := range []struct {
		name, claims, csrf string
		cookie             bool
		want               int
	}{
		{"bearer", nativeClaims(true), "bound-token", false, 401},
		{"not-admin", nativeClaims(false), "bound-token", true, 403},
		{"step-up", sessionClaims(true, "false"), "bound-token", true, 403},
		{"wrong-csrf", nativeClaims(true), "forged-token", true, 403},
		{"unwired", nativeClaims(true), "bound-token", true, 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := networkFixture(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/auth/whoami":
					io.WriteString(w, tc.claims)
				case "/v1/auth/browser-session":
					io.WriteString(w, `{"csrf_token":"bound-token"}`)
				default:
					t.Errorf("unexpected product call %s", r.URL.Path)
					w.WriteHeader(500)
				}
			})
			body := url.Values{"csrf_token": {tc.csrf}, "op": {"backup"}, "disk_digest": {strings.Repeat("a", 64)}, "stage": {"plan"}}.Encode()
			r := httptest.NewRequest("POST", "https://appliance.test:9443/storage/action", strings.NewReader(body))
			r.RemoteAddr = localPeer
			r.Header.Set("Origin", "https://appliance.test:9443")
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tc.cookie {
				r.AddCookie(&http.Cookie{Name: productSessionCookie, Value: "fixture-session"})
			} else {
				r.Header.Set("Authorization", "Bearer fixture-session")
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("status=%d want %d: %s", w.Code, tc.want, w.Body.String())
			}
		})
	}
}

// Exercise the real form/Acts/ActionTask path, with only the native disk boundary
// substituted. The executor still measures the resulting ext4 mount.
func TestPortalStorage_ConfirmationPolicyAndRetryNeverRepeatDiskPreparation(t *testing.T) {
	const target = "/mnt/olivares-backups/12345678-1234-1234-1234-123456789abc"
	id := storage.Identity{Kind: storage.IdentityDrive, Source: storage.SourceSerial, Value: "backup-disk", Size: 20 << 30}
	payload, _ := json.Marshal(struct {
		Schema   string           `json:"schema"`
		Identity storage.Identity `json:"identity"`
	}{"storage-identity/v1", id})
	sum := sha256.Sum256(payload)
	id.Digest = hex.EncodeToString(sum[:])
	inv := storage.Inventory{Schema: storage.Schema, Disks: []storage.Disk{{Device: "/dev/vdb", Size: id.Size, Identity: id, Target: "drive:" + id.Digest}}}
	formats, writes, checks := 0, 0, 0
	deny := false
	_, access := networkFixture(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/whoami":
			io.WriteString(w, nativeClaims(true))
		case "/v1/auth/browser-session":
			io.WriteString(w, `{"csrf_token":"bound-token"}`)
		case "/v1/console/appliance/storage/authorize":
			checks++
			var request map[string]string
			if json.NewDecoder(r.Body).Decode(&request) != nil || request["task"] != "storage.backup" || request["target"] != "drive:"+id.Digest || !storageHex.MatchString(request["intent_digest"]) {
				t.Errorf("incorrect exact authority request: %v", request)
			}
			json.NewEncoder(w).Encode(map[string]any{"allowed": !deny, "actor": nativeActor, "valid_until": time.Now().Add(time.Second)})
		case "/v1/console/dr/schedule":
			if r.Method == "GET" {
				io.WriteString(w, `{"enabled":true,"cron":"0 2 * * *","retain_days":7,"require_dual_control_restore":true}`)
				return
			}
			writes++
			var update map[string]any
			if json.NewDecoder(r.Body).Decode(&update) != nil || update["local_target"] != target || update["cron"] != "0 2 * * *" || update["require_dual_control_restore"] != nil {
				t.Errorf("schedule was changed unexpectedly: %v", update)
			}
			if writes == 1 {
				w.WriteHeader(503)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"local_target": target})
		default:
			t.Errorf("unexpected product request %s", r.URL.Path)
			w.WriteHeader(500)
		}
	})
	executor := storage.ActionExecutor{Read: func(context.Context) (storage.Inventory, error) { return inv, nil }, Backup: func(context.Context, storage.Disk) (string, error) {
		formats++
		inv.Disks[0].Filesystem = &storage.Filesystem{Type: "ext4", UUID: strings.TrimPrefix(target, "/mnt/olivares-backups/"), MountPoints: []string{target}}
		return target, nil
	}}
	call := func(ctx context.Context, name string, req helperschema.Request) (helperschema.Response, error) {
		if name != storage.HelperName {
			t.Fatalf("helper=%s", name)
		}
		if req.Subcommand() == storage.SubcommandInventory {
			return storage.Answer(inv, nil), nil
		}
		return storage.ActionAnswer(ctx, executor, req.(*storage.ActionRequest)), nil
	}
	operationDirectory := t.TempDir()
	handler := networkHandler(Status{StorageCall: call, StorageDirectory: operationDirectory}, access)
	submit := func(form url.Values) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "https://appliance.test:9443/storage/action", strings.NewReader(form.Encode()))
		r.RemoteAddr = localPeer
		r.Header.Set("Origin", "https://appliance.test:9443")
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(&http.Cookie{Name: productSessionCookie, Value: "fixture-session"})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	form := url.Values{"csrf_token": {"bound-token"}, "stage": {"plan"}, "op": {"backup"}, "disk_digest": {id.Digest}}
	plan := submit(form)
	if plan.Code != 200 || formats != 0 {
		t.Fatalf("plan=%d formats=%d: %s", plan.Code, formats, plan.Body.String())
	}
	field := func(name string) string {
		m := regexp.MustCompile(`name="` + name + `" value="([a-f0-9]+)"`).FindStringSubmatch(plan.Body.String())
		if len(m) != 2 {
			t.Fatalf("missing %s: %s", name, plan.Body.String())
		}
		return m[1]
	}
	form.Set("stage", "apply")
	form.Set("operation_id", field("operation_id"))
	form.Set("confirmation", strings.Repeat("f", 64))
	if bad := submit(form); bad.Code < 400 || formats != 0 {
		t.Fatalf("forged confirmation=%d formats=%d", bad.Code, formats)
	}
	form.Set("confirmation", field("confirmation"))
	deny = true
	if bad := submit(form); bad.Code < 400 || formats != 0 {
		t.Fatalf("policy denial=%d formats=%d", bad.Code, formats)
	}
	deny = false
	t.Run("unwritable-journal", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("read-only directory fixture requires a non-root writer")
		}
		if err := os.Chmod(operationDirectory, 0500); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(operationDirectory, 0700)
		refused := submit(form)
		if refused.Code != http.StatusServiceUnavailable || formats != 0 || writes != 0 {
			t.Fatalf("journal failure status=%d formats=%d schedule_writes=%d", refused.Code, formats, writes)
		}
	})
	first := submit(form)
	if first.Code != 503 || formats != 1 || writes != 1 || !strings.Contains(first.Body.String(), "Finish backup setup") {
		t.Fatalf("first=%d formats=%d writes=%d: %s", first.Code, formats, writes, first.Body.String())
	}
	retry := submit(form)
	if retry.Code != 200 || formats != 1 || writes != 2 || checks < 3 || !strings.Contains(retry.Body.String(), "configured as the backup target") {
		t.Fatalf("retry=%d formats=%d writes=%d checks=%d: %s", retry.Code, formats, writes, checks, retry.Body.String())
	}
}

func TestPortalStorage_GrowResultSaysWhenNothingWasResized(t *testing.T) {
	for _, tc := range []struct {
		facts []string
		want  string
	}{
		{[]string{"disk=/dev/vda", "resized=yes", "data_size_bytes=1"}, "now uses the available space"},
		{[]string{"disk=/dev/vda", "resized=no", "data_size_bytes=1"}, "already uses all the available space"},
	} {
		if got := growResult(tc.facts); !strings.Contains(got, tc.want) {
			t.Errorf("facts %v: %q does not say %q", tc.facts, got, tc.want)
		}
	}
}
