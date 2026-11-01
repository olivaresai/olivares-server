// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package storage_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/olivaresai/olivares/appliance/layer/storage"
)

const signIn = "Sign-in is refused on this appliance; use the repair console on tty1."

// get serves one request to page.
func get(page http.Handler, method string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	page.ServeHTTP(rec, httptest.NewRequest(method, "/storage", nil))
	return rec
}

// served is get for GET.
func served(t *testing.T, page http.Handler) *httptest.ResponseRecorder {
	t.Helper()
	return get(page, http.MethodGet)
}

func TestSnapshotPage_ShowsTheInventoryMarksAndOperationsAndChangesNothing(t *testing.T) {
	h := newHost()
	h.disk("sda", "SYS0001", 8<<8, 64<<30, "gpt")
	h.partition("sda", "sda1", 1, "c12a7328-f81f-11d2-ba4b-00a0c93ec93b")
	h.partition("sda", "sda2", 2, "4f68bce3-e8cd-4db1-96e7-fbcaf984b709")
	h.with("sda1", mounted("vfat", "/boot/efi"))
	h.with("sda2", mounted("ext4", "/"))
	h.with("sda2", func(b *storage.Block) { b.IDLabel = "<script>alert(1)</script>" })
	caps := map[string]storage.Capability{"resize/ext4": {Available: true, Modes: storage.ResizeOfflineGrow | storage.ResizeOnlineGrow}}
	inv := read(t, &fakeBus{objects: h.objects, caps: caps}, &fakeKernel{boot: bootA})
	page := storage.SnapshotPage(signIn, inv, time.Now(), true)

	rec := get(page, http.MethodGet)
	body := rec.Body.String()
	if rec.Header().Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatalf("type %q", rec.Header().Get("Content-Type"))
	}
	for _, want := range []string{
		signIn, "/dev/sda", "System disk: yes (/, /boot/efi)", "mount /boot/efi", "grow ext4 (offline, online)",
		"drive:" + diskNamed(t, inv, "/dev/sda").Identity.Digest, "LVM: read", "Nothing on this page changes the appliance",
		"An LVM metadata backup or a snapshot is not a data backup", "olivares-appliance storage list --plan",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	if strings.Contains(body, "<script>") || !strings.Contains(body, "&lt;script&gt;") {
		t.Fatal("a filesystem label reached the page unescaped")
	}
	if strings.Contains(body, "<form") || strings.Contains(body, "method=\"post\"") {
		t.Fatal("the read-only page offers a form")
	}
}

func TestSnapshotPage_ShowsTheInventoryItWasGivenAndReadsNothing(t *testing.T) {
	inv := read(t, &fakeBus{objects: fixture(t, "virtio-blank-serial.json")},
		&fakeKernel{boot: bootA, firstMiB: map[string]string{"/dev/vda": firstMiBOfVda}})
	readAt := time.Date(2026, 10, 16, 20, 0, 0, 0, time.FixedZone("CEST", 2*3600))

	// A read: answered at once with the inventory and when it was read, in UTC.
	rec := served(t, storage.SnapshotPage(signIn, inv, readAt, true))
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "/dev/vda") || !strings.Contains(body, "Inventory read at 2026-10-16T18:00:00Z") || !strings.Contains(body, signIn) {
		t.Fatalf("a read inventory: %d\n%s", rec.Code, body)
	}
	if strings.Contains(body, "unmeasured") || strings.Contains(body, "<form") || strings.Contains(body, "starts a refresh") {
		t.Fatalf("a read inventory is called unmeasured, offers a form or claims a refresh no request starts:\n%s", body)
	}

	// No read yet: 200 and unmeasured, with no disk and no retry loop for a client to follow.
	rec = served(t, storage.SnapshotPage(signIn, storage.Inventory{}, time.Time{}, false))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "unmeasured") || strings.Contains(rec.Body.String(), "/dev/") || rec.Header().Get("Retry-After") != "" {
		t.Fatalf("an unread inventory: %d %q\n%s", rec.Code, rec.Header().Get("Retry-After"), rec.Body.String())
	}

	// Every method but GET and HEAD is refused.
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		rec := httptest.NewRecorder()
		storage.SnapshotPage(signIn, inv, readAt, true).ServeHTTP(rec, httptest.NewRequest(method, "/storage", strings.NewReader("op=format")))
		if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "GET, HEAD" {
			t.Fatalf("%s: status %d Allow %q", method, rec.Code, rec.Header().Get("Allow"))
		}
	}
}
