// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package storage_test

import (
	"github.com/olivaresai/olivares/appliance/layer/storage"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestStorageActionPageNamesTheDiskAndRequiresASeparateConfirmation(t *testing.T) {
	inv := actionInventory(t)
	render := func(v storage.ActionsView) string {
		w := httptest.NewRecorder()
		storage.ActionPage("signed in", inv, time.Now(), true, v).ServeHTTP(w, httptest.NewRequest("GET", "/storage", nil))
		if w.Code != 200 {
			t.Fatal(w.Code)
		}
		return w.Body.String()
	}
	if body := render(storage.ActionsView{}); strings.Contains(body, "<form") {
		t.Fatal("read-only page offers a mutation")
	}
	body := render(storage.ActionsView{CSRF: "bound-token"})
	for _, want := range []string{"Use for backups", "/storage/action", `name="stage" value="plan"`, "bound-token", `name="disk_digest"`, "width=device-width"} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q", want)
		}
	}
	body = render(storage.ActionsView{CSRF: "bound-token", Plan: &storage.ActionPlanView{Op: "backup", DiskDigest: inv.Disks[0].Identity.Digest, DiskName: "/dev/sdb<script>", OperationID: strings.Repeat("1", 32), Confirmation: strings.Repeat("a", 64)}})
	for _, want := range []string{"Confirm", `name="stage" value="apply"`, "erases", "&lt;script&gt;"} {
		if !strings.Contains(body, want) {
			t.Errorf("confirmation missing %q", want)
		}
	}
	if strings.Contains(body, "/dev/sdb<script>") {
		t.Fatal("disk name not escaped")
	}
}
