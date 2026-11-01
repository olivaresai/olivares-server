// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package portal

import (
	"context"
	"encoding/json"
	"html"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/olivaresai/olivares/appliance/layer/helpers/helperschema"
	"github.com/olivaresai/olivares/appliance/layer/storage"
)

// readHelpers answers the units and storage helpers' reads as the console's read round asks them.
func readHelpers(_ context.Context, name string, _ helperschema.Request) (helperschema.Response, error) {
	switch name {
	case helperschema.HelperUnits:
		return helperschema.Response{Result: helperschema.ResultAnswered,
			Bundle: json.RawMessage(`{"units":[{"name":"sshd.service","load_state":"loaded","active_state":"active","sub_state":"running","class":"lockout-risk"},{"name":"<b>x</b>.service","load_state":"loaded","active_state":"active","sub_state":"running"}],"truncated":false}`)}, nil
	case helperschema.HelperStorage:
		inventory := storage.Inventory{Schema: storage.Schema, BootID: strings.Repeat("ab", 16), LVM: storage.LVM{State: storage.LVMRead},
			Disks: []storage.Disk{{Device: "/dev/vda", Size: 1 << 34, Consumers: []storage.Consumer{}, Partitions: []storage.Partition{}, Operations: []storage.Operation{}}}}
		document, _ := json.Marshal(inventory)
		return helperschema.Response{Result: helperschema.ResultAnswered, Bundle: document}, nil
	}
	return helperschema.Response{Result: helperschema.ResultFailed}, nil
}

// readConsole returns the console's read model after one round of the helpers.
func readConsole() *moduleReads {
	reads := newModuleReads(func() time.Time { return time.Date(2026, 10, 16, 20, 0, 0, 0, time.UTC) })
	reads.refresh(context.Background(), readHelpers)
	return reads
}

func TestModulePages_ServeTheConsolesUnitAndDiskReadsOnThisHostWithNoAct(t *testing.T) {
	// Before any read both pages say they are unmeasured and show no unit and no disk.
	unread := NewHandler(Status{Pages: newModuleReads(time.Now)})
	rec := serve(t, unread, http.MethodGet, "/services", localPeer)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "unmeasured") || strings.Contains(rec.Body.String(), "sshd.service") {
		t.Fatalf("GET /services before any read: %d\n%s", rec.Code, rec.Body.String())
	}
	rec = serve(t, unread, http.MethodGet, "/storage", localPeer)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "unmeasured") || strings.Contains(rec.Body.String(), "/dev/vda") {
		t.Fatalf("GET /storage before any read: %d\n%s", rec.Code, rec.Body.String())
	}
	// A console with no read model at all serves them the same way.
	if rec := serve(t, NewHandler(Status{}), http.MethodGet, "/storage", localPeer); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "unmeasured") {
		t.Fatalf("GET /storage with no reads: %d\n%s", rec.Code, rec.Body.String())
	}

	reads := readConsole()
	handler := NewHandler(Status{Pages: reads})
	for path, want := range map[string][]string{
		"/services": {"<h1>Services</h1>", "sshd.service", "lockout-risk", "olivares-appliance service status sshd.service", "1 entries were not unit names", "Inventory read at 2026-10-16T20:00:00Z", html.EscapeString((Status{}).SignIn.Statement())},
		"/storage":  {"<h1>Storage</h1>", "/dev/vda", "Inventory read at 2026-10-16T20:00:00Z", "olivares-appliance storage list --plan", html.EscapeString((Status{}).SignIn.Statement())},
	} {
		rec := serve(t, handler, http.MethodGet, path, localPeer)
		body := rec.Body.String()
		if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
			t.Fatalf("GET %s from this host: %d %v\n%s", path, rec.Code, rec.Header(), body)
		}
		for _, w := range want {
			if !strings.Contains(body, w) {
				t.Errorf("GET %s does not show %q:\n%s", path, w, body)
			}
		}
		if strings.Contains(body, "<b>x</b>") || strings.Contains(body, "<form") || strings.Contains(body, "<button") || strings.Contains(body, "method=") {
			t.Errorf("GET %s carries markup from a read or an act:\n%s", path, body)
		}
		if rec := serve(t, handler, http.MethodHead, path, localPeer); rec.Code != http.StatusOK {
			t.Errorf("HEAD %s: %d", path, rec.Code)
		}
		// No method but GET and HEAD from this host; nothing at all from another host.
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
			if rec := serve(t, handler, method, path, localPeer); rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "GET, HEAD" {
				t.Errorf("%s %s from this host: %d Allow %q", method, path, rec.Code, rec.Header().Get("Allow"))
			}
		}
		for _, peer := range []string{"192.0.2.50:5555", "[2001:db8::50]:5555", "", "not-an-address"} {
			for _, method := range []string{http.MethodGet, http.MethodPost} {
				rec := serve(t, handler, method, path, peer)
				if rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "sshd") || strings.Contains(rec.Body.String(), "vda") {
					t.Errorf("%s %s from %q: %d\n%s", method, path, peer, rec.Code, rec.Body.String())
				}
			}
		}
	}

}
