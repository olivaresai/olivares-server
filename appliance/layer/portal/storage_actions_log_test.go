// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package portal

import (
	"bytes"
	"context"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/olivaresai/olivares/appliance/layer/helpers/helperschema"
)

// Without the cause in the journal, every storage POST answers 503 and nothing
// tells the operator why.
func TestPortalStorage_UnopenableRecordsDirectoryNamesItsCause(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	var logged bytes.Buffer
	log.SetOutput(&logged)
	defer log.SetOutput(os.Stderr)
	_, access := networkFixture(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) })
	call := func(context.Context, string, helperschema.Request) (helperschema.Response, error) {
		return helperschema.Response{}, nil
	}
	h := networkHandler(Status{StorageCall: call, StorageDirectory: filepath.Join(blocker, "records")}, access).(*protectedNetwork)
	if h.storageActs != nil {
		t.Fatal("storage actions opened on an unusable records directory")
	}
	if !strings.Contains(logged.String(), "storage actions unavailable") || !strings.Contains(logged.String(), "not a directory") {
		t.Fatalf("the cause was not logged: %q", logged.String())
	}
}
