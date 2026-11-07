// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package localsession

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/olivaresai/olivares/appliance/layer/helpers/helperschema"
	"github.com/olivaresai/olivares/appliance/layer/hostops"
	"github.com/olivaresai/olivares/appliance/layer/optionalapps"
	"github.com/olivaresai/olivares/appliance/layer/portal/audit"
	"github.com/olivaresai/olivares/appliance/layer/portal/localframe"
)

// appsHelper answers the apps helper's status read: the app is not installed.
type appsHelper struct{ digest string }

func (h appsHelper) Call(_ context.Context, name string, request helperschema.Request) (helperschema.Response, error) {
	if name != helperschema.HelperApps || request.Subcommand() != "status" {
		return helperschema.Response{}, errors.New("a plan asks the apps helper for its status alone")
	}
	body, _ := json.Marshal(map[string]any{"manifest": h.digest, "state": map[string]any{"container_id": "", "installed": false, "running": false}})
	return helperschema.Response{Result: helperschema.ResultAnswered, Bundle: body}, nil
}

type appsIdentity struct{}

func (appsIdentity) Authorize(_ context.Context, d hostops.Descriptor, target, digest string) (hostops.Caller, error) {
	if d.Module != "nginx-proxy-manager" || d.ActVerb != "app" || target != "app:nginx-proxy-manager" || len(digest) != 64 {
		return hostops.Caller{}, errors.New("denied")
	}
	return hostops.Caller{Actor: "operator", Mode: "product-up"}, nil
}

func (a appsIdentity) ReserveExposure(ctx context.Context, d hostops.Descriptor, target, digest string) (hostops.Caller, error) {
	return a.Authorize(ctx, d, target, digest)
}

// The optional app's lifecycle is an adopted act of the portal's local socket: the served catalog
// carries it, and a plan for install reaches the apps helper's status and offers the apply. The
// lifecycle verbs that are not served are not adopted, and an absent helper offers no apply.
func TestLocalSession_OptionalAppLifecycleIsAnAdoptedAct(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "optionalapps", "nginx-proxy-manager.json"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	f := admittedFacts(1000, true)
	own, code := admit(4, f)
	if code != "" {
		t.Fatal(code)
	}
	defer own.Close()
	auditDir := t.TempDir()
	if err := os.Chmod(auditDir, 0700); err != nil {
		t.Fatal(err)
	}
	spool, err := audit.Open(auditDir)
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(context.Context, uint32) (hostops.Authority, error) { return appsIdentity{}, nil }
	served := append([]hostops.Descriptor{hostops.StatusDescriptor()}, optionalapps.Descriptors()...)
	plan := func(helper optionalapps.HelperCaller, descriptors []hostops.Descriptor, verb string) localframe.Record {
		t.Helper()
		s, err := OpenWithPackages(t.Context(), t.TempDir(), descriptors, helper, f, resolve, spool)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(taskRequest{Module: "nginx-proxy-manager", Verb: verb, Surface: "cli", Inputs: json.RawMessage(`{}`)})
		return s.handleFor(t.Context(), localframe.Record{Type: "request", Op: "task.plan", Body: body}, own)
	}
	var p hostops.Plan
	if r := plan(appsHelper{hex.EncodeToString(sum[:])}, served, "install"); r.Status != 200 || json.Unmarshal(r.Body, &p) != nil || !p.Permissions.Apply {
		t.Fatalf("install with the apps helper: %+v, want a plan that offers the apply", r)
	}
	if r := plan(appsHelper{hex.EncodeToString(sum[:])}, served, "stop"); r.Status == 200 {
		t.Fatalf("stop of an app that is not installed was planned: %+v", r)
	}
	if r := plan(nil, served, "install"); r.Status == 200 {
		t.Fatalf("install without the apps helper was planned: %+v", r)
	}
	if r := plan(appsHelper{hex.EncodeToString(sum[:])}, []hostops.Descriptor{hostops.StatusDescriptor()}, "install"); r.Status == 200 {
		t.Fatalf("install is planned although the catalog does not serve it: %+v", r)
	}
}
