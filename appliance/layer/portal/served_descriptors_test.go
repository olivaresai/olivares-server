// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package portal

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/olivaresai/olivares/appliance/layer/firewall"
	"github.com/olivaresai/olivares/appliance/layer/helpers/helperschema"
	"github.com/olivaresai/olivares/appliance/layer/hostops"
	"github.com/olivaresai/olivares/appliance/layer/hostusers"
	"github.com/olivaresai/olivares/appliance/layer/optionalapps"
	"github.com/olivaresai/olivares/appliance/layer/portal/localsession"
	"github.com/olivaresai/olivares/appliance/layer/services"
	"github.com/olivaresai/olivares/appliance/layer/storage"
	"github.com/olivaresai/olivares/appliance/layer/updates"
)

// The local socket serves one catalog for every composed module: the host status, each
// services task, the storage inventory, each firewall task and each optional app task, described to the CLI and the TUI
// alike.
func TestServedCatalog_DescribesEveryComposedModulesTasks(t *testing.T) {
	catalog, packages, err := localsession.CatalogWithPackages(t.Context(), ServedDescriptors(), nil)
	if err != nil {
		t.Fatalf("the served catalog is refused: %v", err)
	}
	if len(packages) != 0 {
		t.Fatal("unavailable native package status supplied an effect descriptor")
	}
	if got, want := len(catalog.Descriptors()), 1+len(services.Ops())+len(storage.Descriptors())+len(firewall.Descriptors())+len(hostusers.Descriptors())+len(optionalapps.Descriptors()); got != want {
		t.Fatalf("the served catalog has %d tasks, want %d", got, want)
	}
	for _, surface := range []string{"cli", "tui"} {
		if _, err := catalog.Describe("host-user", "create", surface); err != nil {
			t.Errorf("%s: host-user create: %v", surface, err)
		}
		if _, err := catalog.Describe("host", "status", surface); err != nil {
			t.Errorf("%s: host status: %v", surface, err)
		}
		for _, op := range services.Ops() {
			if _, err := catalog.Describe(services.Module, op, surface); err != nil {
				t.Errorf("%s: service %s: %v", surface, op, err)
			}
		}
		if _, err := catalog.Describe("storage", "list", surface); err != nil {
			t.Errorf("%s: storage list: %v", surface, err)
		}
		for _, d := range optionalapps.Descriptors() {
			if _, err := catalog.Describe(d.Module, d.Verb, surface); err != nil {
				t.Errorf("%s: %s %s: %v", surface, d.Module, d.Verb, err)
			}
		}
		for _, verb := range firewall.Verbs() {
			if _, err := catalog.Describe(firewall.Module, verb, surface); err != nil {
				t.Errorf("%s: firewall %s: %v", surface, verb, err)
			}
		}
	}
}

// retainedPlan is the host-package helper's answer: a serialized status, as its helper sends it when
// a plan is retained, or the refusal it sends when none is.
type retainedPlan struct {
	status updates.PackageStatus
	none   bool
}

func (h retainedPlan) Call(_ context.Context, name string, request helperschema.Request) (helperschema.Response, error) {
	if r, ok := request.(*updates.PackageRequest); !ok || name != helperschema.HelperApt || r.Op != "status" {
		return helperschema.Response{Result: helperschema.ResultFailed}, nil
	}
	if h.none {
		return helperschema.Response{Result: helperschema.ResultRefused, Code: helperschema.CodeInputRefused}, nil
	}
	body, _ := json.Marshal(h.status)
	return helperschema.Response{Result: helperschema.ResultAnswered, Bundle: body}, nil
}

func packageStatus() updates.PackageStatus {
	p := updates.PackageStatus{Name: "olv-example", Repository: "appstream", PreviousRepository: "baseos",
		From: "olv-example-1.0-1.x86_64", To: "olv-example-1.1-1.x86_64", Installed: "olv-example-1.0-1.x86_64",
		RecoveryScope: "package-version-only", Digest: strings.Repeat("c", 64)}
	for _, op := range []string{"update", "recover"} {
		from, to, repository := p.From, p.To, p.Repository
		if op == "recover" {
			from, to, repository = to, from, p.PreviousRepository
		}
		p.Descriptors = append(p.Descriptors, hostops.Descriptor{ID: "host-package." + op, Module: "host-package", Verb: op, Title: "Host package " + op, Category: "Packages",
			InputSchema:   hostops.InputSchema{Type: "object", Properties: map[string]hostops.InputField{"native_plan": {Type: "string", Enum: []string{p.Digest}}}, Required: []string{"native_plan"}},
			Preconditions: []string{"Current exact-plan authority"}, Consequence: "Change " + from + " to " + to + "; repository=" + repository + "; recovery_scope=package-version-only.",
			Confirmation: "confirm", Modes: []string{"product-up"}, ActVerb: "package", Audience: "appliance-helper:olivares-portal-apt",
			EquivalentCommand: "olivares-appliance host-package " + op + " --plan", OutputSchema: "hostop-v1.schema.json", Surfaces: []string{"web", "cli", "tui"}})
	}
	return p
}

// The host-package tasks come from the helper's retained plan and from nothing else: with a plan the
// served catalog gains exactly the two confirm-gated tasks, on every surface; on an image with no
// retained plan it gains none, and never a task the helper did not seal.
func TestServedCatalog_ComposesTheHostPackageTasksOnlyFromARetainedPlan(t *testing.T) {
	base := len(ServedDescriptors())
	catalog, packages, err := localsession.CatalogWithPackages(t.Context(), ServedDescriptors(), retainedPlan{status: packageStatus()})
	if err != nil {
		t.Fatalf("the served catalog with a retained plan is refused: %v", err)
	}
	if len(packages) != 2 || len(catalog.Descriptors()) != base+2 {
		t.Fatalf("with a plan: %d package tasks, %d tasks in all, want 2 and %d", len(packages), len(catalog.Descriptors()), base+2)
	}
	for _, surface := range []string{"cli", "tui", "web"} {
		for _, verb := range []string{"update", "recover"} {
			d, err := catalog.Describe("host-package", verb, surface)
			if err != nil || d.Confirmation != "confirm" || d.ActVerb != "package" || !slices.Equal(d.Modes, []string{"product-up"}) {
				t.Errorf("%s: host-package %s: %+v %v, want a confirm-gated package task", surface, verb, d, err)
			}
		}
	}

	catalog, packages, err = localsession.CatalogWithPackages(t.Context(), ServedDescriptors(), retainedPlan{none: true})
	if err != nil || len(packages) != 0 || len(catalog.Descriptors()) != base {
		t.Fatalf("with no retained plan: %d package tasks, %d tasks, %v, want none and %d", len(packages), len(catalog.Descriptors()), err, base)
	}
	if _, err := catalog.Describe("host-package", "update", "cli"); err == nil {
		t.Fatal("host-package update is described with no retained plan")
	}
}
