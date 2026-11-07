// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package localsession

import (
	"context"
	"log"
	"slices"
	"time"

	"github.com/olivaresai/olivares/appliance/layer/firewall"
	"github.com/olivaresai/olivares/appliance/layer/helpers/helperschema"
	"github.com/olivaresai/olivares/appliance/layer/hostops"
	"github.com/olivaresai/olivares/appliance/layer/optionalapps"
	"github.com/olivaresai/olivares/appliance/layer/portal/audit"
	"github.com/olivaresai/olivares/appliance/layer/services"
	"github.com/olivaresai/olivares/appliance/layer/updates"
)

// packageDescriptors reads the native owner's sealed-plan task definitions.
// The portal never constructs a native Plan or opens the helper's private RPMs.
func packageDescriptors(ctx context.Context, helper updates.HelperCaller) []hostops.Descriptor {
	if helper == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	answer, err := helper.Call(ctx, updates.HelperName, &updates.PackageRequest{Op: "status"})
	if err == nil && answer.Result == helperschema.ResultRefused {
		return nil // the helper has no plan it can load: the usual state of an appliance before a retention
	}
	var status updates.PackageStatus
	if err != nil || answer.Result != helperschema.ResultAnswered || hostops.DecodeClosed(answer.Bundle, &status) != nil || status.Digest == "" || (&updates.PackageRequest{Op: "status", NativePlan: status.Digest}).Validate() != nil || status.RecoveryScope != "package-version-only" || status.PreviousRepository == "" || len(status.Descriptors) != 2 {
		// No package task exists from here on, so say why (the answer's codes, never its contents): a helper
		// that did not answer inside the budget looks the same to an operator as a console with no plan.
		log.Printf("appliance console: the host-package status is unusable (%v, result %q, code %q); no package task is offered", err, answer.Result, answer.Code)
		return nil
	}
	seen := map[string]bool{}
	for _, d := range status.Descriptors {
		field := d.InputSchema.Properties["native_plan"]
		if d.Module != "host-package" || !slices.Contains([]string{"update", "recover"}, d.Verb) || seen[d.Verb] || d.ID != d.Module+"."+d.Verb || d.ActVerb != "package" || d.Confirmation != "confirm" || !slices.Equal(d.Modes, []string{"product-up"}) || len(d.InputSchema.Properties) != 1 || !slices.Equal(d.InputSchema.Required, []string{"native_plan"}) || field.Type != "string" || !slices.Equal(field.Enum, []string{status.Digest}) {
			return nil
		}
		seen[d.Verb] = true
	}
	catalog, err := hostops.NewCatalog(status.Descriptors)
	if err != nil {
		return nil
	}
	return catalog.Descriptors()
}

// CatalogWithPackages supplies the same trusted catalog to engine authorization
// and portal task rendering. The second return is native metadata for adoption.
// Unavailable or invalid native status preserves the existing tasks.
// Whole-machine effects require installation system:admin/current deny overlays;
// tenant-only roles refuse. Catalog metadata never grants that authority.
func CatalogWithPackages(ctx context.Context, descriptors []hostops.Descriptor, helper updates.HelperCaller) (*hostops.Catalog, []hostops.Descriptor, error) {
	packages := packageDescriptors(ctx, helper)
	catalog, err := hostops.NewCatalog(append(slices.Clone(descriptors), packages...))
	return catalog, packages, err
}

// OpenWithPackages uses one catalog for task.list, task.describe and durable
// claims; the package tasks, the optional apps' tasks and the firewall's app-row act are its adopted effects.
// Effects need the existing audit spool and current identity owner's resolver;
// OS admission never grants authority. Nil resolve preserves read-only use.
func OpenWithPackages(ctx context.Context, dir string, descriptors []hostops.Descriptor, helper updates.HelperCaller, kernel Kernel, resolve AuthorityResolver, spool *audit.Spool) (*Server, error) {
	catalog, packages, err := CatalogWithPackages(ctx, descriptors, helper)
	if err != nil {
		return nil, err
	}
	records, err := hostops.OpenWithCatalog(dir, catalog)
	if err != nil {
		return nil, err
	}
	local := NewServer(records, catalog, kernel)
	tasks := map[string]hostops.AdoptedTask{}
	for _, d := range packages {
		tasks[d.ID] = updates.PackageTask{Op: d.Verb, Helper: helper}
	}
	serves := func(id string) bool {
		return slices.ContainsFunc(descriptors, func(served hostops.Descriptor) bool { return served.ID == id })
	}
	// An optional app's lifecycle is adopted when the served catalog carries it. Its helper is
	// asked at plan and apply, so an absent helper is a refused act, not a missing task.
	for _, d := range optionalapps.Descriptors() {
		if serves(d.ID) {
			task := optionalapps.LifecycleTask{App: d.Module, Op: d.Verb, Helper: helper}
			tasks[d.ID] = task
		}
	}
	// The firewall's app-row act is adopted the same way, with the rows each optional app gives for itself.
	if serves(firewall.Module + "." + firewall.VerbAppRow) {
		tasks[firewall.Module+"."+firewall.VerbAppRow] = firewall.AppRowTask{Helper: helper, Apps: optionalapps.FirewallApps()}
	}
	// Each act of the services module is its own task, the logs act among them: its entries wait in the
	// console's hold for the operator who asked, and module.read collects them by the act's operation id.
	hold := services.NewLogHold()
	for _, d := range services.Descriptors() {
		if services.IsAct(d.Verb) && serves(d.ID) {
			tasks[d.ID] = services.UnitTask{Op: d.Verb, Helper: helper, Hold: hold}
		}
	}
	local.WithLogHold(hold)
	if len(tasks) != 0 && spool != nil {
		local.WithActs(hostops.NewActs(records, catalog, tasks, hostops.SpoolAudit{Spool: spool}), resolve)
	}
	return local, nil
}
