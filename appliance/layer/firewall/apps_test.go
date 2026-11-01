// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package firewall_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/olivaresai/olivares/appliance/layer/firewall"
	"github.com/olivaresai/olivares/appliance/layer/firewall/policy"
	"github.com/olivaresai/olivares/appliance/layer/optionalapps"
)

// nginxProxyManagerRows are the rows the optional app's firewall act adds, from its manifest, the one
// source of its ports and its bridge, answering on interfaces.
func nginxProxyManagerRows(interfaces []string) []policy.AppRow {
	rows := optionalapps.FirewallRows()
	for i := range rows {
		rows[i].Interfaces = slices.Clone(interfaces)
	}
	return rows
}

// Nginx Proxy Manager's rows change through its own act: its two public ports are added and
// measured under confirm-or-revert, its loopback admin port never gets a row, and the app's act
// removes exactly its own rows again. Docker-published ports are forwarded traffic: the loaded
// forward chain admits them, and the app's egress, while the rows are in force and no longer after.
func TestAppRow_NginxProxyManagerAddsAndRemovesItsOwnRows(t *testing.T) {
	ctx := context.Background()
	o := newOwner(t)
	install(t, o, managed())
	rows := nginxProxyManagerRows([]string{"eth0"})
	var ports []string
	for _, row := range rows {
		ports = append(ports, row.Port)
	}
	if !slices.Equal(ports, []string{"80/tcp", "443/tcp"}) {
		t.Fatalf("the app's rows are %v, want its two public ports and not the loopback admin port", ports)
	}
	with := managed()
	with.Apps = rows
	if err := with.Validate(); err != nil {
		t.Fatalf("the app's rows are not a valid policy: %v", err)
	}

	// Another application's act cannot add them.
	if _, err := o.Apply(ctx, firewall.ApplyRequest{OperationID: operationID(1), App: "proxy", Candidate: with}); code(err) != firewall.CodeAppRowNotOwnAct {
		t.Errorf("another application adding the app's rows: %v, want %s", err, firewall.CodeAppRowNotOwnAct)
	}
	if _, err := o.Apply(ctx, firewall.ApplyRequest{OperationID: operationID(2), App: "nginx-proxy-manager", Candidate: with}); err != nil {
		t.Fatalf("the app's act that adds its rows: %v", err)
	}
	if _, err := o.Confirm(ctx, operationID(2)); err != nil {
		t.Fatal(err)
	}
	m, ok := o.published(t)
	if !ok {
		t.Fatal("no measurement after the app's rows were confirmed")
	}
	for _, port := range []string{"80/tcp", "443/tcp"} {
		if r, found := rowOf(m.Rows, port); !found || !slices.Equal(r.Interfaces, []string{"eth0"}) {
			t.Errorf("%s is not measured on eth0: %+v", port, m.Rows)
		}
	}
	if _, found := rowOf(m.Rows, "81/tcp"); found {
		t.Errorf("the loopback admin port was opened: %+v", m.Rows)
	}
	loaded := string(o.kernel.ruleset)
	for _, want := range []string{
		`iifname { "eth0" } meta l4proto tcp ct status dnat ct original proto-dst 80 accept`,
		`iifname { "eth0" } meta l4proto tcp ct status dnat ct original proto-dst 443 accept`,
		`iifname "olv-npm" accept`,
	} {
		if !strings.Contains(forwardChain(loaded), want) {
			t.Errorf("the loaded forward chain lacks %q:\n%s", want, loaded)
		}
	}
	if strings.Contains(forwardChain(loaded), "proto-dst 81") {
		t.Errorf("the loopback admin port is forwarded:\n%s", loaded)
	}

	if _, err := o.Apply(ctx, firewall.ApplyRequest{OperationID: operationID(3), App: "nginx-proxy-manager", Candidate: managed()}); err != nil {
		t.Fatalf("the app's act that removes its rows: %v", err)
	}
	if _, err := o.Confirm(ctx, operationID(3)); err != nil {
		t.Fatal(err)
	}
	m, _ = o.published(t)
	for _, port := range []string{"80/tcp", "443/tcp"} {
		if _, found := rowOf(m.Rows, port); found {
			t.Errorf("%s is still measured after the app's rows were removed: %+v", port, m.Rows)
		}
	}
	if after := forwardChain(string(o.kernel.ruleset)); strings.Contains(after, "dnat") || strings.Contains(after, "olv-npm") {
		t.Errorf("the forward chain still forwards for the app after its rows were removed:\n%s", after)
	}
	if got := confirmedDigest(t, o); got != policy.Digest(managed()) {
		t.Errorf("the confirmed policy is %s after removal, want the policy without the app", got)
	}
}

// forwardChain returns the text of the forward chain of a rendered ruleset.
func forwardChain(ruleset string) string {
	_, after, _ := strings.Cut(ruleset, "chain forward {")
	chain, _, _ := strings.Cut(after, "\n\t}")
	return chain
}
