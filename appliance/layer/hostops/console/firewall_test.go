// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package console

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/olivaresai/olivares/appliance/layer/hostops"
)

// The firewall's app-row act is confirmed like the other adopted acts: the plan's digest, an optional
// operation id and revert window, one submission. The inputs are the closed ones of its descriptor, and
// the window is an integer, as its schema says.
func TestCLI_FirewallAppRowSubmitsTheClosedInputsOnce(t *testing.T) {
	s := &userSession{state: hostops.StateSucceeded}
	var out, diagnostic bytes.Buffer
	dial := func() (Session, error) { return s, nil }
	args := []string{"firewall", "app-row", "nginx-proxy-manager", "add", "--revert-after", "300", "--confirm", strings.Repeat("a", 64), "--operation-id", strings.Repeat("1", 32), "--output", "json"}
	if code := Run(t.Context(), args, nil, &out, &diagnostic, dial); code != 0 || s.applied != 1 || s.calls != 0 {
		t.Fatalf("apply: exit=%d calls=%d applied=%d diagnostic=%s", code, s.calls, s.applied, diagnostic.String())
	}
	var inputs map[string]any
	if json.Unmarshal(s.req.Inputs, &inputs) != nil || len(inputs) != 3 || inputs["app"] != "nginx-proxy-manager" || inputs["change"] != "add" || inputs["revert_after_s"] != float64(300) {
		t.Errorf("the inputs are %s, want app, change and the window as an integer", s.req.Inputs)
	}
	if s.req.Module != "firewall" || s.req.Verb != "app-row" || s.req.Surface != "cli" || s.req.OperationID != strings.Repeat("1", 32) || s.req.Confirmation != strings.Repeat("a", 64) {
		t.Errorf("the request is %+v", s.req)
	}

	// Without a window or an operation id: two inputs, a minted operation id, and a plan before.
	s = &userSession{state: hostops.StateSucceeded}
	out.Reset()
	if code := Run(t.Context(), []string{"firewall", "app-row", "nginx-proxy-manager", "remove", "--plan"}, nil, &out, &diagnostic, func() (Session, error) { return s, nil }); code != 0 || s.applied != 0 || s.calls != 1 || !strings.Contains(out.String(), "Plan: "+strings.Repeat("a", 64)) {
		t.Fatalf("plan: exit=%d calls=%d applied=%d output=%s", code, s.calls, s.applied, out.String())
	}
	if code := Run(t.Context(), []string{"firewall", "app-row", "nginx-proxy-manager", "remove", "--confirm", strings.Repeat("a", 64)}, nil, &out, &diagnostic, func() (Session, error) { return s, nil }); code != 0 || s.applied != 1 {
		t.Fatalf("apply without a window: exit=%d applied=%d", code, s.applied)
	}
	inputs = nil
	if json.Unmarshal(s.req.Inputs, &inputs) != nil || len(inputs) != 2 || inputs["change"] != "remove" || len(s.req.OperationID) != 32 {
		t.Errorf("the inputs are %s (operation %q), want app and change", s.req.Inputs, s.req.OperationID)
	}
}

// Nothing outside the act's grammar is dialed: no other verb of the module, no path or authority as
// the app, a change that is neither add nor remove, a window outside the owner's bounds or written
// another way, a confirmation that is not a digest, and a plan together with a confirmation.
func TestCLI_FirewallAppRowRefusesWhatTheGrammarDoesNotName(t *testing.T) {
	digest := strings.Repeat("a", 64)
	for _, args := range [][]string{
		{"firewall", "apply", "--confirm", digest},
		{"firewall", "confirm", strings.Repeat("a", 32), "--confirm", digest},
		{"firewall", "app-row", "../npm", "add", "--confirm", digest},
		{"firewall", "app-row", "Npm", "add", "--confirm", digest},
		{"firewall", "app-row", "npm", "toggle", "--confirm", digest},
		{"firewall", "app-row", "npm", "add"},
		{"firewall", "app-row", "npm", "add", "--revert-after", "300"},
		{"firewall", "app-row", "npm", "add", "--revert-after", "59", "--confirm", digest},
		{"firewall", "app-row", "npm", "add", "--revert-after", "601", "--confirm", digest},
		{"firewall", "app-row", "npm", "add", "--revert-after", "0300", "--confirm", digest},
		{"firewall", "app-row", "npm", "add", "--revert-after", "300", "--revert-after", "300", "--confirm", digest},
		{"firewall", "app-row", "npm", "add", "--confirm", "yes"},
		{"firewall", "app-row", "npm", "add", "--confirm", digest, "--plan"},
		{"firewall", "app-row", "npm", "add", "--actor", "root", "--confirm", digest},
		{"firewall", "app-row", "npm", "add", "--output", "json"},
		{"firewall", "app-row", "npm", "add", "--operation-id", strings.Repeat("a", 32)},
		{"firewall", "app-row", "npm"},
		{"firewall", "app-row"},
		{"nginx-proxy-manager", "install", "--revert-after", "300", "--confirm", digest},
	} {
		dials := 0
		var out, diagnostic bytes.Buffer
		if code := Run(t.Context(), args, nil, &out, &diagnostic, func() (Session, error) { dials++; return &userSession{}, nil }); code != 1 || dials != 0 {
			t.Errorf("%v: exit=%d dials=%d, want a refusal before dialing", args, code, dials)
		}
	}
}
