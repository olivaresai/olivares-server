// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package console

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/olivaresai/olivares/appliance/layer/hostops"
)

func TestCLI_ServiceRestartPlansThenSubmitsExactUnitOnce(t *testing.T) {
	s := &userSession{state: hostops.StateSucceeded}
	var out, diagnostic bytes.Buffer
	dial := func() (Session, error) { return s, nil }
	args := []string{"service", "restart", "olivares-app-example.service"}
	if code := Run(t.Context(), append(append([]string{}, args...), "--plan"), nil, &out, &diagnostic, dial); code != 0 || s.calls != 1 || s.applied != 0 || !strings.Contains(out.String(), "Plan: "+strings.Repeat("a", 64)) {
		t.Fatalf("plan: exit=%d calls=%d applied=%d output=%s", code, s.calls, s.applied, out.String())
	}
	out.Reset()
	args = append(args, "--confirm", strings.Repeat("a", 64), "--operation-id", strings.Repeat("1", 32), "--output", "json")
	if code := Run(t.Context(), args, nil, &out, &diagnostic, dial); code != 0 || s.applied != 1 || s.calls != 1 {
		t.Fatalf("apply: exit=%d calls=%d applied=%d", code, s.calls, s.applied)
	}
	var inputs map[string]string
	if json.Unmarshal(s.req.Inputs, &inputs) != nil || len(inputs) != 1 || inputs["unit"] != "olivares-app-example.service" || s.req.Module != "service" || s.req.Verb != "restart" || s.req.Surface != "cli" || s.req.OperationID != strings.Repeat("1", 32) {
		t.Fatal("wrong restart intent", s.req)
	}
	if !strings.Contains(diagnostic.String(), "Operation: "+s.req.OperationID) {
		t.Fatal("operation ID unavailable for recovery", diagnostic.String())
	}
}

func TestCLI_ServiceRestartRefusesAuthorityFlagsAndConflictingModes(t *testing.T) {
	base := []string{"service", "restart", "olivares-app-example.service"}
	for _, extra := range [][]string{{"--actor", "root"}, {"--unit", "sshd.service"}, {"--confirm", "yes"}, {"--confirm", strings.Repeat("a", 64), "--plan"}, {"--output", "json"}, {"--operation-id", strings.Repeat("1", 32)}, {"--plan", "--plan"}} {
		dials := 0
		var out, diagnostic bytes.Buffer
		code := Run(t.Context(), append(append([]string{}, base...), extra...), nil, &out, &diagnostic, func() (Session, error) { dials++; return &userSession{}, nil })
		if code != 1 || dials != 0 {
			t.Fatalf("accepted %v: exit=%d dials=%d", extra, code, dials)
		}
	}
}

func TestCLI_ServiceRestartUnknownOutcomeKeepsIDWithoutRetry(t *testing.T) {
	s := &userSession{state: hostops.StateRunning}
	dials := 0
	var out, diagnostic bytes.Buffer
	args := []string{"service", "restart", "olivares-app-example.service", "--confirm", strings.Repeat("a", 64), "--output", "json"}
	code := Run(context.Background(), args, nil, &out, &diagnostic, func() (Session, error) { dials++; return s, nil })
	if code != 2 || dials != 1 || s.applied != 1 || !strings.Contains(out.String(), `"state":"running"`) || !strings.Contains(diagnostic.String(), s.req.OperationID) {
		t.Fatalf("unknown outcome: exit=%d dials=%d applied=%d output=%s diagnostic=%s", code, dials, s.applied, out.String(), diagnostic.String())
	}
}
