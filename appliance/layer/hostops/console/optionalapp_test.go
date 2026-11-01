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

func TestCLI_NPMUsesFixedDefaultsAndOneConfirmedSubmission(t *testing.T) {
	for _, op := range []string{"install", "start", "stop", "uninstall"} {
		t.Run(op, func(t *testing.T) {
			s := &userSession{state: hostops.StateSucceeded}
			var out, diagnostic bytes.Buffer
			dial := func() (Session, error) { return s, nil }
			args := []string{"nginx-proxy-manager", op}
			if code := Run(t.Context(), append(append([]string{}, args...), "--plan"), nil, &out, &diagnostic, dial); code != 0 || s.calls != 1 || s.applied != 0 || !strings.Contains(out.String(), "Plan: "+strings.Repeat("a", 64)) {
				t.Fatalf("plan: exit=%d calls=%d applied=%d output=%s diagnostic=%s", code, s.calls, s.applied, out.String(), diagnostic.String())
			}
			out.Reset()
			args = append(args, "--confirm", strings.Repeat("a", 64), "--operation-id", strings.Repeat("1", 32), "--output", "json")
			if code := Run(t.Context(), args, nil, &out, &diagnostic, dial); code != 0 || s.applied != 1 || s.calls != 1 {
				t.Fatalf("apply: exit=%d calls=%d applied=%d diagnostic=%s", code, s.calls, s.applied, diagnostic.String())
			}
			var inputs map[string]any
			if json.Unmarshal(s.req.Inputs, &inputs) != nil || inputs == nil || len(inputs) != 0 || s.req.Module != "nginx-proxy-manager" || s.req.Verb != op || s.req.OperationID != strings.Repeat("1", 32) || s.req.Surface != "cli" {
				t.Fatalf("fixed app defaults were changed: %+v", s.req)
			}
		})
	}
}

func TestCLI_NPMRefusesUntrustedChoicesAndUnknownAnswerNeverRedials(t *testing.T) {
	for _, extra := range [][]string{nil, {"--image", "untrusted:latest"}, {"--data-dir", "/tmp/foreign"}, {"--actor", "root"}, {"--purge"}, {"--confirm", "yes"}, {"--confirm", strings.Repeat("a", 64), "--plan"}, {"--output", "json"}, {"--operation-id", strings.Repeat("a", 32)}, {"--plan", "--plan"}} {
		dials := 0
		var out, diagnostic bytes.Buffer
		code := Run(t.Context(), append([]string{"nginx-proxy-manager", "install"}, extra...), nil, &out, &diagnostic, func() (Session, error) { dials++; return &userSession{}, nil })
		if code != 1 || dials != 0 {
			t.Fatalf("untrusted option %v accepted: exit=%d dials=%d", extra, code, dials)
		}
	}
	s := &userSession{state: hostops.StateRunning}
	dials := 0
	var out, diagnostic bytes.Buffer
	code := Run(t.Context(), []string{"nginx-proxy-manager", "install", "--confirm", strings.Repeat("a", 64), "--output", "json"}, nil, &out, &diagnostic, func() (Session, error) { dials++; return s, nil })
	if code != 2 || dials != 1 || s.applied != 1 || len(s.req.OperationID) != 32 || !strings.Contains(diagnostic.String(), s.req.OperationID) || !strings.Contains(out.String(), `"state":"running"`) {
		t.Fatalf("unknown answer was lost/retried: exit=%d dials=%d applied=%d output=%s diagnostic=%s", code, dials, s.applied, out.String(), diagnostic.String())
	}
}
