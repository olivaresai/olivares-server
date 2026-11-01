// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package console

import (
	"bytes"
	"encoding/json"
	"github.com/olivaresai/olivares/appliance/layer/hostops"
	"strings"
	"testing"
)

type defaultUserSession struct {
	userSession
	planInputs json.RawMessage
}

func (s *defaultUserSession) Plan(module, verb, surface string, input json.RawMessage) (hostops.Plan, error) {
	s.planInputs = append(json.RawMessage(nil), input...)
	return s.userSession.Plan(module, verb, surface, input)
}
func TestCLI_HostUserDefaultsHomeFromAccountForPlanAndConfirmation(t *testing.T) {
	s := &defaultUserSession{userSession: userSession{state: hostops.StateSucceeded}}
	var out, log bytes.Buffer
	args := []string{"host-user", "create", "alice", "--group", "staff"}
	dial := func() (Session, error) { return s, nil }
	if code := Run(t.Context(), append(append([]string{}, args...), "--plan"), nil, &out, &log, dial); code != 0 {
		t.Fatalf("default plan: exit=%d %s", code, log.String())
	}
	var inputs map[string]string
	if json.Unmarshal(s.planInputs, &inputs) != nil || inputs["home"] != "/home/alice" {
		t.Fatalf("default home absent from plan: %s", s.planInputs)
	}
	if code := Run(t.Context(), append(args, "--confirm", strings.Repeat("a", 64)), nil, &out, &log, dial); code != 0 || s.applied != 1 || !bytes.Equal(s.planInputs, s.req.Inputs) {
		t.Fatalf("default confirmation changed intent: exit=%d plan=%s apply=%s", code, s.planInputs, s.req.Inputs)
	}
}
