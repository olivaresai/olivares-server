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

type userSession struct {
	session
	req     hostops.ApplyRequest
	applied int
	state   string
}

func (s *userSession) Plan(_, _, _ string, inputs json.RawMessage) (hostops.Plan, error) {
	s.calls++
	return hostops.Plan{Descriptor: hostops.StatusDescriptor(), Inputs: inputs, Digest: strings.Repeat("a", 64), Permissions: hostops.Permissions{Apply: true}}, nil
}
func (s *userSession) Apply(r hostops.ApplyRequest) (hostops.Record, int, error) {
	s.req = r
	s.applied++
	return hostops.Record{OperationID: r.OperationID, State: s.state}, 200, s.err
}
func TestCLI_HostUserPlansAndConfirmsWithoutImplicitRetry(t *testing.T) {
	args := []string{"host-user", "create", "alice", "--home", "/home/alice", "--group", "staff"}
	s := &userSession{state: hostops.StateSucceeded}
	var out, log bytes.Buffer
	if code := Run(context.Background(), args, nil, &out, &log, func() (Session, error) { return s, nil }); code != 0 || s.applied != 0 || !strings.Contains(out.String(), "Plan: "+strings.Repeat("a", 64)) {
		t.Fatalf("plan exit/output %d %s", code, out.String())
	}
	out.Reset()
	log.Reset()
	apply := append(append([]string{}, args...), "--confirm", strings.Repeat("a", 64), "--output", "json")
	if code := Run(context.Background(), apply, nil, &out, &log, func() (Session, error) { return s, nil }); code != 0 || s.applied != 1 || s.calls != 1 || len(s.req.OperationID) != 32 || !strings.Contains(log.String(), s.req.OperationID) {
		t.Fatalf("apply %d %+v %s", code, s.req, log.String())
	}
	var got map[string]string
	if json.Unmarshal(s.req.Inputs, &got) != nil || got["account"] != "alice" || got["group"] != "staff" {
		t.Fatal("wrong inputs")
	}
}
func TestCLI_HostUserRefusesAuthorityFlagsAndConflictingModes(t *testing.T) {
	base := []string{"host-user", "create", "alice", "--home", "/home/alice", "--group", "staff"}
	for _, extra := range [][]string{{"--actor", "root"}, {"--home", "/root"}, {"--confirm", "yes"}, {"--confirm", strings.Repeat("a", 64), "--plan"}, {"--output", "json"}, {"--operation-id", strings.Repeat("a", 32)}} {
		dials := 0
		var out, log bytes.Buffer
		if code := Run(context.Background(), append(append([]string{}, base...), extra...), nil, &out, &log, func() (Session, error) { dials++; return &userSession{}, nil }); code != 1 || dials != 0 {
			t.Fatalf("accepted %v", extra)
		}
	}
}
