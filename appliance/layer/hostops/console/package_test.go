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
	"github.com/olivaresai/olivares/appliance/layer/portal/localclient"
)

type packageSession struct {
	userSession
	described  int
	descriptor hostops.Descriptor
	inputs     json.RawMessage
}

func (s *packageSession) Description(_, _, _ string) (hostops.Descriptor, error) {
	s.described++
	return s.descriptor, s.err
}
func (s *packageSession) Plan(_, _, _ string, input json.RawMessage) (hostops.Plan, error) {
	s.calls++
	s.inputs = input
	return hostops.Plan{Descriptor: s.descriptor, Inputs: input, Digest: strings.Repeat("a", 64), Permissions: hostops.Permissions{Apply: true}}, s.err
}
func packageSessionFixture() *packageSession {
	return &packageSession{userSession: userSession{state: hostops.StateSucceeded}, descriptor: hostops.Descriptor{Title: "Update olv-example", Consequence: "olv-example-1.0-1.el10.noarch to olv-example-1.1-1.el10.noarch; repository=appstream; recovery_scope=package-version-only", InputSchema: hostops.InputSchema{Properties: map[string]hostops.InputField{"native_plan": {Type: "string", Enum: []string{strings.Repeat("b", 64)}}}}}}
}

func TestCLI_PackageFillsTrustedNativeDigestAndShowsExactRecoveryScope(t *testing.T) {
	for _, op := range []string{"update", "recover"} {
		t.Run(op, func(t *testing.T) {
			s := packageSessionFixture()
			var out, diagnostic bytes.Buffer
			dials := 0
			dial := func() (Session, error) { dials++; return s, nil }
			if code := Run(t.Context(), []string{"host-package", op, "--plan"}, nil, &out, &diagnostic, dial); code != 0 || s.calls != 1 || s.described != 1 || s.applied != 0 || !strings.Contains(out.String(), s.descriptor.Consequence) || !strings.Contains(out.String(), "Plan: "+strings.Repeat("a", 64)) {
				t.Fatalf("incomplete package preview: %d %s %s", code, out.String(), diagnostic.String())
			}
			var input map[string]string
			if json.Unmarshal(s.inputs, &input) != nil || len(input) != 1 || input["native_plan"] != strings.Repeat("b", 64) {
				t.Fatal("trusted native digest absent from confirmation", string(s.inputs))
			}
			out.Reset()
			if op == "recover" {
				s.state = hostops.StateRolledBack
			}
			if code := Run(t.Context(), []string{"host-package", op, "--confirm", strings.Repeat("a", 64), "--operation-id", strings.Repeat("c", 32), "--output", "json"}, nil, &out, &diagnostic, dial); code != 0 || s.applied != 1 || s.calls != 1 || s.described != 2 || dials != 2 {
				t.Fatalf("single package apply: %d calls=%d effects=%d desc=%d %s", code, s.calls, s.applied, s.described, diagnostic.String())
			}
			if json.Unmarshal(s.req.Inputs, &input) != nil || len(input) != 1 || input["native_plan"] != strings.Repeat("b", 64) || s.req.Verb != op || s.req.Module != "host-package" {
				t.Fatalf("changed intent: %+v", s.req)
			}
		})
	}
}

func TestCLI_PackageRefusesCallerArtifactsAndUncertainAnswerNeverRedials(t *testing.T) {
	for _, extra := range [][]string{nil, {"--package", "foreign"}, {"--repository", "foreign"}, {"--rpm", "/tmp/foreign"}, {"--native-plan", strings.Repeat("f", 64)}, {"--actor", "root"}, {"--confirm", "yes"}, {"--confirm", strings.Repeat("a", 64), "--plan"}} {
		dials := 0
		var out, diagnostic bytes.Buffer
		if code := Run(t.Context(), append([]string{"host-package", "update"}, extra...), nil, &out, &diagnostic, func() (Session, error) { dials++; return packageSessionFixture(), nil }); code != 1 || dials != 0 {
			t.Fatalf("caller artifact %v accepted: %d dials=%d", extra, code, dials)
		}
	}
	for _, digests := range [][]string{nil, {"invalid"}, {strings.Repeat("b", 64), strings.Repeat("c", 64)}} {
		s := packageSessionFixture()
		field := s.descriptor.InputSchema.Properties["native_plan"]
		field.Enum = digests
		s.descriptor.InputSchema.Properties["native_plan"] = field
		var out, diagnostic bytes.Buffer
		if code := Run(t.Context(), []string{"host-package", "update", "--plan"}, nil, &out, &diagnostic, func() (Session, error) { return s, nil }); code != 1 || s.calls != 0 || s.applied != 0 {
			t.Fatalf("untrusted preparation selected: %d %v", code, digests)
		}
	}
	s := packageSessionFixture()
	s.state = hostops.StateRunning
	dials := 0
	var out, diagnostic bytes.Buffer
	if code := Run(t.Context(), []string{"host-package", "update", "--confirm", strings.Repeat("a", 64), "--output", "json"}, nil, &out, &diagnostic, func() (Session, error) { dials++; return s, nil }); code != 2 || dials != 1 || s.applied != 1 || s.described != 1 || !strings.Contains(out.String(), `"state":"running"`) || !strings.Contains(diagnostic.String(), s.req.OperationID) {
		t.Fatalf("uncertain update lost/retried: %d dials=%d output=%s diagnostic=%s", code, dials, out.String(), diagnostic.String())
	}
}

// With no retained plan the console serves no host-package task, so the described task is unknown to the
// server (input_refused). The command says that there is no plan instead of a code that names no cause.
func TestCLI_PackageWithNoRetainedPlanSaysSoAndSendsNothing(t *testing.T) {
	for _, args := range [][]string{{"host-package", "update", "--plan"}, {"host-package", "recover", "--plan"}, {"host-package", "update", "--confirm", strings.Repeat("a", 64)}} {
		s := packageSessionFixture()
		s.err = &localclient.Refused{Code: "input_refused"}
		var out, diagnostic bytes.Buffer
		if code := Run(t.Context(), args, nil, &out, &diagnostic, func() (Session, error) { return s, nil }); code != 1 || out.Len() != 0 || s.calls != 0 || s.applied != 0 || !strings.Contains(diagnostic.String(), "The console offers no host package task: no plan is retained") {
			t.Fatalf("%v: rc=%d out=%q diagnostic=%q calls=%d applied=%d", args, code, out.String(), diagnostic.String(), s.calls, s.applied)
		}
	}
	// A script reading --output json keeps the code alone.
	s := packageSessionFixture()
	s.err = &localclient.Refused{Code: "input_refused"}
	var out, diagnostic bytes.Buffer
	if code := Run(t.Context(), []string{"host-package", "update", "--confirm", strings.Repeat("a", 64), "--output", "json"}, nil, &out, &diagnostic, func() (Session, error) { return s, nil }); code != 1 || diagnostic.String() != "input_refused\n" {
		t.Fatalf("json: rc=%d diagnostic=%q", code, diagnostic.String())
	}
	// Any other refusal keeps its own code: it is not a missing plan.
	s = packageSessionFixture()
	s.err = &localclient.Refused{Code: "pidfd_unproven", BeforeRequest: true}
	out.Reset()
	diagnostic.Reset()
	if code := Run(t.Context(), []string{"host-package", "update", "--plan"}, nil, &out, &diagnostic, func() (Session, error) { return s, nil }); code != 1 || !strings.HasPrefix(diagnostic.String(), "pidfd_unproven\n") || strings.Contains(diagnostic.String(), "offers no host package task") {
		t.Fatalf("rc=%d diagnostic=%q", code, diagnostic.String())
	}
}
