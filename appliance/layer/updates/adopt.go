// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package updates

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/olivaresai/olivares/appliance/layer/helpers/helperschema"
	"github.com/olivaresai/olivares/appliance/layer/hostops"
)

// HelperName is the helper's short socket name, /run/olivares-helpers/apt.sock,
// the name of the existing package audience. The consumer uses rpm, not an apt
// executable.
const HelperName = helperschema.HelperApt

// HelperRules is the helper's admission table: the status read and the two
// package acts, for the Appliance Console alone, attested by the kernel. An act
// also waits for the seam's guest proof, so no update runs before it.
func HelperRules() []helperschema.Rule {
	portal := []helperschema.Invoker{helperschema.Portal}
	return []helperschema.Rule{
		{Subcommand: "status", Invokers: portal},
		{Subcommand: "update", Mutating: true, Invokers: portal},
		{Subcommand: "recover", Mutating: true, Invokers: portal},
	}
}

// Descriptors are composed only from the trusted owner's sealed native plan.
// Native preparation and artifact delivery precede catalog composition; task
// planning never fetches packages, prepares files or changes the host. Existing
// Description/Enum lets the CLI fill the fixed digest without operator fields.
func Descriptors(p Plan) []hostops.Descriptor {
	if p.seal == "" || p.seal != p.Digest || p.digest() != p.seal {
		return nil
	}
	var out []hostops.Descriptor
	for _, op := range []string{"update", "recover"} {
		from, to, repository := p.From, p.To, p.Repository
		if op == "recover" {
			from, to = to, from
			repository = p.previous.Repository
		}
		out = append(out, hostops.Descriptor{ID: "host-package." + op, Module: "host-package", Verb: op,
			Title: strings.ToUpper(op[:1]) + op[1:] + " host package " + p.Name, Category: "Packages",
			InputSchema:   hostops.InputSchema{Type: "object", Properties: map[string]hostops.InputField{"native_plan": {Type: "string", Enum: []string{p.Digest}}}, Required: []string{"native_plan"}},
			Preconditions: []string{"Current authority for this exact package plan", "Verified retained update and previous RPMs", "Installed version matches this operation's starting version"},
			Consequence:   "Change " + from + " to " + to + "; repository=" + repository + "; recovery_scope=package-version-only. Recovery does not restore configuration, data, scriptlet effects or the system.",
			Confirmation:  "confirm", Modes: []string{"product-up"}, ActVerb: "package", Audience: "appliance-helper:olivares-portal-apt",
			EquivalentCommand: "olivares-appliance host-package " + op + " --plan", OutputSchema: "hostop-v1.schema.json", Surfaces: []string{"web", "cli", "tui"}})
	}
	return out
}

type packageInput struct {
	NativePlan string `json:"native_plan"`
}

// PackageRequest carries the retained native plan's identity, not artifacts,
// repository choices or a path. Only a read-only status may omit the digest to
// discover this native owner's retained plan. The protected consumer must bind acts to
// the authorized descriptor, packages target, actor/confirmation and operation.
type PackageRequest struct {
	Op          string `json:"op"`
	OperationID string `json:"operation_id"`
	NativePlan  string `json:"native_plan"`
}

func (r *PackageRequest) Subcommand() string { return r.Op }
func (r *PackageRequest) Operation() string  { return r.OperationID }
func validHex(s string, n int) bool {
	_, err := hex.DecodeString(s)
	return err == nil && len(s) == n && strings.ToLower(s) == s
}
func (r *PackageRequest) Validate() error {
	if r == nil || (!validHex(r.NativePlan, 64) && (r.Op != "status" || r.NativePlan != "")) || !slices.Contains([]string{"status", "update", "recover"}, r.Op) || (r.Op == "status" && r.OperationID != "") || (r.Op != "status" && !validHex(r.OperationID, 32)) {
		return &helperschema.InputError{Field: "$", Reason: "a fixed package operation and retained native plan are required"}
	}
	return nil
}

// PackageStatus is the existing protected native status answer. Its descriptors
// come only from the sealed plan Load verified, never from public Plan fields.
// The portal can compose its catalog without opening the private RPM directory.
type PackageStatus struct {
	Name, Repository, From, To, RecoveryScope, Digest, Installed string
	PreviousRepository                                           string
	Descriptors                                                  []hostops.Descriptor
}
type packageResult struct {
	OperationID string              `json:"operation_id"`
	Op          string              `json:"op"`
	Target      string              `json:"target"`
	NativePlan  string              `json:"native_plan"`
	Observation hostops.Observation `json:"observation"`
}

// PackageAnswer serves the trusted owner's single retained native directory.
// This is an uninstalled producer; caller-supplied paths or artifacts never
// select it. Apply/Recover still validate all retained inputs and the exact
// installed version immediately before one native replay.
func PackageAnswer(ctx context.Context, x RPM, r *PackageRequest) helperschema.Response {
	refused := helperschema.Response{Result: helperschema.ResultRefused, Code: helperschema.CodeInputRefused}
	if r.Validate() != nil {
		return refused
	}
	p, err := x.Load(ctx)
	if err != nil || r.NativePlan != "" && p.Digest != r.NativePlan {
		return refused
	}
	if r.Op == "status" {
		installed, err := x.installed(ctx, p.Name)
		if err != nil {
			return helperschema.Response{Result: helperschema.ResultFailed, Code: helperschema.CodeEffectFailed}
		}
		body, _ := json.Marshal(PackageStatus{
			Name: p.Name, Repository: p.Repository, From: p.From, To: p.To,
			RecoveryScope: p.RecoveryScope, Digest: p.Digest, Installed: installed,
			PreviousRepository: p.previous.Repository, Descriptors: Descriptors(p),
		})
		return helperschema.Response{Result: helperschema.ResultAnswered, Bundle: body}
	}
	var observation hostops.Observation
	if r.Op == "update" {
		observation, _ = x.Apply(ctx, p)
	} else {
		observation, _ = x.Recover(ctx, p)
	}
	if observation.P1 == "not-performed" {
		return refused
	}
	if observation.Postconditions == nil {
		observation.Postconditions = []string{}
	}
	body, _ := json.Marshal(packageResult{r.OperationID, r.Op, "packages", p.Digest, observation})
	result := helperschema.ResultPerformed
	if observation.P1 == "failed" {
		result = helperschema.ResultFailed
	}
	return helperschema.Response{Result: result, Bundle: body}
}

type HelperCaller interface {
	Call(context.Context, string, helperschema.Request) (helperschema.Response, error)
}

// PackageTask uses existing Acts authority, confirmation, audit and durable ID
// retrieval. All package work shares the existing packages target lock, so an
// unknown update cannot be bypassed by a recovery or another selected package.
type PackageTask struct {
	Op     string
	Helper HelperCaller
}

func (x PackageTask) state(ctx context.Context, input json.RawMessage) (PackageStatus, error) {
	var value packageInput
	if hostops.DecodeClosed(input, &value) != nil || !validHex(value.NativePlan, 64) || !slices.Contains([]string{"update", "recover"}, x.Op) {
		return PackageStatus{}, errors.New("input_refused")
	}
	if x.Helper == nil || ctx.Err() != nil {
		return PackageStatus{}, errors.New("consumer_unavailable")
	}
	answer, err := x.Helper.Call(ctx, HelperName, &PackageRequest{Op: "status", NativePlan: value.NativePlan})
	var p PackageStatus
	if err != nil || answer.Result != helperschema.ResultAnswered || hostops.DecodeClosed(answer.Bundle, &p) != nil || p.Digest != value.NativePlan || p.RecoveryScope != "package-version-only" || !validArtifact(Artifact{p.Name, p.From, p.Repository, p.Digest}) || !validArtifact(Artifact{p.Name, p.To, p.Repository, p.Digest}) || arch(p.From) != arch(p.To) || p.From == p.To || (x.Op == "update" && p.Installed != p.From) || (x.Op == "recover" && p.Installed != p.To) {
		return PackageStatus{}, errors.New("package_plan_unavailable")
	}
	return p, nil
}
func (x PackageTask) Prepare(ctx context.Context, input json.RawMessage) (string, error) {
	if _, err := x.state(ctx, input); err != nil {
		return "", err
	}
	return "packages", nil
}
func (x PackageTask) Apply(ctx context.Context, cmd hostops.Command, input json.RawMessage) hostops.Observation {
	if cmd.Module != "host-package" || cmd.Verb != x.Op || cmd.TaskID != "host-package."+x.Op || cmd.Target != "packages" {
		return hostops.Observation{P1: "not-performed"}
	}
	p, err := x.state(ctx, input)
	r := &PackageRequest{Op: x.Op, OperationID: cmd.OperationID, NativePlan: p.Digest}
	if err != nil || r.Validate() != nil {
		return hostops.Observation{P1: "not-performed"}
	}
	answer, err := x.Helper.Call(ctx, HelperName, r)
	if err != nil {
		return hostops.Observation{P1: "unknown"}
	}
	if answer.Result == helperschema.ResultRefused && len(answer.Bundle) == 0 {
		return hostops.Observation{P1: "not-performed"}
	}
	var result packageResult
	if hostops.DecodeClosed(answer.Bundle, &result) != nil || result.OperationID != cmd.OperationID || result.Op != x.Op || result.Target != cmd.Target || result.NativePlan != p.Digest || result.Observation.PendingEffect {
		return hostops.Observation{P1: "unknown"}
	}
	obs := result.Observation
	if answer.Result == helperschema.ResultPerformed {
		if !slices.Contains([]string{"performed", "partial", "unknown"}, obs.P1) {
			return hostops.Observation{P1: "unknown"}
		}
	} else if answer.Result != helperschema.ResultFailed || obs.P1 != "failed" {
		return hostops.Observation{P1: "unknown"}
	}
	if obs.P1 == "performed" {
		installed := p.To
		if x.Op == "recover" {
			installed = p.From
		}
		facts := []string{"package=" + p.Name, "installed=" + installed, "recovery_scope=package-version-only"}
		if x.Op == "update" {
			facts = append(facts, "repository="+p.Repository)
		}
		if !obs.MeasuredChange || !obs.RevertDefined || obs.RevertMeasured != (x.Op == "recover") || !slices.Equal(obs.Postconditions, facts) {
			return hostops.Observation{P1: "unknown"}
		}
	} else if obs.RevertDefined || obs.RevertMeasured {
		return hostops.Observation{P1: "unknown"}
	}
	return obs
}
