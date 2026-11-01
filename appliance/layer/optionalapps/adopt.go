// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package optionalapps

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/olivaresai/olivares/appliance/layer/helpers/helperschema"
	"github.com/olivaresai/olivares/appliance/layer/hostops"
)

// HelperName is the apps helper's socket name: /run/olivares-helpers/apps.sock.
// It is a module helper (helperschema.HelperApps) that admits the Appliance
// Console alone.
const HelperName = helperschema.HelperApps

func manifestDigest() string {
	digest := sha256.Sum256(nginxProxyManager)
	return hex.EncodeToString(digest[:])
}

// The app target stays the same across this pinned lifecycle, so an unknown
// install keeps the existing engine lock even after a container appears. Native
// container identity is freshly captured and checked by the helper, rather than
// changing the app's lock key with every start, stop or container creation.
func appTarget() string { return "app:nginx-proxy-manager" }

// Descriptors are opt-in definitions for the existing host operation catalog.
// No operator supplies an image, folder, port, Docker account or authority flag.
func Descriptors() []hostops.Descriptor {
	var out []hostops.Descriptor
	for _, op := range lifecycleOps {
		out = append(out, hostops.Descriptor{ID: "nginx-proxy-manager." + op, Module: "nginx-proxy-manager", Verb: op,
			Title: strings.ToUpper(op[:1]) + op[1:] + " Nginx Proxy Manager", Category: "Apps",
			InputSchema:   hostops.InputSchema{Type: "object", Properties: map[string]hostops.InputField{}, Required: []string{}},
			Preconditions: []string{"Current authority for this optional app", "Fixed pinned image and private persistent data", "Available published ports before install or start"},
			Consequence:   "Change this optional app's container lifecycle. Uninstall keeps data and certificates. Container state does not prove browser readiness, certificate issuance or a working proxy.",
			Confirmation:  "confirm", Modes: []string{"product-up"}, ActVerb: "app", Audience: "appliance-helper:olivares-portal-apps",
			EquivalentCommand: "olivares-appliance nginx-proxy-manager " + op + " --plan", OutputSchema: "hostop-v1.schema.json", Surfaces: []string{"web", "cli", "tui"}})
	}
	return out
}

// LifecycleRequest is the fixed app helper document. Expected is the latest
// native read, not an authority claim. The protected consumer must bind this
// request to the authorized descriptor, app target, plan and operation ID.
type LifecycleRequest struct {
	Op          string `json:"op"`
	OperationID string `json:"operation_id"`
	Manifest    string `json:"manifest"`
	Expected    State  `json:"expected"`
}

// lifecycleOps are the four acts, in the order the descriptors list them.
var lifecycleOps = []string{"install", "start", "stop", "uninstall"}

func (r *LifecycleRequest) Subcommand() string { return r.Op }
func (r *LifecycleRequest) Operation() string  { return r.OperationID }
func validHex(value string, size int) bool {
	_, err := hex.DecodeString(value)
	return err == nil && len(value) == size && strings.ToLower(value) == value
}
func validState(s State) bool {
	if !s.Installed {
		return s.ContainerID == "" && !s.Running
	}
	return validHex(s.ContainerID, 64)
}
func lifecycleReady(op string, s State) bool {
	switch op {
	case "install":
		return !s.Installed
	case "start":
		return s.Installed && !s.Running
	case "stop":
		return s.Installed && s.Running
	case "uninstall":
		return s.Installed
	}
	return false
}
func (r *LifecycleRequest) Validate() error {
	if r == nil || r.Manifest != manifestDigest() || !validState(r.Expected) || (r.Op == "status" && (r.OperationID != "" || r.Expected != (State{}))) || (r.Op != "status" && (!validHex(r.OperationID, 32) || !lifecycleReady(r.Op, r.Expected))) {
		return &helperschema.InputError{Field: "$", Reason: "a fixed app operation and measured native state are required"}
	}
	return nil
}

type lifecycleStatus struct {
	Manifest string `json:"manifest"`
	State    State  `json:"state"`
}
type lifecycleResult struct {
	OperationID string              `json:"operation_id"`
	Op          string              `json:"op"`
	Target      string              `json:"target"`
	Manifest    string              `json:"manifest"`
	Expected    State               `json:"expected"`
	Observation hostops.Observation `json:"observation"`
}

// LifecycleAnswer is for the authorized attested helper consumer only. It uses
// the same Compose executor; nothing here installs or exposes that consumer.
func LifecycleAnswer(ctx context.Context, x Compose, r *LifecycleRequest) helperschema.Response {
	if r.Validate() != nil {
		return helperschema.Response{Result: helperschema.ResultRefused, Code: helperschema.CodeInputRefused}
	}
	if r.Op == "status" {
		state, err := x.Read(ctx)
		if err != nil {
			return helperschema.Response{Result: helperschema.ResultFailed, Code: helperschema.CodeEffectFailed, Detail: err.Error()}
		}
		data, _ := json.Marshal(lifecycleStatus{manifestDigest(), state})
		return helperschema.Response{Result: helperschema.ResultAnswered, Bundle: data}
	}
	observation, err := x.apply(ctx, r.Op, &r.Expected)
	if observation.P1 == "not-performed" {
		// The reason is one of the executor's fixed tokens, never a value of the request.
		detail := "the act was not performed"
		if err != nil {
			detail = err.Error()
		}
		return helperschema.Response{Result: helperschema.ResultRefused, Code: helperschema.CodeInputRefused, Detail: detail}
	}
	if observation.Postconditions == nil {
		observation.Postconditions = []string{}
	}
	data, _ := json.Marshal(lifecycleResult{r.OperationID, r.Op, appTarget(), r.Manifest, r.Expected, observation})
	result := helperschema.ResultPerformed
	if observation.P1 == "failed" {
		result = helperschema.ResultFailed
	}
	return helperschema.Response{Result: result, Bundle: data}
}

// Rules is the apps helper's admission table: the status read and the four
// lifecycle acts, for the Appliance Console alone. The tty1 repair console has
// no optional-app route.
func Rules() []helperschema.Rule {
	rules := []helperschema.Rule{{Subcommand: "status", Invokers: []helperschema.Invoker{helperschema.Portal}}}
	for _, op := range lifecycleOps {
		rules = append(rules, helperschema.Rule{Subcommand: op, Mutating: true, Invokers: []helperschema.Invoker{helperschema.Portal}})
	}
	return rules
}

type HelperCaller interface {
	Call(context.Context, string, helperschema.Request) (helperschema.Response, error)
}

// LifecycleTask adopts the fixed lifecycle into Acts, which retains authority,
// confirmation, target locking, audit and durable ID retrieval. The portal uses
// its attested helper client, never Docker or the native Compose executor.
type LifecycleTask struct {
	Op     string
	Helper HelperCaller
}

func (x LifecycleTask) state(ctx context.Context, input json.RawMessage) (State, error) {
	var empty struct{}
	if hostops.DecodeClosed(input, &empty) != nil || !slices.Contains(lifecycleOps, x.Op) {
		return State{}, errors.New("input_refused")
	}
	if x.Helper == nil || ctx.Err() != nil {
		return State{}, errors.New("consumer_unavailable")
	}
	answer, err := x.Helper.Call(ctx, HelperName, &LifecycleRequest{Op: "status", Manifest: manifestDigest()})
	var result lifecycleStatus
	if err != nil || answer.Result != helperschema.ResultAnswered || hostops.DecodeClosed(answer.Bundle, &result) != nil || result.Manifest != manifestDigest() || !validState(result.State) || !lifecycleReady(x.Op, result.State) {
		return State{}, errors.New("optional_app_unavailable")
	}
	return result.State, nil
}
func (x LifecycleTask) Prepare(ctx context.Context, input json.RawMessage) (string, error) {
	if _, err := x.state(ctx, input); err != nil {
		return "", err
	}
	return appTarget(), nil
}
func (x LifecycleTask) Apply(ctx context.Context, cmd hostops.Command, input json.RawMessage) hostops.Observation {
	if cmd.Module != "nginx-proxy-manager" || cmd.Verb != x.Op || cmd.TaskID != "nginx-proxy-manager."+x.Op || cmd.Target != appTarget() {
		return hostops.Observation{P1: "not-performed"}
	}
	state, err := x.state(ctx, input)
	request := &LifecycleRequest{Op: x.Op, OperationID: cmd.OperationID, Manifest: manifestDigest(), Expected: state}
	if err != nil || request.Validate() != nil {
		return hostops.Observation{P1: "not-performed"}
	}
	answer, err := x.Helper.Call(ctx, HelperName, request)
	if err != nil {
		return hostops.Observation{P1: "unknown"}
	}
	if answer.Result == helperschema.ResultRefused && len(answer.Bundle) == 0 {
		return hostops.Observation{P1: "not-performed"}
	}
	var result lifecycleResult
	if hostops.DecodeClosed(answer.Bundle, &result) != nil || result.OperationID != cmd.OperationID || result.Op != x.Op || result.Target != cmd.Target || result.Manifest != request.Manifest || result.Expected != state || result.Observation.RevertDefined || result.Observation.RevertMeasured || result.Observation.PendingEffect {
		return hostops.Observation{P1: "unknown"}
	}
	if answer.Result == helperschema.ResultPerformed {
		if !slices.Contains([]string{"performed", "partial", "unknown"}, result.Observation.P1) {
			return hostops.Observation{P1: "unknown"}
		}
	} else if answer.Result != helperschema.ResultFailed || result.Observation.P1 != "failed" {
		return hostops.Observation{P1: "unknown"}
	}
	return result.Observation
}
