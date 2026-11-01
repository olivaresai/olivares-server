// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package hostusers

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

// HelperName is the proposed system socket name for the existing system
// audience. No helper, class, account, service or admission is installed here.
const HelperName = "system"

// CreateRequest is the fixed helper document, not an authority statement. The
// protected consumer must bind it to the authorized descriptor, system target,
// actor/confirmation and operation. Home is already filled from the account;
// ExpectedGID is the fresh native read and is rechecked inside the executor.
type CreateRequest struct {
	Op          string `json:"op"`
	OperationID string `json:"operation_id"`
	Request     `json:"request"`
	ExpectedGID string `json:"expected_gid"`
}

func (r *CreateRequest) Subcommand() string { return r.Op }
func (r *CreateRequest) Operation() string  { return r.OperationID }
func validOperation(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil && len(s) == 32 && strings.ToLower(s) == s
}
func userInput(r Request) json.RawMessage { data, _ := json.Marshal(r); return data }
func (r *CreateRequest) Validate() error {
	if r != nil {
		canonical, err := Decode(userInput(r.Request))
		if err == nil && canonical == r.Request && ((r.Op == "status" && r.OperationID == "" && r.ExpectedGID == "") || (r.Op == "create" && validOperation(r.OperationID) && id(r.ExpectedGID))) {
			return nil
		}
	}
	return &helperschema.InputError{Field: "$", Reason: "a fixed user operation and measured primary group are required"}
}

type createStatus struct {
	Request Request `json:"request"`
	GID     string  `json:"gid"`
}
type createResult struct {
	OperationID string              `json:"operation_id"`
	Op          string              `json:"op"`
	Target      string              `json:"target"`
	Request     Request             `json:"request"`
	ExpectedGID string              `json:"expected_gid"`
	Observation hostops.Observation `json:"observation"`
}

// CreateAnswer is the uninstalled native producer for the protected attested
// helper. Portal composition uses CreateTask, never a Linux Host or useradd.
// This function supplies neither authorization nor operation-ID custody.
func CreateAnswer(ctx context.Context, x Provisioner, r *CreateRequest) helperschema.Response {
	refused := helperschema.Response{Result: helperschema.ResultRefused, Code: helperschema.CodeInputRefused}
	if r.Validate() != nil {
		return refused
	}
	if r.Op == "status" {
		gid, err := x.preflight(ctx, r.Request)
		if err != nil || ctx.Err() != nil {
			return refused
		}
		data, _ := json.Marshal(createStatus{r.Request, gid})
		return helperschema.Response{Result: helperschema.ResultAnswered, Bundle: data}
	}
	cmd := hostops.Command{OperationID: r.OperationID, TaskID: "host-user.create", Module: "host-user", Verb: "create", Target: "system"}
	observation := x.apply(ctx, cmd, userInput(r.Request), r.ExpectedGID)
	if observation.P1 == "not-performed" {
		return refused
	}
	if observation.Postconditions == nil {
		observation.Postconditions = []string{}
	}
	data, _ := json.Marshal(createResult{r.OperationID, r.Op, "system", r.Request, r.ExpectedGID, observation})
	return helperschema.Response{Result: helperschema.ResultPerformed, Bundle: data}
}

type HelperCaller interface {
	Call(context.Context, string, helperschema.Request) (helperschema.Response, error)
}

// CreateTask is the portal-side caller for existing Acts authority, confirmation,
// audit, system locking and durable IDs. Read-only status calls precede one
// admitted mutating Call; lost answers remain unknown and are never retried.
type CreateTask struct{ Helper HelperCaller }

func (x CreateTask) state(ctx context.Context, input json.RawMessage) (createStatus, error) {
	r, err := Decode(input)
	if err != nil {
		return createStatus{}, err
	}
	if x.Helper == nil || ctx.Err() != nil {
		return createStatus{}, errors.New("consumer_unavailable")
	}
	answer, err := x.Helper.Call(ctx, HelperName, &CreateRequest{Op: "status", Request: r})
	var status createStatus
	if err != nil || answer.Result != helperschema.ResultAnswered || hostops.DecodeClosed(answer.Bundle, &status) != nil || status.Request != r || !id(status.GID) {
		return createStatus{}, errors.New("host_user_unavailable")
	}
	return status, nil
}
func (x CreateTask) Prepare(ctx context.Context, input json.RawMessage) (string, error) {
	if _, err := x.state(ctx, input); err != nil {
		return "", err
	}
	return "system", nil
}
func (x CreateTask) Apply(ctx context.Context, cmd hostops.Command, input json.RawMessage) hostops.Observation {
	if cmd.Module != "host-user" || cmd.Verb != "create" || cmd.TaskID != "host-user.create" || cmd.Target != "system" {
		return hostops.Observation{P1: "not-performed"}
	}
	status, err := x.state(ctx, input)
	r := &CreateRequest{Op: "create", OperationID: cmd.OperationID, Request: status.Request, ExpectedGID: status.GID}
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
	var result createResult
	if answer.Result != helperschema.ResultPerformed || hostops.DecodeClosed(answer.Bundle, &result) != nil || result.OperationID != cmd.OperationID || result.Op != r.Op || result.Target != cmd.Target || result.Request != r.Request || result.ExpectedGID != r.ExpectedGID || !slices.Contains([]string{"performed", "partial", "unknown"}, result.Observation.P1) || result.Observation.RevertDefined || result.Observation.RevertMeasured || result.Observation.PendingEffect {
		return hostops.Observation{P1: "unknown"}
	}
	if result.Observation.P1 == "performed" && (!result.Observation.MeasuredChange || len(result.Observation.Postconditions) != 2 || result.Observation.Postconditions[0] != "OS account "+r.Account+" has home "+r.Home+" and primary GID "+r.ExpectedGID) {
		return hostops.Observation{P1: "unknown"}
	}
	return result.Observation
}
