// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package storage

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"

	"github.com/olivaresai/olivares/appliance/layer/helpers/helperschema"
	"github.com/olivaresai/olivares/appliance/layer/hostops"
)

// ActionRequest is an identity-bound effect, never a caller path. The installed
// helper keeps inventory reads as a separate closed alternative.
type ActionRequest struct {
	Op          string   `json:"op"`
	OperationID string   `json:"operation_id,omitempty"`
	Identity    Identity `json:"identity,omitempty"`
}

func (r *ActionRequest) Subcommand() string { return r.Op }
func (r *ActionRequest) Operation() string  { return r.OperationID }
func (r *ActionRequest) Validate() error {
	if r.Op == "backup" || r.Op == "grow" {
		id := r.Identity
		if isHex(r.OperationID, 32) && id.Kind != "" && id.Missing == "" && !id.Ambiguous && isHex(id.Digest, 64) && digestOf(id) == id.Digest {
			data, err := json.Marshal(r)
			if err != nil || len(data) > helperschema.MaxDocument {
				return &helperschema.InputError{Field: "$", Reason: "document exceeds helper bound"}
			}
			return nil
		}
	}
	return &helperschema.InputError{Field: "$", Reason: "expected an identity-bound backup or grow operation"}
}

type actionResult struct {
	OperationID    string              `json:"operation_id"`
	Op             string              `json:"op"`
	IdentityDigest string              `json:"identity_digest"`
	Observation    hostops.Observation `json:"observation"`
}

// ActionAnswer reports the executor's measured outcome. Admission is owned by
// the installed helper seam; product authority and audit precede the call.
func ActionAnswer(ctx context.Context, x ActionExecutor, r *ActionRequest) helperschema.Response {
	if r.Validate() != nil || r.Op == SubcommandInventory {
		return helperschema.Response{Result: helperschema.ResultRefused, Code: CodeInputRefused}
	}
	obs, applyErr := x.Apply(ctx, r.Op, r.Identity)
	if applyErr != nil {
		// Keep native diagnostics in the helper journal; its bounded response
		// carries only the measured outcome, never native error details.
		slog.ErrorContext(ctx, "storage action failed", "op", r.Op, "operation_id", r.OperationID, "outcome", obs.P1, "error", applyErr)
	}
	if obs.P1 == "not-performed" {
		return helperschema.Response{Result: helperschema.ResultRefused, Code: CodeInputRefused}
	}
	if obs.Postconditions == nil {
		obs.Postconditions = []string{}
	}
	data, err := json.Marshal(actionResult{r.OperationID, r.Op, r.Identity.Digest, obs})
	if err != nil {
		return helperschema.Response{Result: helperschema.ResultFailed, Code: helperschema.CodeEffectFailed}
	}
	result := helperschema.ResultPerformed
	if obs.P1 == "failed" {
		result = helperschema.ResultFailed
	}
	return helperschema.Response{Result: result, Bundle: data}
}

// ActionTask adopts these two effects into the existing durable Acts engine.
// The web owner additionally commits a successful backup mount as the existing
// backup schedule's target before presenting the complete workflow as success.
type ActionTask struct {
	Op   string
	Call CallFunc
}

func (x ActionTask) disk(ctx context.Context, input json.RawMessage) (Disk, error) {
	var value struct {
		DiskDigest string `json:"disk_digest"`
	}
	if x.Call == nil || ctx.Err() != nil || hostops.DecodeClosed(input, &value) != nil || !isHex(value.DiskDigest, 64) {
		return Disk{}, errors.New(CodeInputRefused)
	}
	inv, err := HelperReader(x.Call)(ctx)
	if err != nil {
		return Disk{}, err
	}
	return SelectAction(inv, x.Op, value.DiskDigest)
}
func (x ActionTask) Prepare(ctx context.Context, input json.RawMessage) (string, error) {
	disk, err := x.disk(ctx, input)
	if err != nil {
		return "", err
	}
	if (&ActionRequest{Op: x.Op, OperationID: strings.Repeat("0", 32), Identity: disk.Identity}).Validate() != nil {
		return "", errors.New(CodeInputRefused)
	}
	return "drive:" + disk.Identity.Digest, nil
}
func (x ActionTask) Apply(ctx context.Context, cmd hostops.Command, input json.RawMessage) hostops.Observation {
	d, err := x.disk(ctx, input)
	if err != nil || cmd.Module != "storage" || cmd.Verb != x.Op || cmd.TaskID != "storage."+x.Op || cmd.Target != "drive:"+d.Identity.Digest {
		return hostops.Observation{P1: "not-performed"}
	}
	req := &ActionRequest{Op: x.Op, OperationID: cmd.OperationID, Identity: d.Identity}
	if req.Validate() != nil {
		return hostops.Observation{P1: "not-performed"}
	}
	response, err := x.Call(ctx, HelperName, req)
	if err != nil {
		return hostops.Observation{P1: "unknown"}
	}
	if response.Result == helperschema.ResultRefused && len(response.Bundle) == 0 {
		return hostops.Observation{P1: "not-performed"}
	}
	var result actionResult
	if hostops.DecodeClosed(response.Bundle, &result) != nil || result.OperationID != cmd.OperationID || result.Op != x.Op || result.IdentityDigest != d.Identity.Digest || result.Observation.RevertDefined || result.Observation.RevertMeasured || result.Observation.PendingEffect {
		return hostops.Observation{P1: "unknown"}
	}
	if response.Result == helperschema.ResultFailed && result.Observation.P1 == "failed" {
		return result.Observation
	}
	if response.Result == helperschema.ResultPerformed && (result.Observation.P1 == "performed" || result.Observation.P1 == "partial" || result.Observation.P1 == "unknown") {
		return result.Observation
	}
	return hostops.Observation{P1: "unknown"}
}

// HelperRequest is the installed closed union; its pointer fields preserve
// omission so the inventory alternative remains exactly one op field.
type HelperRequest struct {
	Op          string    `json:"op"`
	OperationID *string   `json:"operation_id,omitempty"`
	Identity    *Identity `json:"identity,omitempty"`
}

func (r *HelperRequest) Subcommand() string { return r.Op }
func (r *HelperRequest) Operation() string {
	if r.OperationID == nil {
		return ""
	}
	return *r.OperationID
}
func (r *HelperRequest) Validate() error {
	if r.Op == SubcommandInventory && r.OperationID == nil && r.Identity == nil {
		return nil
	}
	if r.Op != SubcommandInventory && r.OperationID != nil && r.Identity != nil {
		return (&ActionRequest{Op: r.Op, OperationID: *r.OperationID, Identity: *r.Identity}).Validate()
	}
	return &helperschema.InputError{Field: "$", Reason: "expected inventory or a complete identity-bound action"}
}
