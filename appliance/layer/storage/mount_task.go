// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package storage

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/olivaresai/olivares/appliance/layer/helpers/helperschema"
	"github.com/olivaresai/olivares/appliance/layer/hostops"
)

// MountDescriptors are additive. The installed catalog and inventory-only helper
// remain unchanged until their protected consumer and product authority are composed.
func MountDescriptors() []hostops.Descriptor {
	var descriptors []hostops.Descriptor
	for _, op := range []string{"mount", "unmount"} {
		descriptors = append(descriptors, hostops.Descriptor{ID: "storage." + op, Module: "storage", Verb: op, Title: strings.ToUpper(op[:1]) + op[1:] + " a data filesystem", Category: "Storage",
			InputSchema:   hostops.InputSchema{Type: "object", Properties: map[string]hostops.InputField{"filesystem_uuid": {Type: "string"}}, Required: []string{"filesystem_uuid"}},
			Preconditions: []string{"Current storage authority for this filesystem", "Unchanged inventory-issued disk identity", "Non-system, unconfigured volume without another consumer"},
			Consequence:   "Change only this data filesystem's mount state. No format or fstab change; a busy unmount refuses without force. Success requires a fresh measured mount state.",
			Confirmation:  "confirm", Modes: []string{"product-up"}, ActVerb: "storage", Audience: "appliance-helper:olivares-portal-storage", EquivalentCommand: "olivares-appliance storage " + op + " <filesystem-uuid> --plan", OutputSchema: "hostop-v1.schema.json", Surfaces: []string{"web", "cli", "tui"}})
	}
	return descriptors
}

// MountRequest is the fixed storage helper document. Identity comes from the
// inventory; no caller path, force option, actor or authority claim is accepted.
type MountRequest struct {
	Op             string   `json:"op"`
	OperationID    string   `json:"operation_id"`
	Identity       Identity `json:"identity"`
	FilesystemUUID string   `json:"filesystem_uuid"`
}

func (r *MountRequest) Subcommand() string { return r.Op }
func (r *MountRequest) Operation() string  { return r.OperationID }
func (r *MountRequest) Validate() error {
	if r.Op != "mount" && r.Op != "unmount" {
		return &helperschema.InputError{Field: "$.op", Reason: "expected mount or unmount"}
	}
	if !isHex(r.OperationID, 32) || !isUUID(r.FilesystemUUID) {
		return &helperschema.InputError{Field: "$", Reason: "an operation ID and exact filesystem UUID are required"}
	}
	if r.Identity.Kind == "" || r.Identity.Missing != "" || r.Identity.Ambiguous || !isHex(r.Identity.Digest, 64) || digestOf(r.Identity) != r.Identity.Digest {
		return &helperschema.InputError{Field: "$.identity", Reason: "an inventory-issued disk identity is required"}
	}
	data, err := json.Marshal(r)
	if err != nil || len(data) > helperschema.MaxDocument {
		return &helperschema.InputError{Field: "$", Reason: "the document exceeds the helper bound"}
	}
	return nil
}

type mountResult struct {
	OperationID    string              `json:"operation_id"`
	Op             string              `json:"op"`
	IdentityDigest string              `json:"identity_digest"`
	FilesystemUUID string              `json:"filesystem_uuid"`
	Observation    hostops.Observation `json:"observation"`
}

// MountAnswer is for the protected helper consumer, which must authorize before
// calling it. The installed helper does not expose it or add an admission rule.
func MountAnswer(ctx context.Context, x MountExecutor, r *MountRequest) helperschema.Response {
	if r.Validate() != nil {
		return helperschema.Response{Result: helperschema.ResultRefused, Code: CodeInputRefused}
	}
	observation, _ := x.Apply(ctx, r.Op, r.Identity, r.FilesystemUUID)
	if observation.P1 == "not-performed" {
		return helperschema.Response{Result: helperschema.ResultRefused, Code: CodeInputRefused}
	}
	if observation.Postconditions == nil {
		observation.Postconditions = []string{}
	}
	data, err := json.Marshal(mountResult{r.OperationID, r.Op, r.Identity.Digest, r.FilesystemUUID, observation})
	if err != nil {
		return helperschema.Response{Result: helperschema.ResultFailed, Code: helperschema.CodeEffectFailed}
	}
	result := helperschema.ResultPerformed
	if observation.P1 == "failed" {
		result = helperschema.ResultFailed
	}
	return helperschema.Response{Result: result, Bundle: data}
}

// MountTask adopts a fixed mount/unmount descriptor into the existing Acts path.
// Call is the native attested helper client; it never opens a portal-side bus.
type MountTask struct {
	Op   string
	Call CallFunc
}

func (x MountTask) volume(ctx context.Context, input json.RawMessage) (Identity, string, error) {
	var value struct {
		FilesystemUUID string `json:"filesystem_uuid"`
	}
	if x.Call == nil || (x.Op != "mount" && x.Op != "unmount") || ctx.Err() != nil {
		return Identity{}, "", errors.New("consumer_unavailable")
	}
	if hostops.DecodeClosed(input, &value) != nil || !isUUID(value.FilesystemUUID) {
		return Identity{}, "", errors.New(CodeInputRefused)
	}
	inventory, err := HelperReader(x.Call)(ctx)
	if err != nil {
		return Identity{}, "", err
	}
	disk, err := mountDisk(inventory, value.FilesystemUUID)
	if err != nil {
		return Identity{}, "", err
	}
	_, fs, consumers, err := mountVolume(disk, value.FilesystemUUID)
	if err != nil {
		return Identity{}, "", err
	}
	if disk.System {
		return Identity{}, "", errors.New(CodeSystemDisk)
	}
	for _, consumer := range consumers {
		if x.Op == "mount" || consumer.Kind != ConsumerMount {
			return Identity{}, "", errors.New(CodeTargetInUse)
		}
	}
	if len(fs.MountPoints) > 1 || (x.Op == "mount" && len(fs.MountPoints) != 0) || (x.Op == "unmount" && len(fs.MountPoints) != 1) {
		return Identity{}, "", errors.New(CodeTargetInUse)
	}
	if _, err := Reresolve(disk.Identity, inventory); err != nil {
		return Identity{}, "", err
	}
	return disk.Identity, value.FilesystemUUID, nil
}
func (x MountTask) Prepare(ctx context.Context, input json.RawMessage) (string, error) {
	identity, uuid, err := x.volume(ctx, input)
	if err != nil {
		return "", err
	}
	if (&MountRequest{Op: x.Op, OperationID: strings.Repeat("0", 32), Identity: identity, FilesystemUUID: uuid}).Validate() != nil {
		return "", errors.New(CodeInputRefused)
	}
	return "drive:" + identity.Digest, nil
}
func (x MountTask) Apply(ctx context.Context, cmd hostops.Command, input json.RawMessage) hostops.Observation {
	identity, uuid, err := x.volume(ctx, input)
	if err != nil || cmd.Module != "storage" || cmd.Verb != x.Op || cmd.TaskID != "storage."+x.Op || cmd.Target != "drive:"+identity.Digest {
		return hostops.Observation{P1: "not-performed"}
	}
	request := &MountRequest{Op: x.Op, OperationID: cmd.OperationID, Identity: identity, FilesystemUUID: uuid}
	if request.Validate() != nil {
		return hostops.Observation{P1: "not-performed"}
	}
	response, err := x.Call(ctx, HelperName, request)
	if err != nil {
		return hostops.Observation{P1: "unknown"}
	}
	if response.Result == helperschema.ResultRefused && len(response.Bundle) == 0 {
		return hostops.Observation{P1: "not-performed"}
	}
	var result mountResult
	if hostops.DecodeClosed(response.Bundle, &result) != nil || result.OperationID != cmd.OperationID || result.Op != x.Op || result.IdentityDigest != identity.Digest || result.FilesystemUUID != uuid || result.Observation.RevertDefined || result.Observation.RevertMeasured || result.Observation.PendingEffect {
		return hostops.Observation{P1: "unknown"}
	}
	switch response.Result {
	case helperschema.ResultPerformed:
		if result.Observation.P1 != "performed" && result.Observation.P1 != "partial" && result.Observation.P1 != "unknown" {
			return hostops.Observation{P1: "unknown"}
		}
	case helperschema.ResultFailed:
		if result.Observation.P1 != "failed" {
			return hostops.Observation{P1: "unknown"}
		}
	default:
		return hostops.Observation{P1: "unknown"}
	}
	return result.Observation
}
