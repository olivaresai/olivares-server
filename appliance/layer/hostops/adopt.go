// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package hostops

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
)

// ApplyRequest carries intent and confirmation, never the caller's authority.
type ApplyRequest struct {
	OperationID  string          `json:"operation_id"`
	Module       string          `json:"module"`
	Verb         string          `json:"verb"`
	Surface      string          `json:"surface"`
	Inputs       json.RawMessage `json:"inputs"`
	Confirmation string          `json:"confirmation"`
}

// Caller is the current identity and mode returned by the owning authority.
type Caller struct{ Actor, Mode string }

// Authority binds the current identity to this exact task, target and plan.
// An OS-admitted local connection alone is never an implementation of Authority.
type Authority interface {
	Authorize(context.Context, Descriptor, string, string) (Caller, error)
}

// AdoptedTask is a module owner's validated operation. Prepare changes nothing.
// Apply measures the effect; an uncertain effect must return unknown or partial.
type AdoptedTask interface {
	Prepare(context.Context, json.RawMessage) (string, error)
	Apply(context.Context, Command, json.RawMessage) Observation
}

// ActEvent correlates a decision or outcome with the existing operation record.
type ActEvent struct {
	Caller                                                Caller
	OperationID, TaskID, Target, Digest, Surface, Outcome string
}
type ActAudit interface{ Append(ActEvent) error }

// Acts adopts module effects into the existing operation engine. Missing owners,
// authority or audit keep apply unavailable. It owns no second operation ledger.
type Acts struct {
	engine  *Engine
	catalog *Catalog
	tasks   map[string]AdoptedTask
	audit   ActAudit
}

func NewActs(engine *Engine, catalog *Catalog, tasks map[string]AdoptedTask, audit ActAudit) *Acts {
	copy := make(map[string]AdoptedTask, len(tasks))
	for id, task := range tasks {
		copy[id] = task
	}
	return &Acts{engine: engine, catalog: catalog, tasks: copy, audit: audit}
}

// Adopts reports composition only, never authority. Unadopted read and plan
// tasks keep their existing behavior when another module adopts an effect.
func (s *Acts) Adopts(module, verb string) bool {
	if s == nil || s.catalog == nil || s.engine == nil || s.audit == nil {
		return false
	}
	d, err := s.catalog.Describe(module, verb, "cli")
	return err == nil && d.Confirmation != "none" && s.tasks[d.ID] != nil
}

func (s *Acts) prepare(ctx context.Context, module, verb, surface string, inputs json.RawMessage, target string) (Descriptor, AdoptedTask, string, string, error) {
	if s == nil || s.engine == nil || s.catalog == nil || s.audit == nil {
		return Descriptor{}, nil, "", "", errors.New("act_not_adopted")
	}
	d, err := s.catalog.Describe(module, verb, surface)
	if err != nil || d.Confirmation == "none" || d.ValidateInput(inputs) != nil {
		return Descriptor{}, nil, "", "", refuse("inputs")
	}
	t := s.tasks[d.ID]
	if t == nil {
		return Descriptor{}, nil, "", "", errors.New("act_not_adopted")
	}
	// Decode into scalar values so whitespace, key order and string escapes have
	// one canonical digest. Integer decoding preserves integer precision.
	var values map[string]json.RawMessage
	if DecodeClosed(inputs, &values) != nil {
		return Descriptor{}, nil, "", "", refuse("inputs")
	}
	canonical := make(map[string]any, len(values))
	for k, v := range values {
		switch d.InputSchema.Properties[k].Type {
		case "string":
			var text string
			_ = json.Unmarshal(v, &text)
			canonical[k] = text
		case "boolean":
			var b bool
			_ = json.Unmarshal(v, &b)
			canonical[k] = b
		case "integer":
			var n int64
			_ = json.Unmarshal(v, &n)
			canonical[k] = n
		}
	}
	body, _ := json.Marshal(canonical)
	if target == "" {
		target, err = t.Prepare(ctx, body)
		if err != nil {
			return Descriptor{}, nil, "", "", refuse("inputs")
		}
	}
	if !validTarget(target) {
		return Descriptor{}, nil, "", "", refuse("inputs")
	}
	data, _ := json.Marshal(struct {
		Task, Target, Verb, Audience string
		Inputs                       json.RawMessage
	}{d.ID, target, d.ActVerb, d.Audience, body})
	hash := sha256.Sum256(data)
	return d, t, target, hex.EncodeToString(hash[:]), nil
}

// Plan checks current authority without recording or executing an operation.
func (s *Acts) Plan(ctx context.Context, module, verb, surface string, inputs json.RawMessage, authority Authority) (Plan, error) {
	d, _, target, digest, err := s.prepare(ctx, module, verb, surface, inputs, "")
	if err != nil {
		return Plan{}, err
	}
	p := Plan{Descriptor: d, Inputs: inputs, Digest: digest, Permissions: ReadOnlyAccess{}.Permissions(Record{})}
	if authority == nil {
		return p, nil
	}
	caller, err := authority.Authorize(ctx, d, target, digest)
	if err == nil && validCaller(caller, d) {
		p.Digest = confirmationDigest(caller, digest)
		p.Permissions = Permissions{Read: true, Plan: true, Apply: true}
	} else {
		p.Permissions.Code = "mode_refused"
	}
	return p, nil
}

// Confirmation belongs to the identity that reviewed the plan. A different
// authorized operator must review and confirm their own plan.
func confirmationDigest(c Caller, intent string) string {
	data, _ := json.Marshal(struct{ Actor, Mode, Intent string }{c.Actor, c.Mode, intent})
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func validCaller(c Caller, d Descriptor) bool {
	return validActor(c.Actor) && oneOf(c.Mode, "product-up", "product-down-repair", "tty1", "timer", "guard") && slices.Contains(d.Modes, c.Mode)
}

// Apply persists admission before the effect, never retries, and reads the final
// record after measuring. A repeated ID is retrieval through Engine.Submit.
func (s *Acts) Apply(ctx context.Context, r ApplyRequest, authority Authority) (Record, int, error) {
	if !isHex(r.OperationID, 32) {
		return Record{}, 422, refuse("operation_id")
	}
	if authority == nil {
		return Record{}, 503, errors.New("act_not_adopted")
	}
	if s == nil || s.engine == nil {
		return Record{}, 503, errors.New("act_not_adopted")
	}
	// A repeated ID is retrieval, even if the effect changed the preconditions.
	// Unreadable state is never treated as an absent ID eligible for a retry.
	existingTarget := ""
	if old, _, err := s.engine.Get(r.OperationID); err == nil {
		existingTarget = old.Target
	} else if !errors.Is(err, ErrNoSuchOperation) {
		return Record{}, 503, errors.New("consumer_unavailable")
	}
	d, task, target, digest, err := s.prepare(ctx, r.Module, r.Verb, r.Surface, r.Inputs, existingTarget)
	if err != nil {
		return Record{}, 422, err
	}
	caller, authErr := authority.Authorize(ctx, d, target, digest)
	digest = confirmationDigest(caller, digest)
	event := ActEvent{Caller: caller, OperationID: r.OperationID, TaskID: d.ID, Target: target, Digest: digest, Surface: r.Surface, Outcome: "refused"}
	if authErr != nil || !validCaller(caller, d) || r.Confirmation != digest {
		if err := s.audit.Append(event); err != nil {
			return Record{}, 503, errors.New("consumer_unavailable")
		}
		return Record{}, 403, errors.New("mode_refused")
	}
	if ctx.Err() != nil {
		return Record{}, 503, errors.New("consumer_unavailable")
	}
	event.Outcome = "authorized"
	if err := s.audit.Append(event); err != nil {
		return Record{}, 503, errors.New("consumer_unavailable")
	}
	cmd := Command{OperationID: r.OperationID, TaskID: d.ID, Module: r.Module, Verb: r.Verb, Target: target, PlanDigest: digest, Mode: caller.Mode, Surface: r.Surface, Actor: caller.Actor}
	rec, status, err := s.engine.Submit(cmd, func() error {
		obs := task.Apply(ctx, cmd, r.Inputs)
		event.Outcome = obs.P1
		if auditErr := s.audit.Append(event); auditErr != nil {
			// The admission is durable, but the outcome cannot be published as
			// complete without its audit. Keep the native running/unknown record.
			return nil
		}
		_, _ = s.engine.Recover(r.OperationID, obs)
		return nil
	})
	if err != nil {
		return Record{}, status, err
	}
	if current, currentStatus, err := s.engine.Get(r.OperationID); err == nil {
		return current, currentStatus, nil
	}
	// A failed post-effect read cannot turn an admitted act into a refusal.
	// The last durable projection remains available for explicit status lookup.
	return rec, status, nil
}
