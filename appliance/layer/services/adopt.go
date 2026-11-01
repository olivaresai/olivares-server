// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package services

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/olivaresai/olivares/appliance/layer/helpers/helperschema"
	"github.com/olivaresai/olivares/appliance/layer/hostops"
)

// HelperCaller is the existing privileged-helper client. A caller cannot replace
// the units helper's act authorization, admission or durable effect receipt.
type HelperCaller interface {
	Call(context.Context, string, helperschema.Request) (helperschema.Response, error)
}

// UnitTask adopts one act of the services module: an effect (start, stop, restart, reload, enable,
// disable) or logs. Each verb is its own task, so each has its own act authorization, plan digest
// and durable receipt. The portal supplies its fixed helper client, never a direct systemd bus or a
// shell runner. Missing helper composition stays unavailable, and a sent request with no verified
// answer stays unknown.
type UnitTask struct {
	Op     string
	Helper HelperCaller
	// Hold keeps the entries a logs act read until the console that asked collects them. A logs
	// task without one is unavailable: it would read the journal for nobody.
	Hold *LogHold
}

// unitInput reads the closed input of op: the unit, and for logs alone the line count, 100 when
// not given. The class table must admit op for the unit.
func unitInput(op string, input json.RawMessage) (unit string, lines int, err error) {
	var value struct {
		Unit  string `json:"unit"`
		Lines *int   `json:"lines"`
	}
	if hostops.DecodeClosed(input, &value) != nil || Check(op, value.Unit) != nil || value.Lines != nil && op != OpLogs {
		return "", 0, errors.New(CodeInputRefused)
	}
	lines = DefaultLogLines
	if value.Lines != nil {
		lines = *value.Lines
	}
	if lines < 1 || lines > MaxLogLines {
		return "", 0, errors.New(CodeInputRefused)
	}
	return value.Unit, lines, nil
}

// Prepare reads through the existing helper and changes no unit. Inventory and
// the native class table must both admit this exact unit before it is planned.
func (x UnitTask) Prepare(ctx context.Context, input json.RawMessage) (string, error) {
	if !IsAct(x.Op) {
		return "", errors.New(CodeInputRefused)
	}
	unit, _, err := unitInput(x.Op, input)
	if err != nil {
		return "", err
	}
	if x.Helper == nil || x.Op == OpLogs && x.Hold == nil || ctx.Err() != nil {
		return "", errors.New("consumer_unavailable")
	}
	response, err := x.Helper.Call(ctx, HelperName, &Request{Op: OpStatus, Unit: unit})
	var status Status
	if err != nil || response.Result != helperschema.ResultAnswered || hostops.DecodeClosed(response.Bundle, &status) != nil || status.Unit != unit || status.Class != Classify(unit) || !status.State.Measured {
		return "", errors.New("unit_unavailable")
	}
	return "unit:" + unit, nil
}

// Apply sends the native operation ID exactly once. A helper refusal performs
// nothing; otherwise the existing service result owns the observation. An active
// unit alone cannot prove a restart whose JobRemoved signal was not received.
func (x UnitTask) Apply(ctx context.Context, cmd hostops.Command, input json.RawMessage) hostops.Observation {
	unit, lines, err := unitInput(x.Op, input)
	request := &Request{Op: x.Op, Unit: unit, OperationID: cmd.OperationID}
	if x.Op == OpLogs {
		request.Lines = &lines
	}
	if err != nil || !IsAct(x.Op) || x.Helper == nil || x.Op == OpLogs && x.Hold == nil || ctx.Err() != nil || request.Validate() != nil || cmd.TaskID != Module+"."+x.Op || cmd.Module != Module || cmd.Verb != x.Op || cmd.Target != "unit:"+unit {
		return hostops.Observation{P1: "not-performed"}
	}
	response, err := x.Helper.Call(ctx, HelperName, request)
	if err != nil {
		return hostops.Observation{P1: "unknown"}
	}
	if response.Result == helperschema.ResultRefused && len(response.Bundle) == 0 {
		return hostops.Observation{P1: "not-performed"}
	}
	if x.Op == OpLogs {
		return x.applied(ctx, cmd.OperationID, unit, lines, response)
	}
	var effect struct {
		Result
		Outcome string `json:"outcome"`
	}
	if hostops.DecodeClosed(response.Bundle, &effect) != nil || effect.Op != x.Op || effect.Unit != unit || effect.Class != Classify(unit) || effect.Refusal != nil {
		return hostops.Observation{P1: "unknown"}
	}
	if response.Result == helperschema.ResultPerformed {
		if effect.Failure != "" || jobEffect(x.Op) && effect.Job == "" {
			return hostops.Observation{P1: "unknown"}
		}
	} else if response.Result != helperschema.ResultFailed || effect.Failure != CodeEffectFailed {
		return hostops.Observation{P1: "unknown"}
	}
	observation := effect.Observation()
	if effect.Outcome != outcome(observation) {
		return hostops.Observation{P1: "unknown"}
	}
	return observation
}

// jobEffect reports whether op queues a job: only enable and disable change the unit file without one.
func jobEffect(op string) bool { return op != OpEnable && op != OpDisable }

// applied is the receipt of a logs act. A journal reader that failed changed nothing; an answer
// that is not exactly the entries asked for stays unknown. The entries go to the hold, never to
// the receipt: the journal is sensitive, so the durable record keeps only how many were read.
func (x UnitTask) applied(ctx context.Context, operationID, unit string, lines int, response helperschema.Response) hostops.Observation {
	if response.Result == helperschema.ResultFailed && response.Code == CodeEffectFailed && len(response.Bundle) == 0 {
		return hostops.Observation{P1: "not-performed"}
	}
	var logs Logs
	// The answer is bounded by the helper's own MaxAnswerBytes, which is larger than a request may be.
	if response.Result != helperschema.ResultPerformed || hostops.DecodeClosedWithin(response.Bundle, &logs, MaxAnswerBytes) != nil || logs.Unit != unit || logs.Lines != lines || len(logs.Entries) > lines {
		return hostops.Observation{P1: "unknown"}
	}
	x.Hold.Put(operationID, ownerOf(ctx), logs)
	return logs.Observation()
}

type ownerKey struct{}

// WithOwner marks ctx with the uid of the session that asks for an act, so that the entries a logs act reads are
// held for that session alone.
func WithOwner(ctx context.Context, uid uint32) context.Context {
	return context.WithValue(ctx, ownerKey{}, uid)
}

func ownerOf(ctx context.Context) uint32 {
	uid, _ := ctx.Value(ownerKey{}).(uint32)
	return uid
}

// The hold's bounds: a console collects a logs act's entries within moments of the act, so a few
// operations for a short time are enough. An entry older than holdTTL is dropped by the next call of the hold.
const (
	holdCapacity = 8
	holdTTL      = 2 * time.Minute
)

// LogHold keeps the entries of the last logs acts in the console's memory, by operation id and by the uid of the
// session that asked, for holdTTL. It is the only place they are kept: the operation record, the audit spool and
// the helper keep none. The operation id is not a secret (the command line prints it, the receipt and the audit
// spool carry it), so it only names the entries: another session's id collects nothing, and a collection that
// reached the last entry drops them.
type LogHold struct {
	mu   sync.Mutex
	now  func() time.Time
	held []heldLogs
}

type heldLogs struct {
	id    string
	owner uint32
	at    time.Time
	logs  Logs
}

// NewLogHold returns an empty hold.
func NewLogHold() *LogHold { return &LogHold{now: time.Now} }

// Put keeps logs for operationID and owner, dropping the oldest holds beyond holdCapacity.
func (h *LogHold) Put(operationID string, owner uint32, logs Logs) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.expire()
	h.held = slices.DeleteFunc(h.held, func(e heldLogs) bool { return e.id == operationID })
	h.held = append(h.held, heldLogs{operationID, owner, h.now(), logs})
	if over := len(h.held) - holdCapacity; over > 0 {
		h.held = h.held[over:]
	}
}

// Get returns what operationID's logs act read for owner, while it is held. The entries of another owner's act
// are not found.
func (h *LogHold) Get(operationID string, owner uint32) (Logs, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.expire()
	for _, e := range h.held {
		if e.id == operationID && e.owner == owner {
			return e.logs, true
		}
	}
	return Logs{}, false
}

// Drop forgets operationID's entries of owner: what has been collected whole is not kept for a second collector.
func (h *LogHold) Drop(operationID string, owner uint32) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.held = slices.DeleteFunc(h.held, func(e heldLogs) bool { return e.id == operationID && e.owner == owner })
}

func (h *LogHold) expire() {
	cutoff := h.now().Add(-holdTTL)
	h.held = slices.DeleteFunc(h.held, func(e heldLogs) bool { return e.at.Before(cutoff) })
}
