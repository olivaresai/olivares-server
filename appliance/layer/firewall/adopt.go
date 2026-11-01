// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"

	"github.com/olivaresai/olivares/appliance/layer/firewall/policy"
	"github.com/olivaresai/olivares/appliance/layer/helpers/helperschema"
	"github.com/olivaresai/olivares/appliance/layer/hostops"
)

// HelperCaller is the Appliance Console's privileged-helper client. A caller cannot replace the
// firewall helper's admission or the owner's measurement.
type HelperCaller interface {
	Call(context.Context, string, helperschema.Request) (helperschema.Response, error)
}

// maxBundle bounds a helper answer this package reads back.
const maxBundle = 64 * 1024

// AppRowTask adopts firewall.app-row into the Appliance Console's acts: an application's own act,
// which adds or removes that application's rows and nothing else. Apps holds each application's
// rows as its own manifest gives them; the act names an application and a change, never a port, an
// interface or a rule.
//
// The act asks the firewall helper for the confirmed policy, derives the candidate (the confirmed
// policy with the application's rows replaced or dropped), has the owner load and measure it, and
// then confirms it. The operator's confirmation of the plan is the act's own, so no window is left
// open for the target to wait on; the revert window bounds only the moment between the load and the
// confirmation, and an unconfirmed load reverts at its deadline. An answer that is not this
// operation's window is never believed.
type AppRowTask struct {
	Helper HelperCaller
	Apps   map[string][]policy.AppRow
}

// appRowInput is the act's closed input.
type appRowInput struct {
	App          string `json:"app"`
	Change       string `json:"change"`
	RevertAfterS *int   `json:"revert_after_s"`
}

// parse reads the act's input against what the task knows. A missing window is the owner's default.
func (t AppRowTask) parse(input json.RawMessage) (appRowInput, []policy.AppRow, error) {
	var in appRowInput
	if hostops.DecodeClosed(input, &in) != nil {
		return in, nil, errors.New(CodeInputRefused)
	}
	rows, known := t.Apps[in.App]
	if !known || !policy.AppSlug(in.App) || (in.Change != "add" && in.Change != "remove") ||
		(in.RevertAfterS != nil && (*in.RevertAfterS < int(MinRevertAfter.Seconds()) || *in.RevertAfterS > int(MaxRevertAfter.Seconds()))) {
		return in, nil, errors.New(CodeInputRefused)
	}
	return in, rows, nil
}

// status reads the confirmed policy and the windows through the helper.
func (t AppRowTask) status(ctx context.Context) (Status, error) {
	if t.Helper == nil || ctx.Err() != nil {
		return Status{}, errors.New("consumer_unavailable")
	}
	answer, err := t.Helper.Call(ctx, HelperName, &Request{Op: OpStatus})
	var status Status
	if err != nil || answer.Result != helperschema.ResultAnswered || decodeBundle(answer.Bundle, &status) != nil {
		return Status{}, errors.New("firewall_unavailable")
	}
	return status, nil
}

// plan derives the candidate this input would load now, and refuses when there is none to load: no
// confirmed policy, a window still open, or rows that already are what the change makes them.
func (t AppRowTask) plan(ctx context.Context, input json.RawMessage) (appRowInput, policy.Document, error) {
	in, rows, err := t.parse(input)
	if err != nil {
		return in, policy.Document{}, err
	}
	status, err := t.status(ctx)
	if err != nil {
		return in, policy.Document{}, err
	}
	if status.Confirmed == nil || slices.ContainsFunc(status.Windows, func(w Window) bool { return w.State == WindowPending }) {
		return in, policy.Document{}, errors.New(CodeTargetLocked)
	}
	candidate := without(*status.Confirmed, in.App)
	if in.Change == "add" {
		candidate.Apps = append(candidate.Apps, slices.Clone(rows)...)
	}
	if candidate.Validate() != nil || policy.Digest(candidate) == policy.Digest(*status.Confirmed) {
		return in, policy.Document{}, errors.New(CodeInputRefused)
	}
	return in, candidate, nil
}

// Prepare reads through the helper and changes nothing. It targets the network, which every
// firewall effect shares with the NetworkManager plane.
func (t AppRowTask) Prepare(ctx context.Context, input json.RawMessage) (string, error) {
	if _, _, err := t.plan(ctx, input); err != nil {
		return "", err
	}
	return Target, nil
}

// Apply asks the owner to load the candidate and to confirm it, once each. A refusal before any
// load performed nothing; a request that was sent and not answered is unknown; a load that was
// confirmed is performed; a load that stays unconfirmed reverts at its deadline and is partial.
func (t AppRowTask) Apply(ctx context.Context, cmd hostops.Command, input json.RawMessage) hostops.Observation {
	if cmd.TaskID != Module+"."+VerbAppRow || cmd.Module != Module || cmd.Verb != VerbAppRow || cmd.Target != Target {
		return hostops.Observation{P1: "not-performed"}
	}
	in, candidate, err := t.plan(ctx, input)
	if err != nil {
		return hostops.Observation{P1: "not-performed"}
	}
	request := &Request{Op: OpApply, OperationID: cmd.OperationID, Candidate: &candidate, App: in.App}
	if in.RevertAfterS != nil {
		request.RevertAfterS = *in.RevertAfterS
	}
	if request.Validate() != nil {
		return hostops.Observation{P1: "not-performed"}
	}
	answer, err := t.Helper.Call(ctx, HelperName, request)
	if err != nil {
		return hostops.Observation{P1: "unknown"}
	}
	if answer.Result == helperschema.ResultRefused && len(answer.Bundle) == 0 {
		return hostops.Observation{P1: "not-performed"}
	}
	digest := policy.Digest(candidate)
	w, ok := windowOf(answer, cmd.OperationID, in.App, digest)
	if !ok {
		return hostops.Observation{P1: "unknown"}
	}
	if w.State != WindowPending {
		return Observe(w)
	}
	if answer.Result != helperschema.ResultPerformed {
		return unconfirmed(w)
	}
	answer, err = t.Helper.Call(ctx, HelperName, &Request{Op: OpConfirm, OperationID: cmd.OperationID})
	confirmed, ok := windowOf(answer, cmd.OperationID, in.App, digest)
	if err != nil || !ok || answer.Result != helperschema.ResultPerformed || confirmed.State != WindowConfirmed {
		return t.settled(ctx, cmd.OperationID, in.App, digest, w)
	}
	return Observe(confirmed)
}

// settled reads the window again after a confirmation that did not answer as expected: the owner may
// have confirmed it and the answer been lost, and a confirmed load stays. Only a window that is still
// not confirmed is reported as unconfirmed, to revert at its deadline.
func (t AppRowTask) settled(ctx context.Context, operation, app, digest string, pending Window) hostops.Observation {
	if status, err := t.status(ctx); err == nil {
		for _, w := range status.Windows {
			if w.SchemaVersion == WindowSchema && w.OperationID == operation && w.App == app && w.CandidateDigest == digest && w.State == WindowConfirmed {
				return Observe(w)
			}
		}
	}
	return unconfirmed(pending)
}

// unconfirmed is the observation of a candidate the owner loaded at runtime and did not confirm: it
// changed the host, and the guard reverts it at its deadline.
func unconfirmed(w Window) hostops.Observation {
	return hostops.Observation{P1: "partial", MeasuredChange: true, Postconditions: slices.Clone(w.Postconditions)}
}

// windowOf reads the window an answer carries and reports whether it is this operation's, for this
// application and this candidate.
func windowOf(answer helperschema.Response, operation, app, digest string) (Window, bool) {
	var w Window
	if decodeBundle(answer.Bundle, &w) != nil || w.SchemaVersion != WindowSchema || w.OperationID != operation || w.App != app || w.CandidateDigest != digest {
		return Window{}, false
	}
	return w, true
}

// decodeBundle reads one JSON object of at most maxBundle bytes that holds no member the schema does
// not name and nothing after it.
func decodeBundle(data []byte, dst any) error {
	if len(data) < 2 || len(data) > maxBundle {
		return errors.New(CodeInputRefused)
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return errors.New(CodeInputRefused)
	}
	if d.More() {
		return errors.New(CodeInputRefused)
	}
	return nil
}
