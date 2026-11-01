// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package console

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/olivaresai/olivares/appliance/layer/hostops"
	"github.com/olivaresai/olivares/appliance/layer/portal/localclient"
)

// ApplyingSession is additive: existing read-only Session implementations keep
// working. An unavailable mutation owner refuses instead of falling back locally.
type ApplyingSession interface {
	Apply(hostops.ApplyRequest) (hostops.Record, int, error)
}

func runHostUser(ctx context.Context, args []string, out, diagnostic io.Writer, dial Dial) int {
	if len(args) < 3 || args[1] != "create" {
		_, _ = fmt.Fprintln(diagnostic, "input_refused")
		return 1
	}
	values := map[string]string{"account": args[2], "home": "/home/" + args[2]}
	var confirm, operation string
	asJSON, planOnly := false, false
	seen := map[string]bool{}
	for i := 3; i < len(args); i++ {
		flag := args[i]
		if seen[flag] {
			_, _ = fmt.Fprintln(diagnostic, "input_refused")
			return 1
		}
		seen[flag] = true
		if flag == "--plan" {
			planOnly = true
			continue
		}
		if i+1 >= len(args) {
			_, _ = fmt.Fprintln(diagnostic, "input_refused")
			return 1
		}
		i++
		value := args[i]
		switch flag {
		case "--home":
			values["home"] = value
		case "--group":
			values["group"] = value
		case "--confirm":
			confirm = value
		case "--operation-id":
			operation = value
		case "--output":
			if value != "json" {
				_, _ = fmt.Fprintln(diagnostic, "input_refused")
				return 1
			}
			asJSON = true
		default:
			_, _ = fmt.Fprintln(diagnostic, "input_refused")
			return 1
		}
	}
	if values["home"] == "" || values["group"] == "" || confirm != "" && (!validDigest(confirm) || planOnly) || operation != "" && (!validID(operation) || confirm == "") || asJSON && confirm == "" {
		_, _ = fmt.Fprintln(diagnostic, "input_refused")
		return 1
	}
	return runConfirmedTask(ctx, "host-user", "create", values, confirm, operation, asJSON, out, diagnostic, dial)
}

// runConfirmedTask keeps the same local transport, record output and uncertain
// outcome behavior for host-user creation and the adopted service restart.
func runConfirmedTask(ctx context.Context, module, verb string, values map[string]string, confirm, operation string, asJSON bool, out, diagnostic io.Writer, dial Dial) int {
	if ctx.Err() != nil {
		_, _ = fmt.Fprintln(diagnostic, "session_lost")
		return 2
	}
	s, err := dial()
	if err != nil {
		return reportError(diagnostic, err, asJSON)
	}
	defer s.Close()
	if module == "host-package" {
		// The trusted catalog owns the prepared plan. Reuse its existing
		// description to fill the sole allowed digest; no caller chooses an
		// artifact, repository, version or helper directory.
		d, err := s.Description(module, verb, "cli")
		var refused *localclient.Refused
		if errors.As(err, &refused) && refused.Code == "input_refused" && !asJSON {
			// The console serves the two tasks only from a retained plan it could read when its listener opened, so
			// an unknown task is no plan, or a plan retained since or one the console could not read.
			_, _ = fmt.Fprintln(diagnostic, "The console offers no host package task: no plan is retained, or it was retained after the console started or could not be read (see the Appliance Console journal).")
			return 1
		}
		if err != nil {
			return reportError(diagnostic, err, asJSON)
		}
		field := d.InputSchema.Properties["native_plan"]
		if len(values) != 0 || len(field.Enum) != 1 || field.Type != "string" || !validDigest(field.Enum[0]) {
			_, _ = fmt.Fprintln(diagnostic, "input_refused")
			return 1
		}
		values["native_plan"] = field.Enum[0]
	}
	inputs, _ := json.Marshal(taskInputs(values))
	if confirm == "" {
		p, err := s.Plan(module, verb, "cli", inputs)
		if err != nil {
			return reportError(diagnostic, err, false)
		}
		changes := "Changes: disabled (" + safe(p.Permissions.Code) + ")"
		if p.Permissions.Apply {
			changes = "Changes: available after confirmation"
		}
		_, err = fmt.Fprintf(out, "%s\n%s\n%s\nPlan: %s\n", safe(p.Descriptor.Title), safe(p.Descriptor.Consequence), changes, safe(p.Digest))
		if err != nil {
			return 2
		}
		return 0
	}
	apply, ok := s.(ApplyingSession)
	if !ok {
		_, _ = fmt.Fprintln(diagnostic, "act_not_adopted")
		return 1
	}
	if operation == "" {
		var id [16]byte
		if _, err := rand.Read(id[:]); err != nil {
			return 2
		}
		operation = hex.EncodeToString(id[:])
	}
	// Keep the ID available even when the server's answer cannot be verified.
	if _, err := fmt.Fprintln(diagnostic, "Operation:", operation); err != nil {
		return 2
	}
	rec, _, err := apply.Apply(hostops.ApplyRequest{OperationID: operation, Module: module, Verb: verb, Surface: "cli", Inputs: inputs, Confirmation: confirm})
	if err != nil {
		return reportError(diagnostic, err, asJSON)
	}
	if printRecord(out, rec, asJSON) != nil || rec.State != hostops.StateSucceeded && !(module == "host-package" && verb == "recover" && rec.State == hostops.StateRolledBack) {
		return 2
	}
	return 0
}

// taskInputs is the document a task's inputs are sent as: every value a string, except the revert
// window of the firewall's act and the entry count of a logs act, which their schemas type as integers.
func taskInputs(values map[string]string) map[string]any {
	inputs := make(map[string]any, len(values))
	for name, value := range values {
		inputs[name] = value
	}
	for _, name := range []string{"revert_after_s", "lines"} {
		if n, err := strconv.Atoi(values[name]); err == nil {
			inputs[name] = n
		}
	}
	return inputs
}
func validDigest(s string) bool { return len(s) == 64 && validID(s[:32]) && validID(s[32:]) }
