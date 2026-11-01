// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package localclient

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/olivaresai/olivares/appliance/layer/hostops"
	"github.com/olivaresai/olivares/appliance/layer/portal/localframe"
)

func TestLocalClient_ApplyNeverResendsAnUnverifiedEffect(t *testing.T) {
	r := hostops.ApplyRequest{OperationID: strings.Repeat("1a", 16), Module: "host-user", Verb: "create", Surface: "cli", Inputs: json.RawMessage(`{}`), Confirmation: strings.Repeat("a", 64)}
	for _, reply := range []localframe.Record{
		{Type: "error", Op: "task.apply", Status: 403, Code: "mode_refused"},
		{Type: "response", Op: "task.apply", Status: 200, Body: json.RawMessage(`{"operation_id":"wrong"}`)},
	} {
		wire := &transport{records: []localframe.Record{{Type: "ready", Version: 1}, reply}}
		client, err := connect(wire)
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = client.Apply(r)
		if err == nil || len(wire.writes) != 1 {
			t.Fatal("unverified or denied apply accepted")
		}
		var failure *Failure
		if errors.As(err, &failure) {
			_, _, _ = client.Apply(r)
			if len(wire.writes) != 1 || !failure.Sent {
				t.Fatal("unverified effect resent")
			}
		}
	}
}
