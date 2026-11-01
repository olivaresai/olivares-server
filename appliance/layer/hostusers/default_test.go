// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package hostusers_test

import (
	"encoding/json"
	"github.com/olivaresai/olivares/appliance/layer/hostops"
	"github.com/olivaresai/olivares/appliance/layer/hostusers"
	"testing"
)

func TestHostUser_OmittedHomeUsesThePrivateAccountHome(t *testing.T) {
	input := json.RawMessage(`{"account":"alice","group":"staff"}`)
	descriptor := hostusers.Descriptors()[0]
	if err := descriptor.ValidateInput(input); err != nil {
		t.Fatalf("a home that can be derived is still mandatory: %v", err)
	}
	host := &host{}
	task := hostusers.Provisioner{Host: host}
	if _, err := task.Prepare(t.Context(), input); err != nil {
		t.Fatal(err)
	}
	observation := task.Apply(t.Context(), hostops.Command{}, input)
	if observation.P1 != "performed" || host.account.Home != "/home/alice" || !host.homeExists {
		t.Fatalf("default home: %+v account=%+v", observation, host.account)
	}
	if recovered := task.Recover(t.Context(), input); recovered.P1 != "performed" {
		t.Fatalf("defaulted recovery: %+v", recovered)
	}
}
