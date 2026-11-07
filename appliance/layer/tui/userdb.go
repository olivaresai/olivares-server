// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package tui

import (
	"encoding/json"
	"os"
)

// UserDBHostRecord reads the administrator recorded by systemd-userdb, not a second account store.
type UserDBHostRecord string

// RecordedHuman returns the recorded login and uid.
func (path UserDBHostRecord) RecordedHuman() (Human, error) {
	data, err := os.ReadFile(string(path))
	if err != nil {
		return Human{}, err
	}
	var record struct {
		UserName string `json:"userName"`
		UID      uint32 `json:"uid"`
	}
	if err := json.Unmarshal(data, &record); err != nil {
		return Human{}, err
	}
	return Human{Login: record.UserName, UID: record.UID}, nil
}
