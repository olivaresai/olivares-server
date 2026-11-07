// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package hostusers

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestUserdbRecordSaveIsAtomicAndPreservesTheAdministrator(t *testing.T) {
	path := UserdbRecord(filepath.Join(t.TempDir(), "userdb", "olivares.user"))
	if err := path.Save("alice", "1000"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(string(path))
	if err != nil {
		t.Fatal(err)
	}
	var record struct {
		UserName string `json:"userName"`
		UID      uint32 `json:"uid"`
	}
	if json.Unmarshal(data, &record) != nil || record.UserName != "alice" || record.UID != 1000 {
		t.Fatalf("record = %s", data)
	}
	info, err := os.Stat(string(path))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("record mode = %v, %v", info.Mode(), err)
	}
	if err := path.Save("alice", "1000"); err != nil {
		t.Fatal(err)
	}
	if err := path.Save("bob", "1000"); err == nil {
		t.Fatal("a different administrator replaced the record")
	}
	if _, err := os.Stat(string(path) + ".new"); !os.IsNotExist(err) {
		t.Fatalf("staging file remains: %v", err)
	}
}
