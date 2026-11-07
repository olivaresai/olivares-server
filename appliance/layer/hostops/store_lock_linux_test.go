// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

//go:build linux

package hostops_test

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/olivaresai/olivares/appliance/layer/hostops"
)

// The repair console's power verb holds the store lock and reads every record too, through the
// host-operations group the portal runs as: the lock and the records are 0640 with the engine's own
// group, whatever the umask, and a lock or record an earlier release left 0600 is brought to that
// mode when the engine opens.
func TestEngine_TheStoreLockAndRecordsAreSharedWithTheOperationsGroup(t *testing.T) {
	catalog, err := hostops.NewCatalog([]hostops.Descriptor{hostops.StatusDescriptor()})
	if err != nil {
		t.Fatal(err)
	}
	old := syscall.Umask(0o027)
	defer syscall.Umask(old)
	for _, existing := range []bool{false, true} {
		dir := t.TempDir()
		lock := filepath.Join(dir, "store.lock")
		record := filepath.Join(dir, "0123456789abcdef0123456789abcdef.json")
		files := []string{lock}
		if existing {
			if err := os.WriteFile(lock, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(record, []byte("{}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			files = append(files, record)
		}
		if _, err := hostops.OpenWithCatalog(dir, catalog); err != nil {
			t.Fatal(err)
		}
		for _, file := range files {
			info, err := os.Stat(file)
			if err != nil {
				t.Fatal(err)
			}
			if mode := info.Mode().Perm(); mode != 0o640 {
				t.Errorf("existing=%v: %s is %o, not 0640", existing, filepath.Base(file), mode)
			}
			if gid := info.Sys().(*syscall.Stat_t).Gid; int(gid) != os.Getegid() {
				t.Errorf("existing=%v: %s's group is %d, not the engine's %d", existing, filepath.Base(file), gid, os.Getegid())
			}
		}
	}
}
