// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

//go:build linux

package entitled

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// The product user owns the handoff directory and can leave a named pipe where the file belongs. Opening it
// for reading would block the root helper until the unit's timeout, so it is refused before it is opened.
func TestReadHandoffRefusesANamedPipeWithoutBlocking(t *testing.T) {
	dir := handoffDir(t)
	if err := syscall.Mkfifo(filepath.Join(dir, testCycle+".json"), 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := ReadHandoff(dir, testCycle, testCycle, os.Getuid())
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("ReadHandoff accepted a named pipe")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadHandoff blocked on a named pipe")
	}
}
