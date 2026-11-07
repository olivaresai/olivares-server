// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package hostusers

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// A failed useradd or usermod names its own reason in the helper's journal, bounded and on one line.
func TestLinuxRunJournalsAFailedToolsBoundedStderr(t *testing.T) {
	if _, err := os.Stat("/usr/sbin/useradd"); err != nil {
		t.Skip("this host has no /usr/sbin/useradd")
	}
	var journal bytes.Buffer
	err := Linux{Diagnostics: &journal}.Run(t.Context(), "/usr/sbin/useradd", []string{"--no-such-option-" + strings.Repeat("x", 600)})
	if err == nil {
		t.Fatal("useradd with an unknown option succeeded")
	}
	line := journal.String()
	const prefix = "system helper: /usr/sbin/useradd failed: "
	if !strings.HasPrefix(line, prefix) || !strings.Contains(line, "no-such-option") {
		t.Fatalf("the journal does not name useradd's own reason: %q", line)
	}
	if strings.Count(line, "\n") != 1 || !strings.HasSuffix(line, "\n") {
		t.Fatalf("the tool's output is not one journal line: %q", line)
	}
	if _, reason, _ := strings.Cut(line, ": exit status "); len(reason) > toolStderrBytes+8 {
		t.Fatalf("the journal line carries %d bytes of tool output, more than %d", len(reason), toolStderrBytes)
	}
}
