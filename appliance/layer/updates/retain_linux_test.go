// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

//go:build linux

package updates_test

import (
	"os"
	"syscall"
	"testing"
)

// Two Retain at once would let the cleanup of the second remove the plan the first has just written.
func TestRetain_RefusesASecondRetentionWhileOneRuns(t *testing.T) {
	d := newDelivery(t)
	held, err := os.Open(d.state)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(held.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if _, err := d.rpm().Retain(t.Context(), d.from); err == nil || err.Error() != "retention_running" || len(d.retained(t)) != 0 {
		t.Fatalf("%v, left %v", err, d.retained(t))
	}
	if err := held.Close(); err != nil {
		t.Fatal(err)
	}
	if plan, err := d.rpm().Retain(t.Context(), d.from); err != nil || plan.Digest == "" {
		t.Fatalf("after the first retention ended: %+v %v", plan, err)
	}
}
