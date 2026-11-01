// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

//go:build linux && (amd64 || arm64)

package netguard

import "testing"

// The network runtime records the init process's pid namespace without reading /proc/1/ns/pid, which needs ptrace-read
// access to PID 1 and is refused under the unit's capability bounding set (#2834). It reads its own
// namespace instead, after /proc/self/status shows it is not in a nested pid namespace: NSpid has one field there.
func TestRuntime_ReadsTheInitPIDNamespaceOnlyFromOutsideANestedOne(t *testing.T) {
	for _, tc := range []struct {
		name, status string
		ok           bool
	}{
		{"the initial pid namespace", "Name:\tolivares-net-gu\nNSpid:\t761\nNSpgid:\t761\n", true},
		{"a nested pid namespace", "Name:\tolivares-net-gu\nNSpid:\t31661\t7\n", false},
		{"three levels", "NSpid:\t9\t4\t1\n", false},
		{"no NSpid line", "Name:\tolivares-net-gu\nPid:\t761\n", false},
		{"an empty NSpid line", "NSpid:\t\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := inInitialPIDNamespace([]byte(tc.status)); (err == nil) != tc.ok {
				t.Fatalf("inInitialPIDNamespace(%q) = %v, want ok=%v", tc.status, err, tc.ok)
			}
		})
	}
}
