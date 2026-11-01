// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

//go:build linux && (amd64 || arm64)

package netguard

import (
	"errors"
	"os"
	"strings"
)

// initPIDNamespace returns the pid namespace of the init process without reading /proc/1/ns/pid. The kernel serves that
// link only to a caller with ptrace-read access to PID 1, which needs CAP_SYS_PTRACE unless the caller's capabilities are
// a superset of PID 1's, so the root units, whose bounding sets are much smaller, are refused (#2834). A process whose
// NSpid has one field is in the pid namespace of its procfs, which is PID 1's, so its own link is the same namespace.
func initPIDNamespace() (string, error) {
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return "", err
	}
	if err := inInitialPIDNamespace(status); err != nil {
		return "", err
	}
	return os.Readlink("/proc/self/ns/pid")
}

// inInitialPIDNamespace reads a /proc/<pid>/status: NSpid lists the process's pid in its procfs's pid namespace and in
// each nested one below it, so one field means it is in no nested namespace.
func inInitialPIDNamespace(status []byte) error {
	for _, line := range strings.Split(string(status), "\n") {
		if value, ok := strings.CutPrefix(line, "NSpid:"); ok {
			switch fields := len(strings.Fields(value)); {
			case fields == 1:
				return nil
			case fields > 1:
				return errors.New("network_runtime_not_in_the_init_pid_namespace")
			}
		}
	}
	return errors.New("network_runtime_cannot_read_its_pid_namespace")
}
