// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package firewall

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/olivaresai/olivares/appliance/layer/firewall/policy"
)

// Runner runs a program with fixed arguments and returns its standard output.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// sshdProgram is sshd by absolute path; -G prints its effective configuration.
const sshdProgram = "/usr/sbin/sshd"

// SysClassNet is where the kernel lists network interfaces.
const SysClassNet = "/sys/class/net"

// SSHPort is the one port sshd reports in its effective configuration (sshd -G). A failed run,
// no port, a value that is not a port or more than one port is an error: the operator's SSH
// row is measured, never guessed. Configuration-only mode avoids loading private host keys.
func SSHPort(ctx context.Context, run Runner) (int, error) {
	out, err := run(ctx, sshdProgram, "-G")
	if err != nil {
		return 0, &sshProbeFailure{cause: err}
	}
	port := 0
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "port" {
			continue
		}
		if len(fields) != 2 {
			return 0, errors.New("sshd reports a port line that is not one port")
		}
		n, err := strconv.Atoi(fields[1])
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != fields[1] {
			return 0, errors.New("sshd reports a port that is not a port")
		}
		if port != 0 && port != n {
			return 0, errors.New("sshd listens on more than one port; the policy admits one")
		}
		port = n
	}
	if port == 0 {
		return 0, errors.New("sshd reports no port")
	}
	return port, nil
}

// Keep native diagnostics out of the public refusal, which also crosses the local helper.
type sshProbeFailure struct{ cause error }

// Preserve the published refusal text; the journal names the current native mode.
func (e *sshProbeFailure) Error() string { return "sshd -T did not report its configuration" }
func (e *sshProbeFailure) Unwrap() error { return e.cause }

// Diagnostic is for the owner's journal. Never print arbitrary stderr, paths or config values.
func (e *sshProbeFailure) Diagnostic() string {
	return nativeDiagnostic("sshd -G", e.cause, []string{"Permission denied", "Operation not permitted", "No such file or directory",
		"no hostkeys available", "Unable to load host key", "Missing privilege separation directory"})
}

// nativeDiagnostic reports only process status and fixed categories, never child text.
func nativeDiagnostic(command string, cause error, categories []string) string {
	var child *exec.ExitError
	if errors.As(cause, &child) && child.ProcessState != nil {
		detail := command + ": " + child.ProcessState.String()
		for _, category := range categories {
			if strings.Contains(string(child.Stderr), category) {
				detail += "; stderr reports " + category
			}
		}
		if len(child.Stderr) != 0 {
			detail += fmt.Sprintf("; stderr prefix %d bytes (raw text withheld)", len(child.Stderr))
		}
		return detail
	}
	for _, category := range []struct {
		err  error
		text string
	}{{context.Canceled, "canceled"}, {context.DeadlineExceeded, "deadline exceeded"},
		{os.ErrPermission, "permission denied"}, {os.ErrNotExist, "executable unavailable"}} {
		if errors.Is(cause, category.err) {
			return command + ": " + category.text
		}
	}
	return command + ": execution or output failure (details withheld)"
}

// ClientInterfaces lists the links a DHCPv6 client may run on: each interface under
// sysClassNet with a device (a physical or virtual NIC, not loopback, a bridge or a veth) whose
// name the policy renders, sorted. More than policy.MaxInterfaces is an error.
func ClientInterfaces(sysClassNet string) ([]string, error) {
	entries, err := os.ReadDir(sysClassNet)
	if err != nil {
		return nil, errors.New("the kernel's interface list cannot be read")
	}
	names := []string{}
	for _, entry := range entries {
		name := entry.Name()
		if name == "lo" || !policy.InterfaceName(name) {
			continue
		}
		if _, err := os.Stat(filepath.Join(sysClassNet, name, "device")); err != nil {
			continue
		}
		names = append(names, name)
	}
	slices.Sort(names)
	if len(names) > policy.MaxInterfaces {
		return nil, errors.New("more links than the policy bounds")
	}
	return names, nil
}
