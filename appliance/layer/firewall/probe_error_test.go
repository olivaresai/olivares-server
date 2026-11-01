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
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestSSHProbeChild(t *testing.T) {
	if len(os.Args) < 3 || os.Args[len(os.Args)-2] != "--probe-child" {
		return
	}
	switch os.Args[len(os.Args)-1] {
	case "exit":
		fmt.Fprintln(os.Stderr, "Load key /private/secret-sentinel: Permission denied")
	case "signal":
		_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
		// kill(2) may deliver to another thread; leaving main now would let the
		// exit below beat the runtime's signal handler. Wait for the handler; the
		// caller's deadline ends the child if the signal never arrives.
		time.Sleep(time.Minute)
	case "large":
		fmt.Fprint(os.Stderr, strings.Repeat("secret-sentinel", 100000))
	case "stdout":
		fmt.Fprint(os.Stdout, strings.Repeat("x", 256*1024+1))
	case "success":
		fmt.Fprintln(os.Stdout, "port 2222")
		os.Exit(0)
	}
	os.Exit(255)
}

func TestSSHProbeFailurePreservesNativeCause(t *testing.T) {
	program, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"exit", "signal", "large", "stdout", "success"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			runner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
				if name != sshdProgram || strings.Join(args, " ") != "-G" {
					t.Fatal("probe argv changed")
				}
				return runBounded(ctx, program, []string{"-test.run=^TestSSHProbeChild$", "--", "--probe-child", mode}, nil, 256*1024)
			}
			port, err := SSHPort(ctx, runner)
			if mode == "success" {
				if err != nil || port != 2222 {
					t.Fatalf("port=%d error=%v", port, err)
				}
				return
			}
			if port != 0 || err == nil || err.Error() != "sshd -T did not report its configuration" {
				t.Fatalf("public refusal changed: port=%d error=%v", port, err)
			}
			if mode == "stdout" {
				if cause := errors.Unwrap(err); cause == nil || cause.Error() != "the program's output exceeds its bound" {
					t.Fatal("stdout overflow cause lost")
				}
				return
			}
			var child *exec.ExitError
			if !errors.As(err, &child) {
				t.Fatal("native exit/signal cause lost")
			}
			if mode == "signal" {
				status, ok := child.Sys().(syscall.WaitStatus)
				if !ok || !status.Signaled() || status.Signal() != syscall.SIGTERM {
					t.Fatalf("signal lost: %v", child)
				}
			} else if child.ExitCode() != 255 {
				t.Fatalf("exit status lost: %v", child)
			}
			if mode == "exit" && !strings.Contains(string(child.Stderr), "Permission denied") {
				t.Fatal("native stderr lost")
			}
			if mode == "large" && (len(child.Stderr) == 0 || len(child.Stderr) > 4096) {
				t.Fatalf("stderr bound not preserved: %d", len(child.Stderr))
			}
			var diagnostic interface{ Diagnostic() string }
			if !errors.As(err, &diagnostic) {
				t.Fatal("safe owner diagnostic absent")
			}
			detail := diagnostic.Diagnostic()
			if strings.Contains(detail, "secret-sentinel") || strings.Contains(detail, "/private/") || strings.ContainsAny(detail, "\r\n\x1b") || len(detail) > 512 {
				t.Fatal("unsafe owner diagnostic")
			}
			if mode == "exit" && (!strings.Contains(detail, "exit status 255") || !strings.Contains(detail, "Permission denied")) {
				t.Fatalf("diagnostic lost discriminant: %q", detail)
			}
			if mode == "signal" && !strings.Contains(detail, "signal") {
				t.Fatalf("signal diagnostic absent: %q", detail)
			}
		})
	}
}

func TestSSHProbeStartFailureWithholdsPrivatePath(t *testing.T) {
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded,
		&os.PathError{Op: "fork/exec", Path: "/private/secret-sentinel", Err: os.ErrPermission},
		&os.PathError{Op: "fork/exec", Path: "/private/secret-sentinel", Err: os.ErrNotExist}} {
		_, err := SSHPort(context.Background(), func(context.Context, string, ...string) ([]byte, error) {
			return nil, cause
		})
		if !errors.Is(err, cause) || err.Error() != "sshd -T did not report its configuration" {
			t.Fatal("native cause or public refusal changed")
		}
		var diagnostic interface{ Diagnostic() string }
		if !errors.As(err, &diagnostic) || strings.Contains(diagnostic.Diagnostic(), "secret-sentinel") {
			t.Fatal("missing or unsafe startup diagnostic")
		}
	}
}

// Exercise the native parser with no usable host key. Only this test supplies a
// private config; the installed Exec continues to accept one fixed argv.
func TestSSHPortNativeWithoutHostKeys(t *testing.T) {
	if _, err := os.Stat(sshdProgram); errors.Is(err, os.ErrNotExist) {
		t.Skip("native OpenSSH server is not installed")
	} else if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	include := filepath.Join(dir, "port.conf")
	if err := os.WriteFile(include, []byte("Port 2222\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, config string
		want         int
	}{
		{"included port", "Include " + include + "\n", 2222},
		{"multiple ports", "Port 22\nPort 2222\n", 0},
		{"invalid config", "NotAnOpenSSHOption yes\n", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := filepath.Join(dir, "sshd_config")
			if err := os.WriteFile(config, []byte(tc.config+"HostKey "+filepath.Join(dir, "absent-key")+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if tc.want != 0 {
				_, err := runBounded(ctx, sshdProgram, []string{"-T", "-f", config}, nil, 256*1024)
				var child *exec.ExitError
				if !errors.As(err, &child) || !strings.Contains(string(child.Stderr), "no hostkeys available") {
					t.Fatalf("legacy key-loading control did not reproduce: %v", err)
				}
			}
			port, err := SSHPort(ctx, func(ctx context.Context, name string, args ...string) ([]byte, error) {
				return runBounded(ctx, name, append(args, "-f", config), nil, 256*1024)
			})
			if tc.want != 0 && (err != nil || port != tc.want) {
				t.Fatalf("configuration-only port=%d error=%v; want %d without host keys", port, err, tc.want)
			}
			if tc.want == 0 && (err == nil || port != 0) {
				t.Fatalf("unsafe configuration admitted: port=%d error=%v", port, err)
			}
		})
	}
}
