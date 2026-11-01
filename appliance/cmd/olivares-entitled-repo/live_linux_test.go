// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

//go:build linux

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/olivaresai/olivares/appliance/layer/entitled"
)

// stub installs a shell script as the host tool *target, which records its arguments, one line per call, in the log
// returned, and runs body. The tool runs with the fixed environment of hostCommand, so everything it needs is in its text.
func stub(t *testing.T, target *string, body string) (log string) {
	t.Helper()
	dir := t.TempDir()
	log = filepath.Join(dir, "calls")
	path := filepath.Join(dir, "tool")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + log + "\n" + body + "\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	previous := *target
	*target = path
	t.Cleanup(func() { *target = previous })
	return log
}

func calls(t *testing.T, log string) []string {
	t.Helper()
	data, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(data)), "\n")
}

func TestInstalledReadsRpmsExitStatusAndNothingElse(t *testing.T) {
	cases := []struct {
		body    string
		want    bool
		wantErr bool
	}{
		{"exit 0", true, false},
		{"exit 1", false, false},
		{"exit 2", false, true},
		{"exit 127", false, true},
	}
	for _, tc := range cases {
		log := stub(t, &rpmPath, tc.body)
		got, err := installed(context.Background(), "olivares-business")
		if got != tc.want || (err != nil) != tc.wantErr {
			t.Errorf("%s: installed = %v, %v; want %v, error %v", tc.body, got, err, tc.want, tc.wantErr)
		}
		// The package name only: rpm -q does not match what a package provides, and the answer is rpm's exit status.
		if c := calls(t, log); len(c) != 1 || c[0] != "-q --quiet olivares-business" {
			t.Errorf("rpm was run as %q", c)
		}
	}
	rpmPath = filepath.Join(t.TempDir(), "missing")
	if got, err := installed(context.Background(), "olivares"); got || err == nil {
		t.Errorf("a missing rpm read as %v, %v: it must be an error, not 'not installed'", got, err)
	}
}

func TestProductActiveReadsTheUnitsState(t *testing.T) {
	cases := map[string]bool{"active": true, "activating": true, "reloading": true, "inactive": false, "failed": false, "deactivating": false}
	for state, want := range cases {
		log := stub(t, &systemctlPath, "echo "+state)
		got, err := productActive(context.Background())
		if err != nil || got != want {
			t.Errorf("state %s: productActive = %v, %v; want %v", state, got, err, want)
		}
		if c := calls(t, log); len(c) != 1 || c[0] != "show --property=ActiveState --value olivares.service" {
			t.Errorf("systemctl was run as %q", c)
		}
	}
	// What is not a state systemd defines, or no answer at all, is not "stopped".
	stub(t, &systemctlPath, "echo maybe")
	if got, err := productActive(context.Background()); got || err == nil {
		t.Errorf("an unknown state read as %v, %v", got, err)
	}
	stub(t, &systemctlPath, "exit 1")
	if got, err := productActive(context.Background()); got || err == nil {
		t.Errorf("a failed question read as %v, %v", got, err)
	}
	systemctlPath = filepath.Join(t.TempDir(), "missing")
	if got, err := productActive(context.Background()); got || err == nil {
		t.Errorf("a missing systemctl read as %v, %v", got, err)
	}
}

func TestDnfSwapIsOneTransactionAndTakesCommunityFromThePublicRepositoryAlone(t *testing.T) {
	common := "--assumeyes --setopt=install_weak_deps=False --setopt=clean_requirements_on_remove=False"
	for _, tc := range []struct {
		swap entitled.Swap
		want string
	}{
		// Business comes from the entitled repository, which its own file enables.
		{entitled.Swap{From: "olivares", To: "olivares-business"}, common + " swap olivares olivares-business"},
		// Community comes from the public repository, which the image ships disabled; the entitled repositories, whose
		// credential has expired without a licence to renew it, are not asked.
		{entitled.Swap{From: "olivares-business", To: "olivares"}, common + " --disablerepo=olivares-entitled-* --enablerepo=olivares swap olivares-business olivares"},
	} {
		log := stub(t, &dnfPath, "exit 0")
		if err := dnfSwap(context.Background(), tc.swap); err != nil {
			t.Fatal(err)
		}
		if c := calls(t, log); len(c) != 1 || c[0] != tc.want {
			t.Errorf("dnf was run as %q, want %q", c, tc.want)
		}
	}
	stub(t, &dnfPath, "exit 1")
	if err := dnfSwap(context.Background(), entitled.Swap{From: "olivares", To: "olivares-business"}); err == nil {
		t.Error("a failed dnf was reported as success")
	}
}

// A cancelled context asks dnf to stop with SIGTERM and waits for it; SIGKILL in the middle of a package transaction
// can leave the host with neither package or both.
func TestDnfSwapIsAskedToStopNotKilled(t *testing.T) {
	dir := t.TempDir()
	started, marker := filepath.Join(dir, "started"), filepath.Join(dir, "term")
	stub(t, &dnfPath, "trap 'echo term > "+marker+"; exit 143' TERM\n: > "+started+"\nwhile :; do sleep 0.05; done")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- dnfSwap(ctx, entitled.Swap{From: "olivares", To: "olivares-business"}) }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(started); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the stub dnf never started")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Error("a cancelled swap was reported as success")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the swap did not end after the cancel")
	}
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("dnf was not sent SIGTERM: %v", err)
	}
}

func TestStartProductStartsTheProductsUnit(t *testing.T) {
	log := stub(t, &systemctlPath, "exit 0")
	if err := startProduct(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c := calls(t, log); len(c) != 1 || c[0] != "start olivares.service" {
		t.Errorf("systemctl was run as %q", c)
	}
	stub(t, &systemctlPath, "exit 1")
	if err := startProduct(context.Background()); err == nil {
		t.Error("a failed start was reported as success")
	}
}
