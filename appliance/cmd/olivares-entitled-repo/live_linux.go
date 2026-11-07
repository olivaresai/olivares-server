// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/olivaresai/olivares/appliance/layer/entitled"
	"github.com/olivaresai/olivares/appliance/layer/updates"
	"github.com/olivaresai/olivares/core/license/dnfrefresh"
)

// productBinary is the installed product; a development binary elsewhere is never run by this command.
const productBinary = "/usr/bin/olivares"

// reportLimit bounds the product's printed report, which carries identifiers and never a credential.
const reportLimit = 64 << 10

// live is the environment of an installed appliance.
func live() env {
	volume := updates.LiveDataVolume(hostSnapshotRun)
	volume.ProductActive = productActive
	volume.StopProduct = stopProduct
	volume.StartProduct = startProduct
	volume.VerifyPackages = verifyPrevious
	volume.InstallPackages = installPrevious
	return env{
		HandoffDir: dnfrefresh.HandoffDir,
		RepoDir:    "/etc/yum.repos.d",
		DataDir:    "/var/lib/olivares",
		EnvFile:    "/etc/olivares/olivares.env",
		Product:    "olivares",
		Invocation: os.Getenv("INVOCATION_ID"),
		Now:        time.Now,
		Lookup:     lookup,
		Chown:      os.Lchown,
		RunProduct: runProduct,

		Installed:   installed,
		Swap:        dnfSwap,
		SwapOffered: dnfSwapOffered,
		Snapshot: func(ctx context.Context) (point, error) {
			p, err := volume.Before(ctx)
			return &p, err
		},
		UpgradeAvailable: dnfUpgradeAvailable,
		Upgrade:          dnfUpgrade,
		RetainPrevious:   retainPrevious,
		Rollback:         volume.Rollback,
		ProductActive:    productActive,
		StartProduct:     startProduct,
	}
}

// The host tools, by absolute path; tests point them at stubs.
var (
	rpmPath       = "/usr/bin/rpm"
	rpmkeysPath   = "/usr/bin/rpmkeys"
	dnfPath       = "/usr/bin/dnf"
	systemctlPath = "/usr/bin/systemctl"
)

// hostEnv is the environment of the package manager and the service manager: a fixed path and the C locale,
// nothing inherited.
var hostEnv = []string{"PATH=/usr/sbin:/usr/bin", "LC_ALL=C"}

// stopGrace is how long a host tool gets, after the SIGTERM a cancelled context sends, before it is killed. A
// package transaction is not cut off by the first signal: dnf finishes or unwinds what it is doing.
const stopGrace = 10 * time.Minute

// hostCommand runs a host tool with its output on standard error (the journal's) and returns its exit status:
// -1 when it did not run at all.
func hostCommand(ctx context.Context, name string, args ...string) (int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = hostEnv
	cmd.Dir = "/"
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = stopGrace
	err := cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return 0, nil
	case errors.As(err, &exit):
		return exit.ExitCode(), err
	}
	return -1, err
}

func hostSnapshotRun(ctx context.Context, argv []string, _ int64) ([]byte, error) {
	_, err := hostCommand(ctx, argv[0], argv[1:]...)
	return nil, err
}

// dnfUpgradeAvailable is dnf's own answer: check-upgrade exits 100 when a newer package is offered and 0 when none is.
func dnfUpgradeAvailable(ctx context.Context) (bool, error) {
	code, err := hostCommand(ctx, dnfPath, "--refresh", "check-upgrade", "olivares*")
	switch code {
	case 0:
		return false, nil
	case 100:
		return true, nil
	}
	return false, err
}

func dnfUpgrade(ctx context.Context) error {
	_, err := hostCommand(ctx, dnfPath, "--assumeyes", "--setopt=install_weak_deps=False", "upgrade", "olivares*")
	return err
}

// retainPrevious downloads into dir the installed version of every Olivares package, the set the update's
// `dnf upgrade olivares*` may replace: dnf's reinstall --downloadonly fetches them from the channel the update reads
// and installs nothing. A set the channel no longer offers whole is not kept at all, so the rollback refuses rather
// than reinstall half of it. The rollback verifies the set before any use.
func retainPrevious(ctx context.Context, dir string) error {
	if err := os.Mkdir(dir, 0o700); err != nil {
		return err
	}
	if _, err := hostCommand(ctx, dnfPath, "--assumeyes", "--downloadonly", "--downloaddir="+dir, "reinstall", "olivares*"); err != nil {
		return errors.Join(err, os.RemoveAll(dir))
	}
	return nil
}

// verifyPrevious requires every kept file to pass rpm's signature check against the host's keyring, the level its
// reinstall enforces, and to be a version of a package installed now; then rpm's own test transaction proves that
// the kept versions replace the installed ones with every dependency met. Nothing has stopped yet.
func verifyPrevious(ctx context.Context, paths []string) error {
	for _, path := range paths {
		if _, err := hostCommand(ctx, rpmkeysPath, "--define", "_pkgverify_level signature", "--checksig", "--", path); err != nil {
			return fmt.Errorf("signature check of %s: %w", filepath.Base(path), err)
		}
	}
	changed, err := changedPackages(ctx, paths)
	if err != nil || len(changed) == 0 {
		return err
	}
	if _, err := hostCommand(ctx, rpmPath, append([]string{"-U", "--oldpackage", "--test", "--define", "_pkgverify_level signature", "--"}, changed...)...); err != nil {
		return fmt.Errorf("rpm's test transaction: %w", err)
	}
	return nil
}

// installPrevious reinstalls the kept packages in one rpm transaction, signature required, allowing older versions.
// A rollback run again after its reinstall finds those versions installed and installs nothing.
func installPrevious(ctx context.Context, paths []string) error {
	changed, err := changedPackages(ctx, paths)
	if err != nil || len(changed) == 0 {
		return err
	}
	_, err = hostCommand(ctx, rpmPath, append([]string{"-U", "--oldpackage", "--define", "_pkgverify_level signature", "--"}, changed...)...)
	return err
}

// changedPackages returns the kept files whose version is not the one installed now; a kept file of a package that
// is not installed is refused.
func changedPackages(ctx context.Context, paths []string) ([]string, error) {
	var changed []string
	for _, path := range paths {
		kept, err := hostOutput(ctx, rpmPath, "-qp", "--queryformat", "%{NAME} %{NEVRA}", "--", path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", filepath.Base(path), err)
		}
		name, nevra, _ := strings.Cut(kept, " ")
		current, err := hostOutput(ctx, rpmPath, "-q", "--queryformat", "%{NEVRA}", "--", name)
		if err != nil {
			return nil, fmt.Errorf("%s is kept, and %s is not installed", filepath.Base(path), name)
		}
		if current != nevra {
			changed = append(changed, path)
		}
	}
	return changed, nil
}

// hostOutput runs a host tool for its answer on standard output; its errors go to the journal.
func hostOutput(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = hostEnv
	cmd.Dir = "/"
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	return strings.TrimSpace(string(out)), err
}

func stopProduct(ctx context.Context) error {
	_, err := hostCommand(ctx, systemctlPath, "stop", "olivares.service")
	return err
}

// installed asks rpm by package name, the tool's own answer: 0 installed, 1 not installed. A provider of the
// name does not count, so olivares-business, which provides olivares, does not read as Community. rpm's own
// message goes to the journal. A database that cannot be read answers like a missing package, which makes both
// questions false, and Wanted refuses a host that holds neither: it never makes a swap.
func installed(ctx context.Context, pkg string) (bool, error) {
	code, err := hostCommand(ctx, rpmPath, "-q", "--quiet", pkg)
	switch {
	case code == 0:
		return true, nil
	case code == 1:
		return false, nil
	}
	return false, err
}

// dnfSwap is dnf's own swap: remove one package and install the other in a single transaction, so a conflict between
// the two is resolved inside it and a failure before the transaction leaves the host as it was. Weak dependencies stay
// off and removal cleans nothing up: the swap changes the product package and no other. The way back to Community
// comes from the public repository, which the image ships disabled, so it is enabled for that one command, and the
// entitled repositories are left out of it; the way to Business comes from the entitled repository, which enables itself.
func dnfSwap(ctx context.Context, s entitled.Swap) error {
	args := []string{"--assumeyes", "--setopt=install_weak_deps=False", "--setopt=clean_requirements_on_remove=False"}
	_, err := hostCommand(ctx, dnfPath, append(append(args, swapRepos(s)...), "swap", s.From, s.To)...)
	return err
}

// dnfSwapOffered asks the repositories the swap reads, with fresh metadata, for the package it installs: dnf's list
// exits 0 when one is offered and 1 when none is (or a repository cannot be read, which dnf names in the journal).
func dnfSwapOffered(ctx context.Context, s entitled.Swap) (bool, error) {
	code, err := hostCommand(ctx, dnfPath, append(swapRepos(s), "--refresh", "list", "--available", s.To)...)
	switch code {
	case 0:
		return true, nil
	case 1:
		return false, nil
	}
	return false, err
}

func swapRepos(s entitled.Swap) []string {
	if s.To == entitled.CommunityPackage {
		return []string{"--disablerepo=" + entitledRepos, "--enablerepo=" + publicRepo}
	}
	return nil
}

// publicRepo is the id of the public product repository the image ships in olivares.repo, disabled. entitledRepos
// matches the ids of the entitled channel's repositories (olivares-<suite>, entitled.Render): without a licence their
// credential is a day old at most and then expires, and dnf refreshes every enabled repository, so one that answers
// 401 would fail the swap back to a package that does not come from them.
const (
	publicRepo    = "olivares"
	entitledRepos = "olivares-entitled-*"
)

// productActive asks systemd for the unit's state. A product that is starting or reloading is running as far as
// the swap is concerned: its package stops it, and it is started again after. Only a failure to ask is an error.
func productActive(ctx context.Context) (bool, error) {
	cmd := exec.CommandContext(ctx, systemctlPath, "show", "--property=ActiveState", "--value", "olivares.service")
	cmd.Env = hostEnv
	cmd.Dir = "/"
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return false, err
	}
	switch state := strings.TrimSpace(string(out)); state {
	case "active", "activating", "reloading":
		return true, nil
	case "inactive", "failed", "deactivating":
		return false, nil
	default:
		return false, fmt.Errorf("the product's unit reports the state %q", state)
	}
}

func startProduct(ctx context.Context) error {
	_, err := hostCommand(ctx, systemctlPath, "start", "olivares.service")
	return err
}

func lookup(name string) (int, int, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, 0, err
	}
	uid, uerr := strconv.Atoi(u.Uid)
	gid, gerr := strconv.Atoi(u.Gid)
	if uerr != nil || gerr != nil || uid <= 0 {
		return 0, 0, errors.New("the product user has no ordinary numeric ids")
	}
	return uid, gid, nil
}

// runProduct runs the installed product as uid and gid with no supplementary groups, in the given
// environment and nothing else, and returns what it prints on standard output (bounded).
func runProduct(ctx context.Context, uid, gid int, args, environ []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, productBinary, args...)
	cmd.Env = environ
	cmd.Dir = "/"
	// A grandchild that keeps standard output open must not hold Wait past the product's own end.
	cmd.WaitDelay = 5 * time.Second
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{}}}
	var out limited
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	return out.buf.Bytes(), err
}

// limited keeps at most reportLimit bytes and fails the write after that, which ends the copy; the context ends the child.
type limited struct{ buf bytes.Buffer }

func (l *limited) Write(p []byte) (int, error) {
	if l.buf.Len()+len(p) > reportLimit {
		return 0, errors.New("the product's report is larger than expected")
	}
	return l.buf.Write(p)
}
