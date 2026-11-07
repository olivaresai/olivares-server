// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

// olivares-entitled-repo gives the appliance its entitled package channel: it asks the product to
// refresh its DNF download credential and writes the repository file DNF reads.
//
// It is started by olivares-entitled-repo.service, as root, once per service invocation. It runs
// `olivares license connect dnf-refresh` as the product's own user, which holds the licence binding
// and proves it to the licensing service; takes the handoff the product publishes; and replaces
// /etc/yum.repos.d/olivares-entitled.repo with the suites the licence earns. It takes no option and
// no path. The cycle is the unit's invocation id, which the product records in the handoff, so a
// handoff made by hand or left by another run is refused.
//
// `update`, run by olivares-appliance-update.service, upgrades the Olivares packages and keeps, beside the data
// snapshot it takes first, the Olivares packages it replaces; `rollback`, run by olivares-appliance-rollback.service,
// returns the product to that snapshot and reinstalls those packages.
//
// `edition`, run by olivares-edition.service after a refresh, brings the installed edition to the one the
// licence earns: the image ships Community, a licence that earns the feature suite swaps it for the Business
// package the channel offers, and removing the licence swaps it back. The refresh runs under a hardened unit
// that can write only the repository directory; a package transaction cannot, so it is a separate unit.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/olivaresai/olivares/appliance/layer/entitled"
	"github.com/olivaresai/olivares/core/license/dnfrefresh"
)

// productTimeout bounds the product's exchange with the licensing service; the unit allows more.
const productTimeout = 120 * time.Second

var id128 = regexp.MustCompile(`^[0-9a-f]{32}$`)

// licenseFile is the installed licence under the data directory: the product's own file, whose presence is
// the whole meaning of "a licence is installed" (the units start on it).
const licenseFile = "license.key"

// env is the host this command acts on. live (per platform) fills it for an installed appliance;
// tests replace the product, the ownership calls and the package manager.
type env struct {
	HandoffDir string
	RepoDir    string
	DataDir    string
	EnvFile    string
	Product    string
	Invocation string
	Now        func() time.Time
	Log        io.Writer
	Lookup     func(name string) (uid, gid int, err error)
	Chown      func(path string, uid, gid int) error
	RunProduct func(ctx context.Context, uid, gid int, args, environ []string) ([]byte, error)

	// The edition step's host actions. Installed asks the package database, Swap runs one package transaction,
	// ProductActive and StartProduct read and start the product's unit.
	Installed     func(ctx context.Context, pkg string) (bool, error)
	Swap          func(ctx context.Context, s entitled.Swap) error
	ProductActive func(ctx context.Context) (bool, error)
	StartProduct  func(ctx context.Context) error

	// Each product transaction's host actions. Snapshot quiesces the product and takes the read-only data
	// snapshot before a swap or an upgrade; its Close releases the transaction lock. SwapOffered asks whether
	// the channel offers the package a swap installs, UpgradeAvailable whether a newer Olivares package is
	// offered, and Upgrade installs it. RetainPrevious keeps the installed Olivares packages in the point's
	// package directory, and Rollback returns the product to the last transaction's point and those packages.
	Snapshot         func(ctx context.Context) (point, error)
	SwapOffered      func(ctx context.Context, s entitled.Swap) (bool, error)
	UpgradeAvailable func(ctx context.Context) (bool, error)
	Upgrade          func(ctx context.Context) error
	RetainPrevious   func(ctx context.Context, dir string) error
	Rollback         func(ctx context.Context) error
}

// point is a completed data snapshot that holds the product transaction lock until it is closed.
type point interface {
	io.Closer
	PackageDir() string
}

// liveEnv is the environment of the host the command runs on; tests replace it.
var liveEnv = live

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, _, stderr io.Writer) int {
	var step func(context.Context, env) error
	switch {
	case len(args) == 1 && args[0] == "refresh":
		step = refresh
	case len(args) == 1 && args[0] == "edition":
		step = edition
	case len(args) == 1 && args[0] == "update":
		step = update
	case len(args) == 1 && args[0] == "rollback":
		step = func(ctx context.Context, e env) error { return e.Rollback(ctx) }
	default:
		fmt.Fprintln(stderr, "usage: olivares-entitled-repo refresh|edition|update|rollback")
		return 2
	}
	e := liveEnv()
	e.Log = stderr
	if err := step(ctx, e); err != nil {
		fmt.Fprintf(stderr, "olivares-entitled-repo: %v\n", err)
		return 1
	}
	return 0
}

// update owns the whole product transaction: quiesce and snapshot before DNF,
// then restore the product's prior running state after DNF succeeds or fails.
// With nothing to upgrade it changes nothing: a point taken then would push the
// pre-upgrade one out of the three kept.
func update(ctx context.Context, e env) error {
	available, err := e.UpgradeAvailable(ctx)
	if err != nil {
		return fmt.Errorf("ask the channel for Olivares updates: %w", err)
	}
	if !available {
		return nil
	}
	wasActive, err := e.ProductActive(ctx)
	if err != nil {
		return fmt.Errorf("ask whether the product runs: %w", err)
	}
	point, err := e.Snapshot(ctx)
	if err != nil {
		return fmt.Errorf("prepare the product update: %w", err)
	}
	// The point holds the product transaction lock through the upgrade and the restart.
	defer point.Close()
	// The installed package is the way back. A channel that no longer offers it does not hold the update back.
	if err := e.RetainPrevious(ctx, point.PackageDir()); err != nil {
		fmt.Fprintf(e.Log, "olivares-entitled-repo: update: the installed Olivares packages were not kept (%v); a rollback to this point will refuse\n", err)
	}
	upgradeErr := e.Upgrade(ctx)
	if upgradeErr != nil {
		upgradeErr = fmt.Errorf("upgrade the Olivares packages: %w", upgradeErr)
	}
	return errors.Join(upgradeErr, startAgain(ctx, e, wasActive))
}

// startAgain starts a product that was running before the transaction, also when the unit was told to stop.
func startAgain(ctx context.Context, e env, wasActive bool) error {
	if !wasActive {
		return nil
	}
	startCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), restartTimeout)
	defer cancel()
	if err := e.StartProduct(startCtx); err != nil {
		return fmt.Errorf("start the product: %w", err)
	}
	return nil
}

// editionPasses bounds the passes of one run: each pass re-reads the facts, so a licence removed while a swap ran is
// acted on in the same run, because a start request that arrives while this unit runs is merged into the running job
// and would be lost.
const editionPasses = 4

// restartTimeout bounds the start of the product after a swap.
const restartTimeout = 5 * time.Minute

// edition brings the installed edition to the one the licence earns, in one package transaction per pass.
//
// The facts it reads are each the owner's own: the licence file the product keeps (or a licence the unit's
// environment file hands the product), the repository file the last refresh wrote (its feature suite is the
// licensing service's answer for this licence now), and the package database. Only a missing file means "none";
// any other failure to read them stops the step before anything is changed, so a transient error never takes an
// edition away.
//
// The product stops with the package it belongs to and the new package starts nothing, so a product that was
// running is started again, also after a failed transaction, which may have stopped it, and also when the unit
// was told to stop. Data, configuration and keys belong to the product's state and are kept by both packages.
func edition(ctx context.Context, e env) error {
	var previous *entitled.Swap
	for pass := 0; pass < editionPasses; pass++ {
		swapped, err := editionPass(ctx, e, previous)
		if err != nil || swapped == nil {
			return err
		}
		previous = swapped
	}
	return fmt.Errorf("the edition did not settle after %d passes; the next run starts again from the facts", editionPasses)
}

// editionPass reads the facts once and makes at most one swap; it returns the swap it made, or nil. After a swap back
// (previous) the pass does not go forward again: the way to Business rests on the repository file the last refresh
// wrote, which may describe a licence that has since been replaced. A licence installed while a swap back ran waits
// for the next refresh, which starts this step again.
func editionPass(ctx context.Context, e env, previous *entitled.Swap) (*entitled.Swap, error) {
	fileLicensed, err := licencePresent(filepath.Join(e.DataDir, licenseFile))
	if err != nil {
		return nil, err
	}
	// A licence the product takes from its environment is no file in the data directory; without this a host licensed
	// that way would read as unlicensed and lose Business.
	envLicensed, err := licenceFromEnvironment(e.EnvFile)
	if err != nil {
		return nil, err
	}
	licensed := fileLicensed || envLicensed
	if previous != nil && previous.To == entitled.CommunityPackage && licensed {
		fmt.Fprintln(e.Log, "olivares-entitled-repo: edition: a licence was installed while the swap back ran; the next refresh decides")
		return nil, nil
	}
	repo, err := os.ReadFile(filepath.Join(e.RepoDir, entitled.RepoFile))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("read the entitled repository: %w", err)
	}
	community, err := e.Installed(ctx, entitled.CommunityPackage)
	if err != nil {
		return nil, fmt.Errorf("ask for %s: %w", entitled.CommunityPackage, err)
	}
	business, err := e.Installed(ctx, entitled.BusinessPackage)
	if err != nil {
		return nil, fmt.Errorf("ask for %s: %w", entitled.BusinessPackage, err)
	}
	feature := entitled.HasFeatureSuite(repo)
	swap, needed, err := entitled.Wanted(licensed, feature, community, business)
	decision := "keep the installed edition"
	if needed {
		decision = "swap " + swap.From + " for " + swap.To
	}
	fmt.Fprintf(e.Log, "olivares-entitled-repo: edition: licence file %t, licence in the environment %t, feature suite %t, %s installed: %s\n",
		fileLicensed, envLicensed, feature, installedName(community, business), decision)
	if err != nil {
		return nil, err
	}
	if !needed {
		// Without a licence the channel's credential has no use, and the refresh does not run to replace it. It goes
		// only once nothing is left to swap, so a swap back that failed can be tried again from the same channel.
		if !licensed {
			if err := os.Remove(filepath.Join(e.RepoDir, entitled.RepoFile)); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return nil, fmt.Errorf("remove the entitled repository: %w", err)
			}
		}
		return nil, nil
	}
	wasActive, err := e.ProductActive(ctx)
	if err != nil {
		return nil, fmt.Errorf("ask whether the product runs: %w", err)
	}
	// A channel that does not offer the edition yet leaves the product running and the kept points as they are;
	// the timer's next run asks again.
	offered, err := e.SwapOffered(ctx, swap)
	if err != nil {
		return nil, fmt.Errorf("ask the channel for %s: %w", swap.To, err)
	}
	if !offered {
		return nil, fmt.Errorf("the channel does not offer %s yet; the product is left as it is", swap.To)
	}
	point, err := e.Snapshot(ctx)
	if err != nil {
		return nil, fmt.Errorf("prepare the edition swap: %w", err)
	}
	// The point holds the product transaction lock through the swap and the restart; the next pass takes its own.
	defer point.Close()
	swapErr := e.Swap(ctx, swap)
	startErr := startAgain(ctx, e, wasActive)
	if swapErr != nil {
		return nil, errors.Join(fmt.Errorf("swap %s for %s: %w", swap.From, swap.To, swapErr), startErr)
	}
	return &swap, startErr
}

func installedName(community, business bool) string {
	switch {
	case community && !business:
		return entitled.CommunityPackage
	case business && !community:
		return entitled.BusinessPackage
	case community && business:
		return "both packages"
	}
	return "neither package"
}

// licenceFromEnvironment reports whether the product's environment file names a licence (OLIVARES_LICENSE or
// OLIVARES_LICENSE_PATH with a value), which outranks the data directory's file. A missing file names none.
func licenceFromEnvironment(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read the product's environment file: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && (key == "OLIVARES_LICENSE" || key == "OLIVARES_LICENSE_PATH") && strings.Trim(strings.TrimSpace(value), `"'`) != "" {
			return true, nil
		}
	}
	return false, nil
}

// licencePresent reports whether the product's licence file is there: missing is no licence, a file that is
// not a regular file or cannot be inspected is an error.
func licencePresent(path string) (bool, error) {
	info, err := os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("look for the licence: %w", err)
	case !info.Mode().IsRegular():
		return false, fmt.Errorf("look for the licence: %s is not a regular file", path)
	}
	return true, nil
}

// refresh obtains this invocation's credential and rewrites the repository file. Every refusal leaves the
// repository file as it was: an old credential keeps working until it expires, a half-written one never does.
func refresh(ctx context.Context, e env) error {
	cycle := e.Invocation
	if !id128.MatchString(cycle) {
		return errors.New("INVOCATION_ID is not a service invocation id: run it through olivares-entitled-repo.service")
	}
	uid, gid, err := e.Lookup(e.Product)
	if err != nil {
		return fmt.Errorf("look up the product user %s: %w", e.Product, err)
	}
	// The product publishes only into a directory of its own user with mode 0700; the unit's
	// RuntimeDirectory is created for root, so it is handed over before the product runs.
	if err := e.Chown(e.HandoffDir, uid, gid); err != nil {
		return fmt.Errorf("hand the handoff directory to %s: %w", e.Product, err)
	}
	defer func() { _ = os.Remove(filepath.Join(e.HandoffDir, cycle+".json")) }()

	ctx, cancel := context.WithTimeout(ctx, productTimeout)
	defer cancel()
	report, runErr := e.RunProduct(ctx, uid, gid,
		[]string{"license", "connect", "dnf-refresh", "--data-dir", e.DataDir, "--cycle", cycle},
		[]string{"PATH=/usr/sbin:/usr/bin", "LC_ALL=C", "HOME=" + e.DataDir, "INVOCATION_ID=" + cycle})
	doc, err := entitled.ReadHandoff(e.HandoffDir, cycle, cycle, uid)
	if err != nil {
		if runErr != nil {
			return fmt.Errorf("the product handed over nothing usable (%v): %w", runErr, err)
		}
		return err
	}
	if doc.Outcome != dnfrefresh.OutcomeIssued {
		code := ""
		if doc.Code != nil {
			code = " (" + *doc.Code + ")"
		}
		return fmt.Errorf("the product obtained no credential: outcome %s%s", doc.Outcome, code)
	}
	var rep struct {
		Endpoint string `json:"endpoint"`
	}
	if err := json.Unmarshal(report, &rep); err != nil {
		if runErr != nil {
			return fmt.Errorf("the product's report is not the JSON document it prints (the product: %v)", runErr)
		}
		return errors.New("the product's report is not the JSON document it prints")
	}
	content, err := entitled.Render(rep.Endpoint, doc, e.Now())
	if err != nil {
		return err
	}
	if err := entitled.Install(e.RepoDir, content); err != nil {
		return err
	}
	fmt.Fprintf(e.Log, "olivares-entitled-repo: class %s, suites %s, credential expires %s\n",
		*doc.Class, strings.Join(doc.Suites, " "), time.Unix(*doc.Exp, 0).UTC().Format(time.RFC3339))
	return nil
}
