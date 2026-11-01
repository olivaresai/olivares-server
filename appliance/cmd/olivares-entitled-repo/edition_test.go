// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/olivaresai/olivares/appliance/layer/entitled"
)

const (
	currentRepo      = "[olivares-entitled-security]\nname=Olivares entitled security\n\n[olivares-entitled-stable]\nname=Olivares entitled stable\n"
	securityOnlyRepo = "[olivares-entitled-security]\nname=Olivares entitled security\n"
)

// host is the machine the edition step acts on: which packages it holds, whether the product runs, and what was
// asked of it, in order. Its package manager is a function, so each test chooses what the transaction does. A swap
// that succeeds stops the product, as the removed package's scriptlet does; a start that succeeds runs it.
type host struct {
	e           env
	held        map[string]bool
	active      bool
	calls       []string
	swapErr     error
	startErr    error
	onSwap      func(h *host) // the world changing while the transaction runs
	startCtxErr error         // the error of the context the product was started with
	log         bytes.Buffer
}

func newHost(t *testing.T, held string, licensed bool, repo string) *host {
	t.Helper()
	h := &host{held: map[string]bool{held: true}}
	data, repoDir := t.TempDir(), t.TempDir()
	h.e = env{
		DataDir: data,
		RepoDir: repoDir,
		Log:     &h.log,
		Installed: func(_ context.Context, pkg string) (bool, error) {
			return h.held[pkg], nil
		},
		Swap: func(_ context.Context, s entitled.Swap) error {
			h.calls = append(h.calls, "swap "+s.From+" "+s.To)
			if h.onSwap != nil {
				h.onSwap(h)
			}
			if h.swapErr != nil {
				return h.swapErr
			}
			delete(h.held, s.From)
			h.held[s.To] = true
			h.active = false
			return nil
		},
		ProductActive: func(context.Context) (bool, error) { return h.active, nil },
		StartProduct: func(ctx context.Context) error {
			h.calls = append(h.calls, "start")
			h.startCtxErr = ctx.Err()
			if h.startErr == nil {
				h.active = true
			}
			return h.startErr
		},
	}
	h.setLicence(t, licensed)
	if repo != "" {
		if err := os.WriteFile(filepath.Join(repoDir, entitled.RepoFile), []byte(repo), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

func (h *host) setLicence(t *testing.T, on bool) {
	t.Helper()
	path := filepath.Join(h.e.DataDir, "license.key")
	if !on {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		return
	}
	if err := os.WriteFile(path, []byte("synthetic licence"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (h *host) repoExists() bool {
	_, err := os.Stat(filepath.Join(h.e.RepoDir, entitled.RepoFile))
	return err == nil
}

func TestEditionActivationSwapsCommunityForBusinessAndRestartsARunningProduct(t *testing.T) {
	h := newHost(t, "olivares", true, currentRepo)
	h.active = true
	if err := edition(context.Background(), h.e); err != nil {
		t.Fatal(err)
	}
	// The product stops with the old package and the new one starts nothing, so a product that ran must be started again.
	if got, want := h.calls, []string{"swap olivares olivares-business", "start"}; !slices.Equal(got, want) {
		t.Errorf("calls %q, want %q", got, want)
	}
	if !h.held["olivares-business"] || h.held["olivares"] {
		t.Errorf("host holds %v after the swap", h.held)
	}
	if !h.active {
		t.Error("the product that ran before the swap is not running after it")
	}
	if !h.repoExists() {
		t.Error("activation removed the entitled repository the Business package still updates from")
	}
}

func TestEditionActivationLeavesAStoppedProductStopped(t *testing.T) {
	h := newHost(t, "olivares", true, currentRepo)
	if err := edition(context.Background(), h.e); err != nil {
		t.Fatal(err)
	}
	if got, want := h.calls, []string{"swap olivares olivares-business"}; !slices.Equal(got, want) {
		t.Errorf("calls %q, want %q (first boot owns the first start)", got, want)
	}
	if h.active {
		t.Error("a product that was stopped was started")
	}
}

func TestEditionDeactivationReturnsToCommunityAndDropsTheCredential(t *testing.T) {
	h := newHost(t, "olivares-business", false, currentRepo)
	h.active = true
	if err := edition(context.Background(), h.e); err != nil {
		t.Fatal(err)
	}
	if got, want := h.calls, []string{"swap olivares-business olivares", "start"}; !slices.Equal(got, want) {
		t.Errorf("calls %q, want %q", got, want)
	}
	if h.repoExists() {
		t.Error("the entitled repository, which carries a download credential, is still there without a licence")
	}
	if !h.active {
		t.Error("the product that ran before the swap is not running after it")
	}
}

// The credential goes once nothing is left to swap: a swap back that failed is tried again from the same channel.
func TestEditionKeepsTheCredentialWhileTheWayBackFails(t *testing.T) {
	h := newHost(t, "olivares-business", false, currentRepo)
	h.swapErr = errors.New("no match for argument: olivares")
	if err := edition(context.Background(), h.e); err == nil {
		t.Fatal("a failed swap back was reported as success")
	}
	if !h.repoExists() {
		t.Error("the entitled repository was removed before the swap back succeeded")
	}
	if !h.held["olivares-business"] {
		t.Errorf("host holds %v after a failed swap", h.held)
	}
}

func TestEditionWithoutALicenceOnCommunityOnlyDropsTheStaleCredential(t *testing.T) {
	h := newHost(t, "olivares", false, currentRepo)
	if err := edition(context.Background(), h.e); err != nil {
		t.Fatal(err)
	}
	if len(h.calls) != 0 {
		t.Errorf("calls %q, want none", h.calls)
	}
	if h.repoExists() {
		t.Error("the stale entitled repository is still there")
	}
}

func TestEditionChangesNothingWhenTheLicenceAndTheHostAlreadyAgree(t *testing.T) {
	cases := []struct {
		name     string
		held     string
		licensed bool
		repo     string
	}{
		{"Business on a current licence", "olivares-business", true, currentRepo},
		{"Community without a licence", "olivares", false, ""},
		// An expired licence keeps its edition and gets security updates only.
		{"expired licence on Business", "olivares-business", true, securityOnlyRepo},
		{"expired licence on Community", "olivares", true, securityOnlyRepo},
		// The channel has not been refreshed (or the refresh failed): there is nothing to act on yet.
		{"licence but no repository on Community", "olivares", true, ""},
		{"licence but no repository on Business", "olivares-business", true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHost(t, tc.held, tc.licensed, tc.repo)
			h.active = true
			if err := edition(context.Background(), h.e); err != nil {
				t.Fatal(err)
			}
			if len(h.calls) != 0 {
				t.Errorf("calls %q, want none", h.calls)
			}
			if tc.licensed && tc.repo != "" && !h.repoExists() {
				t.Error("the repository of an installed licence was removed")
			}
		})
	}
}

// A failed transaction leaves the old edition installed; the product it may have stopped is started again, and the
// failure is the unit's, not a success.
func TestEditionFailedSwapReportsItAndStartsAProductItMayHaveStopped(t *testing.T) {
	h := newHost(t, "olivares", true, currentRepo)
	h.active = true
	h.swapErr = errors.New("no match for argument: olivares-business")
	err := edition(context.Background(), h.e)
	if err == nil || !strings.Contains(err.Error(), "no match for argument") {
		t.Fatalf("err = %v, want the package manager's failure", err)
	}
	if got, want := h.calls, []string{"swap olivares olivares-business", "start"}; !slices.Equal(got, want) {
		t.Errorf("calls %q, want %q", got, want)
	}
	if !h.held["olivares"] {
		t.Errorf("host holds %v after a failed swap", h.held)
	}
}

func TestEditionReportsASwapAndAStartThatBothFail(t *testing.T) {
	h := newHost(t, "olivares", true, currentRepo)
	h.active = true
	h.swapErr = errors.New("transaction failed")
	h.startErr = errors.New("unit failed")
	err := edition(context.Background(), h.e)
	if err == nil || !strings.Contains(err.Error(), "transaction failed") || !strings.Contains(err.Error(), "unit failed") {
		t.Fatalf("err = %v, want both failures", err)
	}
}

func TestEditionReportsAProductThatDoesNotStartAfterTheSwap(t *testing.T) {
	h := newHost(t, "olivares", true, currentRepo)
	h.active = true
	h.startErr = errors.New("unit failed")
	if err := edition(context.Background(), h.e); err == nil || !strings.Contains(err.Error(), "unit failed") {
		t.Fatalf("err = %v, want the start failure", err)
	}
}

// The unit is told to stop while a swap runs: the product still has to come back, with a context of its own.
func TestEditionStartsTheProductAfterTheUnitWasToldToStop(t *testing.T) {
	h := newHost(t, "olivares", true, currentRepo)
	h.active = true
	ctx, cancel := context.WithCancel(context.Background())
	h.onSwap = func(*host) { cancel() }
	_ = edition(ctx, h.e)
	if !slices.Contains(h.calls, "start") {
		t.Fatalf("calls %q: the product was not started", h.calls)
	}
	if h.startCtxErr != nil {
		t.Errorf("the product was started with a cancelled context: %v", h.startCtxErr)
	}
}

// Only a missing file means "no licence" or "no repository". Any other failure to read them must not be read as
// one, or a transient error would take Business away.
func TestEditionTakesNothingAwayOnAnUnreadableLicenceOrRepository(t *testing.T) {
	t.Run("data directory is not a directory", func(t *testing.T) {
		h := newHost(t, "olivares-business", false, currentRepo)
		file := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(file, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		h.e.DataDir = file
		if err := edition(context.Background(), h.e); err == nil {
			t.Fatal("an unreadable licence location was read as no licence")
		}
		if len(h.calls) != 0 || !h.repoExists() {
			t.Errorf("calls %q, repository kept %v: nothing may change", h.calls, h.repoExists())
		}
	})
	t.Run("licence is a directory", func(t *testing.T) {
		h := newHost(t, "olivares-business", false, currentRepo)
		if err := os.Mkdir(filepath.Join(h.e.DataDir, "license.key"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := edition(context.Background(), h.e); err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("err = %v, want a refusal of a licence that is not a regular file", err)
		}
		if len(h.calls) != 0 {
			t.Errorf("calls %q, want none", h.calls)
		}
	})
	t.Run("repository file is not a regular file", func(t *testing.T) {
		h := newHost(t, "olivares", true, "")
		if err := os.Mkdir(filepath.Join(h.e.RepoDir, entitled.RepoFile), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := edition(context.Background(), h.e); err == nil {
			t.Fatal("an unreadable repository was read as absent")
		}
		if len(h.calls) != 0 {
			t.Errorf("calls %q, want none", h.calls)
		}
	})
	t.Run("environment file is unreadable", func(t *testing.T) {
		h := newHost(t, "olivares-business", false, currentRepo)
		h.e.EnvFile = t.TempDir() // a directory: reading it fails with something other than "missing"
		if err := edition(context.Background(), h.e); err == nil {
			t.Fatal("an unreadable environment file was read as naming no licence")
		}
		if len(h.calls) != 0 || !h.repoExists() {
			t.Errorf("calls %q, repository kept %v: nothing may change", h.calls, h.repoExists())
		}
	})
}

// A host whose package database or service manager cannot be asked is not one to act on.
func TestEditionActsOnNothingItCouldNotAskAbout(t *testing.T) {
	boom := errors.New("cannot ask")
	for name, arm := range map[string]func(h *host){
		"community":     func(h *host) { h.e.Installed = func(_ context.Context, p string) (bool, error) { return false, boom } },
		"product state": func(h *host) { h.e.ProductActive = func(context.Context) (bool, error) { return false, boom } },
	} {
		t.Run(name, func(t *testing.T) {
			h := newHost(t, "olivares", true, currentRepo)
			arm(h)
			if err := edition(context.Background(), h.e); err == nil || !strings.Contains(err.Error(), "cannot ask") {
				t.Fatalf("err = %v, want the failure", err)
			}
			if len(h.calls) != 0 {
				t.Errorf("calls %q, want none", h.calls)
			}
		})
	}
}

func TestEditionRefusesAHostThatHoldsBothEditionsOrNeither(t *testing.T) {
	for _, held := range []map[string]bool{{"olivares": true, "olivares-business": true}, {}} {
		h := newHost(t, "olivares", true, currentRepo)
		h.held = held
		if err := edition(context.Background(), h.e); err == nil {
			t.Errorf("held %v: no refusal", held)
		}
		if len(h.calls) != 0 {
			t.Errorf("held %v: calls %q, want none", held, h.calls)
		}
	}
}

// OLIVARES_LICENSE and OLIVARES_LICENSE_PATH outrank the data directory's file, so a host licensed that way has no
// license.key and still has a licence.
func TestEditionDoesNotReturnToCommunityWhileTheEnvironmentFileNamesALicence(t *testing.T) {
	for name, line := range map[string]string{
		"path":   "OLIVARES_LICENSE_PATH=/etc/olivares/licence.blob",
		"inline": "OLIVARES_LICENSE=\"blob\"",
	} {
		t.Run(name, func(t *testing.T) {
			h := newHost(t, "olivares-business", false, currentRepo)
			h.e.EnvFile = filepath.Join(t.TempDir(), "olivares.env")
			if err := os.WriteFile(h.e.EnvFile, []byte("OLIVARES_LOG=info\n"+line+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := edition(context.Background(), h.e); err != nil {
				t.Fatal(err)
			}
			if len(h.calls) != 0 || !h.repoExists() {
				t.Errorf("calls %q, repository kept %v: a licensed Business host was changed", h.calls, h.repoExists())
			}
		})
	}
	for name, text := range map[string]string{
		"empty value": "OLIVARES_LICENSE_PATH=\n",
		"empty quote": "OLIVARES_LICENSE=''\n",
		"commented":   "# OLIVARES_LICENSE=blob\n",
		"other key":   "OLIVARES_LICENSE_NOTE=blob\n",
	} {
		t.Run("names none: "+name, func(t *testing.T) {
			h := newHost(t, "olivares-business", false, currentRepo)
			h.e.EnvFile = filepath.Join(t.TempDir(), "olivares.env")
			if err := os.WriteFile(h.e.EnvFile, []byte(text), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := edition(context.Background(), h.e); err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(h.calls, "swap olivares-business olivares") {
				t.Errorf("calls %q: a host with no licence stayed on Business", h.calls)
			}
		})
	}
}

// A start request that arrives while the unit runs is merged into the running job; the next pass reads the facts again.
func TestEditionActsOnALicenceThatChangedWhileASwapRan(t *testing.T) {
	h := newHost(t, "olivares", true, currentRepo)
	removed := false
	h.onSwap = func(h *host) {
		if !removed {
			removed = true
			h.setLicence(t, false)
		}
	}
	if err := edition(context.Background(), h.e); err != nil {
		t.Fatal(err)
	}
	if got, want := h.calls, []string{"swap olivares olivares-business", "swap olivares-business olivares"}; !slices.Equal(got, want) {
		t.Errorf("calls %q, want %q", got, want)
	}
	if !h.held["olivares"] || h.held["olivares-business"] || h.repoExists() {
		t.Errorf("host holds %v, repository kept %v: the run did not converge to the removed licence", h.held, h.repoExists())
	}
}

// The way to Business rests on the repository file the last refresh wrote; a licence installed while a swap back ran
// may be a different one, so it waits for the next refresh instead of reusing the old credential.
func TestEditionDoesNotSwapToBusinessOnAStaleRepositoryAfterALicenceWasInstalledDuringTheWayBack(t *testing.T) {
	h := newHost(t, "olivares-business", false, currentRepo)
	h.onSwap = func(h *host) { h.setLicence(t, true) }
	if err := edition(context.Background(), h.e); err != nil {
		t.Fatal(err)
	}
	if got, want := h.calls, []string{"swap olivares-business olivares"}; !slices.Equal(got, want) {
		t.Errorf("calls %q, want %q (the next refresh decides)", got, want)
	}
	if !h.repoExists() {
		t.Error("the repository file was removed although a licence is installed again")
	}
	if !strings.Contains(h.log.String(), "the next refresh decides") {
		t.Errorf("the log does not say why the step stopped: %q", h.log.String())
	}
}

func TestEditionStopsAfterAFewPassesOfASwapThatChangesNothing(t *testing.T) {
	// A package manager that reports success and leaves the host as it was makes every pass want the same swap.
	h := newHost(t, "olivares-business", false, currentRepo)
	h.e.Swap = func(_ context.Context, s entitled.Swap) error {
		h.calls = append(h.calls, "swap "+s.From+" "+s.To)
		return nil
	}
	err := edition(context.Background(), h.e)
	if err == nil || !strings.Contains(err.Error(), "did not settle") {
		t.Fatalf("err = %v, want the did-not-settle failure", err)
	}
	if n := len(h.calls); n != editionPasses {
		t.Errorf("%d swaps, want %d (the bound)", n, editionPasses)
	}
}

func TestEditionSaysWhatItDecidedAndNeverLogsTheCredential(t *testing.T) {
	h := newHost(t, "olivares", true, currentRepo+"password="+credential+"\n")
	if err := edition(context.Background(), h.e); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"licence file true", "feature suite true", "olivares installed", "swap olivares for olivares-business"} {
		if !strings.Contains(h.log.String(), want) {
			t.Errorf("the log lacks %q: %q", want, h.log.String())
		}
	}
	if strings.Contains(h.log.String(), credential) {
		t.Error("the log carries the credential")
	}
	// A decision to change nothing is logged too: a licensed host that stays on Community has to say why.
	h = newHost(t, "olivares", true, securityOnlyRepo)
	if err := edition(context.Background(), h.e); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(h.log.String(), "feature suite false") || !strings.Contains(h.log.String(), "keep the installed edition") {
		t.Errorf("the log does not say why nothing changed: %q", h.log.String())
	}
}

// run reaches the verb it was given, and no other.
func TestRunDispatchesEachVerbToItsStep(t *testing.T) {
	h := newHost(t, "olivares", true, currentRepo)
	previous := liveEnv
	liveEnv = func() env { return h.e }
	t.Cleanup(func() { liveEnv = previous })
	var stderr bytes.Buffer
	if code := run(context.Background(), []string{"edition"}, nil, &stderr); code != 0 {
		t.Fatalf("run(edition) = %d: %s", code, stderr.String())
	}
	if !slices.Contains(h.calls, "swap olivares olivares-business") {
		t.Errorf("calls %q: the edition verb did not reach the edition step", h.calls)
	}
	// refresh reaches refresh, which refuses outside a service invocation (no INVOCATION_ID in this environment).
	stderr.Reset()
	if code := run(context.Background(), []string{"refresh"}, nil, &stderr); code != 1 || !strings.Contains(stderr.String(), "INVOCATION_ID") {
		t.Errorf("run(refresh) = %d, %q: the refresh verb did not reach the refresh step", code, stderr.String())
	}
}

func TestRunTakesEditionAsAVerbAndNothingElse(t *testing.T) {
	var stderr bytes.Buffer
	for _, args := range [][]string{{}, {"status"}, {"edition", "x"}, {"refresh", "edition"}} {
		if code := run(context.Background(), args, nil, &stderr); code != 2 {
			t.Errorf("run(%q) = %d, want 2", args, code)
		}
	}
	if !strings.Contains(stderr.String(), "edition") {
		t.Errorf("the usage does not name the edition verb: %q", stderr.String())
	}
}
