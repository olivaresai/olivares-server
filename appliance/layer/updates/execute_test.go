// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package updates_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/olivaresai/olivares/appliance/layer/updates"
)

const previousNEVRA = "olv-example-1.0-1.el10.noarch"
const nextNEVRA = "olv-example-1.1-1.el10.noarch"

// The OS seam models rpm 4.19's "rpm -U" on one local file, its test mode and its native
// queries. It never launches RPM and uses actual private files for retained inputs.
type packageHost struct {
	t                                                       *testing.T
	dir, installed                                          string
	replays                                                 []string
	tests                                                   int
	signatureError, testError, replayError, lostMeasurement bool
	changedFailure, wrongMeasurement, installonly           bool
	multiversion, providesError, noChange                   bool
	obsoletes, previousObsoletes, installedNames            string
	lossAfter                                               int
	listingError                                            bool
	scoped                                                  []string
}

func (h *packageHost) run(_ context.Context, argv []string, _ int64) ([]byte, error) {
	if len(argv) < 2 {
		h.t.Fatal("empty native command")
	}
	switch argv[0] {
	case "/usr/bin/rpm":
		if h.lostMeasurement && len(h.replays) >= max(1, h.lossAfter) {
			return nil, errors.New("rpmdb unavailable")
		}
		if slices.Contains(argv, "--provides") {
			h.scoped = append(h.scoped, h.queriedFile(argv, "/usr/bin/rpm", "-qp", "--provides"))
			if h.providesError {
				return nil, errors.New("cannot read the package")
			}
			if h.installonly {
				return []byte("olv-example = 1.1-1.el10\ninstallonlypkg(kernel)\n"), nil
			}
			if h.multiversion {
				return []byte("olv-example = 1.1-1.el10\nmultiversion(kernel)\n"), nil
			}
			return []byte("olv-example = 1.1-1.el10\n"), nil
		}
		if slices.Contains(argv, "[%{OBSOLETENAME}\n]") {
			if strings.HasSuffix(h.queriedFile(argv, "/usr/bin/rpm", "-qp", "--queryformat", "[%{OBSOLETENAME}\n]"), "previous.rpm") && h.previousObsoletes != "" {
				return []byte(h.previousObsoletes), nil
			}
			return []byte(h.obsoletes), nil
		}
		if slices.Contains(argv, "-qa") {
			if !slices.Equal(argv, []string{"/usr/bin/rpm", "-qa", "--queryformat", "%{NAME}\n"}) {
				h.t.Fatal("unexpected installed listing", argv)
			}
			if h.listingError {
				return nil, errors.New("rpmdb listing cut")
			}
			return []byte("bash\nolv-example\n" + h.installedNames), nil
		}
		if slices.Contains(argv, "-qp") {
			if strings.HasSuffix(argv[len(argv)-1], "previous.rpm") {
				return []byte(previousNEVRA + "\n"), nil
			}
			return []byte(nextNEVRA + "\n"), nil
		}
		if argv[1] == "-U" {
			return h.upgrade(argv)
		}
		if !slices.Equal(argv, []string{"/usr/bin/rpm", "-q", "--queryformat", "%{NEVRA}\n", "--", "olv-example"}) {
			h.t.Fatal("unexpected RPM query", argv)
		}
		return []byte(h.installed + "\n"), nil
	case "/usr/bin/rpmkeys":
		if !slices.Equal(argv[:5], []string{"/usr/bin/rpmkeys", "--define", "_pkgverify_level signature", "--checksig", "--"}) {
			h.t.Fatal("signature enforcement absent", argv)
		}
		if h.signatureError {
			return nil, errors.New("unsigned package")
		}
		return []byte("digests signatures OK\n"), nil
	}
	h.t.Fatal("unexpected native command", argv)
	return nil, errors.New("unexpected command")
}

// queriedFile checks that argv is exactly prefix, "--", FILE with FILE one of the files rpm -U is run on (the prepared
// next package, the update's copy, the recovery's copy and the previous package), and returns FILE as a path under the
// bundle directory.
func (h *packageHost) queriedFile(argv []string, prefix ...string) string {
	if len(argv) != len(prefix)+2 || !slices.Equal(argv[:len(prefix)], prefix) || argv[len(prefix)] != "--" {
		h.t.Fatal("unexpected scope query", argv)
	}
	file := argv[len(argv)-1]
	rel, ok := strings.CutPrefix(file, h.dir+"/")
	if !ok || !slices.Contains([]string{"next.rpm", "previous.rpm", "update/packages/next.rpm", "recovery/packages/previous.rpm"}, rel) {
		h.t.Fatal("scope query on a file that is not retained", argv)
	}
	return rel
}

// upgrade models "rpm -U --define _pkgverify_level signature [--test] [--oldpackage] -- FILE": one file, signatures
// required, no other option, and the older package only for the recovery.
func (h *packageHost) upgrade(argv []string) ([]byte, error) {
	if !slices.Equal(argv[1:4], []string{"-U", "--define", "_pkgverify_level signature"}) {
		h.t.Fatal("signature enforcement absent from the upgrade", argv)
	}
	options, file := argv[4:len(argv)-2], argv[len(argv)-1]
	if argv[len(argv)-2] != "--" {
		h.t.Fatal("the package is not after --", argv)
	}
	test := slices.Contains(options, "--test")
	older := slices.Contains(options, "--oldpackage")
	// The test runs in the retaining unit's read-only filesystems, where rpm counts no free space and
	// would refuse every package that installs a file, so only the test skips the space check. The act
	// keeps it: a full disk must stop the transaction before it changes anything.
	if slices.Contains(options, "--ignoresize") != test || len(options) != 2*btoi(test)+btoi(older) {
		h.t.Fatal("unplanned rpm option", argv)
	}
	if test {
		h.tests++
		if older || file != filepath.Join(h.dir, "next.rpm") {
			h.t.Fatal("unexpected test run", argv)
		}
		if h.testError {
			return nil, errors.New("Failed dependencies")
		}
		return nil, nil
	}
	h.replays = append(h.replays, file)
	if h.noChange {
		return nil, nil
	}
	if h.replayError {
		if h.changedFailure {
			h.installed = nextNEVRA
		}
		return nil, errors.New("native transaction failed")
	}
	switch file {
	case filepath.Join(h.dir, "update/packages/next.rpm"):
		if older {
			h.t.Fatal("the update installs an older package", argv)
		}
		h.installed = nextNEVRA
	case filepath.Join(h.dir, "recovery/packages/previous.rpm"):
		if !older {
			h.t.Fatal("the recovery does not allow the older package", argv)
		}
		h.installed = previousNEVRA
	default:
		h.t.Fatal("unplanned native target", argv)
	}
	if h.wrongMeasurement {
		h.installed = "olv-example-1.2-1.el10.noarch"
	}
	return nil, nil
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

func fixture(t *testing.T) (*packageHost, *os.Root, updates.Artifact, updates.Artifact) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	h := &packageHost{t: t, dir: dir, installed: previousNEVRA}
	artifacts := []updates.Artifact{{Name: "olv-example", NEVRA: previousNEVRA, Repository: "baseos"}, {Name: "olv-example", NEVRA: nextNEVRA, Repository: "appstream"}}
	for i, kind := range []string{"previous", "next"} {
		data := []byte("verified " + kind + " RPM")
		sum := sha256.Sum256(data)
		artifacts[i].SHA256 = hex.EncodeToString(sum[:])
		if err := os.WriteFile(filepath.Join(dir, kind+".rpm"), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return h, root, artifacts[0], artifacts[1]
}

func TestRPM_OneRetainedPackageUpdatesAndRecoversWithMeasuredVersions(t *testing.T) {
	h, root, previous, next := fixture(t)
	x := updates.RPM{Root: root, Run: h.run}
	plan, err := x.Prepare(t.Context(), previous, next)
	if err != nil || plan.From != previousNEVRA || plan.To != nextNEVRA || plan.Repository != "appstream" || len(plan.Digest) != 64 || plan.RecoveryScope != "package-version-only" {
		t.Fatalf("plan %+v %v", plan, err)
	}
	if len(h.replays) != 0 || h.installed != previousNEVRA || h.tests != 1 {
		t.Fatal("prepare changed the host or skipped rpm's test mode", h.replays, h.tests)
	}
	obs, err := x.Apply(t.Context(), plan)
	if err != nil || obs.P1 != "performed" || !obs.MeasuredChange || obs.RevertMeasured || len(obs.Postconditions) == 0 {
		t.Fatalf("update %+v %v", obs, err)
	}
	obs, err = x.Recover(t.Context(), plan)
	if err != nil || obs.P1 != "performed" || !obs.RevertDefined || !obs.RevertMeasured || len(obs.Postconditions) == 0 {
		t.Fatalf("recovery %+v %v", obs, err)
	}
	if h.installed != previousNEVRA || !slices.Equal(h.replays, []string{filepath.Join(h.dir, "update/packages/next.rpm"), filepath.Join(h.dir, "recovery/packages/previous.rpm")}) {
		t.Fatal("native effects", h.installed, h.replays)
	}
}

func TestRPM_ReopeningTheNativeDirectoryRetainsExactRecovery(t *testing.T) {
	h, root, previous, next := fixture(t)
	x := updates.RPM{Root: root, Run: h.run}
	plan, err := x.Prepare(t.Context(), previous, next)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = x.Apply(t.Context(), plan); err != nil {
		t.Fatal(err)
	}
	if err = root.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := os.OpenRoot(h.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	x = updates.RPM{Root: reopened, Run: h.run}
	recoveredPlan, err := x.Load(t.Context())
	if err != nil || recoveredPlan.Digest != plan.Digest {
		t.Fatal("prepared native inputs were lost", recoveredPlan, err)
	}
	obs, err := x.Recover(t.Context(), recoveredPlan)
	if err != nil || !obs.RevertMeasured || h.installed != previousNEVRA || len(h.replays) != 2 {
		t.Fatal("reopened recovery", obs, h.replays, err)
	}
}

func TestRPM_UnverifiedRecoveryExtraTransactionsAndChangedPlansRefuseBeforeReplay(t *testing.T) {
	for _, cause := range []string{"missing recovery", "bad hash", "unsigned", "bad repo", "other architecture", "needs another package", "installonly package", "multiversion package", "provides unreadable", "obsoletes an installed package", "preparation failed", "changed installed", "edited plan", "changed artifact", "changed transaction", "caller plan", "public directory", "changed durable metadata", "replaced native directory", "linked native directory"} {
		t.Run(cause, func(t *testing.T) {
			h, root, previous, next := fixture(t)
			x := updates.RPM{Root: root, Run: h.run}
			preparationRefusal := true
			switch cause {
			case "missing recovery":
				if err := root.Remove("previous.rpm"); err != nil {
					t.Fatal(err)
				}
			case "bad hash":
				previous.SHA256 = strings.Repeat("0", 64)
			case "unsigned":
				h.signatureError = true
			case "bad repo":
				next.Repository = "*"
			case "other architecture":
				next.NEVRA = "olv-example-1.1-1.el10.aarch64"
				previous.NEVRA = "olv-example-1.0-1.el10.x86_64"
			case "needs another package":
				h.testError = true
			case "installonly package":
				h.installonly = true
			case "multiversion package":
				h.multiversion = true
			case "provides unreadable":
				h.providesError = true
			case "obsoletes an installed package":
				h.obsoletes, h.installedNames = "olv-example\nother-installed\n", "other-installed\n"
			case "preparation failed":
				h.testError = true
			default:
				preparationRefusal = false
			}
			plan, err := x.Prepare(t.Context(), previous, next)
			if preparationRefusal {
				if err == nil || len(h.replays) != 0 || h.installed != previousNEVRA {
					t.Fatal("unsafe plan admitted", plan, err, h.replays)
				}
				// A refused preparation leaves nothing retained that would block the next attempt.
				if _, statErr := root.Lstat("update"); statErr == nil {
					t.Fatal("a refused preparation left an update directory")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			nativeCalls := 0
			switch cause {
			case "changed installed":
				h.installed = nextNEVRA
			case "edited plan":
				plan.Repository = "foreign-repo"
			case "changed artifact":
				if err = os.WriteFile(filepath.Join(h.dir, "recovery/packages/previous.rpm"), []byte("changed RPM"), 0600); err != nil {
					t.Fatal(err)
				}
			case "changed transaction":
				if err = os.WriteFile(filepath.Join(h.dir, "update/transaction.json"), []byte(`{"version":"1.0","action":"Upgrade","nevra":"another-1-1.noarch","path":"packages/next.rpm"}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "caller plan":
				plan = updates.Plan{Name: "olv-example", From: previousNEVRA, To: nextNEVRA, Digest: strings.Repeat("a", 64)}
			case "public directory":
				if err = os.Chmod(h.dir, 0755); err != nil {
					t.Fatal(err)
				}
			case "replaced native directory", "linked native directory":
				retained := filepath.Join(t.TempDir(), "retained")
				if err = os.Rename(h.dir, retained); err != nil {
					t.Fatal(err)
				}
				if cause == "linked native directory" {
					err = os.Symlink(retained, h.dir)
				} else {
					err = os.Mkdir(h.dir, 0700)
				}
				if err != nil {
					t.Fatal(err)
				}
				// The held directory still has the verified inputs. Native
				// commands must not reopen a substituted pathname instead.
				x.Run = func(ctx context.Context, argv []string, limit int64) ([]byte, error) {
					nativeCalls++
					return h.run(ctx, argv, limit)
				}
			case "changed durable metadata":
				data, readErr := os.ReadFile(filepath.Join(h.dir, "plan.json"))
				if readErr != nil {
					t.Fatal(readErr)
				}
				data = []byte(strings.Replace(string(data), "appstream", "foreign-repo", 1))
				if err = os.WriteFile(filepath.Join(h.dir, "plan.json"), data, 0600); err != nil {
					t.Fatal(err)
				}
				if _, err = x.Load(t.Context()); err == nil || len(h.replays) != 0 {
					t.Fatal("changed durable plan admitted", err)
				}
				return
			}
			obs, err := x.Apply(t.Context(), plan)
			if err == nil || obs.P1 != "not-performed" || len(h.replays) != 0 {
				t.Fatal("changed plan executed", obs, err, h.replays)
			}
			if cause == "replaced native directory" || cause == "linked native directory" {
				if _, err = x.Load(t.Context()); err == nil {
					t.Fatal("substituted native pathname loaded")
				}
				if obs, err = x.Recover(t.Context(), plan); err == nil || obs.P1 != "not-performed" || nativeCalls != 0 {
					t.Fatal("substituted native pathname reached RPM or DNF", obs, err, nativeCalls)
				}
			}
		})
	}
}

func TestRPM_NativeFailureAndLostMeasurementsNeverClaimSuccessOrRetry(t *testing.T) {
	for _, cause := range []string{"native failed", "native failed after change", "postcondition differs", "rpm reports success and nothing changed", "update measurement lost", "recovery measurement lost"} {
		t.Run(cause, func(t *testing.T) {
			h, root, previous, next := fixture(t)
			x := updates.RPM{Root: root, Run: h.run}
			plan, err := x.Prepare(t.Context(), previous, next)
			if err != nil {
				t.Fatal(err)
			}
			expected, changed, calls := "failed", false, 1
			switch cause {
			case "native failed":
				h.replayError = true
			case "native failed after change":
				h.replayError = true
				h.changedFailure = true
				changed = true
			case "postcondition differs":
				h.wrongMeasurement = true
				expected = "partial"
				changed = true
			case "rpm reports success and nothing changed":
				h.noChange = true
				expected = "partial"
			case "update measurement lost":
				h.lostMeasurement = true
				expected = "unknown"
			case "recovery measurement lost":
				if _, err = x.Apply(t.Context(), plan); err != nil {
					t.Fatal(err)
				}
				h.lostMeasurement = true
				h.lossAfter = 2
				expected = "unknown"
				calls = 2
			}
			var obsP1 string
			var measured, reverted bool
			if cause == "recovery measurement lost" {
				obs, actErr := x.Recover(t.Context(), plan)
				obsP1, measured, reverted, err = obs.P1, obs.MeasuredChange, obs.RevertMeasured, actErr
			} else {
				obs, actErr := x.Apply(t.Context(), plan)
				obsP1, measured, reverted, err = obs.P1, obs.MeasuredChange, obs.RevertMeasured, actErr
			}
			if err == nil || obsP1 != expected || measured != changed || reverted || len(h.replays) != calls {
				t.Fatal("incorrect package outcome", obsP1, measured, reverted, err, h.replays)
			}
		})
	}
}

func TestRPM_AnObsoleteOfAPackageThatIsNotInstalledIsHarmless(t *testing.T) {
	h, root, previous, next := fixture(t)
	h.obsoletes, h.installedNames = "olv-example\nlong-gone-name\n", "unrelated\n"
	x := updates.RPM{Root: root, Run: h.run}
	if _, err := x.Prepare(t.Context(), previous, next); err != nil {
		t.Fatal("a rename history was refused", err)
	}
}

// What rpm -U does depends on the host when it runs, not when the plan was made: a package the update obsoletes, installed
// by an administrator between Prepare and the authorized act, must stop Apply and Recover before they reach rpm, and so
// must a listing rpm cannot give. Each check is asked of the file rpm -U is about to install.
func TestRPM_TheScopeIsAskedAgainOfTheFileAboutToBeInstalledByApplyAndRecover(t *testing.T) {
	for name, spoil := range map[string]struct {
		set  func(h *packageHost)
		code string
	}{
		"an obsoleted package is installed": {func(h *packageHost) {
			h.obsoletes, h.installedNames = "olv-example\nlate-installed\n", "late-installed\n"
		}, "transaction_scope_refused"},
		"the installed listing fails":     {func(h *packageHost) { h.obsoletes, h.listingError = "other-name\n", true }, "package_measurement_unavailable"},
		"the file turns out installonly":  {func(h *packageHost) { h.installonly = true }, "transaction_scope_refused"},
		"the file turns out multiversion": {func(h *packageHost) { h.multiversion = true }, "transaction_scope_refused"},
		"the provides cannot be read":     {func(h *packageHost) { h.providesError = true }, "transaction_scope_refused"},
	} {
		t.Run(name, func(t *testing.T) {
			h, root, previous, next := fixture(t)
			x := updates.RPM{Root: root, Run: h.run}
			plan, err := x.Prepare(t.Context(), previous, next)
			if err != nil {
				t.Fatal(err)
			}
			h.scoped = nil
			clean := *h
			spoil.set(h)
			if obs, err := x.Apply(t.Context(), plan); err == nil || err.Error() != spoil.code || obs.P1 != "not-performed" || len(h.replays) != 0 || h.installed != previousNEVRA {
				t.Fatal("Apply reached rpm", obs, err, h.replays)
			}
			*h = clean
			if _, err = x.Apply(t.Context(), plan); err != nil {
				t.Fatal(err)
			}
			if want := filepath.Join(h.dir, "update/packages/next.rpm"); h.replays[0] != want || !slices.Contains(h.scoped, "update/packages/next.rpm") || slices.Contains(h.scoped, "next.rpm") {
				t.Fatal("Apply asked about a file other than the one it installs", h.scoped, h.replays)
			}
			clean = *h
			spoil.set(h)
			if obs, err := x.Recover(t.Context(), plan); err == nil || err.Error() != spoil.code || obs.P1 != "not-performed" || len(h.replays) != 1 || h.installed != nextNEVRA {
				t.Fatal("Recover reached rpm", obs, err, h.replays)
			}
			*h = clean
			h.scoped = nil
			if _, err = x.Recover(t.Context(), plan); err != nil || h.installed != previousNEVRA {
				t.Fatal("the honest recovery was refused", err)
			}
			if !slices.Contains(h.scoped, "recovery/packages/previous.rpm") || slices.Contains(h.scoped, "update/packages/next.rpm") {
				t.Fatal("Recover asked about a file other than the one it installs", h.scoped)
			}
		})
	}
}

// A recovery that is already refused must not be promised: a previous package that obsoletes an installed package fails
// the preparation, not the recovery.
func TestRPM_APreviousPackageThatWouldEraseAnInstalledPackageHasNoPlan(t *testing.T) {
	h, root, previous, next := fixture(t)
	h.previousObsoletes, h.installedNames = "olv-example\nother-installed\n", "other-installed\n"
	x := updates.RPM{Root: root, Run: h.run}
	if plan, err := x.Prepare(t.Context(), previous, next); err == nil || err.Error() != "transaction_scope_refused" {
		t.Fatal("a plan whose recovery rpm would refuse was admitted", plan, err)
	}
	if _, statErr := root.Lstat("update"); statErr == nil {
		t.Fatal("a refused preparation left an update directory")
	}
}

// A step that is well formed but is not what the artifacts imply, with the plan's digest recomputed to cover it, is
// refused when the plan is reopened: the sealed step is rebuilt from the artifacts, never trusted from the files.
func TestRPM_AStepThatIsNotTheArtifactsOwnIsRefusedEvenWithItsDigestRecomputed(t *testing.T) {
	for name, forged := range map[string]struct{ update, recovery string }{
		"update installs the previous file": {`{"version":"1.0","action":"Upgrade","nevra":"` + nextNEVRA + `","path":"packages/previous.rpm"}`, ""},
		"update is a downgrade":             {`{"version":"1.0","action":"Downgrade","nevra":"` + nextNEVRA + `","path":"packages/next.rpm"}`, ""},
		"recovery installs the next file":   {"", `{"version":"1.0","action":"Downgrade","nevra":"` + previousNEVRA + `","path":"packages/next.rpm"}`},
		"recovery is an upgrade":            {"", `{"version":"1.0","action":"Upgrade","nevra":"` + previousNEVRA + `","path":"packages/previous.rpm"}`},
	} {
		t.Run(name, func(t *testing.T) {
			h, root, previous, next := fixture(t)
			x := updates.RPM{Root: root, Run: h.run}
			plan, err := x.Prepare(t.Context(), previous, next)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = x.Load(t.Context()); err != nil {
				t.Fatal("the honest plan does not reload", err)
			}
			update, _ := os.ReadFile(filepath.Join(h.dir, "update/transaction.json"))
			recovery, _ := os.ReadFile(filepath.Join(h.dir, "recovery/transaction.json"))
			if forged.update != "" {
				update = []byte(forged.update)
			}
			if forged.recovery != "" {
				recovery = []byte(forged.recovery)
			}
			for path, data := range map[string][]byte{"update/transaction.json": update, "recovery/transaction.json": recovery} {
				if err = os.WriteFile(filepath.Join(h.dir, path), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			metadata, _ := json.Marshal(map[string]any{"schema": "olivares-package-plan/v1", "previous": previous, "next": next,
				"update_rpm": "update/packages/next.rpm", "digest": updates.DigestWithSteps(plan, update, recovery)})
			if err = os.WriteFile(filepath.Join(h.dir, "plan.json"), metadata, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err = x.Load(t.Context()); err == nil || err.Error() != "plan_changed" {
				t.Fatal("a forged step with a recomputed digest was not refused as plan_changed", err)
			}
			if len(h.replays) != 0 {
				t.Fatal("a forged step reached rpm", h.replays)
			}
		})
	}
}
