// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

// Package updates owns the single host-package path. It does not update the
// appliance, distribution or entitled modules, or promise restoration of files,
// scriptlet effects, application data or the whole system.
//
// The transaction is RPM's own. AlmaLinux 10 ships DNF 4.20, which cannot store a
// transaction without running it and has no stored form for a local package (its
// "history store" records an executed transaction, and "history replay" resolves
// packages from enabled repositories), so the retained, verified RPM is installed
// with "rpm -U" and recovered with "rpm -U --oldpackage". RPM replaces exactly the
// one package and refuses what needs another (a dependency, a conflict, a newer
// installed version), which is the scope this path promises; rpm's own test mode
// proves that before any authorization is asked for.
package updates

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/olivaresai/olivares/appliance/layer/hostops"
)

// Artifact comes from the trusted package/repository owner, never a caller's
// path or hash. The fixed helper retains previous.rpm and next.rpm in its own
// private operation directory before Prepare. This package does not fetch RPMs
// or change repository configuration or the RPM keyring.
type Artifact struct{ Name, NEVRA, Repository, SHA256 string }

// RPM runs inside the attested root helper under the existing host target lock.
// Root is a private, helper-owned operation directory. Run is the native command
// seam; LinuxRun is its production adapter. The portal must use the protected
// helper transport instead: olivares-portal-apt serves this package, and the portal
// composes the catalog from its status answer.
type RPM struct {
	Root *os.Root
	Run  func(context.Context, []string, int64) ([]byte, error)
}

// Plan binds the exact retained inputs and native transaction. The private seal
// refuses caller-created or edited values; host authority remains external.
// RecoveryScope describes the measured package version, not system rollback.
type Plan struct {
	Name, Repository, From, To, RecoveryScope, Digest string
	previous, next                                    Artifact
	update, recovery                                  []byte
	updateRPM, bundle                                 string
	seal                                              string
}

// transaction is the sealed record of one native step: the package version it
// installs and the retained file it installs it from. The plan writes it, and
// every later use checks it byte for byte against what the artifacts imply, so
// no stored value is ever trusted as a command.
type transaction struct {
	Version string `json:"version"`
	Action  string `json:"action"`
	NEVRA   string `json:"nevra"`
	Path    string `json:"path"`
}

const (
	updatePath   = "packages/next.rpm"
	recoveryPath = "packages/previous.rpm"
)

func sealedTransaction(action string, a Artifact, path string) []byte {
	// Four strings always marshal; an error here would be a broken encoder, and the sealed bytes would then never
	// equal the stored ones, so every later check refuses.
	data, _ := json.Marshal(transaction{Version: "1.0", Action: action, NEVRA: a.NEVRA, Path: path})
	return data
}

// This is the package input cache, not an operation/audit journal. The shared
// host operations still owns admission, duplicate IDs and outcome persistence.
type diskPlan struct {
	Schema    string   `json:"schema"`
	Previous  Artifact `json:"previous"`
	Next      Artifact `json:"next"`
	UpdateRPM string   `json:"update_rpm"`
	Digest    string   `json:"digest"`
}

var packageName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+_.-]{0,127}$`)
var versionPart = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+_.~^:]*$`)
var repositoryID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)

// Prepare verifies both retained RPMs, then proves with rpm's test mode (nothing
// is installed) that installing the next one replaces the installed previous
// version and needs nothing else: an extra dependency, a conflict or an older
// target fails the test and no plan exists. Two more things rpm -U would do are
// refused because the test cannot show them (withinScope): removing the older
// versions of an installonly package (a kernel; DNF's installonly_limit and the
// retained boot points keep them), and erasing an installed package the new one
// obsoletes. The previous file is asked too, so that no plan is made whose
// recovery would be refused at once.
func (x RPM) Prepare(ctx context.Context, previous, next Artifact) (Plan, error) {
	if err := x.available(ctx); err != nil {
		return Plan{}, err
	}
	if !validArtifact(previous) || !validArtifact(next) || previous.Name != next.Name || arch(previous.NEVRA) != arch(next.NEVRA) || previous.NEVRA == next.NEVRA {
		return Plan{}, errors.New("input_refused")
	}
	current, err := x.installed(ctx, previous.Name)
	if err != nil || current != previous.NEVRA {
		return Plan{}, errors.New("package_changed")
	}
	for _, item := range []struct {
		path     string
		artifact Artifact
	}{{"previous.rpm", previous}, {"next.rpm", next}} {
		if err = x.verify(ctx, item.path, item.artifact); err != nil {
			return Plan{}, err
		}
	}
	if _, err = x.Root.Lstat("update"); !errors.Is(err, os.ErrNotExist) {
		return Plan{}, errors.New("preparation_already_exists")
	}
	for _, file := range []string{"next.rpm", "previous.rpm"} {
		if err = x.withinScope(ctx, file, next.Name); err != nil {
			return Plan{}, err
		}
	}
	if _, err = x.Run(ctx, x.install(false, true, filepath.Join(x.Root.Name(), "next.rpm")), 64<<10); err != nil {
		return Plan{}, errors.New("package_preparation_failed")
	}
	if err = x.Root.Mkdir("update", 0700); err != nil {
		return Plan{}, errors.New("retained_input_unavailable")
	}
	if err = x.Root.Mkdir("update/packages", 0700); err != nil {
		return Plan{}, errors.New("retained_input_unavailable")
	}
	retained, err := x.read("next.rpm", maxRPMBytes)
	if err != nil || x.write("update/"+updatePath, retained) != nil {
		return Plan{}, errors.New("retained_input_unavailable")
	}
	if err = x.verify(ctx, "update/"+updatePath, next); err != nil {
		return Plan{}, err
	}
	update := sealedTransaction("Upgrade", next, updatePath)
	if x.write("update/transaction.json", update) != nil {
		return Plan{}, errors.New("retained_input_unavailable")
	}
	if err = x.Root.Mkdir("recovery", 0700); err != nil {
		return Plan{}, errors.New("recovery_unavailable")
	}
	if err = x.Root.Mkdir("recovery/packages", 0700); err != nil {
		return Plan{}, errors.New("recovery_unavailable")
	}
	old, err := x.read("previous.rpm", maxRPMBytes)
	if err != nil || x.write("recovery/"+recoveryPath, old) != nil {
		return Plan{}, errors.New("recovery_unavailable")
	}
	if err = x.verify(ctx, "recovery/"+recoveryPath, previous); err != nil {
		return Plan{}, err
	}
	// The exact inverse: the retained previous RPM, installed over the next one as
	// an older package.
	recovery := sealedTransaction("Downgrade", previous, recoveryPath)
	if x.write("recovery/transaction.json", recovery) != nil {
		return Plan{}, errors.New("recovery_unavailable")
	}
	p := Plan{Name: previous.Name, Repository: next.Repository, From: previous.NEVRA, To: next.NEVRA, RecoveryScope: "package-version-only", previous: previous, next: next, update: update, recovery: recovery, updateRPM: "update/" + updatePath, bundle: x.Root.Name()}
	p.Digest = p.digest()
	p.seal = p.Digest
	for _, name := range []string{"previous.rpm", "next.rpm", p.updateRPM, "update/transaction.json", "update/packages", "update", "recovery", "."} {
		f, syncErr := x.Root.Open(name)
		if syncErr != nil {
			return Plan{}, errors.New("retained_input_unavailable")
		}
		syncErr = f.Sync()
		closeErr := f.Close()
		if syncErr != nil || closeErr != nil {
			return Plan{}, errors.New("retained_input_unavailable")
		}
	}
	metadata, err := json.Marshal(diskPlan{Schema: "olivares-package-plan/v1", Previous: previous, Next: next, UpdateRPM: p.updateRPM, Digest: p.Digest})
	if err != nil || x.write("plan.json", metadata) != nil {
		return Plan{}, errors.New("retained_input_unavailable")
	}
	return p, nil
}

// Load reopens helper-owned prepared inputs after its process restarts. It
// validates those inputs and signatures without issuing an update or recovery.
func (x RPM) Load(ctx context.Context) (Plan, error) {
	if err := x.available(ctx); err != nil {
		return Plan{}, err
	}
	stored, err := x.readPlan()
	if err != nil {
		return Plan{}, err
	}
	update, err := x.read("update/transaction.json", 16<<10)
	if err != nil {
		return Plan{}, err
	}
	recovery, err := x.read("recovery/transaction.json", 16<<10)
	if err != nil {
		return Plan{}, err
	}
	p := Plan{Name: stored.Previous.Name, Repository: stored.Next.Repository, From: stored.Previous.NEVRA, To: stored.Next.NEVRA, RecoveryScope: "package-version-only", previous: stored.Previous, next: stored.Next, update: update, recovery: recovery, updateRPM: stored.UpdateRPM, bundle: x.Root.Name(), Digest: stored.Digest, seal: stored.Digest}
	if err = x.validated(ctx, p); err != nil {
		return Plan{}, err
	}
	return p, nil
}

// readPlan reads plan.json. A file that cannot be read as a retained file (a link, another owner, a loose mode, no
// size) is retained_input_unavailable; one that can be read and is not a plan is plan_changed.
func (x RPM) readPlan() (diskPlan, error) {
	metadata, err := x.read("plan.json", 4096)
	if err != nil {
		return diskPlan{}, err
	}
	var stored diskPlan
	if hostops.DecodeClosed(metadata, &stored) != nil || stored.Schema != "olivares-package-plan/v1" || !validArtifact(stored.Previous) || !validArtifact(stored.Next) || stored.Previous.Name != stored.Next.Name || arch(stored.Previous.NEVRA) != arch(stored.Next.NEVRA) || stored.Previous.NEVRA == stored.Next.NEVRA || stored.UpdateRPM != "update/"+updatePath {
		return diskPlan{}, errors.New("plan_changed")
	}
	return stored, nil
}

func validArtifact(a Artifact) bool {
	if !packageName.MatchString(a.Name) || !repositoryID.MatchString(a.Repository) || len(a.NEVRA) > 256 || !strings.HasPrefix(a.NEVRA, a.Name+"-") || len(a.SHA256) != 64 {
		return false
	}
	hash, err := hex.DecodeString(a.SHA256)
	if err != nil || len(hash) != 32 || strings.ToLower(a.SHA256) != a.SHA256 {
		return false
	}
	// Version and release can contain dots; the final dot separates architecture.
	value := strings.TrimPrefix(a.NEVRA, a.Name+"-")
	i := strings.LastIndex(value, ".")
	if i < 1 {
		return false
	}
	value = value[:i]
	architecture := arch(a.NEVRA)
	parts := strings.Split(value, "-")
	return len(parts) == 2 && len(parts[0]) <= 96 && len(parts[1]) <= 96 && versionPart.MatchString(parts[0]) && versionPart.MatchString(parts[1]) && slices.Contains([]string{"noarch", "x86_64", "aarch64"}, architecture)
}
func arch(nevra string) string {
	i := strings.LastIndex(nevra, ".")
	if i < 0 {
		return ""
	}
	return nevra[i+1:]
}

func (p Plan) digest() string {
	data, _ := json.Marshal([]any{p.Name, p.Repository, p.From, p.To, p.RecoveryScope, p.previous, p.next, p.update, p.recovery, p.updateRPM, p.bundle})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// maxRPMBytes bounds each retained RPM, and so the work of one status answer: Load verifies four files (hash,
// rpmkeys, rpm -qp) inside the console's 5 s budget (portal/localsession/packages.go). Measured on AlmaLinux 10
// (rpm 4.19.1.1) with four 63 MiB RPMs: 1.6 s with a cold page cache, 1.0 s warm. A larger cap needs a new
// measurement, because a status that runs out of budget composes no package task at all.
const maxRPMBytes = 64 << 20

func (x RPM) read(path string, limit int64) ([]byte, error) {
	info, err := x.Root.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || !ownedByHelper(info) || info.Mode().Perm()&0022 != 0 || info.Size() < 1 || info.Size() > limit {
		return nil, errors.New("retained_input_unavailable")
	}
	f, err := x.Root.Open(path)
	if err != nil {
		return nil, errors.New("retained_input_unavailable")
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("retained_input_unavailable")
	}
	return data, nil
}
func (x RPM) write(path string, data []byte) error {
	f, err := x.Root.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	syncErr := f.Sync()
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if syncErr != nil {
		return syncErr
	}
	if closeErr != nil {
		return closeErr
	}
	dir, err := x.Root.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
