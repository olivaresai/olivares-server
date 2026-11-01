// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package updates

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/olivaresai/olivares/appliance/layer/hostops"
)

// install is rpm's upgrade of one retained file, with signature verification
// required (not the digest-only default); test proves it without installing, and
// recovery allows the older retained version. The test skips rpm's free-space check
// (--ignoresize) because the unit that prepares the plan has read-only filesystems,
// which rpm counts as having no space (measured on AlmaLinux 10, rpm 4.19.1.1: "needs
// 22MB more space on the / filesystem"); the act keeps the check.
func (RPM) install(recovery, test bool, path string) []string {
	argv := []string{"/usr/bin/rpm", "-U", "--define", "_pkgverify_level signature"}
	if test {
		argv = append(argv, "--test", "--ignoresize")
	}
	if recovery {
		argv = append(argv, "--oldpackage")
	}
	return append(argv, "--", path)
}

// withinScope refuses a retained file whose rpm -U would do more than replace the one installed package, which rpm's test
// mode cannot show: the file is installonly or multiversion (the older versions of a kernel would go), or it obsoletes an
// installed package other than itself (rpm -U would erase it, and recovery would not bring it back). An obsolete of a
// package that is not installed (the usual rename history) is harmless. A listing that cannot be read or is cut at the
// output limit refuses. Prepare asks it of next.rpm; Apply and Recover ask it again of the file they are about to install,
// because the installed set can change between the preparation and the authorized act.
func (x RPM) withinScope(ctx context.Context, path, name string) error {
	native := filepath.Join(x.Root.Name(), path)
	provides, err := x.Run(ctx, []string{"/usr/bin/rpm", "-qp", "--provides", "--", native}, 64<<10)
	if err != nil || bytes.Contains(provides, []byte("installonlypkg(")) || bytes.Contains(provides, []byte("multiversion(")) {
		return errors.New("transaction_scope_refused")
	}
	obsoleted, err := x.Run(ctx, []string{"/usr/bin/rpm", "-qp", "--queryformat", "[%{OBSOLETENAME}\n]", "--", native}, 64<<10)
	if err != nil {
		return errors.New("transaction_scope_refused")
	}
	var names []string
	for _, other := range strings.Split(strings.TrimSuffix(string(obsoleted), "\n"), "\n") {
		if other != "" && other != name {
			names = append(names, other)
		}
	}
	if len(names) == 0 {
		return nil
	}
	installed, err := x.Run(ctx, []string{"/usr/bin/rpm", "-qa", "--queryformat", "%{NAME}\n"}, 64<<10)
	if err != nil {
		return errors.New("package_measurement_unavailable")
	}
	for _, other := range strings.Split(string(installed), "\n") {
		if slices.Contains(names, other) {
			return errors.New("transaction_scope_refused")
		}
	}
	return nil
}

func (x RPM) available(ctx context.Context) error {
	if x.Root == nil || x.Run == nil || ctx.Err() != nil {
		return errors.New("consumer_unavailable")
	}
	info, err := x.Root.Stat(".")
	path := x.Root.Name()
	native, nativeErr := os.Lstat(path)
	resolved, resolveErr := filepath.EvalSymlinks(path)
	if err != nil || !info.IsDir() || !ownedByHelper(info) || info.Mode().Perm()&0077 != 0 || !filepath.IsAbs(path) || filepath.Clean(path) != path || nativeErr != nil || resolveErr != nil || resolved != path || !os.SameFile(info, native) {
		return errors.New("retained_input_unavailable")
	}
	return nil
}
func (x RPM) installed(ctx context.Context, name string) (string, error) {
	if !packageName.MatchString(name) {
		return "", errors.New("input_refused")
	}
	data, err := x.Run(ctx, []string{"/usr/bin/rpm", "-q", "--queryformat", "%{NEVRA}\n", "--", name}, 1024)
	if err != nil {
		return "", errors.New("package_measurement_unavailable")
	}
	value := strings.TrimSuffix(string(data), "\n")
	if len(value) > 256 || strings.ContainsAny(value, "\r\n\x00") || !strings.HasPrefix(value, name+"-") {
		return "", errors.New("package_measurement_unavailable")
	}
	return value, nil
}
func (x RPM) verify(ctx context.Context, path string, a Artifact) error {
	data, err := x.read(path, maxRPMBytes)
	if err != nil {
		return errors.New("recovery_input_unavailable")
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != a.SHA256 {
		return errors.New("artifact_changed")
	}
	native := filepath.Join(x.Root.Name(), path)
	if _, err = x.Run(ctx, []string{"/usr/bin/rpmkeys", "--define", "_pkgverify_level signature", "--checksig", "--", native}, 4096); err != nil {
		return errors.New("artifact_signature_refused")
	}
	data, err = x.Run(ctx, []string{"/usr/bin/rpm", "-qp", "--queryformat", "%{NEVRA}\n", "--", native}, 1024)
	if err != nil || string(data) != a.NEVRA+"\n" {
		return errors.New("artifact_identity_changed")
	}
	return nil
}
func (x RPM) validated(ctx context.Context, p Plan) error {
	if err := x.available(ctx); err != nil {
		return err
	}
	if p.seal == "" || p.seal != p.Digest || p.digest() != p.seal || p.bundle != x.Root.Name() {
		return errors.New("plan_changed")
	}
	for _, item := range []struct {
		path     string
		artifact Artifact
	}{{"previous.rpm", p.previous}, {"next.rpm", p.next}, {p.updateRPM, p.next}, {"recovery/packages/previous.rpm", p.previous}} {
		if err := x.verify(ctx, item.path, item.artifact); err != nil {
			return err
		}
	}
	// The sealed steps are what the artifacts imply and nothing else: the step is
	// rebuilt here, never taken from the stored bytes.
	if p.updateRPM != "update/"+updatePath || !bytes.Equal(p.update, sealedTransaction("Upgrade", p.next, updatePath)) ||
		!bytes.Equal(p.recovery, sealedTransaction("Downgrade", p.previous, recoveryPath)) {
		return errors.New("plan_changed")
	}
	for _, item := range []struct {
		path string
		data []byte
	}{{"update/transaction.json", p.update}, {"recovery/transaction.json", p.recovery}} {
		data, err := x.read(item.path, 16<<10)
		if err != nil || !bytes.Equal(data, item.data) {
			return errors.New("plan_changed")
		}
	}
	return nil
}

// Apply submits the sealed native transaction once. A caller must first obtain
// the existing exact-act host authorization. No retry is performed here, and a
// lost measurement after sending never proves success or absence of an effect.
func (x RPM) Apply(ctx context.Context, p Plan) (hostops.Observation, error) {
	return x.replay(ctx, p, false)
}

func (x RPM) replay(ctx context.Context, p Plan, recovery bool) (hostops.Observation, error) {
	refuse := func(err error) (hostops.Observation, error) { return hostops.Observation{P1: "not-performed"}, err }
	if err := x.validated(ctx, p); err != nil {
		return refuse(err)
	}
	before, after, dir, file := p.From, p.To, "update", updatePath
	if recovery {
		before, after, dir, file = p.To, p.From, "recovery", recoveryPath
	}
	current, err := x.installed(ctx, p.Name)
	if err != nil || current != before {
		return refuse(errors.New("package_changed"))
	}
	if err = x.withinScope(ctx, filepath.Join(dir, file), p.Name); err != nil {
		return refuse(err)
	}
	if ctx.Err() != nil {
		return refuse(errors.New("consumer_unavailable"))
	}
	_, actErr := x.Run(ctx, x.install(recovery, false, filepath.Join(x.Root.Name(), dir, file)), 64<<10)
	current, err = x.installed(ctx, p.Name)
	if err != nil {
		return hostops.Observation{P1: "unknown"}, err
	}
	changed := current != before
	if actErr != nil {
		return hostops.Observation{P1: "failed", MeasuredChange: changed}, errors.New("package_transaction_failed")
	}
	if current != after {
		return hostops.Observation{P1: "partial", MeasuredChange: changed}, errors.New("package_postcondition_missing")
	}
	obs := hostops.Observation{P1: "performed", MeasuredChange: changed, RevertDefined: true, Postconditions: []string{"package=" + p.Name, "installed=" + current, "recovery_scope=package-version-only"}}
	if recovery {
		obs.RevertMeasured = true
	} else {
		obs.Postconditions = append(obs.Postconditions, "repository="+p.Repository)
	}
	return obs, nil
}
