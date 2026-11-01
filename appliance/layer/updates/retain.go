// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package updates

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/olivaresai/olivares/appliance/layer/hostops"
)

// DeliverySchema names the document a trusted source leaves beside the two RPM files it
// delivers: delivery.json, previous.rpm and next.rpm in one root-owned private directory. The
// document says which package each file is and the SHA-256 the source expects of it; it is
// an input to Prepare, which verifies it, and never a command. The signature the preinstalled
// rpm keyring verifies is what makes a package genuine; this package does not choose which
// package a source may deliver, so that source must be root's alone.
const DeliverySchema = "olivares-package-delivery/v1"

type delivery struct {
	Schema   string   `json:"schema"`
	Previous Artifact `json:"previous"`
	Next     Artifact `json:"next"`
}

// Retain is the one writer of the retained plan. It takes the two RPM files a trusted source
// delivered in from (it fetches nothing), copies them into the helper's private directory and
// calls Prepare, which verifies both files, proves the transaction with rpm's test mode and
// leaves plan.json last. The console's package tasks exist only once that file does.
//
// An act needs a plan, so what Retain writes can be acted on only once plan.json is whole, and
// Retain refuses to replace a plan (plan_exists: the retained previous RPM is the recovery of an
// update that may have run). The same pair delivered again is not a replacement: it loads the plan
// and succeeds, which lets a start whose console restart failed be run again. A refused or
// interrupted retention leaves no plan, so what it left (inputs, or a plan.json that is empty or
// not a plan) is cleared and the next try starts empty. An exclusive lock on the directory
// refuses a second Retain while one runs (retention_running), so that the cleanup of one cannot
// remove the plan another has just written.
func (x RPM) Retain(ctx context.Context, from *os.Root) (Plan, error) {
	source := RPM{Root: from, Run: x.Run}
	if err := x.available(ctx); err != nil {
		return Plan{}, err
	}
	if err := source.available(ctx); err != nil {
		return Plan{}, err
	}
	dir, err := x.Root.Open(".")
	if err != nil {
		return Plan{}, errors.New("retained_input_unavailable")
	}
	defer dir.Close()
	if lockDirectory(dir) != nil {
		return Plan{}, errors.New("retention_running")
	}
	document, err := source.read("delivery.json", 4096)
	if err != nil {
		return Plan{}, named(err, "delivery.json")
	}
	var d delivery
	if hostops.DecodeClosed(document, &d) != nil || d.Schema != DeliverySchema || !validArtifact(d.Previous) || !validArtifact(d.Next) {
		return Plan{}, errors.New("input_refused")
	}
	if retained, err := x.retainedPlan(); err != nil {
		return Plan{}, err
	} else if retained != nil {
		if retained.Previous == d.Previous && retained.Next == d.Next {
			return x.Load(ctx)
		}
		return Plan{}, errors.New("plan_exists")
	}
	files := map[string][]byte{}
	for _, name := range []string{"previous.rpm", "next.rpm"} {
		if files[name], err = source.read(name, maxRPMBytes); err != nil {
			return Plan{}, named(err, name)
		}
	}
	if err = x.clear(); err != nil {
		return Plan{}, errors.New("retained_input_unavailable")
	}
	for _, name := range []string{"previous.rpm", "next.rpm"} {
		if err = x.write(name, files[name]); err != nil {
			_ = x.clear()
			return Plan{}, errors.New("retained_input_unavailable")
		}
	}
	plan, err := x.Prepare(ctx, d.Previous, d.Next)
	if err != nil {
		// A failed cleanup is not a second error to report: the next Retain clears again first.
		_ = x.clear()
		return Plan{}, err
	}
	return plan, nil
}

// retainedPlan returns the plan the directory holds, or nil when it holds none that could have been acted on: no
// plan.json, one with no bytes, or one that is read as a file and is not a plan (a write that was cut short). A
// plan.json that cannot be read as a retained file is an error and is left alone.
func (x RPM) retainedPlan() (*diskPlan, error) {
	info, err := x.Root.Lstat("plan.json")
	if errors.Is(err, os.ErrNotExist) || err == nil && info.Mode().IsRegular() && info.Size() == 0 {
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("retained_input_unavailable")
	}
	stored, err := x.readPlan()
	if err != nil && err.Error() == "plan_changed" {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &stored, nil
}

// named adds the file an input error is about, to the code it keeps.
func named(err error, file string) error { return fmt.Errorf("%w (%s)", err, file) }

// clear empties the helper's directory. It is called only while no plan is retained.
func (x RPM) clear() error {
	entries, err := fs.ReadDir(x.Root.FS(), ".")
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err = x.Root.RemoveAll(e.Name()); err != nil {
			return err
		}
	}
	return nil
}
