// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package updates_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/olivaresai/olivares/appliance/layer/helpers/helperschema"
	"github.com/olivaresai/olivares/appliance/layer/hostops"
	"github.com/olivaresai/olivares/appliance/layer/portal/localsession"
	"github.com/olivaresai/olivares/appliance/layer/updates"
)

// delivery models what a trusted source leaves for the owner: two RPM files and the document that
// names them. state is the helper's empty private directory.
type delivery struct {
	host           *packageHost
	state, source  string
	previous, next updates.Artifact
	stateRoot      *os.Root
	from           *os.Root
}

func newDelivery(t *testing.T) *delivery {
	t.Helper()
	d := &delivery{state: t.TempDir(), source: t.TempDir()}
	for _, dir := range []string{d.state, d.source} {
		if err := os.Chmod(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	d.host = &packageHost{t: t, dir: d.state, installed: previousNEVRA}
	artifacts := []updates.Artifact{{Name: "olv-example", NEVRA: previousNEVRA, Repository: "baseos"}, {Name: "olv-example", NEVRA: nextNEVRA, Repository: "appstream"}}
	for i, kind := range []string{"previous", "next"} {
		data := []byte("delivered " + kind + " RPM")
		sum := sha256.Sum256(data)
		artifacts[i].SHA256 = hex.EncodeToString(sum[:])
		if err := os.WriteFile(filepath.Join(d.source, kind+".rpm"), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	d.previous, d.next = artifacts[0], artifacts[1]
	d.writeDocument(t, d.previous, d.next)
	var err error
	if d.stateRoot, err = os.OpenRoot(d.state); err != nil {
		t.Fatal(err)
	}
	if d.from, err = os.OpenRoot(d.source); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.stateRoot.Close(); d.from.Close() })
	return d
}

func (d *delivery) writeDocument(t *testing.T, previous, next updates.Artifact) {
	t.Helper()
	data, err := json.Marshal(map[string]any{"schema": "olivares-package-delivery/v1", "previous": previous, "next": next})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d.source, "delivery.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
}

func (d *delivery) rpm() updates.RPM { return updates.RPM{Root: d.stateRoot, Run: d.host.run} }

// retained lists what the helper's private directory holds.
func (d *delivery) retained(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(d.state)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestRetain_LeavesThePlanTheHelperServesAndTheActsCanRun(t *testing.T) {
	d := newDelivery(t)
	x := d.rpm()
	plan, err := x.Retain(t.Context(), d.from)
	if err != nil || plan.From != previousNEVRA || plan.To != nextNEVRA || len(plan.Digest) != 64 {
		t.Fatalf("retain: %+v %v", plan, err)
	}
	if len(d.host.replays) != 0 || d.host.installed != previousNEVRA {
		t.Fatal("retaining a plan changed the host", d.host.replays)
	}
	// The helper process starts afresh: it reloads the directory and answers the console's status.
	answer := updates.PackageAnswer(t.Context(), updates.RPM{Root: d.stateRoot, Run: d.host.run}, &updates.PackageRequest{Op: "status"})
	var status updates.PackageStatus
	if answer.Result != helperschema.ResultAnswered || json.Unmarshal(answer.Bundle, &status) != nil || status.Digest != plan.Digest || len(status.Descriptors) != 2 || status.Installed != previousNEVRA {
		t.Fatalf("status of the retained plan: %+v %+v", answer, status)
	}
	loaded, err := x.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if obs, err := x.Apply(t.Context(), loaded); err != nil || obs.P1 != "performed" || d.host.installed != nextNEVRA {
		t.Fatalf("apply of the retained plan: %+v %v", obs, err)
	}
	if obs, err := x.Recover(t.Context(), loaded); err != nil || obs.P1 != "performed" || d.host.installed != previousNEVRA {
		t.Fatalf("recovery of the retained plan: %+v %v", obs, err)
	}
}

// helperOverDirectory is the package helper as the console reaches it: each call is answered by
// PackageAnswer over the helper's directory, loaded afresh.
type helperOverDirectory struct{ x updates.RPM }

func (h helperOverDirectory) Call(ctx context.Context, _ string, r helperschema.Request) (helperschema.Response, error) {
	return updates.PackageAnswer(ctx, h.x, r.(*updates.PackageRequest)), nil
}

// The gap the issue measured: on an image nothing retained a plan, so the console composed no host-package task.
func TestRetain_TheConsoleComposesItsTwoPackageTasksFromTheRetainedPlanAndFromNothingElse(t *testing.T) {
	d := newDelivery(t)
	helper := helperOverDirectory{d.rpm()}
	_, before, err := localsession.CatalogWithPackages(t.Context(), []hostops.Descriptor{hostops.StatusDescriptor()}, helper)
	if err != nil || len(before) != 0 {
		t.Fatalf("with nothing retained the console composes %d package tasks (%v)", len(before), err)
	}
	plan, err := d.rpm().Retain(t.Context(), d.from)
	if err != nil {
		t.Fatal(err)
	}
	catalog, packages, err := localsession.CatalogWithPackages(t.Context(), []hostops.Descriptor{hostops.StatusDescriptor()}, helper)
	if err != nil || len(packages) != 2 {
		t.Fatalf("with a retained plan the console composes %d package tasks (%v), want 2", len(packages), err)
	}
	for _, verb := range []string{"update", "recover"} {
		got, err := catalog.Describe("host-package", verb, "cli")
		if err != nil || got.EquivalentCommand != "olivares-appliance host-package "+verb+" --plan" || !slices.Equal(got.InputSchema.Properties["native_plan"].Enum, []string{plan.Digest}) ||
			!strings.Contains(got.Consequence, previousNEVRA) || !strings.Contains(got.Consequence, nextNEVRA) {
			t.Errorf("host-package %s: %+v %v", verb, got, err)
		}
	}
}

func TestRetain_RefusalsLeaveTheDirectoryEmptyForTheNextTry(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		spoil      func(*testing.T, *delivery)
	}{
		{"a digest that is not the delivered file's", "artifact_changed", func(t *testing.T, d *delivery) {
			next := d.next
			next.SHA256 = strings.Repeat("0", 64)
			d.writeDocument(t, d.previous, next)
		}},
		{"an unsigned package", "artifact_signature_refused", func(_ *testing.T, d *delivery) { d.host.signatureError = true }},
		{"a package that is not the installed one", "package_changed", func(_ *testing.T, d *delivery) { d.host.installed = "olv-example-0.9-1.el10.noarch" }},
		{"a transaction rpm's test mode refuses", "package_preparation_failed", func(_ *testing.T, d *delivery) { d.host.testError = true }},
		{"a package that would remove another", "transaction_scope_refused", func(_ *testing.T, d *delivery) { d.host.obsoletes, d.host.installedNames = "bash\n", "" }},
		{"no delivery document", "retained_input_unavailable (delivery.json)", func(t *testing.T, d *delivery) {
			if err := os.Remove(filepath.Join(d.source, "delivery.json")); err != nil {
				t.Fatal(err)
			}
		}},
		{"a delivery document over 4096 bytes", "retained_input_unavailable (delivery.json)", func(t *testing.T, d *delivery) {
			if err := os.WriteFile(filepath.Join(d.source, "delivery.json"), []byte(strings.Repeat(" ", 4097)), 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"a missing package file", "retained_input_unavailable (next.rpm)", func(t *testing.T, d *delivery) {
			if err := os.Remove(filepath.Join(d.source, "next.rpm")); err != nil {
				t.Fatal(err)
			}
		}},
		{"an empty package file", "retained_input_unavailable (next.rpm)", func(t *testing.T, d *delivery) {
			if err := os.Truncate(filepath.Join(d.source, "next.rpm"), 0); err != nil {
				t.Fatal(err)
			}
		}},
		{"a package file over the size cap", "retained_input_unavailable (next.rpm)", func(t *testing.T, d *delivery) {
			if err := os.Truncate(filepath.Join(d.source, "next.rpm"), 64<<20+1); err != nil {
				t.Fatal(err)
			}
		}},
		{"a package file that is a link", "retained_input_unavailable (previous.rpm)", func(t *testing.T, d *delivery) {
			link := filepath.Join(d.source, "previous.rpm")
			if err := os.Remove(link); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("next.rpm", link); err != nil {
				t.Fatal(err)
			}
		}},
		{"a package file others can write", "retained_input_unavailable (previous.rpm)", func(t *testing.T, d *delivery) {
			if err := os.Chmod(filepath.Join(d.source, "previous.rpm"), 0666); err != nil {
				t.Fatal(err)
			}
		}},
		{"a delivery directory others can enter", "retained_input_unavailable", func(t *testing.T, d *delivery) {
			if err := os.Chmod(d.source, 0755); err != nil {
				t.Fatal(err)
			}
		}},
		{"a document with a field it does not define", "input_refused", func(t *testing.T, d *delivery) {
			// Everything else in it is valid: the extra field is the only defect.
			data, _ := json.Marshal(map[string]any{"schema": "olivares-package-delivery/v1", "previous": d.previous, "next": d.next, "path": "/etc/passwd"})
			if err := os.WriteFile(filepath.Join(d.source, "delivery.json"), data, 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"another schema", "input_refused", func(t *testing.T, d *delivery) {
			data, _ := json.Marshal(map[string]any{"schema": "olivares-package-delivery/v2", "previous": d.previous, "next": d.next})
			if err := os.WriteFile(filepath.Join(d.source, "delivery.json"), data, 0600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newDelivery(t)
			tc.spoil(t, d)
			_, err := d.rpm().Retain(t.Context(), d.from)
			if err == nil || err.Error() != tc.code {
				t.Fatalf("want %s, got %v", tc.code, err)
			}
			if left := d.retained(t); len(left) != 0 {
				t.Fatalf("a refused retention left %v behind", left)
			}
			if len(d.host.replays) != 0 {
				t.Fatal("a refused retention changed the host")
			}
		})
	}
}

func TestRetain_ACancelledContextWritesNothing(t *testing.T) {
	d := newDelivery(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := d.rpm().Retain(ctx, d.from); err == nil || err.Error() != "consumer_unavailable" || len(d.retained(t)) != 0 {
		t.Fatalf("%v, left %v", err, d.retained(t))
	}
}

func TestRetain_ARefusedTryDoesNotBlockTheNextOne(t *testing.T) {
	d := newDelivery(t)
	d.host.signatureError = true
	if _, err := d.rpm().Retain(t.Context(), d.from); err == nil {
		t.Fatal("an unsigned package was retained")
	}
	d.host.signatureError = false
	plan, err := d.rpm().Retain(t.Context(), d.from)
	if err != nil || plan.Digest == "" {
		t.Fatalf("the retry after a refusal: %+v %v", plan, err)
	}
}

func TestRetain_NeverReplacesARetainedPlanButAcceptsTheSamePairAgain(t *testing.T) {
	d := newDelivery(t)
	first, err := d.rpm().Retain(t.Context(), d.from)
	if err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, d.state)
	// The same pair again is the answer to a start whose console restart failed: the plan loads and nothing is written.
	again, err := d.rpm().Retain(t.Context(), d.from)
	if err != nil || again.Digest != first.Digest || !slices.Equal(before, snapshot(t, d.state)) {
		t.Fatalf("the same pair: %+v %v", again, err)
	}
	// Any other pair finds the plan and leaves it as it is: the retained previous RPM is the recovery of an
	// update that may have run.
	other := d.next
	other.SHA256 = strings.Repeat("1", 64)
	d.writeDocument(t, d.previous, other)
	if _, err = d.rpm().Retain(t.Context(), d.from); err == nil || err.Error() != "plan_exists" {
		t.Fatalf("want plan_exists, got %v", err)
	}
	if after := snapshot(t, d.state); !slices.Equal(before, after) {
		t.Fatalf("the retained plan changed:\n%v\n%v", before, after)
	}
}

func TestRetain_ClearsWhatAnInterruptedRetentionLeftWithoutAPlan(t *testing.T) {
	for name, leave := range map[string]func(*testing.T, string){
		"inputs and a half-built update": func(t *testing.T, state string) {
			for _, name := range []string{"previous.rpm", "next.rpm", ".hidden"} {
				if err := os.WriteFile(filepath.Join(state, name), []byte("half"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.MkdirAll(filepath.Join(state, "update", "packages"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(state, "update", "packages", "next.rpm"), []byte("half"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/etc/passwd", filepath.Join(state, "recovery")); err != nil {
				t.Fatal(err)
			}
		},
		"a plan.json with no bytes": func(t *testing.T, state string) {
			if err := os.WriteFile(filepath.Join(state, "plan.json"), nil, 0600); err != nil {
				t.Fatal(err)
			}
		},
		"a plan.json cut short": func(t *testing.T, state string) {
			if err := os.WriteFile(filepath.Join(state, "plan.json"), []byte(`{"schema":"olivares-package-plan/v1","previ`), 0600); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			d := newDelivery(t)
			leave(t, d.state)
			plan, err := d.rpm().Retain(t.Context(), d.from)
			if err != nil || plan.Digest == "" {
				t.Fatalf("retain over leftovers: %+v %v", plan, err)
			}
			if _, err := d.rpm().Load(t.Context()); err != nil {
				t.Fatalf("the retained plan does not load: %v", err)
			}
			if _, err := os.Lstat(filepath.Join(d.state, ".hidden")); err == nil {
				t.Fatal("a leftover survived")
			}
		})
	}
}

// A plan.json that cannot be read as a retained file is not a cut-short write: the directory may hold a plan whose update
// ran, so Retain refuses and leaves everything.
func TestRetain_LeavesAPlanFileItCannotReadAsAFile(t *testing.T) {
	for name, make_ := range map[string]func(*testing.T, string){
		"a link": func(t *testing.T, state string) {
			if err := os.Symlink("/etc/passwd", filepath.Join(state, "plan.json")); err != nil {
				t.Fatal(err)
			}
		},
		"a file others can write": func(t *testing.T, state string) {
			if err := os.WriteFile(filepath.Join(state, "plan.json"), []byte("{}"), 0666); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(filepath.Join(state, "plan.json"), 0666); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			d := newDelivery(t)
			make_(t, d.state)
			before := d.retained(t)
			if _, err := d.rpm().Retain(t.Context(), d.from); err == nil || err.Error() != "retained_input_unavailable" || !slices.Equal(before, d.retained(t)) {
				t.Fatalf("%v, left %v", err, d.retained(t))
			}
		})
	}
}

// snapshot is every file of the directory with its bytes, sorted.
func snapshot(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(path string, e os.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		out = append(out, strings.TrimPrefix(path, dir)+"="+string(data))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(out)
	return out
}
