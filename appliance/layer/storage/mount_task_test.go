// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package storage_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/olivaresai/olivares/appliance/layer/helpers/helperschema"
	"github.com/olivaresai/olivares/appliance/layer/hostops"
	"github.com/olivaresai/olivares/appliance/layer/portal/audit"
	"github.com/olivaresai/olivares/appliance/layer/storage"
)

type mountAuthority struct {
	deny  bool
	actor string
}

func (a mountAuthority) Authorize(_ context.Context, d hostops.Descriptor, target, digest string) (hostops.Caller, error) {
	caller := hostops.Caller{Actor: "fran", Mode: "product-up"}
	if a.actor != "" {
		caller.Actor = a.actor
	}
	if a.deny || !strings.HasPrefix(d.ID, "storage.") || !strings.HasPrefix(target, "drive:") || len(digest) != 64 {
		return caller, errors.New("denied")
	}
	return caller, nil
}
func mountCall(bus *mountBus, kernel *fakeKernel) storage.CallFunc {
	return func(ctx context.Context, name string, request helperschema.Request) (helperschema.Response, error) {
		if name != storage.HelperName || request.Validate() != nil {
			return helperschema.Response{}, errors.New("invalid fixed helper request")
		}
		switch r := request.(type) {
		case *storage.InventoryRequest:
			return storage.Answer(storage.Read(ctx, bus, kernel)), nil
		case *storage.MountRequest:
			return storage.MountAnswer(ctx, storage.MountExecutor{Bus: bus, Kernel: kernel}, r), nil
		}
		return helperschema.Response{}, errors.New("unexpected request")
	}
}
func TestMountTask_ConfirmedMountUnmountHaveAuditAndReplayNeverCallsNativeAgain(t *testing.T) {
	bus := newMountBus()
	kernel := &fakeKernel{boot: bootA}
	catalog, err := hostops.NewCatalog(append(storage.Descriptors(), storage.MountDescriptors()...))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	engine, err := hostops.OpenWithCatalog(dir, catalog)
	if err != nil {
		t.Fatal(err)
	}
	auditDir := t.TempDir()
	if err := os.Chmod(auditDir, 0700); err != nil {
		t.Fatal(err)
	}
	spool, err := audit.Open(auditDir)
	if err != nil {
		t.Fatal(err)
	}
	tasks := map[string]hostops.AdoptedTask{}
	for _, op := range []string{"mount", "unmount"} {
		tasks["storage."+op] = storage.MountTask{Op: op, Call: mountCall(bus, kernel)}
	}
	acts := hostops.NewActs(engine, catalog, tasks, hostops.SpoolAudit{Spool: spool})
	for i, op := range []string{"mount", "unmount"} {
		r := hostops.ApplyRequest{Module: "storage", Verb: op, Surface: "cli", OperationID: strings.Repeat([]string{"12", "34"}[i], 16), Inputs: json.RawMessage(`{"filesystem_uuid":"` + dataUUID + `"}`)}
		plan, err := acts.Plan(t.Context(), r.Module, r.Verb, r.Surface, r.Inputs, mountAuthority{})
		if err != nil || !plan.Permissions.Apply {
			t.Fatalf("plan: %+v %v", plan, err)
		}
		r.Confirmation = plan.Digest
		if _, status, err := acts.Apply(t.Context(), r, mountAuthority{actor: "another-operator"}); err == nil || status != 403 || len(bus.actions) != i {
			t.Fatal("another operator reused confirmation", status, err, bus.actions)
		}
		rec, status, err := acts.Apply(t.Context(), r, mountAuthority{})
		if err != nil || status != 200 || rec.State != hostops.StateSucceeded || !strings.HasPrefix(rec.Target, "drive:") || len(bus.actions) != i+1 {
			t.Fatalf("apply: %+v %d %v calls=%v", rec, status, err, bus.actions)
		}
		engine, err = hostops.OpenWithCatalog(dir, catalog)
		if err != nil {
			t.Fatal(err)
		}
		acts = hostops.NewActs(engine, catalog, tasks, hostops.SpoolAudit{Spool: spool})
		if again, _, err := acts.Apply(t.Context(), r, mountAuthority{}); err != nil || again.State != rec.State || len(bus.actions) != i+1 {
			t.Fatalf("replay: %+v %v calls=%v", again, err, bus.actions)
		}
	}
	events, err := spool.Pending()
	if err != nil || len(events) != 8 || events[0].Outcome != "refused" || events[2].Outcome != "performed" {
		t.Fatalf("audit: %+v %v", events, err)
	}
	t.Logf("native_calls=%v audit_events=%d; both reopened IDs retrieved without an effect", bus.actions, len(events))
}
func TestMountTask_TargetChangedAfterPlanRefusesBeforeEffect(t *testing.T) {
	bus := newMountBus()
	kernel := &fakeKernel{boot: bootA}
	task := storage.MountTask{Op: "mount", Call: mountCall(bus, kernel)}
	input := json.RawMessage(`{"filesystem_uuid":"` + dataUUID + `"}`)
	target, err := task.Prepare(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	bus.objects.Drives["/org/freedesktop/UDisks2/drives/data"] = storage.Drive{Serial: "replaced"}
	observation := task.Apply(t.Context(), hostops.Command{OperationID: strings.Repeat("a", 32), TaskID: "storage.mount", Module: "storage", Verb: "mount", Target: target}, input)
	if observation.P1 != "not-performed" || len(bus.actions) != 0 {
		t.Fatalf("changed target: %+v calls=%v", observation, bus.actions)
	}
}

func TestMountTask_BusyAndLostAnswersKeepTheirOutcomeWithoutAnImplicitRetry(t *testing.T) {
	for _, cause := range []string{"busy", "lost answer", "foreign operation"} {
		t.Run(cause, func(t *testing.T) {
			bus := newMountBus()
			kernel := &fakeKernel{boot: bootA}
			block := bus.objects.Blocks[dataPath]
			block.Filesystem = &storage.FilesystemFacts{MountPoints: []string{"/run/media/root/data"}}
			bus.objects.Blocks[dataPath] = block
			if cause == "busy" {
				bus.mountError = errors.New("org.freedesktop.UDisks2.Error.DeviceBusy")
			}
			call := mountCall(bus, kernel)
			wrapped := func(ctx context.Context, name string, r helperschema.Request) (helperschema.Response, error) {
				response, err := call(ctx, name, r)
				if _, effect := r.(*storage.MountRequest); effect {
					if cause == "lost answer" {
						return helperschema.Response{}, errors.New("answer lost after native call")
					}
					if cause == "foreign operation" {
						var body map[string]any
						if err := json.Unmarshal(response.Bundle, &body); err != nil {
							t.Fatal(err)
						}
						body["operation_id"] = strings.Repeat("f", 32)
						response.Bundle, err = json.Marshal(body)
					}
				}
				return response, err
			}
			catalog, err := hostops.NewCatalog(storage.MountDescriptors())
			if err != nil {
				t.Fatal(err)
			}
			engine, err := hostops.OpenWithCatalog(t.TempDir(), catalog)
			if err != nil {
				t.Fatal(err)
			}
			auditDir := t.TempDir()
			if err := os.Chmod(auditDir, 0700); err != nil {
				t.Fatal(err)
			}
			spool, err := audit.Open(auditDir)
			if err != nil {
				t.Fatal(err)
			}
			acts := hostops.NewActs(engine, catalog, map[string]hostops.AdoptedTask{"storage.unmount": storage.MountTask{Op: "unmount", Call: wrapped}}, hostops.SpoolAudit{Spool: spool})
			r := hostops.ApplyRequest{Module: "storage", Verb: "unmount", Surface: "cli", OperationID: strings.Repeat("a", 32), Inputs: json.RawMessage(`{"filesystem_uuid":"` + dataUUID + `"}`)}
			plan, err := acts.Plan(t.Context(), r.Module, r.Verb, r.Surface, r.Inputs, mountAuthority{})
			if err != nil {
				t.Fatal(err)
			}
			r.Confirmation = plan.Digest
			want := hostops.StateRunning
			if cause == "busy" {
				want = hostops.StateFailed
			}
			for range 2 {
				rec, _, err := acts.Apply(t.Context(), r, mountAuthority{})
				if err != nil || rec.State != want || len(bus.actions) != 1 {
					t.Fatalf("%s: %+v %v calls=%v", cause, rec, err, bus.actions)
				}
			}
		})
	}
}
