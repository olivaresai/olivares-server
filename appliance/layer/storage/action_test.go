// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package storage_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/olivaresai/olivares/appliance/layer/helpers/helperschema"
	"github.com/olivaresai/olivares/appliance/layer/storage"
)

func TestActionAnswerJournalsNativeFailureWithoutReturningItsDetails(t *testing.T) {
	var journal bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&journal, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	inv := actionInventory(t)
	r := &storage.ActionRequest{Op: "backup", OperationID: strings.Repeat("a", 32), Identity: inv.Disks[0].Identity}
	const nativeError = "measure backup disk sequence: native probe failed"
	x := storage.ActionExecutor{Read: func(context.Context) (storage.Inventory, error) { return inv, nil }, Backup: func(context.Context, storage.Disk) (string, error) { return "", errors.New(nativeError) }}
	response := storage.ActionAnswer(t.Context(), x, r)
	if response.Result != helperschema.ResultFailed || strings.Contains(string(response.Bundle), nativeError) {
		t.Fatalf("native failure escaped measured response: %+v", response)
	}
	for _, want := range []string{"storage action failed", "op=backup", "operation_id=" + r.OperationID, "outcome=failed", nativeError} {
		if !strings.Contains(journal.String(), want) {
			t.Fatalf("missing diagnostic %q in %s", want, journal.String())
		}
	}
}

func actionInventory(t *testing.T) storage.Inventory {
	t.Helper()
	bus := newMountBus()
	block := bus.objects.Blocks[dataPath]
	block.IDUsage = ""
	block.IDType = ""
	block.IDUUID = ""
	block.Filesystem = nil
	bus.objects.Blocks[dataPath] = block
	return read(t, &bus.fakeBus, &fakeKernel{boot: bootA})
}

func TestInventory_ReadOnlyMediaFact(t *testing.T) {
	bus := newMountBus()
	block := bus.objects.Blocks[dataPath]
	block.ReadOnly = true
	bus.objects.Blocks[dataPath] = block
	inv := read(t, &bus.fakeBus, &fakeKernel{boot: bootA})
	if !inv.Disks[0].ReadOnly {
		t.Fatal("inventory dropped the native read-only fact")
	}
}

func TestDiskActions_ReadOnlyMediaNeverReachesAnEffect(t *testing.T) {
	for _, op := range []string{"backup", "grow"} {
		t.Run(op, func(t *testing.T) {
			inv := actionInventory(t)
			d := &inv.Disks[0]
			if op == "grow" {
				d.System, d.PartitionTable = true, "gpt"
				d.Partitions = []storage.Partition{{Device: "/dev/sdb1", Number: 1, Offset: 1 << 20, Size: 512 << 20, Filesystem: &storage.Filesystem{Type: "btrfs", UUID: dataUUID, MountPoints: []string{"/"}}}}
			}
			if _, err := storage.SelectAction(inv, op, d.Identity.Digest); err != nil {
				t.Fatalf("writable control refused: %v", err)
			}
			d.ReadOnly = true
			calls := 0
			x := storage.ActionExecutor{Read: func(context.Context) (storage.Inventory, error) { return inv, nil },
				Backup: func(context.Context, storage.Disk) (string, error) {
					calls++
					return "", errors.New("unexpected format")
				},
				Grow: func(context.Context, storage.Disk) error { calls++; return errors.New("unexpected grow") }}
			obs, err := x.Apply(t.Context(), op, d.Identity)
			if err == nil || obs.P1 != "not-performed" || calls != 0 {
				t.Fatalf("read-only media reached %s: %+v %v calls=%d", op, obs, err, calls)
			}
		})
	}
}
func TestDiskActionsSystemDiskCannotBecomeBackupAndOnlyMountedRootCanGrow(t *testing.T) {
	inv := actionInventory(t)
	inv.Disks[0].System = true
	for _, op := range []string{"backup", "grow"} {
		if _, err := storage.SelectAction(inv, op, inv.Disks[0].Identity.Digest); err == nil {
			t.Fatalf("%s accepted system disk without a mounted root", op)
		}
	}
	d := &inv.Disks[0]
	d.PartitionTable = "gpt"
	d.Partitions = []storage.Partition{{Device: "/dev/sdb1", Number: 1, Offset: 1 << 20, Size: 512 << 20, Filesystem: &storage.Filesystem{Type: "btrfs", UUID: dataUUID, MountPoints: []string{"/"}}, Consumers: []storage.Consumer{{Kind: storage.ConsumerMount, Name: "/"}}}}
	if _, err := storage.SelectAction(inv, "grow", d.Identity.Digest); err != nil {
		t.Fatal(err)
	}
	d.Partitions = append(d.Partitions, storage.Partition{Number: 2, Offset: 900 << 20, Size: 1 << 20})
	if _, err := storage.SelectAction(inv, "grow", d.Identity.Digest); err == nil {
		t.Fatal("grew root with a later partition")
	}
}
func TestBackupActionReresolvesAndMeasuresMountBeforeReportingPerformed(t *testing.T) {
	inv := actionInventory(t)
	captured := inv.Disks[0].Identity
	calls := 0
	x := storage.ActionExecutor{Read: func(context.Context) (storage.Inventory, error) { return inv, nil }, Backup: func(_ context.Context, d storage.Disk) (string, error) {
		calls++
		target := "/mnt/olivares-backups/" + dataUUID
		inv.Disks[0].Filesystem = &storage.Filesystem{Type: "ext4", UUID: dataUUID, MountPoints: []string{target}}
		return target, nil
	}}
	got, err := x.Apply(t.Context(), "backup", captured)
	if err != nil || got.P1 != "performed" || !strings.Contains(strings.Join(got.Postconditions, ";"), "backup_target=/mnt/olivares-backups/"+dataUUID) || calls != 1 {
		t.Fatalf("%+v %v calls=%d", got, err, calls)
	}
	inv.Disks[0].Identity.Digest = strings.Repeat("f", 64)
	if got, err = x.Apply(t.Context(), "backup", captured); err == nil || got.P1 != "not-performed" || calls != 1 {
		t.Fatalf("changed identity: %+v %v calls=%d", got, err, calls)
	}
}
func TestDiskActionNativeFailureNeverClaimsSuccessOrRetries(t *testing.T) {
	inv := actionInventory(t)
	calls := 0
	x := storage.ActionExecutor{Read: func(context.Context) (storage.Inventory, error) { return inv, nil }, Backup: func(context.Context, storage.Disk) (string, error) { calls++; return "", errors.New("native failure") }}
	got, err := x.Apply(t.Context(), "backup", inv.Disks[0].Identity)
	if err == nil || got.P1 == "performed" || calls != 1 {
		t.Fatalf("%+v %v calls=%d", got, err, calls)
	}
}

func TestDiskActionCapabilityDriftIsNotAMeasuredDiskChange(t *testing.T) {
	inv := actionInventory(t)
	captured := inv.Disks[0].Identity
	x := storage.ActionExecutor{Read: func(context.Context) (storage.Inventory, error) { return inv, nil }, Backup: func(context.Context, storage.Disk) (string, error) {
		inv.Disks[0].Operations = []storage.Operation{{Name: storage.OperationFormat, Type: "ext4", Disabled: "native_tool_unavailable"}}
		return "", errors.New("native failure before any disk write")
	}}
	got, err := x.Apply(t.Context(), "backup", captured)
	if err == nil || got.P1 != "failed" || got.MeasuredChange {
		t.Fatalf("advisory capability drift is not a disk change: %+v %v", got, err)
	}
}

func TestGrowDefinitionsMatchEveryExistingPartitionWithoutCreatingFormattingOrGrowingBoot(t *testing.T) {
	const generic = "0fc63daf-8483-4772-8e79-3d69d8477de4"
	d := storage.Disk{Device: "/dev/vda", Size: 20 << 30, PartitionTable: "gpt", System: true, Partitions: []storage.Partition{
		{Device: "/dev/vda1", Number: 1, Type: generic, Offset: 1 << 20, Size: 1 << 30, Filesystem: &storage.Filesystem{Type: "ext4", MountPoints: []string{"/boot"}}},
		{Device: "/dev/vda2", Number: 2, Type: generic, Offset: 2 << 30, Size: 10 << 30, Filesystem: &storage.Filesystem{Type: "btrfs", UUID: dataUUID, MountPoints: []string{"/"}}},
	}}
	defs, err := storage.GrowDefinitions(d)
	if err != nil || len(defs) != 2 {
		t.Fatalf("definitions=%v err=%v", defs, err)
	}
	if !strings.Contains(defs[0], "Type="+generic) || !strings.Contains(defs[0], "SizeMaxBytes=1073741824") || strings.Contains(defs[0], "GrowFileSystem=yes") {
		t.Fatalf("boot is not fixed: %s", defs[0])
	}
	if !strings.Contains(defs[1], "Type="+generic) || strings.Contains(defs[1], "SizeMaxBytes=") {
		t.Fatalf("root cannot grow: %s", defs[1])
	}
	for _, def := range defs {
		if strings.Contains(def, "Format=") || strings.Contains(def, "CopyBlocks=") {
			t.Fatalf("destructive definition: %s", def)
		}
	}
	d.Partitions[1].Type = "not-a-guid"
	if _, err := storage.GrowDefinitions(d); err == nil {
		t.Fatal("unmeasured GPT type accepted")
	}
}

func TestActionRequestAcceptsOnlyInventoryOrTheTwoIdentityBoundActions(t *testing.T) {
	inv := actionInventory(t)
	for _, op := range []string{"backup", "grow"} {
		r := storage.ActionRequest{Op: op, OperationID: strings.Repeat("a", 32), Identity: inv.Disks[0].Identity}
		if err := r.Validate(); err != nil {
			t.Fatal(err)
		}
		r.Identity.Digest = strings.Repeat("f", 64)
		if err := r.Validate(); err == nil {
			t.Fatal("forged identity accepted")
		}
	}
	for _, op := range []string{"format", "shrink", "repair", "mount"} {
		r := storage.ActionRequest{Op: op, OperationID: strings.Repeat("a", 32), Identity: inv.Disks[0].Identity}
		if err := r.Validate(); err == nil {
			t.Fatalf("accepted %s", op)
		}
	}
}

func TestGrowRefusesAnotherDeviceOfTheRootBtrfsFilesystem(t *testing.T) {
	inv := actionInventory(t)
	d := &inv.Disks[0]
	d.System = true
	d.PartitionTable = "gpt"
	d.Partitions = []storage.Partition{{Device: "/dev/sdb1", Number: 1, Offset: 1 << 20, Size: 512 << 20, Filesystem: &storage.Filesystem{Type: "btrfs", UUID: dataUUID, MountPoints: []string{"/"}}}}
	inv.Disks = append(inv.Disks, storage.Disk{Device: "/dev/sdc", Filesystem: &storage.Filesystem{Type: "btrfs", UUID: dataUUID}})
	if _, err := storage.SelectAction(inv, "grow", d.Identity.Digest); err == nil {
		t.Fatal("multi-device btrfs filesystem accepted for grow")
	}
}

func TestInventoryCarriesMeasuredFilesystemSize(t *testing.T) {
	bus := newMountBus()
	b := bus.objects.Blocks[dataPath]
	b.Filesystem.Size = 700 << 20
	bus.objects.Blocks[dataPath] = b
	inv := read(t, &bus.fakeBus, &fakeKernel{boot: bootA})
	if got := inv.Disks[0].Filesystem.Size; got != 700<<20 {
		t.Fatalf("filesystem size=%d", got)
	}
}

func TestActionDescriptorsPreserveConfirmationAndClosedDiskIdentityInput(t *testing.T) {
	for _, d := range storage.ActionDescriptors() {
		if d.Confirmation != "confirm" || d.ActVerb != "storage" || d.InputSchema.AdditionalProperties || len(d.InputSchema.Properties) != 1 || d.InputSchema.Properties["disk_digest"].Type != "string" {
			t.Fatalf("unsafe descriptor: %+v", d)
		}
	}
}

func TestBlankSerialBackupMeasuresExpectedIdentityMetadataChanges(t *testing.T) {
	const blockPath = "/org/freedesktop/UDisks2/block_devices/vda"
	objects := fixture(t, "virtio-blank-serial.json")
	kernel := &fakeKernel{boot: bootA, firstMiB: map[string]string{"/dev/vda": firstMiBOfVda}}
	bus := &fakeBus{objects: objects}
	inv := read(t, bus, kernel)
	captured := inv.Disks[0].Identity
	if captured.Kind != storage.IdentityBlank {
		t.Fatal("fixture must have no serial", captured)
	}
	target := "/mnt/olivares-backups/" + dataUUID
	x := storage.ActionExecutor{Read: func(context.Context) (storage.Inventory, error) { return read(t, bus, kernel), nil }, Backup: func(context.Context, storage.Disk) (string, error) {
		b := bus.objects.Blocks[blockPath]
		b.PartitionTable = nil
		b.IDUsage = "filesystem"
		b.IDType = "ext4"
		b.IDUUID = dataUUID
		b.Filesystem = &storage.FilesystemFacts{MountPoints: []string{target}}
		bus.objects.Blocks[blockPath] = b
		delete(bus.objects.Blocks, "/org/freedesktop/UDisks2/block_devices/vda1")
		delete(bus.objects.Blocks, "/org/freedesktop/UDisks2/block_devices/vda2")
		kernel.firstMiB["/dev/vda"] = strings.Repeat("b", 64)
		return target, nil
	}}
	obs, err := x.Apply(t.Context(), "backup", captured)
	if err != nil || obs.P1 != "performed" {
		t.Fatalf("expected format metadata change was refused: %+v %v", obs, err)
	}
}

type sizedRootKernel struct {
	fakeKernel
	size uint64
}

func (k *sizedRootKernel) RootSize() (uint64, error) { return k.size, nil }

func TestBlankSerialGrowthMeasuresPartitionAndBtrfsAcrossGPTHeaderChange(t *testing.T) {
	for _, cause := range []string{"success", "filesystem resize failed", "filesystem unchanged", "filesystem size initially unknown", "different root filesystem", "post read lost", "nothing to grow"} {
		t.Run(cause, func(t *testing.T) {
			objects := fixture(t, "virtio-blank-serial.json")
			boot := objects.Blocks["/org/freedesktop/UDisks2/block_devices/vda1"]
			boot.Filesystem.MountPoints = []string{"/boot"}
			objects.Blocks["/org/freedesktop/UDisks2/block_devices/vda1"] = boot
			rootPath := "/org/freedesktop/UDisks2/block_devices/vda2"
			root := objects.Blocks[rootPath]
			root.IDUsage = "filesystem"
			root.IDType = "btrfs"
			root.IDUUID = dataUUID
			root.Filesystem = &storage.FilesystemFacts{MountPoints: []string{"/"}}
			objects.Blocks[rootPath] = root
			bus := &fakeBus{objects: objects}
			kernel := &sizedRootKernel{fakeKernel: fakeKernel{boot: bootA, firstMiB: map[string]string{"/dev/vda": firstMiBOfVda}}, size: 12 << 30}
			if cause == "filesystem size initially unknown" {
				kernel.size = 0
			}
			lost := false
			readNow := func(ctx context.Context) (storage.Inventory, error) {
				if lost {
					return storage.Inventory{}, errors.New("post read lost")
				}
				return storage.Read(ctx, bus, kernel)
			}
			inv, err := readNow(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			captured := inv.Disks[0].Identity
			calls := 0
			x := storage.ActionExecutor{Read: readNow, Grow: func(context.Context, storage.Disk) error {
				calls++
				if cause == "nothing to grow" {
					return nil
				}
				root := bus.objects.Blocks[rootPath]
				root.Partition.Size += 512 << 10
				root.Size += 512 << 10
				if cause == "different root filesystem" {
					root.IDUUID = "00000000-0000-0000-0000-000000000001"
				}
				bus.objects.Blocks[rootPath] = root
				kernel.firstMiB["/dev/vda"] = strings.Repeat("c", 64)
				if cause == "filesystem resize failed" {
					return errors.New("btrfs resize failed")
				}
				if cause == "post read lost" {
					lost = true
				}
				if cause != "filesystem unchanged" {
					kernel.size += 512 << 10
				}
				return nil
			}}
			obs, err := x.Apply(t.Context(), "grow", captured)
			want := map[string]string{"success": "performed", "filesystem resize failed": "failed", "filesystem unchanged": "partial", "filesystem size initially unknown": "partial", "different root filesystem": "partial", "post read lost": "unknown", "nothing to grow": "performed"}[cause]
			if obs.P1 != want || calls != 1 {
				t.Fatalf("%+v err=%v calls=%d want=%s", obs, err, calls, want)
			}
			facts := strings.Join(obs.Postconditions, ";")
			if cause == "success" && (!obs.MeasuredChange || !strings.Contains(facts, "data_size_bytes=") || !strings.Contains(facts, "resized=yes")) {
				t.Fatal(obs)
			}
			if cause == "nothing to grow" && (obs.MeasuredChange || !strings.Contains(facts, "resized=no")) {
				t.Fatal(obs)
			}
		})
	}
}
