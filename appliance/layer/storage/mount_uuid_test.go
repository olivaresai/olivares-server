// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package storage_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/olivaresai/olivares/appliance/layer/hostops"
	"github.com/olivaresai/olivares/appliance/layer/storage"
)

func TestMountUUIDAmbiguityRefusesAllMatchingLocations(t *testing.T) {
	for _, duplicate := range []bool{false, true} {
		name := "unique_uuid_control"
		if duplicate {
			name = "three_uuid_matches_on_two_disks"
		}
		t.Run(name, func(t *testing.T) {
			bus := newMountBus()
			kernel := &fakeKernel{boot: bootA}
			if duplicate {
				h := newHost()
				h.disk("sdc", "distinct-disk-A", 8<<8|32, 4<<30, "gpt")
				h.partition("sdc", "sdc1", 1, "11111111-1111-4111-8111-111111111111")
				h.partition("sdc", "sdc2", 2, "22222222-2222-4222-8222-222222222222")
				for _, partition := range []string{"sdc1", "sdc2"} {
					h.with(partition, func(b *storage.Block) {
						b.IDUsage, b.IDType, b.IDUUID = "filesystem", "ext4", dataUUID
						b.Filesystem = &storage.FilesystemFacts{}
						b.ConfigurationKnown = true
					})
				}
				for path, drive := range h.objects.Drives {
					bus.objects.Drives[path] = drive
				}
				for path, block := range h.objects.Blocks {
					bus.objects.Blocks[path] = block
				}
			}
			inventory := read(t, &bus.fakeBus, kernel)
			matches := 0
			for _, disk := range inventory.Disks {
				if disk.Identity.Ambiguous || disk.Identity.Digest == "" {
					t.Fatal("fixture did not produce distinct native disk identities")
				}
				if disk.Filesystem != nil && disk.Filesystem.UUID == dataUUID {
					matches++
				}
				for _, partition := range disk.Partitions {
					if partition.Filesystem != nil && partition.Filesystem.UUID == dataUUID {
						matches++
					}
				}
			}
			want := 1
			if duplicate {
				want = 3
			}
			if matches != want {
				t.Fatalf("native inventory contains %d UUID matches, want %d", matches, want)
			}
			task := storage.MountTask{Op: "mount", Call: mountCall(bus, kernel)}
			target, err := task.Prepare(t.Context(), json.RawMessage(`{"filesystem_uuid":"`+dataUUID+`"}`))
			if len(bus.actions) != 0 {
				t.Fatal("planning made a native effect")
			}
			if duplicate && err == nil {
				t.Fatalf("ambiguous UUID accepted as target %s despite %d matching native locations", target, matches)
			}
			if !duplicate && (err != nil || target == "") {
				t.Fatalf("unique UUID control refused: %s %v", target, err)
			}
		})
	}
}

func TestMountUUID_NewDuplicateAfterPlanRefusesTaskAndNativeEffect(t *testing.T) {
	for _, cause := range []string{"data disk", "unsupported filesystem", "logical volume"} {
		t.Run(cause, func(t *testing.T) {
			bus := newMountBus()
			kernel := &fakeKernel{boot: bootA}
			task := storage.MountTask{Op: "mount", Call: mountCall(bus, kernel)}
			input := json.RawMessage(`{"filesystem_uuid":"` + dataUUID + `"}`)
			target, err := task.Prepare(t.Context(), input)
			if err != nil {
				t.Fatal(err)
			}
			captured := diskNamed(t, read(t, &bus.fakeBus, kernel), "/dev/sdb").Identity
			h := newHost()
			h.disk("sdc", "duplicate-other-disk", 8<<8|32, 4<<30, "")
			h.with("sdc", func(b *storage.Block) {
				b.IDUsage, b.IDType, b.IDUUID = "filesystem", "ext4", dataUUID
				b.Filesystem = &storage.FilesystemFacts{}
				b.ConfigurationKnown = true
				if cause == "unsupported filesystem" {
					b.IDType = "vfat"
				}
				if cause == "logical volume" {
					b.LogicalVolume = lvmPath + "data/duplicate"
				}
			})
			for path, drive := range h.objects.Drives {
				bus.objects.Drives[path] = drive
			}
			for path, block := range h.objects.Blocks {
				bus.objects.Blocks[path] = block
			}
			if cause == "logical volume" {
				bus.lvm = newObjects()
				bus.lvm.Blocks[blockDevices+"sdc"] = storage.Block{LogicalVolume: lvmPath + "data/duplicate"}
				bus.lvm.VolumeGroups[lvmPath+"data"] = storage.VolumeGroup{Name: "data", UUID: "duplicate-vg"}
				bus.lvm.LogicalVolumes[lvmPath+"data/duplicate"] = storage.LogicalVolume{VolumeGroup: lvmPath + "data", Name: "duplicate", UUID: "duplicate-lv", Active: true, BlockDevice: blockDevices + "sdc"}
			}
			if accepted, err := task.Prepare(t.Context(), input); err == nil {
				t.Fatalf("duplicate accepted in plan: %s", accepted)
			}
			command := hostops.Command{OperationID: strings.Repeat("a", 32), TaskID: "storage.mount", Module: "storage", Verb: "mount", Target: target}
			if observation := task.Apply(t.Context(), command, input); observation.P1 != "not-performed" {
				t.Fatalf("duplicate accepted after plan: %+v", observation)
			}
			observation, err := (storage.MountExecutor{Bus: bus, Kernel: kernel}).Apply(t.Context(), "mount", captured, dataUUID)
			if err == nil || observation.P1 != "not-performed" || len(bus.actions) != 0 {
				t.Fatalf("duplicate reached native effect: %+v %v calls=%v", observation, err, bus.actions)
			}
		})
	}
}
