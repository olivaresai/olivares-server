// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package storage_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/olivaresai/olivares/appliance/layer/storage"
)

const dataPath = "/org/freedesktop/UDisks2/block_devices/sdb"
const dataUUID = "617359a8-818f-4d2d-a901-cc4b7b2911a1"

type mountBus struct {
	fakeBus
	actions        []string
	mountError     error
	afterReadError bool
}

func newMountBus() *mountBus {
	objects := newObjects()
	objects.Drives["/org/freedesktop/UDisks2/drives/data"] = storage.Drive{Serial: "data-1"}
	objects.Blocks[dataPath] = storage.Block{Device: "/dev/sdb", DeviceNumber: 8<<8 | 16, Size: 1 << 30, Drive: "/org/freedesktop/UDisks2/drives/data", CryptoBackingDevice: storage.NoObject, IDUsage: "filesystem", IDType: "ext4", IDUUID: dataUUID, Filesystem: &storage.FilesystemFacts{}, ConfigurationKnown: true}
	return &mountBus{fakeBus: fakeBus{objects: objects}}
}
func (b *mountBus) Objects(ctx context.Context) (storage.Objects, error) {
	if b.afterReadError && len(b.actions) > 0 {
		return storage.Objects{}, errors.New("inventory lost after send")
	}
	return b.fakeBus.Objects(ctx)
}
func (b *mountBus) Mount(_ context.Context, path string) (string, error) {
	b.actions = append(b.actions, "mount "+path)
	if b.mountError != nil {
		return "", b.mountError
	}
	block := b.objects.Blocks[path]
	block.Filesystem = &storage.FilesystemFacts{MountPoints: []string{"/run/media/root/data"}}
	b.objects.Blocks[path] = block
	return "/run/media/root/data", nil
}
func (b *mountBus) Unmount(_ context.Context, path string) error {
	b.actions = append(b.actions, "unmount "+path)
	if b.mountError != nil {
		return b.mountError
	}
	block := b.objects.Blocks[path]
	block.Filesystem = &storage.FilesystemFacts{}
	b.objects.Blocks[path] = block
	return nil
}

func TestMount_ExactDataVolumeMountsAndUnmountsWithObservedState(t *testing.T) {
	bus := newMountBus()
	kernel := &fakeKernel{boot: bootA}
	captured := diskNamed(t, read(t, &bus.fakeBus, kernel), "/dev/sdb").Identity
	executor := storage.MountExecutor{Bus: bus, Kernel: kernel}
	for _, op := range []string{"mount", "unmount"} {
		observation, err := executor.Apply(t.Context(), op, captured, dataUUID)
		if err != nil || observation.P1 != "performed" || len(observation.Postconditions) == 0 {
			t.Fatalf("%s: %+v %v", op, observation, err)
		}
	}
	if strings.Join(bus.actions, ";") != "mount "+dataPath+";unmount "+dataPath {
		t.Fatal("wrong native target", bus.actions)
	}
}

func TestMount_SystemConsumersConfigurationAndChangedIdentityRefuseBeforeNativeCall(t *testing.T) {
	for _, cause := range []string{"system", "holder", "configured", "configuration unreadable", "disk replaced", "filesystem replaced", "ambiguous", "caller path"} {
		t.Run(cause, func(t *testing.T) {
			bus := newMountBus()
			kernel := &fakeKernel{boot: bootA}
			captured := diskNamed(t, read(t, &bus.fakeBus, kernel), "/dev/sdb").Identity
			block := bus.objects.Blocks[dataPath]
			switch cause {
			case "system":
				block.Filesystem = &storage.FilesystemFacts{MountPoints: []string{"/"}}
			case "holder":
				kernel.holders = map[string][]string{"/dev/sdb": {"dm-0"}}
			case "configured":
				block.Configured = true
			case "configuration unreadable":
				block.ConfigurationKnown = false
			case "disk replaced":
				bus.objects.Drives[block.Drive] = storage.Drive{Serial: "replacement"}
			case "filesystem replaced":
				block.IDUUID = "changed"
			case "ambiguous":
				bus.objects.Blocks[dataPath+"2"] = block
			case "caller path":
				captured.Digest = "/dev/sdb"
			}
			bus.objects.Blocks[dataPath] = block
			observation, err := (storage.MountExecutor{Bus: bus, Kernel: kernel}).Apply(t.Context(), "mount", captured, dataUUID)
			if err == nil || observation.P1 != "not-performed" || len(bus.actions) != 0 {
				t.Fatalf("unsafe volume: %+v err=%v actions=%v", observation, err, bus.actions)
			}
		})
	}
}

func TestMount_BusyUnmountRefusesWithoutForceAndLostInventoryStaysUnknown(t *testing.T) {
	for _, cause := range []string{"busy", "lost inventory"} {
		t.Run(cause, func(t *testing.T) {
			bus := newMountBus()
			kernel := &fakeKernel{boot: bootA}
			block := bus.objects.Blocks[dataPath]
			block.Filesystem = &storage.FilesystemFacts{MountPoints: []string{"/run/media/root/data"}}
			bus.objects.Blocks[dataPath] = block
			captured := diskNamed(t, read(t, &bus.fakeBus, kernel), "/dev/sdb").Identity
			want := "failed"
			if cause == "busy" {
				bus.mountError = errors.New("org.freedesktop.UDisks2.Error.DeviceBusy")
			} else {
				bus.afterReadError = true
				want = "unknown"
			}
			observation, _ := (storage.MountExecutor{Bus: bus, Kernel: kernel}).Apply(t.Context(), "unmount", captured, dataUUID)
			if observation.P1 != want || len(bus.actions) != 1 {
				t.Fatalf("%s: %+v calls=%v", cause, observation, bus.actions)
			}
		})
	}
}
