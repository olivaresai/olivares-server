// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package storage

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"

	"github.com/godbus/dbus/v5"
	"github.com/olivaresai/olivares/appliance/layer/hostops"
)

// FilesystemBus is the storage helper's native mount seam. Existing inventory
// readers remain read-only; neither operation formats, edits fstab or forces an unmount.
type FilesystemBus interface {
	Bus
	Mount(context.Context, string) (string, error)
	Unmount(context.Context, string) error
}

// MountExecutor operates on an inventory-issued disk identity and exact filesystem
// UUID, under the host operation's target lock. The privileged helper owns this
// executor; the portal must use the attested helper transport instead of a bus.
type MountExecutor struct {
	Bus    FilesystemBus
	Kernel Kernel
}

// Apply calls the native filesystem method once after re-resolving the captured
// identity. A fresh snapshot measures the result; losing it keeps the effect unknown.
func (x MountExecutor) Apply(ctx context.Context, op string, captured Identity, filesystemUUID string) (hostops.Observation, error) {
	refuse := func(err error) (hostops.Observation, error) { return hostops.Observation{P1: "not-performed"}, err }
	if (op != "mount" && op != "unmount") || !isUUID(filesystemUUID) {
		return refuse(errors.New(CodeInputRefused))
	}
	if x.Bus == nil || x.Kernel == nil || ctx.Err() != nil {
		return refuse(errors.New("consumer_unavailable"))
	}
	objects, inventory, err := x.snapshot(ctx)
	if err != nil {
		return refuse(err)
	}
	selected, err := mountDisk(inventory, filesystemUUID)
	if err != nil || selected.Identity.Digest != captured.Digest {
		return refuse(errors.New(CodeIdentityChanged))
	}
	disk, err := Reresolve(captured, inventory)
	if err != nil {
		return refuse(err)
	}
	device, fs, consumers, err := mountVolume(disk, filesystemUUID)
	if err != nil {
		return refuse(err)
	}
	if disk.System {
		return refuse(&Refusal{Code: CodeSystemDisk, Reason: "a system volume cannot be mounted or unmounted here"})
	}
	for _, consumer := range consumers {
		if op == "mount" || consumer.Kind != ConsumerMount {
			return refuse(&Refusal{Code: CodeTargetInUse, Reason: "the volume has another consumer"})
		}
	}
	if len(fs.MountPoints) > 1 || (op == "mount" && len(fs.MountPoints) != 0) || (op == "unmount" && len(fs.MountPoints) != 1) {
		return refuse(&Refusal{Code: CodeTargetInUse, Reason: "the volume is not in the expected mount state"})
	}
	var path string
	for p, block := range objects.Blocks {
		if block.IDUUID != filesystemUUID || block.IDUsage != "filesystem" {
			continue
		}
		if block.Device != device || block.Filesystem == nil {
			return refuse(errors.New(CodeIdentityChanged))
		}
		if path != "" || !nativeBlockPath(p) || !block.ConfigurationKnown || block.Configured {
			return refuse(&Refusal{Code: CodeInputRefused, Reason: "the native volume is ambiguous or has an existing or unreadable configuration"})
		}
		path = p
	}
	if path == "" {
		return refuse(&Refusal{Code: CodeIdentityChanged, Reason: "the filesystem has no native block object"})
	}
	if ctx.Err() != nil {
		return refuse(errors.New("consumer_unavailable"))
	}
	var returned string
	if op == "mount" {
		returned, err = x.Bus.Mount(ctx, path)
	} else {
		err = x.Bus.Unmount(ctx, path)
	}
	_, after, readErr := x.snapshot(ctx)
	if readErr != nil {
		return hostops.Observation{P1: "unknown"}, readErr
	}
	afterSelected, readErr := mountDisk(after, filesystemUUID)
	if readErr != nil || afterSelected.Identity.Digest != captured.Digest {
		return hostops.Observation{P1: "unknown"}, errors.New(CodeIdentityChanged)
	}
	afterDisk, readErr := Reresolve(captured, after)
	if readErr != nil {
		return hostops.Observation{P1: "unknown"}, readErr
	}
	_, afterFS, _, readErr := mountVolume(afterDisk, filesystemUUID)
	if readErr != nil {
		return hostops.Observation{P1: "unknown"}, readErr
	}
	if len(afterFS.MountPoints) > 1 {
		return hostops.Observation{P1: "unknown"}, errors.New("outcome_unknown")
	}
	for _, point := range afterFS.MountPoints {
		if !mountPoint(point) {
			return hostops.Observation{P1: "unknown"}, errors.New("outcome_unknown")
		}
	}
	changed := !slices.Equal(fs.MountPoints, afterFS.MountPoints)
	if err != nil {
		return hostops.Observation{P1: "failed", MeasuredChange: changed}, err
	}
	facts := []string{"filesystem_uuid=" + filesystemUUID}
	observed := false
	if op == "mount" {
		observed = mountPoint(returned) && len(afterFS.MountPoints) == 1 && afterFS.MountPoints[0] == returned
		facts = append(facts, "mounted=true")
		if len(afterFS.MountPoints) == 1 {
			facts = append(facts, "mount_point="+afterFS.MountPoints[0])
		}
	} else {
		observed = len(afterFS.MountPoints) == 0
		facts = append(facts, "mounted=false")
	}
	if !observed {
		return hostops.Observation{P1: "partial", MeasuredChange: changed}, nil
	}
	return hostops.Observation{P1: "performed", MeasuredChange: changed, Postconditions: facts}, nil
}

func (x MountExecutor) snapshot(ctx context.Context) (Objects, Inventory, error) {
	lvmErr := x.Bus.EnableModule(ctx, lvmModule)
	objects, err := x.Bus.Objects(ctx)
	if err != nil {
		return Objects{}, Inventory{}, errors.New("consumer_unavailable")
	}
	inventory, err := readObjects(ctx, x.Bus, x.Kernel, objects, lvmErr)
	return objects, inventory, err
}

// mountDisk counts every matching filesystem before selecting a disk. Unsupported
// or layered matches still make a UUID ambiguous; eligibility cannot hide them.
func mountDisk(inventory Inventory, uuid string) (Disk, error) {
	var selected Disk
	matches := 0
	match := func(fs *Filesystem) bool { return fs != nil && fs.UUID == uuid }
	for _, disk := range inventory.Disks {
		if match(disk.Filesystem) {
			matches++
			selected = disk
		}
		for _, partition := range disk.Partitions {
			if match(partition.Filesystem) {
				matches++
				selected = disk
			}
		}
	}
	for _, group := range inventory.LVM.VolumeGroups {
		for _, volume := range group.LogicalVolumes {
			if match(volume.Filesystem) {
				matches++
			}
		}
	}
	if matches != 1 || selected.Identity.Kind == "" {
		return Disk{}, errors.New(CodeIdentityChanged)
	}
	return selected, nil
}

// mountVolume admits only an existing, uniquely identified ext4, xfs or btrfs
// data filesystem on the selected disk. Layered and destructive operations stay separate.
func mountVolume(disk Disk, uuid string) (string, *Filesystem, []Consumer, error) {
	var device string
	var fs *Filesystem
	var consumers []Consumer
	selectVolume := func(node string, filesystem *Filesystem, used []Consumer) bool {
		if filesystem == nil || filesystem.UUID != uuid {
			return true
		}
		if fs != nil {
			return false
		}
		device, fs, consumers = node, filesystem, used
		return true
	}
	if !selectVolume(disk.Device, disk.Filesystem, disk.Consumers) {
		return "", nil, nil, errors.New(CodeIdentityChanged)
	}
	for _, partition := range disk.Partitions {
		if !selectVolume(partition.Device, partition.Filesystem, partition.Consumers) {
			return "", nil, nil, errors.New(CodeIdentityChanged)
		}
	}
	if fs == nil || !slices.Contains([]string{"ext4", "xfs", "btrfs"}, fs.Type) {
		return "", nil, nil, errors.New(CodeIdentityChanged)
	}
	if device != disk.Device && len(disk.Consumers) > 0 {
		return "", nil, nil, errors.New(CodeTargetInUse)
	}
	return device, fs, consumers, nil
}

func nativeBlockPath(path string) bool {
	return strings.HasPrefix(path, udisksRoot+"/block_devices/") && dbus.ObjectPath(path).IsValid() && !strings.Contains(strings.TrimPrefix(path, udisksRoot+"/block_devices/"), "/")
}
func mountPoint(path string) bool {
	if path == "" || len(path) > 1024 || !filepath.IsAbs(path) || filepath.Clean(path) != path || systemMount(path) {
		return false
	}
	for _, r := range path {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}

// Mount uses fixed safe options on the selected native object. The executor
// refuses fstab-configured volumes before these options could be ignored.
func (b *SystemBus) Mount(ctx context.Context, path string) (string, error) {
	if !nativeBlockPath(path) {
		return "", errors.New(CodeInputRefused)
	}
	var point string
	err := b.conn.Object(udisksName, dbus.ObjectPath(path)).CallWithContext(ctx, ifFilesystem+".Mount", 0, map[string]dbus.Variant{"auth.no_user_interaction": dbus.MakeVariant(true), "options": dbus.MakeVariant("nodev,nosuid")}).Store(&point)
	return point, err
}

// Unmount omits force and tear-down options. A busy filesystem stays mounted.
func (b *SystemBus) Unmount(ctx context.Context, path string) error {
	if !nativeBlockPath(path) {
		return errors.New(CodeInputRefused)
	}
	return b.conn.Object(udisksName, dbus.ObjectPath(path)).CallWithContext(ctx, ifFilesystem+".Unmount", 0, map[string]dbus.Variant{"auth.no_user_interaction": dbus.MakeVariant(true)}).Err
}
