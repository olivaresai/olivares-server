// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package storage

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"

	"github.com/olivaresai/olivares/appliance/layer/hostops"
)

// SelectAction resolves a current inventory identity and the deliberately narrow
// backup or online root-growth policy. The generic destructive operation guards
// remain unchanged: this is the sole grow-only exception for the mounted root.
func SelectAction(inv Inventory, op, digest string) (Disk, error) {
	var disk Disk
	matches := 0
	for _, d := range inv.Disks {
		if d.Identity.Digest == digest {
			disk = d
			matches++
		}
	}
	if matches != 1 || !isHex(digest, 64) || disk.Identity.Ambiguous || disk.Identity.Kind == IdentityLoop || disk.Target == "" {
		return Disk{}, errors.New(CodeIdentityChanged)
	}
	if _, err := Reresolve(disk.Identity, inv); err != nil {
		return Disk{}, err
	}
	if disk.ReadOnly {
		return Disk{}, errors.New(CodeInputRefused)
	}
	switch op {
	case "backup":
		if disk.System {
			return Disk{}, errors.New(CodeSystemDisk)
		}
		if diskInUse(&disk) {
			return Disk{}, errors.New(CodeTargetInUse)
		}
	case "grow":
		root, err := rootPartition(disk)
		if err != nil {
			return Disk{}, err
		}
		count := 0
		for _, d := range inv.Disks {
			if d.Filesystem != nil && d.Filesystem.UUID == root.Filesystem.UUID {
				count++
			}
			for _, p := range d.Partitions {
				if p.Filesystem != nil && p.Filesystem.UUID == root.Filesystem.UUID {
					count++
				}
			}
		}
		if count != 1 {
			return Disk{}, errors.New(CodeTargetInUse)
		}
	default:
		return Disk{}, errors.New(CodeInputRefused)
	}
	return disk, nil
}
func rootPartition(d Disk) (Partition, error) {
	if !d.System || d.PartitionTable != "gpt" || len(d.Consumers) != 0 {
		return Partition{}, errors.New(CodeSystemDisk)
	}
	var root Partition
	for _, p := range d.Partitions {
		if p.Filesystem != nil && slices.Contains(p.Filesystem.MountPoints, "/") {
			if root.Device != "" || p.Filesystem.Type != "btrfs" || !isUUID(p.Filesystem.UUID) {
				return Partition{}, errors.New(CodeSystemDisk)
			}
			root = p
		}
		for _, c := range p.Consumers {
			if c.Kind != ConsumerMount {
				return Partition{}, errors.New(CodeTargetInUse)
			}
		}
	}
	if root.Device == "" || root.Offset > d.Size || root.Size > d.Size-root.Offset {
		return Partition{}, errors.New(CodeSystemDisk)
	}
	for _, p := range d.Partitions {
		if p.Device != root.Device && (p.Offset >= root.Offset || p.Offset > d.Size || p.Size > root.Offset-p.Offset) {
			return Partition{}, errors.New(CodeTargetInUse)
		}
	}
	return root, nil
}

// GrowDefinitions describes every existing GPT slot in slot order. Matching all
// existing type ordinals prevents a generic /boot partition being mistaken for
// root or an architecture-specific root definition creating a new partition.
// No definition formats, copies, moves, shrinks or creates an unmatched slot.
func GrowDefinitions(d Disk) ([]string, error) {
	root, err := rootPartition(d)
	if err != nil {
		return nil, err
	}
	parts := slices.Clone(d.Partitions)
	slices.SortFunc(parts, func(a, b Partition) int { return int(a.Number) - int(b.Number) })
	defs := make([]string, 0, len(parts))
	var previous uint32
	for _, p := range parts {
		if p.Number == 0 || p.Number <= previous || !isUUID(p.Type) || p.Size == 0 {
			return nil, errors.New(CodeInputRefused)
		}
		previous = p.Number
		def := fmt.Sprintf("[Partition]\nType=%s\nSizeMinBytes=4096\n", p.Type)
		if p.Device == root.Device {
			// Generic Linux partitions have no discoverable grow flag. The same
			// native unit explicitly grows btrfs after repart, including at boot.
			if p.Type == "4f68bce3-e8cd-4db1-96e7-fbcaf984b709" || p.Type == "b921b045-1df0-41c3-af44-4c6f280d3fae" {
				def += "GrowFileSystem=yes\n"
			}
		} else {
			def += fmt.Sprintf("SizeMaxBytes=%d\nWeight=0\n", p.Size)
		}
		defs = append(defs, def)
	}
	return defs, nil
}

// ActionExecutor owns fresh reads on both sides of the native boundary. Native
// failures and missing measurements are never converted to an inferred success.
type ActionExecutor struct {
	Read   Reader
	Backup func(context.Context, Disk) (string, error)
	Grow   func(context.Context, Disk) error
}

func (x ActionExecutor) Apply(ctx context.Context, op string, captured Identity) (hostops.Observation, error) {
	refuse := func(err error) (hostops.Observation, error) { return hostops.Observation{P1: "not-performed"}, err }
	if x.Read == nil || ctx.Err() != nil {
		return refuse(errors.New("consumer_unavailable"))
	}
	before, err := x.Read(ctx)
	if err != nil {
		return refuse(err)
	}
	d, err := Reresolve(captured, before)
	if err != nil {
		return refuse(err)
	}
	if _, err = SelectAction(before, op, captured.Digest); err != nil {
		return refuse(err)
	}
	var target string
	switch {
	case op == "backup" && x.Backup != nil:
		target, err = x.Backup(ctx, d)
	case op == "grow" && x.Grow != nil:
		err = x.Grow(ctx, d)
	default:
		return refuse(errors.New("consumer_unavailable"))
	}
	after, readErr := x.Read(ctx)
	if readErr != nil {
		return hostops.Observation{P1: "unknown"}, readErr
	}
	var measured *Disk
	for i := range after.Disks {
		candidate := &after.Disks[i]
		if sameActionDisk(d, *candidate) {
			if measured != nil {
				return hostops.Observation{P1: "unknown"}, errors.New(CodeIdentityChanged)
			}
			measured = candidate
		}
	}
	if measured == nil {
		return hostops.Observation{P1: "unknown"}, errors.New(CodeIdentityChanged)
	}
	changed := measuredDiskChange(d, *measured)
	if err != nil {
		return hostops.Observation{P1: "failed", MeasuredChange: changed}, err
	}
	facts := []string{"disk=" + d.Device}
	if op == "backup" {
		fs := measured.Filesystem
		if fs == nil || fs.Type != "ext4" || !isUUID(fs.UUID) || target != "/mnt/olivares-backups/"+fs.UUID || !slices.Equal(fs.MountPoints, []string{target}) {
			return hostops.Observation{P1: "partial", MeasuredChange: changed}, nil
		}
		selected, selectErr := mountDisk(after, fs.UUID)
		if selectErr != nil || selected.Device != measured.Device {
			return hostops.Observation{P1: "unknown", MeasuredChange: changed}, errors.New(CodeIdentityChanged)
		}
		facts = append(facts, "backup_target="+target, "filesystem_uuid="+fs.UUID)
	} else {
		root, rootErr := rootPartition(*measured)
		if rootErr != nil || root.Filesystem.Size == 0 || !sameGrowthLayout(d, *measured) {
			return hostops.Observation{P1: "partial", MeasuredChange: changed}, nil
		}
		resized := "no"
		if changed {
			resized = "yes"
		}
		facts = append(facts, "resized="+resized, fmt.Sprintf("data_size_bytes=%d", root.Filesystem.Size), fmt.Sprintf("partition_size_bytes=%d", root.Size))
	}
	return hostops.Observation{P1: "performed", MeasuredChange: changed, Postconditions: facts}, nil
}

// Native tool availability is advisory, not a measurement of a disk effect.
func measuredDiskChange(before, after Disk) bool {
	before.Operations, after.Operations = nil, nil
	before.Partitions = slices.Clone(before.Partitions)
	after.Partitions = slices.Clone(after.Partitions)
	for i := range before.Partitions {
		before.Partitions[i].Operations = nil
	}
	for i := range after.Partitions {
		after.Partitions[i].Operations = nil
	}
	return !reflect.DeepEqual(before, after)
}

func sameActionDisk(before, after Disk) bool {
	a, b := before.Identity, after.Identity
	return before.Device == after.Device && a.Kind == b.Kind && a.Source == b.Source && a.Value == b.Value && a.Size == b.Size && a.BootID == b.BootID && !b.Ambiguous && b.Kind != ""
}

// ActionDescriptors are adopted by the protected web operation owner. Merely
// listing a descriptor never exposes an effect on an uncomposed local surface.
func ActionDescriptors() []hostops.Descriptor {
	out := []hostops.Descriptor{}
	for _, op := range []string{"backup", "grow"} {
		title, consequence := "Use this disk for backups", "Erase this non-system disk as ext4 and mount it permanently by UUID for local backups. Existing contents will be lost."
		if op == "grow" {
			title = "Grow now"
			consequence = "Grow only the mounted root partition into free trailing space, then grow its btrfs filesystem online."
		}
		out = append(out, hostops.Descriptor{ID: "storage." + op, Module: "storage", Verb: op, Title: title, Category: "Storage", InputSchema: hostops.InputSchema{Type: "object", Properties: map[string]hostops.InputField{"disk_digest": {Type: "string"}}, Required: []string{"disk_digest"}}, Preconditions: []string{"Current product authority and confirmation for this exact disk", "Unchanged inventory identity and eligible storage state"}, Consequence: consequence, Confirmation: "confirm", Modes: []string{"product-up"}, ActVerb: "storage", Audience: "appliance-helper:olivares-portal-storage", EquivalentCommand: "Open Appliance Console > Storage", OutputSchema: "hostop-v1.schema.json", Surfaces: []string{"web", "cli", "tui"}})
	}
	return out
}

func sameGrowthLayout(before, after Disk) bool {
	root, err := rootPartition(before)
	if err != nil {
		return false
	}
	grown, err := rootPartition(after)
	if err != nil {
		return false
	}
	if root.Filesystem.Size == 0 || root.Filesystem.UUID != grown.Filesystem.UUID || grown.Filesystem.Size < root.Filesystem.Size || len(before.Partitions) != len(after.Partitions) {
		return false
	}
	if grown.Size > root.Size && grown.Filesystem.Size <= root.Filesystem.Size {
		return false
	}
	for _, p := range before.Partitions {
		found := false
		for _, q := range after.Partitions {
			if p.Number == q.Number {
				if p.Device != q.Device || p.UUID != q.UUID || p.Type != q.Type || p.Offset != q.Offset {
					return false
				}
				if p.Device == root.Device {
					if q.Size < p.Size {
						return false
					}
				} else if p.Size != q.Size {
					return false
				}
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func knownImageProfile(profile string) bool {
	return profile == "almalinux10-server-amd64\n" || profile == "almalinux10-desktop-amd64\n" || profile == "debian13-server-amd64\n"
}
