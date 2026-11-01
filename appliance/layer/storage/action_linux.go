// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

//go:build linux

package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/godbus/dbus/v5"
	"github.com/olivaresai/olivares/appliance/layer/services"
	"golang.org/x/sys/unix"
)

const growUnitPrefix = "olivares-grow-data@"
const backupParent = "/mnt/olivares-backups"

// NativeExecutor composes only the two fixed native effects. The helper never
// invokes a shell, accepts a path, or obtains raw block-write capabilities.
func NativeExecutor(bus *SystemBus) ActionExecutor {
	read := func(ctx context.Context) (Inventory, error) { return Read(ctx, bus, LinuxKernel{}) }
	return ActionExecutor{Read: read, Backup: bus.backupDisk, Grow: bus.growDisk}
}

func (b *SystemBus) backupDisk(ctx context.Context, d Disk) (string, error) {
	lvmErr := b.EnableModule(ctx, lvmModule)
	objects, err := b.Objects(ctx)
	if err != nil {
		return "", fmt.Errorf("read backup native objects: %w", err)
	}
	inv, err := readObjects(ctx, b, LinuxKernel{}, objects, lvmErr)
	if err != nil {
		return "", fmt.Errorf("read backup inventory: %w", err)
	}
	current, err := Reresolve(d.Identity, inv)
	if err != nil {
		return "", fmt.Errorf("resolve backup identity: %w", err)
	}
	if _, err = SelectAction(inv, "backup", d.Identity.Digest); err != nil {
		return "", fmt.Errorf("select backup disk: %w", err)
	}
	var path string
	var number uint64
	for p, block := range objects.Blocks {
		if block.Device == current.Device && block.Partition == nil {
			if path != "" || !nativeBlockPath(p) || !block.ConfigurationKnown || block.Configured {
				return "", fmt.Errorf("backup block configuration untrusted (duplicate=%t native_path=%t known=%t configured=%t): %s", path != "", nativeBlockPath(p), block.ConfigurationKnown, block.Configured, CodeInputRefused)
			}
			path = p
			number = block.DeviceNumber
		}
		// Even inactive fstab/crypttab entries belong to another configuration.
		for _, part := range current.Partitions {
			if block.Device == part.Device && (!block.ConfigurationKnown || block.Configured) {
				return "", fmt.Errorf("backup partition configuration untrusted: %s", CodeTargetInUse)
			}
		}
	}
	if path == "" {
		return "", fmt.Errorf("backup native block absent: %s", CodeIdentityChanged)
	}
	parent, err := os.Lstat(backupParent)
	if err != nil {
		return "", fmt.Errorf("inspect backup mount parent: %w", err)
	}
	if !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("backup_mount_parent_unavailable")
	}
	stat, ok := parent.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || parent.Mode().Perm()&0022 != 0 {
		return "", errors.New("backup_mount_parent_untrusted")
	}
	account, err := user.Lookup("olivares")
	if err != nil {
		return "", fmt.Errorf("find product account: %w", err)
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		return "", err
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil {
		return "", err
	}
	if uid == 0 {
		return "", errors.New("backup_product_account_untrusted")
	}
	opts := "nofail,nodev,nosuid,noexec"
	if _, err = os.Stat("/sys/fs/selinux/enforce"); err == nil {
		label := make([]byte, 1024)
		n, labelErr := unix.Lgetxattr(backupParent, "security.selinux", label)
		if labelErr != nil {
			return "", fmt.Errorf("measure backup mount label: %w", labelErr)
		}
		fields := strings.Split(strings.TrimRight(string(label[:n]), "\x00"), ":")
		if len(fields) < 3 || fields[2] != "olivares_backups_t" {
			return "", errors.New("backup_mount_parent_not_labeled")
		}
		opts += ",context=system_u:object_r:olivares_backups_t:s0"
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("measure SELinux: %w", err)
	}
	held, err := openNode(current.Device, number)
	if err != nil {
		return "", fmt.Errorf("hold backup block device: %w", err)
	}
	defer held.Close()
	// Keep the original kernel device open through the native operation. A
	// changed/recycled node is never accepted as its measured mounted result.
	original, err := diskSequence(held)
	if err != nil {
		return "", fmt.Errorf("measure backup disk sequence: %w", err)
	}
	options := map[string]dbus.Variant{"auth.no_user_interaction": dbus.MakeVariant(true), "label": dbus.MakeVariant("Olivares backups"), "no-discard": dbus.MakeVariant(true)}
	if err = b.conn.Object(udisksName, dbus.ObjectPath(path)).CallWithContext(ctx, ifBlock+".Format", 0, "ext4", options).Err; err != nil {
		return "", fmt.Errorf("format backup disk: %w", err)
	}
	objects, err = b.Objects(ctx)
	if err != nil {
		return "", err
	}
	block, ok := objects.Blocks[path]
	if !ok || block.Device != current.Device || block.DeviceNumber != number || block.IDType != "ext4" || !isUUID(block.IDUUID) || block.Filesystem == nil || len(block.Filesystem.MountPoints) != 0 {
		return "", errors.New(CodeIdentityChanged)
	}
	reopened, err := openNode(current.Device, number)
	if err != nil {
		return "", err
	}
	sequence, sequenceErr := diskSequence(reopened)
	closeErr := reopened.Close()
	if sequenceErr != nil || sequence != original || closeErr != nil {
		return "", errors.New(CodeIdentityChanged)
	}
	target := backupParent + "/" + block.IDUUID
	// The package owns the parent; users may never substitute a mount-point
	// parent or hide pre-existing files behind the new volume.
	if err = os.Mkdir(target, 0700); err != nil {
		return "", fmt.Errorf("create backup mount point: %w", err)
	}
	text := func(s string) dbus.Variant { return dbus.MakeVariant(append([]byte(s), 0)) }
	item := struct {
		Type    string
		Details map[string]dbus.Variant
	}{"fstab", map[string]dbus.Variant{
		"fsname": text("UUID=" + block.IDUUID), "dir": text(target), "type": text("ext4"), "opts": text(opts), "freq": dbus.MakeVariant(int32(0)), "passno": dbus.MakeVariant(int32(2)),
	}}
	if err = b.conn.Object(udisksName, dbus.ObjectPath(path)).CallWithContext(ctx, ifBlock+".AddConfigurationItem", 0, item, map[string]dbus.Variant{"auth.no_user_interaction": dbus.MakeVariant(true)}).Err; err != nil {
		return "", fmt.Errorf("persist backup mount: %w", err)
	}
	var mounted string
	if err = b.conn.Object(udisksName, dbus.ObjectPath(path)).CallWithContext(ctx, ifFilesystem+".Mount", 0, map[string]dbus.Variant{"auth.no_user_interaction": dbus.MakeVariant(true)}).Store(&mounted); err != nil {
		return "", fmt.Errorf("mount backup disk: %w", err)
	}
	if mounted != target {
		return "", errors.New("backup_mount_unmeasured")
	}
	fd, err := unix.Open(target, unix.O_DIRECTORY|unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	defer unix.Close(fd)
	var mountedStat unix.Stat_t
	var fs unix.Statfs_t
	if err = unix.Fstat(fd, &mountedStat); err != nil {
		return "", err
	}
	if uint64(mountedStat.Dev) != number {
		return "", errors.New("backup_mount_device_changed")
	}
	if err = unix.Fstatfs(fd, &fs); err != nil || fs.Type != unix.EXT4_SUPER_MAGIC {
		return "", errors.New("backup_mount_not_ext4")
	}
	if err = unix.Fchown(fd, int(uid), int(gid)); err != nil {
		return "", fmt.Errorf("assign backup filesystem: %w", err)
	}
	if err = unix.Fchmod(fd, 0700); err != nil {
		return "", fmt.Errorf("protect backup filesystem: %w", err)
	}
	return target, nil
}

func (b *SystemBus) growDisk(ctx context.Context, d Disk) error {
	if !isHex(d.Identity.Digest, 64) {
		return errors.New(CodeInputRefused)
	}
	bus, err := services.DialSystemBus()
	if err != nil {
		return fmt.Errorf("connect growth systemd bus: %w", err)
	}
	defer bus.Close()
	events, stop, err := bus.Subscribe(ctx)
	if err != nil {
		return fmt.Errorf("subscribe growth systemd jobs: %w", err)
	}
	defer stop()
	unit := growUnitPrefix + d.Identity.Digest + ".service"
	manager := b.conn.Object("org.freedesktop.systemd1", dbus.ObjectPath("/org/freedesktop/systemd1"))
	var unitPath dbus.ObjectPath
	if err = manager.CallWithContext(ctx, "org.freedesktop.systemd1.Manager.LoadUnit", 0, unit).Store(&unitPath); err != nil {
		return fmt.Errorf("load growth unit: %w", err)
	}
	if err = manager.CallWithContext(ctx, "org.freedesktop.systemd1.Manager.RefUnit", 0, unit).Err; err != nil {
		return fmt.Errorf("reference growth unit: %w", err)
	}
	// Closing the private owner connection also releases this reference if a
	// canceled context prevents the best-effort unref.
	defer func() { _ = manager.CallWithContext(ctx, "org.freedesktop.systemd1.Manager.UnrefUnit", 0, unit).Err }()

	job, err := bus.QueueJob(ctx, "StartUnit", unit, "fail")
	if err != nil {
		return fmt.Errorf("start growth unit: %w", err)
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case event, ok := <-events:
			if !ok {
				return errors.New("grow_job_unmeasured")
			}
			if event.Job == job && event.Unit == unit {
				if event.Result != "done" {
					return fmt.Errorf("grow job: %s", event.Result)
				}
				var result dbus.Variant
				if err = b.conn.Object("org.freedesktop.systemd1", unitPath).CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", 0, "org.freedesktop.systemd1.Service", "Result").Store(&result); err != nil {
					return fmt.Errorf("measure growth unit result: %w", err)
				}
				if value, ok := result.Value().(string); !ok || value != "success" {
					return errors.New("grow_unit_not_performed")
				}
				return nil
			}
		}
	}
}

// PrepareGrowth is invoked only by the installed native maintenance unit.
// It produces definitions, not disk writes; PID 1 executes the distribution's
// repart and btrfs utilities after this precondition succeeds. Manual instances
// carry the approved digest; the boot instance measures its current root.
func PrepareGrowth(ctx context.Context, instance string) error {
	if instance != "auto" && !isHex(instance, 64) {
		return errors.New(CodeInputRefused)
	}
	if err := GrowthCondition(instance); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New(CodeInputRefused)
	}
	unit := growUnitPrefix + instance + ".service"
	group, err := readBounded("/proc/self/cgroup", 4096)
	if err != nil || !strings.Contains(string(group), "/system.slice/"+unit+"\n") {
		return errors.New("grow_unit_not_attested")
	}
	bus, err := DialSystemBus(ctx)
	if err != nil {
		return err
	}
	defer bus.Close()
	inv, err := Read(ctx, bus, LinuxKernel{})
	if err != nil {
		return err
	}
	var selected *Disk
	for i := range inv.Disks {
		d := &inv.Disks[i]
		if _, err := rootPartition(*d); err == nil {
			if selected != nil {
				return errors.New(CodeSystemDisk)
			}
			selected = d
		}
	}
	if selected == nil || (instance != "auto" && selected.Identity.Digest != instance) {
		return errors.New(CodeIdentityChanged)
	}
	if _, err = SelectAction(inv, "grow", selected.Identity.Digest); err != nil {
		return err
	}
	if err = singleRootDevice(); err != nil {
		return err
	}
	definitions, err := GrowDefinitions(*selected)
	if err != nil {
		return err
	}
	dir := "/run/olivares-storage-grow-" + instance
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("grow_runtime_directory_unavailable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || info.Mode().Perm() != 0700 {
		return errors.New("grow_runtime_directory_untrusted")
	}
	for i, data := range definitions {
		name := filepath.Join(dir, fmt.Sprintf("%03d.conf", i))
		file, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
		if err != nil {
			return err
		}
		_, writeErr := file.WriteString(data)
		closeErr := file.Close()
		if writeErr != nil {
			return writeErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

// BTRFS_IOC_FS_INFO reports the filesystem's complete device count, including
// missing devices. Counting only visible UDisks objects is insufficient for a
// degraded multi-device root. This read-only ioctl is fixed to the mounted /.
func singleRootDevice() error {
	file, err := os.Open("/")
	if err != nil {
		return err
	}
	defer file.Close()
	var info struct {
		MaxID, Devices uint64
		FSID           [16]byte
		Rest           [992]byte
	}
	const btrfsFSInfo = 0x8400941f
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), btrfsFSInfo, uintptr(unsafe.Pointer(&info))); errno != 0 {
		return errno
	}
	if info.Devices != 1 {
		return errors.New("grow_requires_single_device_btrfs")
	}
	return nil
}

func (LinuxKernel) RootSize() (uint64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs("/", &st); err != nil {
		return 0, err
	}
	if st.Type != unix.BTRFS_SUPER_MAGIC || st.Bsize <= 0 {
		return 0, errors.New("root_not_btrfs")
	}
	return st.Blocks * uint64(st.Bsize), nil
}

// BLKGETDISKSEQ distinguishes a recycled device number after hot removal.
func diskSequence(file *os.File) (uint64, error) {
	var sequence uint64
	const blkGetDiskSequence = 0x80081280
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), blkGetDiskSequence, uintptr(unsafe.Pointer(&sequence))); errno != 0 {
		return 0, errno
	}
	if sequence == 0 {
		return 0, errors.New(CodeIdentityChanged)
	}
	return sequence, nil
}

// GrowthCondition skips automatic growth on a host without the recipe-owned
// neutral image declaration. Explicit confirmed growth remains available to
// legacy images; this marker never chooses a service account.
func GrowthCondition(instance string) error {
	if isHex(instance, 64) {
		return nil
	}
	if instance != "auto" {
		return errors.New(CodeInputRefused)
	}
	file, err := os.OpenFile("/etc/olivares-appliance/image", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || st.Gid != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0644 {
		return errors.New("image_declaration_untrusted")
	}
	data, err := io.ReadAll(io.LimitReader(file, 128))
	if err != nil {
		return err
	}
	if !knownImageProfile(string(data)) {
		return errors.New("image_declaration_invalid")
	}
	return nil
}
