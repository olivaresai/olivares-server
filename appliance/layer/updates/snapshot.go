// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package updates

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

const snapshotRequestPrefix = "upgrade-snapshot."

// packageSuffix names the directory beside a restore point where the update keeps the Olivares packages it replaces.
const packageSuffix = ".package"

// rollbackMarkerName is the file a rollback writes beside the restore points before it restores the data volume, and
// removes once the data and its packages are whole. The product unit refuses to start while it exists.
const rollbackMarkerName = "rollback-in-progress"

var (
	snapshotDigest  = regexp.MustCompile(`^[0-9a-f]{32}$`)
	partialSnapshot = regexp.MustCompile(`^\.[0-9a-f]{32}\.partial$`)
)

// DataVolume is the appliance's product data subvolume and the host actions a
// product package transaction needs. The three paths are fixed by
// LiveDataVolume in production; tests use private temporary directories.
type DataVolume struct {
	DataDir, SnapshotsDir, RequestPath string
	Run                                func(context.Context, []string, int64) ([]byte, error)
	ProductActive                      func(context.Context) (bool, error)
	StopProduct, StartProduct          func(context.Context) error
	// VerifyPackages and InstallPackages are a rollback's check of the kept packages, before anything stops, and
	// their reinstall as one transaction.
	VerifyPackages, InstallPackages func(context.Context, []string) error
	Relabel                         bool
	statfs                          func(string) (blocks, available uint64, err error)
}

// DataSnapshot is one completed read-only restore point. Restart starts the
// product only when it was running before the transaction.
type DataSnapshot struct {
	Digest, Path string
	start        func(context.Context) error
	lock         *os.File
}

func (s *DataSnapshot) Close() error {
	if s == nil || s.lock == nil {
		return nil
	}
	err := s.lock.Close()
	s.lock = nil
	return err
}

// PackageDir is where the update keeps, beside this point, the Olivares packages it replaces.
func (s *DataSnapshot) PackageDir() string { return s.Path + packageSuffix }

func (s *DataSnapshot) Restart(ctx context.Context) error {
	var err error
	if s.start != nil {
		err = s.start(ctx)
	}
	return errors.Join(err, s.Close())
}

// LiveDataVolume returns the fixed appliance paths and the native btrfs and
// restorecon adapter; the caller supplies the product unit's actions.
// Snapshots live beside, not inside, the source subvolume, on the same btrfs
// filesystem.
func LiveDataVolume(run func(context.Context, []string, int64) ([]byte, error)) DataVolume {
	return DataVolume{
		DataDir:      "/var/lib/olivares",
		SnapshotsDir: "/var/lib/olivares-snapshots",
		RequestPath:  "/var/lib/olivares-package/upgrade-snapshot",
		Run:          run,
		Relabel:      true,
	}
}

// Before quiesces the product and takes a read-only snapshot before any package
// mutation. A capacity refusal happens before the product is stopped. It
// publishes the database-snapshot request with the snapshot's digest; %post
// keeps that request only while this lock is held and the matching completed
// data snapshot exists.
//
// The returned point holds the product transaction lock until Close or
// Restart: the caller holds it through the package mutation and the product
// restart. On failure the lock is released and a product that was stopped is
// started again. The lock is on the snapshot directory, which only root can
// open; the package state directory is world-readable, so any local user could
// hold a lock there.
func (v DataVolume) Before(ctx context.Context) (DataSnapshot, error) {
	if v.DataDir == "" || v.SnapshotsDir == "" || v.RequestPath == "" || v.Run == nil || v.ProductActive == nil || v.StopProduct == nil || v.StartProduct == nil {
		return DataSnapshot{}, errors.New("data snapshot is unavailable")
	}
	lock, err := v.lock()
	if err != nil {
		return DataSnapshot{}, err
	}
	point := DataSnapshot{lock: lock}
	if err := v.take(ctx, &point); err != nil {
		return DataSnapshot{}, errors.Join(err, point.Restart(context.WithoutCancel(ctx)))
	}
	return point, nil
}

// lock takes the product transaction lock on the root-only snapshot directory.
func (v DataVolume) lock() (*os.File, error) {
	if err := v.prepareSnapshotsDir(); err != nil {
		return nil, err
	}
	lock, err := os.Open(v.SnapshotsDir)
	if err != nil {
		return nil, fmt.Errorf("open the product transaction lock: %w", err)
	}
	if err := lockDirectory(lock); err != nil {
		return nil, errors.Join(fmt.Errorf("another product transaction is running: %w", err), lock.Close())
	}
	return lock, nil
}

// Rollback returns the product to the restore point the last product transaction's request names: it stops the
// product, replaces the data volume's content with the point's, reinstalls the packages the update kept beside it
// and starts the product. Every refusal (no request, a request no appliance transaction published, a point that is
// gone, no kept package, or kept packages that do not verify or cannot go back together) comes before the product
// is stopped. A failure after the stop leaves the product stopped, and the same rollback can run again: the point
// and the packages stay until the reinstall succeeds. Then they are used up, so a second rollback cannot wipe what
// was written since.
func (v DataVolume) Rollback(ctx context.Context) error {
	if v.DataDir == "" || v.SnapshotsDir == "" || v.RequestPath == "" || v.Run == nil || v.StopProduct == nil || v.StartProduct == nil || v.VerifyPackages == nil || v.InstallPackages == nil {
		return errors.New("rollback is unavailable")
	}
	lock, err := v.lock()
	if err != nil {
		return fmt.Errorf("%w; nothing was stopped", err)
	}
	defer lock.Close()
	point, packages, err := v.rollbackInputs(ctx)
	if err != nil {
		return fmt.Errorf("%w; nothing was stopped", err)
	}
	if err := v.StopProduct(ctx); err != nil {
		return fmt.Errorf("stop the product: %w", err)
	}
	if err := v.markRollback(point); err != nil {
		return fmt.Errorf("mark the rollback of %s: %w; the product is left stopped: run the rollback again", point, err)
	}
	if err := v.restore(ctx, point); err != nil {
		return fmt.Errorf("restore the data of %s: %w; the product is left stopped: run the rollback again", point, err)
	}
	if err := v.InstallPackages(ctx, packages); err != nil {
		return fmt.Errorf("reinstall the packages kept beside %s: %w; the data is restored and the product is left stopped: run the rollback again", point, err)
	}
	// The data is whole again. The marker goes before the packages: a failure here leaves the point and the packages
	// for the rollback run again, and the product start, which the marker blocks, happens only after the marker is gone.
	if err := v.unmarkRollback(); err != nil {
		return fmt.Errorf("finish the rollback of %s: %w; the product is left stopped: run the rollback again", point, err)
	}
	usedUp := os.RemoveAll(point + packageSuffix)
	if usedUp != nil {
		usedUp = fmt.Errorf("remove the used packages beside %s: %w", point, usedUp)
	}
	return errors.Join(usedUp, v.StartProduct(ctx))
}

// rollbackInputs reads the request the last product transaction published and returns its completed point and the
// packages kept beside it, verified together. A request whose point is gone is not trusted.
func (v DataVolume) rollbackInputs(ctx context.Context) (point string, packages []string, err error) {
	info, err := os.Lstat(v.RequestPath)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil, fmt.Errorf("no product transaction has published a data snapshot request (%s)", v.RequestPath)
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > 128 {
		return "", nil, fmt.Errorf("the data snapshot request %s is not a regular file", v.RequestPath)
	}
	request, err := os.ReadFile(v.RequestPath)
	if err != nil {
		return "", nil, fmt.Errorf("read the data snapshot request: %w", err)
	}
	digest, ok := strings.CutPrefix(strings.TrimSuffix(string(request), "\n"), snapshotRequestPrefix)
	if !ok || !snapshotDigest.MatchString(digest) {
		return "", nil, errors.New("the last package transaction took no data snapshot (an upgrade outside the appliance update or the edition swap)")
	}
	point = filepath.Join(v.SnapshotsDir, digest)
	if info, err := os.Lstat(point); err != nil || !info.IsDir() {
		return "", nil, fmt.Errorf("the restore point %s the last transaction named is gone", point)
	}
	entries, err := os.ReadDir(point + packageSuffix)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", nil, fmt.Errorf("read the packages kept beside %s: %w", point, err)
	}
	for _, entry := range entries {
		if entry.Type().IsRegular() && strings.HasSuffix(entry.Name(), ".rpm") {
			packages = append(packages, filepath.Join(point+packageSuffix, entry.Name()))
		}
	}
	if len(packages) == 0 {
		return "", nil, fmt.Errorf("no previous package is kept beside %s (an edition swap keeps none, a rollback uses them up, and an update keeps none when the channel no longer offered the installed versions)", point)
	}
	if err := v.VerifyPackages(ctx, packages); err != nil {
		return "", nil, fmt.Errorf("the packages kept beside %s cannot go back: %w", point, err)
	}
	return point, packages, nil
}

// restore replaces the data volume's content with the point's. The copy shares the point's extents on btrfs and
// keeps owners, modes, times and SELinux labels.
func (v DataVolume) restore(ctx context.Context, point string) error {
	entries, err := os.ReadDir(v.DataDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := os.RemoveAll(filepath.Join(v.DataDir, entry.Name())); err != nil {
			return err
		}
	}
	_, err = v.Run(ctx, []string{"/usr/bin/cp", "-a", "--reflink=auto", "--", point + "/.", v.DataDir}, 4096)
	return err
}

// rollbackMarker is the rollback's in-progress marker. It sits in the snapshot directory, which the restore never
// touches; the product unit's ExecCondition tests for it (packaging/service/systemd.service).
func (v DataVolume) rollbackMarker() string { return filepath.Join(v.SnapshotsDir, rollbackMarkerName) }

// markRollback makes the marker durable before the restore touches the data volume.
func (v DataVolume) markRollback(point string) error {
	file, err := os.OpenFile(v.rollbackMarker(), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, err = file.WriteString(filepath.Base(point) + "\n")
	if err == nil {
		err = file.Sync()
	}
	return errors.Join(err, file.Close(), syncDirectory(v.SnapshotsDir))
}

// unmarkRollback removes the marker once the data volume and its packages are whole, durably.
func (v DataVolume) unmarkRollback() error {
	if err := os.Remove(v.rollbackMarker()); err != nil {
		return err
	}
	return syncDirectory(v.SnapshotsDir)
}

// take measures capacity, stops the product and publishes the snapshot and its
// request. It records the product's start in point before stopping it, so the
// caller's one Restart covers every failure after the stop.
func (v DataVolume) take(ctx context.Context, point *DataSnapshot) error {
	// A point taken from a half-restored data volume would replace the last good point at the next prune.
	if _, err := os.Lstat(v.rollbackMarker()); err == nil {
		return errors.New("a rollback is in progress: run the rollback again before updating")
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("check for a rollback in progress: %w", err)
	}
	capacity := v.statfs
	if capacity == nil {
		capacity = filesystemCapacity
	}
	blocks, available, err := capacity(v.DataDir)
	if err != nil {
		return fmt.Errorf("measure data volume capacity: %w", err)
	}
	if blocks == 0 {
		return errors.New("measure data volume capacity: zero-sized filesystem")
	}
	if available <= blocks/20 {
		// The kept points hold the blocks of data deleted since they were taken.
		return fmt.Errorf("data volume is 95%% full or more; free space before upgrading (the restore points in %s keep deleted data: btrfs subvolume delete the oldest)", v.SnapshotsDir)
	}
	active, err := v.ProductActive(ctx)
	if err != nil {
		return fmt.Errorf("ask whether the product runs: %w", err)
	}
	if active {
		point.start = v.StartProduct
		if err := v.StopProduct(ctx); err != nil {
			return fmt.Errorf("stop the product before the data snapshot: %w", err)
		}
	}
	random := make([]byte, 10)
	if _, err := rand.Read(random); err != nil {
		return fmt.Errorf("mint snapshot request: %w", err)
	}
	// Twelve hexadecimal digits of epoch milliseconds make request identities
	// sortable; eighty random bits keep concurrent transactions distinct.
	digest := fmt.Sprintf("%012x%s", time.Now().UnixMilli(), hex.EncodeToString(random))
	stage := filepath.Join(v.SnapshotsDir, "."+digest+".partial")
	path := filepath.Join(v.SnapshotsDir, digest)
	published, requestPublished := false, false
	defer func() {
		if published {
			return
		}
		if requestPublished {
			_ = os.Remove(v.RequestPath)
		}
		// Best effort: a leftover partial or unpublished point is never selected as a restore point.
		for _, leftover := range []string{stage, path} {
			if _, statErr := os.Lstat(leftover); statErr == nil {
				_, _ = v.Run(context.WithoutCancel(ctx), []string{"/usr/sbin/btrfs", "subvolume", "delete", leftover}, 4096)
			}
		}
	}()
	if _, err := v.Run(ctx, []string{"/usr/sbin/btrfs", "filesystem", "sync", v.DataDir}, 4096); err != nil {
		return fmt.Errorf("sync the data volume before the snapshot: %w", err)
	}
	if _, err := v.Run(ctx, []string{"/usr/sbin/btrfs", "subvolume", "snapshot", "-r", v.DataDir, stage}, 4096); err != nil {
		return fmt.Errorf("take the read-only data snapshot: %w", err)
	}
	if err := os.Rename(stage, path); err != nil {
		return fmt.Errorf("publish the data snapshot: %w", err)
	}
	if err := syncDirectory(v.SnapshotsDir); err != nil {
		return fmt.Errorf("persist the data snapshot: %w", err)
	}
	if err := publishSnapshotRequest(v.RequestPath, digest); err != nil {
		return err
	}
	requestPublished = true
	if v.Relabel {
		if _, err := v.Run(ctx, []string{"/usr/sbin/restorecon", v.RequestPath}, 4096); err != nil {
			return fmt.Errorf("relabel the snapshot request: %w", err)
		}
	}
	if err := v.prune(ctx, digest); err != nil {
		return err
	}
	published = true
	point.Digest, point.Path = digest, path
	return nil
}

func (v DataVolume) prepareSnapshotsDir() error {
	if err := os.Mkdir(v.SnapshotsDir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("create the snapshot directory: %w", err)
	}
	info, err := os.Lstat(v.SnapshotsDir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return errors.New("snapshot directory is not a private real directory")
	}
	return nil
}

// prune runs after the new point is complete and keeps it plus the newest two
// others; a clock stepped back cannot make it delete the point just taken. A
// partial left by a transaction that crashed is never a restore point, and it
// goes too: under the lock no other transaction is taking one. Unrelated
// entries are left alone.
func (v DataVolume) prune(ctx context.Context, keep string) error {
	if err := v.prepareSnapshotsDir(); err != nil {
		return err
	}
	entries, err := os.ReadDir(v.SnapshotsDir)
	if err != nil {
		return fmt.Errorf("list data snapshots: %w", err)
	}
	names, partials := []string{}, []string{}
	for _, entry := range entries {
		name := entry.Name()
		switch {
		case !entry.IsDir() || name == keep:
		case snapshotDigest.MatchString(name):
			names = append(names, name)
		case partialSnapshot.MatchString(name):
			partials = append(partials, name)
		}
	}
	slices.Sort(names)
	for _, name := range append(partials, names[:max(0, len(names)-2)]...) {
		path := filepath.Join(v.SnapshotsDir, name)
		if _, err := v.Run(ctx, []string{"/usr/sbin/btrfs", "subvolume", "delete", path}, 4096); err != nil {
			return fmt.Errorf("remove the old data snapshot %s: %w", path, err)
		}
		if err := os.RemoveAll(path + packageSuffix); err != nil {
			return fmt.Errorf("remove the package kept beside %s: %w", path, err)
		}
	}
	return nil
}

func publishSnapshotRequest(path, digest string) error {
	stage, err := os.CreateTemp(filepath.Dir(path), ".upgrade-snapshot-")
	if err != nil {
		return fmt.Errorf("stage the snapshot request: %w", err)
	}
	name := stage.Name()
	defer os.Remove(name)
	if err = stage.Chmod(0o644); err == nil {
		_, err = stage.WriteString(snapshotRequestPrefix + digest + "\n")
	}
	if err == nil {
		err = stage.Sync()
	}
	if closeErr := stage.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("write the snapshot request: %w", err)
	}
	if err = os.Rename(name, path); err != nil {
		return fmt.Errorf("publish the snapshot request: %w", err)
	}
	if err = syncDirectory(filepath.Dir(path)); err != nil {
		return fmt.Errorf("persist the snapshot request: %w", err)
	}
	return nil
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}
