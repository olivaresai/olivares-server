// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package updates

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type snapshotHost struct {
	dataDir      string
	snapshotsDir string
	requestPath  string
	calls        []string
	active       bool
	starts       int
	snapshotErr  error
}

func (h *snapshotHost) volume() DataVolume {
	return DataVolume{
		DataDir: h.dataDir, SnapshotsDir: h.snapshotsDir, RequestPath: h.requestPath,
		Run: func(_ context.Context, argv []string, _ int64) ([]byte, error) {
			h.calls = append(h.calls, strings.Join(argv, " "))
			switch argv[1] {
			case "subvolume":
				if argv[2] == "snapshot" {
					if h.snapshotErr != nil {
						return nil, h.snapshotErr
					}
					return nil, os.Mkdir(argv[len(argv)-1], 0o700)
				}
				return nil, os.RemoveAll(argv[len(argv)-1])
			}
			return nil, nil
		},
		ProductActive: func(context.Context) (bool, error) { return h.active, nil },
		StopProduct: func(context.Context) error {
			h.calls = append(h.calls, "stop")
			return nil
		},
		StartProduct: func(context.Context) error {
			h.starts++
			return nil
		},
		statfs: func(string) (uint64, uint64, error) { return 100, 50, nil },
	}
}

func newSnapshotHost(t *testing.T) *snapshotHost {
	t.Helper()
	dir := t.TempDir()
	h := &snapshotHost{
		dataDir:      filepath.Join(dir, "data"),
		snapshotsDir: filepath.Join(dir, "snapshots"),
		requestPath:  filepath.Join(dir, "package", "upgrade-snapshot"),
		active:       true,
	}
	for _, dir := range []string{h.dataDir, filepath.Dir(h.requestPath)} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

func TestDataVolumeSnapshotIsReadOnlyBoundToRequestAndProductIsQuiesced(t *testing.T) {
	h := newSnapshotHost(t)
	snapshot, err := h.volume().Before(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Digest) != 32 || filepath.Base(snapshot.Path) != snapshot.Digest {
		t.Fatalf("snapshot identity %+v", snapshot)
	}
	request, err := os.ReadFile(h.requestPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(request) != "upgrade-snapshot."+snapshot.Digest+"\n" {
		t.Fatalf("request %q does not name snapshot %q", request, snapshot.Digest)
	}
	if info, err := os.Stat(snapshot.Path); err != nil || !info.IsDir() {
		t.Fatalf("snapshot was not published: %v", err)
	}
	joined := strings.Join(h.calls, "\n")
	if !strings.Contains(joined, "subvolume snapshot -r "+h.dataDir+" ") {
		t.Fatalf("snapshot is not read-only: %s", joined)
	}
	if len(h.calls) < 3 || h.calls[0] != "stop" || !strings.HasPrefix(h.calls[1], "/usr/sbin/btrfs filesystem sync ") {
		t.Fatalf("product writes were not quiesced before the snapshot: %v", h.calls)
	}
	if h.starts != 0 {
		t.Fatal("product restarted before the package transaction finished")
	}
	if err := snapshot.Restart(t.Context()); err != nil || h.starts != 1 {
		t.Fatalf("restart = %d, %v", h.starts, err)
	}
}

func TestDataVolumeSnapshotRefusesAt95PercentBeforeAnyEffect(t *testing.T) {
	h := newSnapshotHost(t)
	volume := h.volume()
	volume.statfs = func(string) (uint64, uint64, error) { return 100, 5, nil }
	_, err := volume.Before(t.Context())
	if err == nil || !strings.Contains(err.Error(), "95%") {
		t.Fatalf("capacity refusal = %v", err)
	}
	// The kept points hold the blocks of data deleted since; the refusal says where they are.
	if !strings.Contains(err.Error(), h.snapshotsDir) {
		t.Fatalf("capacity refusal %q does not name the snapshot directory %s", err, h.snapshotsDir)
	}
	if len(h.calls) != 0 || h.starts != 0 {
		t.Fatalf("capacity refusal had an effect: %v, starts=%d", h.calls, h.starts)
	}
	if _, statErr := os.Lstat(h.requestPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("capacity refusal published a request: %v", statErr)
	}
}

func TestDataVolumeSnapshotFailureRestartsProductWithoutPublishingRequest(t *testing.T) {
	h := newSnapshotHost(t)
	h.snapshotErr = errors.New("not btrfs")
	_, err := h.volume().Before(t.Context())
	if err == nil || h.starts != 1 {
		t.Fatalf("snapshot failure = %v, restarts=%d", err, h.starts)
	}
	if _, statErr := os.Lstat(h.requestPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failed snapshot published a request: %v", statErr)
	}
}

func TestDataVolumeSerializesProductTransactions(t *testing.T) {
	h := newSnapshotHost(t)
	first, err := h.volume().Before(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	second, err := h.volume().Before(t.Context())
	if err == nil {
		t.Fatalf("concurrent transaction took snapshot %q", second.Path)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := h.volume().Before(t.Context()); err != nil {
		t.Fatalf("transaction after close: %v", err)
	}
}

// The lock is on the root-only snapshot directory: the package state directory is world-readable, so any local user
// can hold a lock there, and that must neither block a transaction nor pass for its owner.
func TestDataVolumeTransactionLockIsTheRootOnlySnapshotDirectory(t *testing.T) {
	h := newSnapshotHost(t)
	if err := os.Mkdir(h.snapshotsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	hold := func(dir string) *os.File {
		f, err := os.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		if err := lockDirectory(f); err != nil {
			t.Fatal(err)
		}
		return f
	}
	other := hold(filepath.Dir(h.requestPath))
	point, err := h.volume().Before(t.Context())
	if err != nil {
		t.Fatalf("a lock on the package state directory blocked the transaction: %v", err)
	}
	if err := errors.Join(point.Close(), other.Close()); err != nil {
		t.Fatal(err)
	}
	owner := hold(h.snapshotsDir)
	defer owner.Close()
	if _, err := h.volume().Before(t.Context()); err == nil || !strings.Contains(err.Error(), "another product transaction") {
		t.Fatalf("err = %v with the snapshot directory locked, want the running transaction named", err)
	}
}

func TestDataVolumeSnapshotKeepsTheLastThreeCompletedPoints(t *testing.T) {
	h := newSnapshotHost(t)
	if err := os.Mkdir(h.snapshotsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	oldest := ""
	for i, digest := range []string{"00000000000000000000000000000001", "00000000000000000000000000000002", "00000000000000000000000000000003"} {
		path := filepath.Join(h.snapshotsDir, digest)
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			oldest = path
		}
	}
	// The previous package an update retained beside its point goes with the point.
	if err := os.Mkdir(oldest+".package", 0o700); err != nil {
		t.Fatal(err)
	}
	// A partial left by a transaction that crashed is never a restore point and pins its blocks: it goes too.
	if err := os.Mkdir(filepath.Join(h.snapshotsDir, ".00000000000000000000000000000000.partial"), 0o700); err != nil {
		t.Fatal(err)
	}
	snapshot, err := h.volume().Before(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(h.snapshotsDir)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	if len(names) != 3 || slices.Contains(names, filepath.Base(oldest)) || slices.Contains(names, filepath.Base(oldest)+".package") || !slices.Contains(names, filepath.Base(snapshot.Path)) {
		t.Fatalf("retained snapshots %v", names)
	}
}

// A clock stepped back sorts the new point before the kept ones; it is still kept.
func TestDataVolumeSnapshotKeepsTheNewPointWhenTheClockSteppedBack(t *testing.T) {
	h := newSnapshotHost(t)
	if err := os.Mkdir(h.snapshotsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	future := []string{"fffffffffff0000000000000000000a1", "fffffffffff0000000000000000000a2", "fffffffffff0000000000000000000a3"}
	for _, digest := range future {
		if err := os.Mkdir(filepath.Join(h.snapshotsDir, digest), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	snapshot, err := h.volume().Before(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(h.snapshotsDir)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	if len(names) != 3 || !slices.Contains(names, filepath.Base(snapshot.Path)) || slices.Contains(names, future[0]) {
		t.Fatalf("retained snapshots %v, want the new point %s and the newest two others", names, filepath.Base(snapshot.Path))
	}
}

// A rollback restores the point the last product transaction's request names and reinstalls the package retained
// beside it. Every refusal comes before the product is stopped; a rollback uses the retained package up.
func TestDataVolumeRollbackRestoresTheRequestedPointAndReinstallsTheRetainedPackage(t *testing.T) {
	const digest = "019a5b1c2d3e4f5061728394a5b6c7d8"
	keptPackages := []string{"olivares-0.7.0-1.x86_64.rpm", "olivares-appliance-base-0.7.0-1.x86_64.rpm"}
	bases := func(paths []string) string {
		names := make([]string, 0, len(paths))
		for _, path := range paths {
			names = append(names, filepath.Base(path))
		}
		return strings.Join(names, " ")
	}
	setup := func(t *testing.T, request string, point, pkg bool) (*snapshotHost, DataVolume, *[]string) {
		h := newSnapshotHost(t)
		if err := os.Mkdir(h.snapshotsDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if request != "" {
			if err := os.WriteFile(h.requestPath, []byte(request+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if point {
			if err := os.MkdirAll(filepath.Join(h.snapshotsDir, digest, "store"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(h.snapshotsDir, digest, "store", "olivares.db"), []byte("before"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if pkg {
			if err := os.Mkdir(filepath.Join(h.snapshotsDir, digest+".package"), 0o700); err != nil {
				t.Fatal(err)
			}
			// The update keeps every Olivares package it replaces: the layer requires the product at its own version.
			for _, kept := range keptPackages {
				if err := os.WriteFile(filepath.Join(h.snapshotsDir, digest+".package", kept), []byte("rpm"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}
		for name, data := range map[string]string{"store/olivares.db": "after", "written-after-the-update": "x"} {
			if err := os.MkdirAll(filepath.Dir(filepath.Join(h.dataDir, name)), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(h.dataDir, name), []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		volume := h.volume()
		run := volume.Run
		volume.Run = func(ctx context.Context, argv []string, limit int64) ([]byte, error) {
			if argv[0] == "/usr/bin/cp" {
				h.calls = append(h.calls, strings.Join(argv, " "))
				src, dst := strings.TrimSuffix(argv[len(argv)-2], "/."), argv[len(argv)-1]
				return nil, os.CopyFS(dst, os.DirFS(src))
			}
			return run(ctx, argv, limit)
		}
		installed := []string{}
		volume.VerifyPackages = func(_ context.Context, paths []string) error {
			h.calls = append(h.calls, "verify "+bases(paths))
			return nil
		}
		volume.InstallPackages = func(_ context.Context, paths []string) error {
			h.calls = append(h.calls, "install "+bases(paths))
			installed = append(installed, bases(paths))
			return nil
		}
		return h, volume, &installed
	}

	for _, refusal := range []struct {
		name, request string
		point, pkg    bool
		verifyErr     error
		want          string
	}{
		{"no request", "", true, true, nil, "no product transaction"},
		{"a request no appliance transaction published", "upgrade-snapshot.Ab3dEf9h", true, true, nil, "took no data snapshot"},
		{"a request whose point is gone", "upgrade-snapshot." + digest, false, true, nil, "is gone"},
		{"no retained package", "upgrade-snapshot." + digest, true, false, nil, "no previous package"},
		{"kept packages that do not verify or cannot go back together", "upgrade-snapshot." + digest, true, true, errors.New("NOT OK"), "cannot go back"},
	} {
		t.Run(refusal.name, func(t *testing.T) {
			h, volume, installed := setup(t, refusal.request, refusal.point, refusal.pkg)
			if refusal.verifyErr != nil {
				volume.VerifyPackages = func(context.Context, []string) error { return refusal.verifyErr }
			}
			err := volume.Rollback(t.Context())
			if err == nil || !strings.Contains(err.Error(), refusal.want) || !strings.Contains(err.Error(), "nothing was stopped") {
				t.Fatalf("err = %v, want a refusal naming %q that says nothing was stopped", err, refusal.want)
			}
			if slices.Contains(h.calls, "stop") || len(*installed) != 0 || h.starts != 0 {
				t.Fatalf("a refused rollback had an effect: %v, installed %v, starts %d", h.calls, *installed, h.starts)
			}
			if data, _ := os.ReadFile(filepath.Join(h.dataDir, "store", "olivares.db")); string(data) != "after" {
				t.Fatalf("a refused rollback changed the data: %q", data)
			}
		})
	}

	h, volume, installed := setup(t, "upgrade-snapshot."+digest, true, true)
	if err := volume.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(h.dataDir, "store", "olivares.db")); err != nil || string(data) != "before" {
		t.Fatalf("restored store = %q, %v; want the point's", data, err)
	}
	if _, err := os.Lstat(filepath.Join(h.dataDir, "written-after-the-update")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("data written after the update survived the rollback: %v", err)
	}
	// The kept packages are checked together before the stop and go back in one transaction, so a layer that requires
	// the product at its own version goes back with it.
	want := []string{"verify " + strings.Join(keptPackages, " "), "stop",
		"/usr/bin/cp -a --reflink=auto -- " + filepath.Join(h.snapshotsDir, digest) + "/. " + h.dataDir,
		"install " + strings.Join(keptPackages, " ")}
	if !slices.Equal(h.calls, want) || h.starts != 1 {
		t.Fatalf("calls %q, starts %d; want %q and one start", h.calls, h.starts, want)
	}
	if _, err := os.Lstat(filepath.Join(h.snapshotsDir, digest)); err != nil {
		t.Fatalf("the restore point went with the rollback: %v", err)
	}
	// The retained package is used up: a second rollback would wipe what was written since the first.
	if err := volume.Rollback(t.Context()); err == nil || !strings.Contains(err.Error(), "no previous package") {
		t.Fatalf("second rollback = %v, want the used-up package named", err)
	}
	if len(*installed) != 1 {
		t.Fatalf("installed %v, want one reinstall", *installed)
	}
}

// A power loss during the restore leaves the data volume half-restored. The rollback marker sits in the snapshot
// directory, which the restore does not touch, and the product unit refuses to start while it exists. Until a rollback
// run again finishes the restore, the product stays down and an update takes no point of the half-restored tree.
func TestDataVolumeRollbackCrashMidRestoreKeepsTheProductDownUntilRestored(t *testing.T) {
	const digest = "019a5b1c2d3e4f5061728394a5b6c7d8"
	h := newSnapshotHost(t)
	if err := os.Mkdir(h.snapshotsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(path, data string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(h.requestPath, []byte("upgrade-snapshot."+digest+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(h.snapshotsDir, digest, "store", "olivares.db"), "before")
	write(filepath.Join(h.snapshotsDir, digest+".package", "olivares-0.7.0-1.x86_64.rpm"), "rpm")
	write(filepath.Join(h.dataDir, "store", "olivares.db"), "after")
	write(filepath.Join(h.dataDir, "written-after-the-update"), "x")

	volume := h.volume()
	hostRun := volume.Run
	volume.Run = func(ctx context.Context, argv []string, limit int64) ([]byte, error) {
		if argv[0] != "/usr/bin/cp" {
			return hostRun(ctx, argv, limit)
		}
		// The power goes after the copy has written the store and before the rest of the point.
		write(filepath.Join(h.dataDir, "store", "olivares.db"), "before")
		return nil, errors.New("power lost")
	}
	volume.VerifyPackages = func(context.Context, []string) error { return nil }
	volume.InstallPackages = func(context.Context, []string) error { return nil }
	if err := volume.Rollback(t.Context()); err == nil {
		t.Fatal("a rollback whose copy lost power reported success")
	}

	marker := filepath.Join(h.snapshotsDir, "rollback-in-progress")
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("a crashed restore left no marker in the snapshot directory: %v", err)
	}
	if h.starts != 0 {
		t.Fatalf("the product started %d times on a half-restored data volume", h.starts)
	}
	unit, err := os.ReadFile(filepath.Join("..", "..", "..", "packaging", "systemd", "olivares.service"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(unit), "ExecCondition=+/usr/bin/test ! -e /var/lib/olivares-snapshots/rollback-in-progress\n") {
		t.Fatal("the product unit does not refuse to start while the rollback marker exists")
	}
	if _, err := volume.Before(t.Context()); err == nil || !strings.Contains(err.Error(), "rollback is in progress") {
		t.Fatalf("an update took a point of the half-restored data volume: %v", err)
	}

	volume.Run = func(ctx context.Context, argv []string, limit int64) ([]byte, error) {
		if argv[0] == "/usr/bin/cp" {
			return nil, os.CopyFS(argv[len(argv)-1], os.DirFS(strings.TrimSuffix(argv[len(argv)-2], "/.")))
		}
		return hostRun(ctx, argv, limit)
	}
	if err := volume.Rollback(t.Context()); err != nil {
		t.Fatalf("a rollback run again after the crash: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(h.dataDir, "store", "olivares.db")); err != nil || string(data) != "before" {
		t.Fatalf("restored store = %q, %v; want the point's", data, err)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the marker outlived a completed restore: %v", err)
	}
	if h.starts != 1 {
		t.Fatalf("starts = %d after the completed restore, want 1", h.starts)
	}
}
