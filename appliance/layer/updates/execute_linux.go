// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package updates

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"slices"
	"syscall"
	"time"
)

// LinuxRun is for the fixed attested root helper. It uses only the two native
// package programs and fixed environment; stderr and command failures never
// expose RPM scriptlet output or host paths through the product response.
func LinuxRun(ctx context.Context, argv []string, limit int64) ([]byte, error) {
	if os.Geteuid() != 0 || len(argv) < 2 || limit < 1 || limit > 64<<10 || !slices.Contains([]string{"/usr/bin/rpm", "/usr/bin/rpmkeys"}, argv[0]) {
		return nil, errors.New("consumer_unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.WaitDelay = 2 * time.Second
	defer func() {
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
	}()
	out := boundedOutput{remaining: limit}
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	if cmd.Run() != nil || out.overflow {
		return nil, errors.New("native_package_command_failed")
	}
	return out.Bytes(), nil
}

func ownedByHelper(info fs.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}

type boundedOutput struct {
	bytes.Buffer
	remaining int64
	overflow  bool
}

func (b *boundedOutput) Write(data []byte) (int, error) {
	if int64(len(data)) > b.remaining {
		b.overflow = true
		return 0, errors.New("native_output_limit")
	}
	n, err := b.Buffer.Write(data)
	b.remaining -= int64(n)
	return n, err
}

// lockDirectory takes an exclusive lock on the open directory without waiting. It is held until f is closed, and
// only another lock on the same directory is refused: the helper's reads take none.
func lockDirectory(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}

func filesystemCapacity(path string) (uint64, uint64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, 0, err
	}
	return stat.Blocks, stat.Bavail, nil
}
