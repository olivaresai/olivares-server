// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package optionalapps

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"syscall"
	"time"
)

// LinuxRun is for the fixed root helper, with the local Docker socket and a
// helper-owned empty Docker config. It inherits no account environment, accepts
// no shell, and discards native diagnostics rather than publishing app output.
// Killing a client never promises cancellation of an accepted daemon action.
func LinuxRun(ctx context.Context, argv []string, limit int64) ([]byte, error) {
	if os.Geteuid() != 0 || len(argv) < 6 || !slices.Equal(argv[:4], []string{"/usr/bin/docker", "--host", "unix:///var/run/docker.sock", "--config"}) || filepath.Base(argv[4]) != "docker-config" || !filepath.IsAbs(argv[4]) || limit < 1 || limit > 16<<10 {
		return nil, errors.New("consumer_unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir = filepath.Dir(argv[4])
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "COMPOSE_DISABLE_ENV_FILE=true"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.WaitDelay = 2 * time.Second
	out := boundedOutput{remaining: limit}
	cmd.Stdout, cmd.Stderr = &out, io.Discard
	if cmd.Run() != nil || out.overflow {
		return nil, errors.New("native_docker_command_failed")
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
