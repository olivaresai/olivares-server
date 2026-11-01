// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package hostusers

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
	"time"
)

// Linux is used inside the fixed, kernel-attested root helper. It is not a
// portal privilege escalator and is deliberately not composed by this package.
type Linux struct{}

func (Linux) Account(_ context.Context, name string) (Account, bool, error) {
	u, err := user.Lookup(name)
	var missing user.UnknownUserError
	if errors.As(err, &missing) {
		return Account{}, false, nil
	}
	if err != nil {
		return Account{}, false, errors.New("account_unavailable")
	}
	return Account{Name: u.Username, UID: u.Uid, GID: u.Gid, Home: u.HomeDir}, true, nil
}
func (Linux) Group(_ context.Context, name string) (string, error) {
	g, err := user.LookupGroup(name)
	if err != nil {
		return "", errors.New("group_unavailable")
	}
	return g.Gid, nil
}
func (Linux) Home(_ context.Context, path string) (Home, error) {
	parent, err := os.Lstat("/home")
	if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 || parent.Mode().Perm()&0o022 != 0 {
		return Home{}, errors.New("home_unavailable")
	}
	stat, ok := parent.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return Home{}, errors.New("home_unavailable")
	}
	child, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return Home{}, nil
	}
	if err != nil || child.Mode()&os.ModeSymlink != 0 {
		return Home{}, errors.New("home_unavailable")
	}
	stat, ok = child.Sys().(*syscall.Stat_t)
	if !ok {
		return Home{}, errors.New("home_unavailable")
	}
	return Home{Exists: true, Directory: child.IsDir(), Private: child.Mode().Perm()&0o077 == 0, UID: strconv.FormatUint(uint64(stat.Uid), 10), GID: strconv.FormatUint(uint64(stat.Gid), 10)}, nil
}
func (Linux) Run(ctx context.Context, path string, args []string) error {
	if path != "/usr/sbin/useradd" {
		return errors.New("input_refused")
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	if cmd.Run() != nil {
		return errors.New("effect_failed")
	}
	return nil
}
