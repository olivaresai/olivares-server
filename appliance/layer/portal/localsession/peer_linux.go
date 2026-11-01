// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

//go:build linux && (amd64 || arm64)

package localsession

import (
	"context"
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// DuplicatePeerSocket returns a fresh close-on-exec duplicate of the original
// admitted connection, for one engine authorization. The caller owns the FD and
// must close it on every outcome. It must not read, shut down or change socket
// flags through the duplicate, which shares the original stream's state.
// Missing, canceled or no longer held proof refuses; UID is never a substitute.
func DuplicatePeerSocket(ctx context.Context) (int, error) {
	refused := errors.New("mode_refused")
	if ctx == nil {
		return -1, refused
	}
	p, ok := ctx.Value(peerContextKey{}).(heldPeer)
	if !ok || p.owner == nil || ctx.Err() != nil || p.owner.Check() != nil || !peerSocketAlive(p.connection) {
		return -1, refused
	}
	raw, err := p.connection.SyscallConn()
	if err != nil {
		return -1, refused
	}
	fd := -1
	var duplicateErr error
	err = raw.Control(func(original uintptr) { fd, duplicateErr = unix.FcntlInt(original, unix.F_DUPFD_CLOEXEC, 0) })
	if err != nil || duplicateErr != nil || ctx.Err() != nil || p.owner.Check() != nil || !peerSocketAlive(p.connection) {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
		return -1, refused
	}
	return fd, nil
}

// Poll observes a full disconnect without reading data or changing stream flags.
// A write half-close can still await a reply and does not end its held session.
func peerSocketAlive(c *net.UnixConn) bool {
	if c == nil {
		return false
	}
	raw, err := c.SyscallConn()
	if err != nil {
		return false
	}
	alive := false
	err = raw.Control(func(fd uintptr) {
		poll := []unix.PollFd{{Fd: int32(fd)}}
		_, err := unix.Poll(poll, 0)
		// A signal that reaches the thread inside the call is no answer about the peer: ask again.
		for err == unix.EINTR {
			_, err = unix.Poll(poll, 0)
		}
		alive = err == nil && poll[0].Revents&(unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) == 0
	})
	return err == nil && alive
}
