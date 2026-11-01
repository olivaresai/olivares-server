// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

//go:build linux && (amd64 || arm64)

package identityclient

import (
	"context"
	"net"
	"syscall"
	"time"

	"github.com/olivaresai/olivares/appliance/layer/hostops"
	"github.com/olivaresai/olivares/appliance/layer/portal/localframe"
	"github.com/olivaresai/olivares/appliance/layer/portal/localsession"
	"github.com/olivaresai/olivares/core/nativepam"
	"golang.org/x/sys/unix"
)

func (a authority) Authorize(ctx context.Context, d hostops.Descriptor, target, digest string) (hostops.Caller, error) {
	if ctx == nil || ctx.Err() != nil || a.held == nil || a.held.Err() != nil || a.uid == 0 {
		return hostops.Caller{}, refused
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	stopHeld := context.AfterFunc(a.held, cancel)
	defer stopHeld()
	fd, err := localsession.DuplicatePeerSocket(a.held)
	if err != nil {
		return hostops.Caller{}, refused
	}
	defer unix.Close(fd)
	original, err := nativepam.HoldOriginalAuthority(ctx, fd)
	if err != nil {
		return hostops.Caller{}, refused
	}
	defer original.Close()
	if original.UID() != a.uid {
		return hostops.Caller{}, refused
	}
	engine, err := nativepam.HoldEngineAuthority(ctx)
	if err != nil {
		return hostops.Caller{}, refused
	}
	defer engine.Close()
	dialer := net.Dialer{Control: func(network, address string, raw syscall.RawConn) error {
		if network != "unix" || address != nativepam.AuthoritySocketPath {
			return refused
		}
		var failure error
		err := raw.Control(func(fd uintptr) { failure = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSCRED, 1) })
		if err != nil {
			return err
		}
		return failure
	}}
	connection, err := dialer.DialContext(ctx, "unix", nativepam.AuthoritySocketPath)
	if err != nil {
		return hostops.Caller{}, refused
	}
	defer connection.Close()
	c, ok := connection.(*net.UnixConn)
	if !ok {
		return hostops.Caller{}, refused
	}
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	until, _ := ctx.Deadline()
	if c.SetDeadline(until) != nil {
		return hostops.Caller{}, refused
	}
	check := func() error {
		if engine.Alive(ctx) != nil || original.Alive(ctx) != nil || a.held.Err() != nil {
			return refused
		}
		return nil
	}
	expect := localframe.Expect{UID: engine.UID(), PID: engine.PID()}
	ready, err := localframe.Next(c, expect, check)
	if err != nil || ready.Type != "ready" || ready.Version != 1 || engine.Check(ctx) != nil || check() != nil {
		return hostops.Caller{}, refused
	}
	request := localframe.AuthorityRequest{Task: d.ID, Target: target, IntentDigest: digest}
	if localframe.WriteAuthorityRequest(c, request, fd) != nil {
		return hostops.Caller{}, refused
	}
	reply, err := localframe.NextAuthorityReply(c, expect, check)
	if err != nil || engine.Check(ctx) != nil || check() != nil || reply.Task != request.Task || reply.Target != request.Target ||
		reply.IntentDigest != request.IntentDigest || reply.Mode != "product-up" || reply.Actor == "" ||
		!reply.ValidUntil.After(time.Now()) || reply.ValidUntil.After(until) {
		return hostops.Caller{}, refused
	}
	return hostops.Caller{Actor: reply.Actor, Mode: reply.Mode}, nil
}
