// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

//go:build linux && (amd64 || arm64)

package identityengine

import (
	"context"
	"errors"
	"github.com/olivaresai/olivares/core/auth"
	"net"
	"sync"
	"time"

	"github.com/olivaresai/olivares/appliance/layer/portal/localframe"
	"github.com/olivaresai/olivares/core/nativepam"
	"golang.org/x/sys/unix"
)

// Serve consumes the system-manager-passed dedicated Unix listener. It never
// binds another endpoint or starts another daemon. Each connection is one call.
func (s *Server) Serve(ctx context.Context, listener *net.UnixListener) error {
	if ctx == nil || listener == nil || ctx.Err() != nil {
		return refused
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	defer listener.Close()
	var jobs sync.WaitGroup
	defer jobs.Wait()
	slots := make(chan struct{}, 4)
	for {
		c, err := listener.AcceptUnix()
		if err != nil {
			stopping := ctx.Err() != nil
			cancel()
			if stopping {
				return nil
			}
			return err
		}
		select {
		case slots <- struct{}{}:
			jobs.Add(1)
			go func() {
				defer jobs.Done()
				defer func() { <-slots }()
				s.serveConnection(ctx, c)
			}()
		default:
			_ = c.Close()
		}
	}
}

func (s *Server) serveConnection(ctx context.Context, c *net.UnixConn) {
	defer c.Close()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	until, _ := ctx.Deadline()
	if c.SetDeadline(until) != nil {
		return
	}
	broker, err := nativepam.HoldPortalAuthority(ctx, c)
	if err != nil {
		return
	}
	defer broker.Close()
	if localframe.Write(c, localframe.Record{Type: "ready", Version: 1}) != nil {
		return
	}
	req, fd, err := localframe.NextAuthorityRequest(c, localframe.Expect{UID: broker.UID(), PID: broker.PID()}, func() error { return broker.Alive(ctx) })
	if err != nil {
		return
	}
	defer unix.Close(fd)
	original, err := nativepam.HoldOriginalAuthority(ctx, fd)
	if err != nil {
		_ = localframe.WriteAuthorityRefusal(c)
		return
	}
	defer original.Close()
	// Remain cancelable while the current auth view is running. No original
	// stream is read or shut down; polling observes only disconnect/held death.
	done, ended := make(chan struct{}), make(chan struct{})
	defer func() { close(done); <-ended }()
	go func() {
		defer close(ended)
		tick := time.NewTicker(25 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-tick.C:
				if broker.Alive(ctx) != nil || original.Alive(ctx) != nil {
					cancel()
					return
				}
			}
		}
	}()
	answer, err := s.authorize(ctx, original.UID(), req)
	if err != nil || broker.Check(ctx) != nil || original.Check(ctx) != nil {
		if errors.Is(err, auth.ErrExposureNeedsStepUp) && broker.Check(ctx) == nil && original.Check(ctx) == nil {
			_ = localframe.WriteExposureRefusal(c)
			return
		}
		_ = localframe.WriteAuthorityRefusal(c)
		return
	}
	_ = localframe.WriteAuthorityReply(c, answer)
}
