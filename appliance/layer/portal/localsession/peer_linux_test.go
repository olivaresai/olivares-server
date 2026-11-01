// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

//go:build linux && (amd64 || arm64)

package localsession

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/olivaresai/olivares/appliance/layer/hostops"
	"github.com/olivaresai/olivares/appliance/layer/hostusers"
	"github.com/olivaresai/olivares/appliance/layer/portal/localframe"
	"golang.org/x/sys/unix"
)

// The socket and pidfd are real. Group admission and product authorization are
// fixtures, so this does not qualify installed identity or host effects.
type socketKernel struct {
	Linux
	exited atomic.Bool
	closed chan struct{}
}

func (*socketKernel) Admin(uint32) (bool, error) { return true, nil }
func (k *socketKernel) Alive(fd int) error {
	if k.exited.Load() {
		return errors.New("owner_exited")
	}
	return k.Linux.Alive(fd)
}
func (k *socketKernel) Close(fd int) {
	k.Linux.Close(fd)
	close(k.closed)
}

type socketAuthority func(context.Context, hostops.Descriptor, string, string) (hostops.Caller, error)

func (a socketAuthority) Authorize(ctx context.Context, d hostops.Descriptor, target, digest string) (hostops.Caller, error) {
	return a(ctx, d, target, digest)
}

func socketSession(t *testing.T, authorize socketAuthority) (*net.UnixConn, net.Listener, *socketKernel, <-chan error, *localTask) {
	t.Helper()
	catalog, err := hostops.NewCatalog(hostusers.Descriptors())
	if err != nil {
		t.Fatal(err)
	}
	engine, err := hostops.OpenWithCatalog(t.TempDir(), catalog)
	if err != nil {
		t.Fatal(err)
	}
	task := &localTask{}
	acts := hostops.NewActs(engine, catalog, map[string]hostops.AdoptedTask{"host-user.create": task}, localAudit{})
	kernel := &socketKernel{closed: make(chan struct{})}
	server := NewServer(engine, catalog, kernel).WithActs(acts, func(_ context.Context, uid uint32) (hostops.Authority, error) {
		if uid != uint32(os.Getuid()) {
			return nil, errors.New("foreign_peer")
		}
		return authorize, nil
	})
	server.lifecycleDir = t.TempDir()
	if err := hostops.InitLifecycle(server.lifecycleDir); err != nil {
		t.Fatal(err)
	}
	// Unix socket paths are bounded independently of the builder's TMPDIR.
	dir, err := os.MkdirTemp("/tmp", "applxc-peer-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	passcred := func(_, _ string, raw syscall.RawConn) error {
		var optionErr error
		err := raw.Control(func(fd uintptr) {
			optionErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_PASSCRED, 1)
		})
		if err != nil {
			return err
		}
		return optionErr
	}
	path := filepath.Join(dir, "local.sock")
	lc := net.ListenConfig{Control: passcred}
	listener, err := lc.Listen(context.Background(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener); close(done) }()
	dialer := net.Dialer{Control: passcred}
	connection, err := dialer.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	c := connection.(*net.UnixConn)
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	r, err := localframe.Next(c, localframe.Expect{UID: uint32(os.Getuid()), PID: int32(os.Getpid())}, nil)
	if err != nil || r.Type != "ready" {
		t.Fatalf("ready: %+v %v", r, err)
	}
	t.Cleanup(func() {
		_ = c.Close()
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("Serve did not finish")
		}
		select {
		case <-kernel.closed:
		case <-time.After(time.Second):
			t.Error("held pidfd was not released")
		}
	})
	return c, listener, kernel, done, task
}

func peerPlan(t *testing.T, c *net.UnixConn) {
	t.Helper()
	body := json.RawMessage(`{"module":"host-user","verb":"create","surface":"cli","inputs":{"account":"alice","home":"/home/alice","group":"staff"}}`)
	if err := localframe.Write(c, localframe.Record{Type: "request", Op: "task.plan", Body: body}); err != nil {
		t.Fatal(err)
	}
}

func TestLocalSession_HeldPeerContext(t *testing.T) {
	for _, end := range []string{"server stop", "disconnect", "owner exit"} {
		t.Run(end+" cancels authorization", func(t *testing.T) {
			entered := make(chan context.Context, 1)
			release := make(chan struct{})
			defer close(release)
			c, listener, kernel, done, _ := socketSession(t, func(ctx context.Context, _ hostops.Descriptor, _, _ string) (hostops.Caller, error) {
				entered <- ctx
				select {
				case <-ctx.Done():
				case <-release:
				}
				return hostops.Caller{}, errors.New("mode_refused")
			})
			peerPlan(t, c)
			var ctx context.Context
			select {
			case ctx = <-entered:
			case <-time.After(2 * time.Second):
				t.Fatal("authorization was not reached")
			}
			switch end {
			case "server stop":
				_ = listener.Close()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("Serve did not stop")
				}
			case "disconnect":
				_ = c.Close()
			case "owner exit":
				kernel.exited.Store(true)
			}
			select {
			case <-ctx.Done():
			case <-time.After(300 * time.Millisecond):
				t.Fatal("authorization retained a live context after " + end)
			}
			select {
			case <-kernel.closed:
			case <-time.After(time.Second):
				t.Fatal("held pidfd was not released")
			}
			if fd, err := DuplicatePeerSocket(ctx); err == nil || fd != -1 {
				t.Fatalf("terminated context supplied a socket: fd=%d err=%v", fd, err)
			}
		})
	}

	t.Run("fresh original peer for plan and apply", func(t *testing.T) {
		var held context.Context
		calls := 0
		c, listener, kernel, _, task := socketSession(t, func(ctx context.Context, d hostops.Descriptor, target, digest string) (hostops.Caller, error) {
			held = ctx
			calls++
			if d.ID != "host-user.create" || target != "system" || len(digest) != 64 {
				t.Errorf("exact task/target/intent missing: %s %s %s", d.ID, target, digest)
			}
			first, err := DuplicatePeerSocket(ctx)
			if err != nil {
				return hostops.Caller{}, err
			}
			defer unix.Close(first)
			second, err := DuplicatePeerSocket(ctx)
			if err != nil {
				return hostops.Caller{}, err
			}
			defer unix.Close(second)
			if first == second {
				t.Error("duplicate was reused")
			}
			for _, fd := range []int{first, second} {
				flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
				if err != nil || flags&unix.FD_CLOEXEC == 0 {
					t.Errorf("not close-on-exec: flags=%d err=%v", flags, err)
				}
				flags, err = unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
				if err != nil || flags&unix.O_NONBLOCK == 0 {
					t.Errorf("original nonblocking state changed: flags=%d err=%v", flags, err)
				}
				cred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
				if err != nil || cred.Pid != int32(os.Getpid()) || cred.Uid != uint32(os.Getuid()) {
					t.Errorf("duplicate does not attest the original peer: %v %v", cred, err)
				}
				pidfd, err := (Linux{}).PeerPidfd(fd)
				if err != nil {
					t.Errorf("duplicate lost peer pidfd: %v", err)
				} else {
					pid, err := (Linux{}).PidOf(pidfd)
					_ = unix.Close(pidfd)
					if err != nil || pid != os.Getpid() {
						t.Errorf("duplicate attests a different process: pid=%d err=%v", pid, err)
					}
				}
			}
			canceled, cancel := context.WithCancel(ctx)
			cancel()
			if fd, err := DuplicatePeerSocket(canceled); err == nil || fd != -1 {
				t.Errorf("canceled context supplied a duplicate: %d %v", fd, err)
			}
			return hostops.Caller{Actor: "product-user", Mode: "product-up"}, nil
		})
		peerPlan(t, c)
		r, err := localframe.Next(c, localframe.Expect{UID: uint32(os.Getuid()), PID: int32(os.Getpid())}, nil)
		var plan hostops.Plan
		if err != nil || r.Status != 200 || json.Unmarshal(r.Body, &plan) != nil || !plan.Permissions.Apply {
			t.Fatalf("confirmed plan: %+v %v", r, err)
		}
		body, _ := json.Marshal(hostops.ApplyRequest{OperationID: strings.Repeat("1a", 16), Module: "host-user", Verb: "create", Surface: "cli", Inputs: plan.Inputs, Confirmation: plan.Digest})
		if err := localframe.Write(c, localframe.Record{Type: "request", Op: "task.apply", Body: body}); err != nil {
			t.Fatal(err)
		}
		r, err = localframe.Next(c, localframe.Expect{UID: uint32(os.Getuid()), PID: int32(os.Getpid())}, nil)
		if err != nil || r.Status != 200 {
			t.Fatalf("confirmed apply: %+v %v", r, err)
		}
		_ = listener.Close()
		select {
		case <-kernel.closed:
		case <-time.After(time.Second):
			t.Fatal("connection did not finish")
		}
		if calls != 2 || task.effects != 1 {
			t.Fatalf("authorizations=%d effects=%d", calls, task.effects)
		}
		if fd, err := DuplicatePeerSocket(held); err == nil || fd != -1 {
			t.Fatalf("retained context supplied a socket: %d %v", fd, err)
		}
	})

	t.Run("half close can receive its authorized reply", func(t *testing.T) {
		entered := make(chan context.Context, 1)
		release := make(chan struct{})
		c, _, _, _, _ := socketSession(t, func(ctx context.Context, _ hostops.Descriptor, _, _ string) (hostops.Caller, error) {
			entered <- ctx
			select {
			case <-release:
			case <-ctx.Done():
				return hostops.Caller{}, errors.New("mode_refused")
			}
			fd, err := DuplicatePeerSocket(ctx)
			if err != nil {
				return hostops.Caller{}, err
			}
			_ = unix.Close(fd)
			return hostops.Caller{Actor: "product-user", Mode: "product-up"}, nil
		})
		peerPlan(t, c)
		var ctx context.Context
		select {
		case ctx = <-entered:
		case <-time.After(time.Second):
			t.Fatal("authorization was not reached")
		}
		if err := c.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		select {
		case <-ctx.Done():
			t.Fatal("write half-close canceled authorization")
		case <-time.After(125 * time.Millisecond):
		}
		close(release)
		r, err := localframe.Next(c, localframe.Expect{UID: uint32(os.Getuid()), PID: int32(os.Getpid())}, nil)
		var plan hostops.Plan
		if err != nil || r.Status != 200 || json.Unmarshal(r.Body, &plan) != nil || !plan.Permissions.Apply {
			t.Fatalf("half-close reply: %+v %v", r, err)
		}
	})

	t.Run("missing context never supplies a socket", func(t *testing.T) {
		for _, ctx := range []context.Context{nil, context.Background()} {
			if fd, err := DuplicatePeerSocket(ctx); err == nil || fd != -1 {
				t.Fatalf("missing proof supplied a socket: %d %v", fd, err)
			}
		}
	})

	t.Run("ordinary socket still refuses incoming descriptors", func(t *testing.T) {
		var calls atomic.Int32
		c, _, kernel, _, _ := socketSession(t, func(context.Context, hostops.Descriptor, string, string) (hostops.Caller, error) {
			calls.Add(1)
			return hostops.Caller{Actor: "product-user", Mode: "product-up"}, nil
		})
		file, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		body, _ := json.Marshal(localframe.Record{Type: "request", Op: "task.plan", Body: json.RawMessage(`{"module":"host-user","verb":"create","surface":"cli","inputs":{"account":"alice","home":"/home/alice","group":"staff"}}`)})
		frame := make([]byte, 8+len(body))
		copy(frame, "OLL1")
		binary.BigEndian.PutUint32(frame[4:8], uint32(len(body)))
		copy(frame[8:], body)
		if _, _, err := c.WriteMsgUnix(frame, syscall.UnixRights(int(file.Fd())), nil); err != nil {
			t.Fatal(err)
		}
		if r, err := localframe.Next(c, localframe.Expect{UID: uint32(os.Getuid()), PID: int32(os.Getpid())}, nil); err == nil {
			t.Fatalf("ordinary socket answered an FD-bearing request: %+v", r)
		}
		select {
		case <-kernel.closed:
		case <-time.After(time.Second):
			t.Fatal("FD-bearing session did not release its held peer")
		}
		if calls.Load() != 0 {
			t.Fatal("incoming FD reached authority")
		}
	})
}
