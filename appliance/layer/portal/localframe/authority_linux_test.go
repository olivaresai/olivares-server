// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

//go:build linux && (amd64 || arm64)

package localframe

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func authorityPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	dir, err := os.MkdirTemp("", "idc-f-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(dir, "a.sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	a, err := net.DialUnix("unix", nil, l.Addr().(*net.UnixAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	b, err := l.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	for _, c := range []*net.UnixConn{a, b} {
		if err := c.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatal(err)
		}
		raw, err := c.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var failure error
		if err = raw.Control(func(fd uintptr) { failure = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_PASSCRED, 1) }); err != nil || failure != nil {
			t.Fatalf("passcred: %v %v", err, failure)
		}
	}
	return a, b
}

func TestAuthorityFrameTransfersOriginalSocketWithoutChangingLegacyProtocol(t *testing.T) {
	a, b := authorityPair(t)
	expect := Expect{UID: uint32(os.Getuid()), PID: int32(os.Getpid())}
	peer, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(peer[0])
	defer syscall.Close(peer[1])
	before, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(peer[0]), syscall.F_GETFL, 0)
	if errno != 0 {
		t.Fatal(errno)
	}
	req := AuthorityRequest{Task: "host-user.create", Target: "host-user:operator", IntentDigest: strings.Repeat("a", 64)}
	if err := WriteAuthorityRequest(a, req, peer[0]); err != nil {
		t.Fatal(err)
	}
	got, fd, err := NextAuthorityRequest(b, expect, nil)
	if err != nil || fd < 0 || got != req {
		t.Fatalf("held socket handoff: fd=%d err=%v", fd, err)
	}
	defer syscall.Close(fd)
	bits, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0)
	if errno != 0 || bits&syscall.FD_CLOEXEC == 0 {
		t.Fatal("authority descriptor lacks CLOEXEC")
	}
	cred, err := syscall.GetsockoptUcred(fd, syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	if err != nil || cred.Pid != int32(os.Getpid()) || cred.Uid != uint32(os.Getuid()) {
		t.Fatalf("received original peer changed: %v", err)
	}
	after, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(peer[0]), syscall.F_GETFL, 0)
	if errno != 0 || before != after {
		t.Fatal("handoff changed the original stream flags")
	}
	answer := AuthorityReply{Task: req.Task, Target: req.Target, IntentDigest: req.IntentDigest, Actor: "user:01234567", Mode: "product-up", ValidUntil: time.Now().UTC().Add(time.Second)}
	if err = WriteAuthorityReply(b, answer); err != nil {
		t.Fatal(err)
	}
	if got, err := NextAuthorityReply(a, expect, nil); err != nil || got != answer {
		t.Fatalf("exact authority answer: %v", err)
	}
	if err = WriteAuthorityRequest(a, req, peer[0]); err != nil {
		t.Fatal(err)
	}
	if _, err = Next(b, expect, nil); Reason(err) != "descriptors_received" {
		t.Fatalf("ordinary reader weakened its FD refusal: %v", err)
	}
	if err = Write(a, Record{Type: "request", Op: "authority.resolve", Body: []byte(`{}`)}); err == nil {
		t.Fatal("ordinary writer acquired authority.resolve")
	}
}

func TestAuthorityFrameRefusesForeignMissingExtraAndMalformedPeerProof(t *testing.T) {
	for _, scenario := range []string{"missing", "extra", "foreign", "ordinary_op", "malformed_body", "truncated"} {
		t.Run(scenario, func(t *testing.T) {
			a, b := authorityPair(t)
			file, err := os.Open(os.DevNull)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			frame := wire(`{"t":"request","op":"authority.resolve","body":{"task":"host-user.create","target":"host-user:operator","intent_digest":"` + strings.Repeat("a", 64) + `"}}`)
			rights := syscall.UnixRights(int(file.Fd()))
			expect := Expect{UID: uint32(os.Getuid()), PID: int32(os.Getpid())}
			switch scenario {
			case "missing":
				rights = nil
			case "extra":
				rights = syscall.UnixRights(int(file.Fd()), int(file.Fd()))
			case "foreign":
				expect.PID++
			case "ordinary_op":
				frame = wire(`{"t":"request","op":"task.plan","body":{}}`)
			case "malformed_body":
				frame = wire(`{"t":"request","op":"authority.resolve","body":{"claimed_uid":123}}`)
			case "truncated":
				frame = frame[:10]
			}
			if _, _, err = a.WriteMsgUnix(frame, rights, nil); err != nil {
				t.Fatal(err)
			}
			if err = a.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			raw, err := b.SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			var received []int
			receive := rawReceiver(raw)
			tracked := func(p, oob []byte, flags int) (int, int, int, error) {
				n, on, out, err := receive(p, oob, flags)
				messages, _ := syscall.ParseSocketControlMessage(oob[:on])
				for _, message := range messages {
					if message.Header.Level == syscall.SOL_SOCKET && message.Header.Type == syscall.SCM_RIGHTS {
						fds, _ := syscall.ParseUnixRights(&message)
						received = append(received, fds...)
					}
				}
				return n, on, out, err
			}
			r, fd, err := readFrame(tracked, expect, nil, 65534, 65534, parseAuthorityRecord, true)
			_, fd, err = decodeAuthorityRequest(r, fd, err)
			if err == nil || fd != -1 {
				if fd >= 0 {
					_ = syscall.Close(fd)
				}
				t.Fatalf("bad authority proof accepted: fd=%d err=%v", fd, err)
			}
			for _, leaked := range received {
				if err := syscall.Close(leaked); err != syscall.EBADF {
					t.Fatalf("authority refusal leaked received FD: %v", err)
				}
			}
		})
	}
}
