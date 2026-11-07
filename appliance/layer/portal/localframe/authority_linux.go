// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

//go:build linux && (amd64 || arm64)

package localframe

import (
	"encoding/json"
	"net"
	"syscall"

	"github.com/olivaresai/olivares/appliance/layer/hostops"
)

// NextAuthorityRequest is used only on the engine's dedicated authority socket.
// Success transfers one CLOEXEC FD to the caller; every refusal closes it.
// Ordinary Next continues to close and refuse every FD before parsing.
func NextAuthorityRequest(c *net.UnixConn, e Expect, onRange func() error) (AuthorityRequest, int, error) {
	r, fd, err := nextConnection(c, e, onRange, parseAuthorityRecord, true)
	return decodeAuthorityRequest(r, fd, err)
}

func decodeAuthorityRequest(r Record, fd int, err error) (AuthorityRequest, int, error) {
	var request AuthorityRequest
	if err == nil && (r.Type != "request" || hostops.DecodeClosed(r.Body, &request) != nil || !validAuthorityRequest(request)) {
		err = fault("record_malformed")
	}
	if err != nil {
		if fd >= 0 {
			_ = syscall.Close(fd)
		}
		return AuthorityRequest{}, -1, err
	}
	return request, fd, nil
}

func WriteAuthorityRequest(c *net.UnixConn, r AuthorityRequest, peerFD int) error {
	if peerFD < 0 || !validAuthorityRequest(r) {
		return fault("record_malformed")
	}
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return writeRecord(c, Record{Type: "request", Op: "authority.resolve", Body: body}, parseAuthorityRecord, peerFD)
}

// NextAuthorityReply authenticates every engine range and refuses all FDs.
// The identity consumer additionally matches the act and finite validity.
func NextAuthorityReply(c *net.UnixConn, e Expect, onRange func() error) (AuthorityReply, error) {
	r, _, err := nextConnection(c, e, onRange, parseAuthorityRecord, false)
	if err != nil {
		return AuthorityReply{}, err
	}
	if r.Type == "error" {
		if r.Code == "exposure_requires_step_up" {
			return AuthorityReply{}, fault(r.Code)
		}
		return AuthorityReply{}, fault("mode_refused")
	}
	var reply AuthorityReply
	if r.Type != "response" || r.Status != 200 || hostops.DecodeClosed(r.Body, &reply) != nil || !validAuthorityReply(reply) {
		return AuthorityReply{}, fault("record_malformed")
	}
	return reply, nil
}

func WriteAuthorityReply(c *net.UnixConn, r AuthorityReply) error {
	if !validAuthorityReply(r) {
		return fault("record_malformed")
	}
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return writeRecord(c, Record{Type: "response", Op: "authority.resolve", Status: 200, Body: body}, parseAuthorityRecord, -1)
}

func WriteAuthorityRefusal(c *net.UnixConn) error {
	return writeRecord(c, Record{Type: "error", Op: "authority.resolve", Status: 403, Code: "mode_refused"}, parseAuthorityRecord, -1)
}

// WriteExposureRefusal is a fixed actionable refusal, never an engine error body.
func WriteExposureRefusal(c *net.UnixConn) error {
	return writeRecord(c, Record{Type: "error", Op: "authority.resolve", Status: 409, Code: "exposure_requires_step_up"}, parseAuthorityRecord, -1)
}
