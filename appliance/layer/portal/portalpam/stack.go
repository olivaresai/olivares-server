// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

// Package portalpam adapts one portal request to the existing repair selector.
package portalpam

import (
	"context"
	"sync"

	"github.com/olivaresai/olivares/appliance/layer/portal/auth"
	"github.com/olivaresai/olivares/core/nativepam"
)

// NewRequestStack borrows the request's password; it creates no retained copy.
// The caller must clear it on every return, including when the selector never
// calls Start. Start clears it before returning, including every refusal.
func NewRequestStack(ctx context.Context, login string, password []byte) (auth.Stack, error) {
	if ctx == nil || ctx.Err() != nil || !nativepam.ValidRequest(login, password) {
		clear(password)
		return nil, auth.ErrNotAdmitted
	}
	return &requestStack{ctx: ctx, login: login, password: password, check: nativepam.CheckRepair}, nil
}

// NewMeasurementStack lets the existing selector measure the repair route for
// GET/startup without inventing an account or credential. It cannot start a
// transaction; a sign-in must create its own request-bound stack.
func NewMeasurementStack(ctx context.Context) auth.Stack {
	return &requestStack{ctx: ctx, used: true}
}

type requestStack struct {
	mu       sync.Mutex
	ctx      context.Context
	login    string
	password []byte
	used     bool
	check    func(context.Context, string, []byte) (nativepam.Result, error)
}

func (*requestStack) String() string   { return "[native-pam-request]" }
func (*requestStack) GoString() string { return "portalpam.requestStack{[redacted]}" }

func (s *requestStack) Measure() auth.PAMMeasurement {
	if s.ctx != nil && s.ctx.Err() == nil && nativepam.MeasureRepair() {
		return auth.PAMMeasurement{Usable: true}
	}
	return auth.PAMMeasurement{Reason: "The native sign-in policy is unavailable."}
}

func (s *requestStack) LocalGroups(login string) ([]string, error) {
	if s.ctx == nil || s.ctx.Err() != nil || login != s.login || s.used {
		return nil, auth.ErrNotAdmitted
	}
	return nativepam.LocalGroups(login)
}

func (s *requestStack) Start(login string) (auth.Transaction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer func() { clear(s.password); s.password = nil }()
	if s.used {
		return nil, auth.ErrNotAdmitted
	}
	s.used = true
	if s.ctx.Err() != nil || login != s.login {
		return nil, auth.ErrNotAdmitted
	}
	result, err := s.check(s.ctx, login, s.password)
	if err != nil || s.ctx.Err() != nil {
		return nil, auth.ErrNotAdmitted
	}
	return &transaction{result: result}, nil
}

// The worker already ended PAM and disposed of all native copies before this
// result exists. The selector still validates auth and account separately.
type transaction struct {
	result        nativepam.Result
	closed        bool
	authenticated bool
}

func (t *transaction) Authenticate() error {
	if t.closed || !t.result.Authenticated {
		return auth.ErrNotAdmitted
	}
	t.authenticated = true
	return nil
}
func (t *transaction) Account() error {
	if t.closed || !t.authenticated || !t.result.AccountAllowed {
		return auth.ErrNotAdmitted
	}
	return nil
}
func (t *transaction) Close() error {
	t.closed = true
	t.result = nativepam.Result{}
	return nil
}
