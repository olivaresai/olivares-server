// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package localsession

import (
	"context"
	"errors"

	"github.com/olivaresai/olivares/appliance/layer/hostops"
	"github.com/olivaresai/olivares/appliance/layer/portal/localframe"
	"github.com/olivaresai/olivares/appliance/layer/services"
)

// AuthorityResolver is supplied by the portal's existing identity owner. UID is
// kernel-attested connection identity, never a product grant by itself.
type AuthorityResolver func(context.Context, uint32) (hostops.Authority, error)

// WithActs must be composed before Serve. Nil authority or owners preserve the
// read-only server. No request can enable or replace this composition.
func (s *Server) WithActs(acts *hostops.Acts, resolve AuthorityResolver) *Server {
	s.acts, s.resolve = acts, resolve
	return s
}

type checkedAuthority struct {
	own      *owner
	delegate hostops.Authority
}

func (a checkedAuthority) Authorize(ctx context.Context, d hostops.Descriptor, target, digest string) (hostops.Caller, error) {
	if a.own.Check() != nil || a.delegate == nil {
		return hostops.Caller{}, errors.New("mode_refused")
	}
	caller, err := a.delegate.Authorize(ctx, d, target, digest)
	if a.own.Check() != nil {
		return caller, errors.New("mode_refused")
	}
	return caller, err
}
func (s *Server) authority(ctx context.Context, own *owner) (hostops.Authority, error) {
	if own == nil || own.Check() != nil {
		return nil, errors.New("mode_refused")
	}
	a, err := s.resolve(ctx, own.uid)
	if err != nil || a == nil {
		return nil, errors.New("mode_refused")
	}
	return checkedAuthority{own: own, delegate: a}, nil
}
func (s *Server) apply(ctx context.Context, request localframe.Record, own *owner) localframe.Record {
	var empty struct{}
	if hostops.DecodeClosed(request.Body, &empty) == nil {
		return refusal(request.Op, 503, "act_not_adopted")
	}
	var req hostops.ApplyRequest
	if hostops.DecodeClosed(request.Body, &req) != nil || !localSurface(req.Surface) {
		return refusal(request.Op, 422, "input_refused")
	}
	a, err := s.authority(ctx, own)
	if err != nil {
		return refusal(request.Op, 403, "mode_refused")
	}
	record, status, err := s.acts.Apply(services.WithOwner(ctx, own.uid), req, a)
	if err == nil {
		return response(request.Op, status, record)
	}
	code := "consumer_unavailable"
	var input *hostops.InputRefused
	var changed *hostops.PlanChanged
	var locked *hostops.TargetLocked
	switch {
	case errors.As(err, &input):
		code = "input_refused"
	case errors.As(err, &changed):
		code = "plan_changed"
	case errors.As(err, &locked):
		code = "target_locked"
	case err.Error() == "mode_refused":
		code = "mode_refused"
	case err.Error() == "act_not_adopted":
		code = "act_not_adopted"
		status = 503
	}
	if status == 0 {
		status = 503
	}
	return refusal(request.Op, status, code)
}
