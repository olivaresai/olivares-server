// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

// Package identityengine runs inside the existing engine owner. It consumes
// native peer proof and the existing core auth store, never a portal registry.
package identityengine

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/olivaresai/olivares/appliance/layer/hostops"
	"github.com/olivaresai/olivares/appliance/layer/portal/localframe"
	"github.com/olivaresai/olivares/core/auth"
)

var refused = errors.New("mode_refused")

type Server struct {
	principals *auth.Authenticator
	authorizer *auth.Authorizer
	accounts   auth.OSAccounts
	bindings   *auth.OSAccountBindings
	catalog    *hostops.Catalog
}

// NewServer receives only engine-owned inputs. The catalog is the same native
// assembly used by the portal; request fields cannot construct a descriptor.
func NewServer(a *auth.Authenticator, az *auth.Authorizer, accounts auth.OSAccounts, catalog *hostops.Catalog) *Server {
	return &Server{principals: a, authorizer: az, accounts: accounts,
		bindings: auth.NewOSAccountBindings(a, az, accounts), catalog: catalog}
}

// authorize is called only after the handler independently verifies the actual
// transferred peer socket. UID here is a kernel observation, never an RPC field.
func (s *Server) authorize(ctx context.Context, uid uint32, req localframe.AuthorityRequest) (localframe.AuthorityReply, error) {
	if s == nil || s.principals == nil || s.authorizer == nil || s.accounts == nil || s.catalog == nil ||
		ctx == nil || ctx.Err() != nil || uid == 0 {
		return localframe.AuthorityReply{}, refused
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var descriptor hostops.Descriptor
	count := 0
	for _, d := range s.catalog.Descriptors() {
		if d.ID == req.Task {
			descriptor = d
			count++
		}
	}
	if count != 1 || descriptor.Confirmation == "none" || descriptor.ActVerb == "" ||
		descriptor.Audience == "" || !slices.Contains(descriptor.Modes, "product-up") {
		return localframe.AuthorityReply{}, refused
	}
	name, err := s.accounts.Name(ctx, uid)
	if err != nil {
		return localframe.AuthorityReply{}, refused
	}
	ref, tenant, err := s.bindings.ResolveInstallation(ctx, uid, name)
	if err != nil {
		return localframe.AuthorityReply{}, refused
	}
	current, err := s.principals.ResolvePrincipalScope(ctx, ref, tenant)
	if err != nil {
		return localframe.AuthorityReply{}, refused
	}
	decision := s.authorizer.AuthorizeEvidence(ctx, auth.Request{Principal: current, Tenant: tenant,
		Permission: auth.PermSystemAdmin, Resource: auth.ResourceAttrs{Kind: "appliance.task", ID: descriptor.ID,
			Extra: map[string]string{"target": req.Target, "act": descriptor.ActVerb,
				"audience": descriptor.Audience, "intent_digest": req.IntentDigest}}})
	until, _ := ctx.Deadline()
	if replyWindow := time.Now().Add(time.Second); replyWindow.Before(until) {
		until = replyWindow
	}
	if decision.FreshUntil.Before(until) {
		until = decision.FreshUntil
	}
	if decision.Outcome != auth.EvidenceAllow || ctx.Err() != nil || !until.After(time.Now()) {
		return localframe.AuthorityReply{}, refused
	}
	return localframe.AuthorityReply{Task: req.Task, Target: req.Target, IntentDigest: req.IntentDigest,
		Actor: current.Actor(), Mode: "product-up", ValidUntil: until.UTC()}, nil
}
