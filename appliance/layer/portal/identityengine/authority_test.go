// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package identityengine

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/olivaresai/olivares/appliance/layer/hostops"
	"github.com/olivaresai/olivares/appliance/layer/hostusers"
	"github.com/olivaresai/olivares/appliance/layer/portal/localframe"
	"github.com/olivaresai/olivares/core/auth"
	"github.com/olivaresai/olivares/core/engine"
	"github.com/olivaresai/olivares/core/model"
	"github.com/olivaresai/olivares/core/nativepam"
	"github.com/olivaresai/olivares/core/store"
)

// Only the physical NSS/PAM boundary is substituted. The binding ceremony,
// exact credential, lifecycle, current policy and store are the real product.
type nativeAccount struct{}

func (nativeAccount) UID(context.Context, string) (uint32, error) { return 1602, nil }
func (nativeAccount) Name(context.Context, uint32) (string, error) {
	return "native-operator", nil
}
func (nativeAccount) Verify(_ context.Context, name string, _ []byte) (nativepam.Result, error) {
	return nativepam.Result{Login: name, UID: 1602, Authenticated: true, AccountAllowed: true}, nil
}

func TestEngineAuthorityUsesCurrentOSCredentialAndExactNativeCatalog(t *testing.T) {
	for _, scenario := range []string{"original_superadmin", "tenant_only_owner", "demoted", "promoted", "credential_rotated", "binding_revoked", "policy_denied"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			st, err := engine.Open(ctx, store.Config{Engine: store.EngineSQLite, DSN: filepath.Join(t.TempDir(), "identity.db"), Debug: true}, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			var tenant model.TenantID
			if err = st.System(ctx, func(sys store.SystemScope) error {
				if _, err := sys.EnsureSystemTenant(ctx); err != nil {
					return err
				}
				org, err := sys.CreateOrg(ctx, model.Org{Name: "native identity", Slug: "native-identity", Status: model.StatusActive})
				tenant = org.TenantID
				return err
			}); err != nil {
				t.Fatal(err)
			}
			var admin, subject model.User
			if err = st.AuthMutate(ctx, func(as store.AuthScope) error {
				var err error
				admin, err = as.Users().Create(ctx, model.User{Email: "admin@identity.test", Status: model.StatusActive})
				if err != nil {
					return err
				}
				subject, err = as.Users().Create(ctx, model.User{Email: "subject@identity.test", Status: model.StatusActive,
					IsSuperadmin: scenario != "tenant_only_owner" && scenario != "promoted"})
				if err != nil {
					return err
				}
				for _, user := range []model.User{admin, subject} {
					if _, err = as.Memberships().Create(ctx, model.Membership{UserID: user.ID, TargetTenantID: tenant, Role: auth.RoleOwner}); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			a, az := auth.NewAuthenticator(st, nil), auth.NewAuthorizer(nil)
			session := func(user model.User) (auth.Principal, model.AuthSession) {
				credential, err := auth.NewCredential(auth.PrefixSession)
				if err != nil {
					t.Fatal(err)
				}
				row := model.AuthSession{UserID: user.ID, Selector: credential.Selector, SecretHash: credential.SecretHash,
					ExpiresAt: model.NewTimestamp(time.Now().Add(time.Hour)), AAL: auth.AAL1, AMR: []string{"pwd"}}
				if err = st.AuthMutate(ctx, func(as store.AuthScope) error {
					row, err = as.Sessions().Create(ctx, row)
					return err
				}); err != nil {
					t.Fatal(err)
				}
				p, err := a.Authenticate(ctx, credential.Token)
				if err != nil {
					t.Fatal(err)
				}
				return p, row
			}
			administrator, _ := session(admin)
			initiator, credential := session(subject)
			b := auth.NewOSAccountBindings(a, az, nativeAccount{})
			ceremony, err := b.Begin(ctx, administrator, tenant, subject.ID, "native-operator")
			if err != nil {
				t.Fatal(err)
			}
			if _, err = b.Complete(ctx, initiator, ceremony.ID, []byte("native-proof")); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "demoted", "promoted":
				err = st.AuthMutate(ctx, func(as store.AuthScope) error {
					subject.IsSuperadmin = scenario == "promoted"
					_, err := as.Users().Update(ctx, subject)
					return err
				})
			case "credential_rotated":
				err = st.AuthMutate(ctx, func(as store.AuthScope) error {
					credential.Revoked = true
					_, err := as.Sessions().Update(ctx, credential)
					return err
				})
			case "binding_revoked":
				err = b.Revoke(ctx, administrator, tenant, subject.ID)
			}
			if err != nil {
				t.Fatal(err)
			}
			catalog, err := hostops.NewCatalog(hostusers.Descriptors())
			if err != nil {
				t.Fatal(err)
			}
			var policy *currentPolicy
			if scenario == "policy_denied" {
				var fact store.AuthorizationFactRef
				if err = st.AuthView(ctx, func(as store.AuthScope) error {
					var err error
					fact, err = as.(store.AuthPrincipalEvidenceScope).ReadDirectoryEpochFact(ctx, tenant)
					return err
				}); err != nil {
					t.Fatal(err)
				}
				policy = &currentPolicy{fact: fact}
				az = auth.NewAuthorizer(policy)
			}
			s := NewServer(a, az, nativeAccount{}, catalog)
			req := localframe.AuthorityRequest{Task: "host-user.create", Target: "system", IntentDigest: strings.Repeat("a", 64)}
			before := time.Now()
			answer, err := s.authorize(ctx, 1602, req)
			if policy != nil {
				if policy.calls != 1 || policy.request.Permission != auth.PermSystemAdmin ||
					policy.request.Resource.Kind != "appliance.task" || policy.request.Resource.ID != req.Task ||
					policy.request.Resource.Extra["target"] != req.Target || policy.request.Resource.Extra["intent_digest"] != req.IntentDigest ||
					policy.request.Resource.Extra["act"] != "system" || policy.request.Resource.Extra["audience"] != "appliance-helper:olivares-portal-system" {
					t.Fatalf("current policy did not see the exact native act: %+v", policy.request)
				}
			}
			if scenario != "original_superadmin" {
				if err == nil {
					t.Fatal("current native product authority was not refused")
				}
				return
			}
			if err != nil || answer.Task != req.Task || answer.Target != req.Target || answer.IntentDigest != req.IntentDigest ||
				answer.Actor != initiator.Actor() || answer.Mode != "product-up" || !answer.ValidUntil.After(before) || answer.ValidUntil.After(time.Now().Add(5*time.Second)) {
				t.Fatalf("current exact act attribution: %+v err=%v", answer, err)
			}
			req.Task = "foreign.task"
			if _, err = s.authorize(ctx, 1602, req); err == nil {
				t.Fatal("request-defined descriptor was admitted")
			}
			req.Task = "host-user.create"
			if _, err = s.authorize(ctx, 0, req); err == nil {
				t.Fatal("UID0 acquired product authority")
			}
			canceled, stop := context.WithCancel(ctx)
			stop()
			if _, err = s.authorize(canceled, 1602, req); err == nil || !errors.Is(canceled.Err(), context.Canceled) {
				t.Fatal("canceled authority request admitted")
			}
		})
	}
}

// The current typed policy seam is the existing deny overlay, not a new grant.
type currentPolicy struct {
	fact    store.AuthorizationFactRef
	request auth.Request
	calls   int
}

func (*currentPolicy) Evaluate(context.Context, auth.Request) (auth.Decision, error) {
	return auth.Decision{}, errors.New("legacy policy unexpectedly called")
}
func (p *currentPolicy) EvaluateEvidence(_ context.Context, req auth.Request) (auth.PolicyEvidenceDecision, error) {
	p.calls++
	p.request = req
	now := time.Now()
	return auth.PolicyEvidenceDecision{ForbidAbsence: auth.CheckEvidence{Verdict: auth.CheckBroken, Code: "native_effect_denied"},
		Facts: []store.AuthorizationFactRef{p.fact}, ObservedAt: now, FreshUntil: now.Add(time.Minute)}, nil
}
