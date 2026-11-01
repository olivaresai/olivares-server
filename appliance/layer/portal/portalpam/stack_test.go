// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package portalpam

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/olivaresai/olivares/appliance/layer/portal/auth"
	"github.com/olivaresai/olivares/core/nativepam"
)

type productProbe bool

func (p productProbe) MeasureProduct() auth.ProductMeasurement {
	return auth.ProductMeasurement{Measured: true, Answers: bool(p)}
}

func TestRequestStackBindsLoginAndClearsSecretBeforeStartReturns(t *testing.T) {
	secret := []byte("fixture-password")
	checks := 0
	s := &requestStack{ctx: context.Background(), login: "operator", password: secret,
		check: func(ctx context.Context, login string, password []byte) (nativepam.Result, error) {
			checks++
			if login != "operator" || !bytes.Equal(password, []byte("fixture-password")) {
				t.Fatal("the native check received a different request")
			}
			return nativepam.Result{Authenticated: true, AccountAllowed: false}, nil
		},
	}
	tx, err := s.Start("operator")
	if err != nil || tx == nil {
		t.Fatalf("start: %v", err)
	}
	if !bytes.Equal(secret, make([]byte, len(secret))) {
		t.Fatal("Start retained the request's credential")
	}
	if err := tx.Authenticate(); err != nil {
		t.Fatalf("authentication succeeded: %v", err)
	}
	if err := tx.Account(); !errors.Is(err, auth.ErrNotAdmitted) {
		t.Fatalf("a refused account was admitted: %v", err)
	}
	_ = tx.Close()
	_ = tx.Close()
	if _, err := s.Start("operator"); !errors.Is(err, auth.ErrNotAdmitted) || checks != 1 {
		t.Fatal("one request supplied more than one native transaction")
	}
}

func TestRequestStackRefusesForeignCanceledAndMalformedRequests(t *testing.T) {
	for _, name := range []string{"foreign", "canceled", "lost completion"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			secret := []byte("fixture-password")
			s := &requestStack{ctx: ctx, login: "operator", password: secret,
				check: func(context.Context, string, []byte) (nativepam.Result, error) {
					if name != "lost completion" {
						t.Fatal("refused input reached PAM")
					}
					cancel()
					return nativepam.Result{Authenticated: true, AccountAllowed: true}, nil
				}}
			login := "operator"
			if name == "foreign" {
				login = "replacement"
			}
			if name == "canceled" {
				cancel()
			}
			if tx, err := s.Start(login); tx != nil || !errors.Is(err, auth.ErrNotAdmitted) {
				t.Fatalf("refused request supplied a transaction: %v", err)
			}
			if !bytes.Equal(secret, make([]byte, len(secret))) {
				t.Fatal("refusal retained a credential")
			}
		})
	}
	for _, secret := range [][]byte{nil, []byte("hidden\x00suffix"), make([]byte, nativepam.MaxPassword+1)} {
		if stack, err := NewRequestStack(context.Background(), "operator", secret); stack != nil || !errors.Is(err, auth.ErrNotAdmitted) {
			t.Fatalf("malformed credential accepted: %v", err)
		}
		if !bytes.Equal(secret, make([]byte, len(secret))) {
			t.Fatal("constructor refusal retained a credential")
		}
	}
}

func TestRequestStackProductRouteNeverPresentsCredentials(t *testing.T) {
	for _, probe := range []auth.ProductProbe{productProbe(true), nil} {
		secret := []byte("fixture-password")
		stack, err := NewRequestStack(context.Background(), "operator", secret)
		if err != nil {
			t.Fatal(err)
		}
		s := stack.(*requestStack)
		if len(s.password) != len(secret) || &s.password[0] != &secret[0] {
			t.Fatal("the constructor copied the ingress password instead of borrowing it")
		}
		s.check = func(context.Context, string, []byte) (nativepam.Result, error) {
			t.Fatal("product-up or unmeasured route presented a credential")
			return nativepam.Result{}, nil
		}
		_, err = auth.NewSelector(probe, auth.NewPAM(stack)).SignIn("operator")
		if err == nil {
			t.Fatal("a repair offer escaped the product route")
		}
		// The ingress owns cleanup when Start is never called; the constructor
		// and selector retain no second password copy or cleanup interface.
		clear(secret)
		if !bytes.Equal(s.password, make([]byte, len(secret))) {
			t.Fatal("the actual constructor retained a credential after no-Start ingress cleanup")
		}
		if s.used {
			t.Fatal("the selector consumed the request on the product route")
		}
	}
}

func TestMeasurementStackNeverStartsAccountTransaction(t *testing.T) {
	for _, ctx := range []context.Context{context.Background(), nil} {
		stack := NewMeasurementStack(ctx)
		_ = stack.Measure()
		if tx, err := stack.Start("operator"); tx != nil || !errors.Is(err, auth.ErrNotAdmitted) {
			t.Fatal("a policy measurement opened a native transaction")
		}
		if groups, err := stack.LocalGroups("operator"); groups != nil || !errors.Is(err, auth.ErrNotAdmitted) {
			t.Fatal("a policy measurement supplied account evidence")
		}
	}
}
