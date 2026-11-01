// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/olivaresai/olivares/core/license/dnfrefresh"
)

const (
	invocation = "0123456789abcdef0123456789abcdef"
	ctxID      = "fedcba9876543210fedcba9876543210"
	credential = "oad1." + "eyJhIjoxfQ" + "." + "c2lnbmF0dXJl" // synthetic: base64 of {"a":1} and of "signature", joined so the secrets sweep does not read one literal
	origin     = `{"status":"issued","endpoint":"https://licenses.example.test"}`
)

var now = time.Date(2026, 10, 16, 18, 0, 0, 0, time.UTC)

// fixture is the host as the unit sees it: a handoff directory, a repository directory and a product
// command that is a function, so each test chooses what the product publishes.
type fixture struct {
	e       env
	chowns  []int
	ran     [][]string
	asUID   []int
	environ []string
	looked  string
	stderr  bytes.Buffer
}

func newFixture(t *testing.T, product func(f *fixture, dir string) ([]byte, error)) *fixture {
	t.Helper()
	f := &fixture{}
	handoff := filepath.Join(t.TempDir(), "handoff")
	if err := os.Mkdir(handoff, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(handoff, 0o700); err != nil {
		t.Fatal(err)
	}
	f.e = env{
		HandoffDir: handoff,
		RepoDir:    t.TempDir(),
		DataDir:    "/var/lib/olivares",
		Product:    "olivares",
		Invocation: invocation,
		Now:        func() time.Time { return now },
		Log:        &f.stderr,
		Lookup:     func(name string) (int, int, error) { f.looked = name; return os.Getuid(), os.Getgid(), nil },
		Chown:      func(_ string, uid, gid int) error { f.chowns = append(f.chowns, uid, gid); return nil },
		RunProduct: func(_ context.Context, uid, gid int, args, environ []string) ([]byte, error) {
			f.ran = append(f.ran, args)
			f.asUID = append(f.asUID, uid)
			f.environ = environ
			return product(f, handoff)
		},
	}
	return f
}

func publish(t *testing.T, dir string, class string, suites []string, exp time.Time) {
	t.Helper()
	inv := invocation
	doc := dnfrefresh.Issued(invocation, &inv, dnfrefresh.Answer{
		Class: class, Set: "biz", Suites: suites, Context: ctxID, Credential: credential, Exp: exp.Unix(),
	}, now)
	if err := dnfrefresh.Publish(dir, doc); err != nil {
		t.Fatal(err)
	}
}

func repoText(t *testing.T, f *fixture) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(f.e.RepoDir, "olivares-entitled.repo"))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestRefreshWritesTheEntitledRepositoryForACurrentLicence(t *testing.T) {
	f := newFixture(t, func(f *fixture, dir string) ([]byte, error) {
		publish(t, dir, "current", []string{"entitled-security", "entitled-stable"}, now.Add(24*time.Hour))
		return []byte(origin), nil
	})
	if err := refresh(context.Background(), f.e); err != nil {
		t.Fatal(err)
	}
	text := repoText(t, f)
	for _, want := range []string{
		"baseurl=https://licenses.example.test/dnf/v1/ctx/" + ctxID + "/entitled-stable\n",
		"baseurl=https://licenses.example.test/dnf/v1/ctx/" + ctxID + "/entitled-security\n",
		"password=" + credential + "\n",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("repository file lacks %q:\n%s", want, text)
		}
	}
	// The product runs as its own user, with the handoff directory handed to that user first, in the
	// unit's invocation, and takes the cycle from it.
	if len(f.ran) != 1 {
		t.Fatalf("the product ran %d times, want once", len(f.ran))
	}
	wantArgs := "license connect dnf-refresh --data-dir /var/lib/olivares --cycle " + invocation
	if got := strings.Join(f.ran[0], " "); got != wantArgs {
		t.Errorf("product arguments %q, want %q", got, wantArgs)
	}
	if f.looked != "olivares" {
		t.Errorf("the product ran as the user %q, want olivares", f.looked)
	}
	if len(f.chowns) != 2 || f.chowns[0] != os.Getuid() || f.chowns[1] != os.Getgid() {
		t.Errorf("handoff directory chown %v, want the product's uid and gid", f.chowns)
	}
	if !containsEnv(f.environ, "INVOCATION_ID="+invocation) {
		t.Errorf("the product's environment lacks the unit's INVOCATION_ID: %v", f.environ)
	}
	if _, err := os.Stat(filepath.Join(f.e.HandoffDir, invocation+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the consumed handoff is still on disk: %v", err)
	}
	if strings.Contains(f.stderr.String(), credential) {
		t.Errorf("the log carries the credential: %s", f.stderr.String())
	}
}

// The service answers an expired licence with the security-only class; the file must then name no feature suite.
func TestRefreshForAnExpiredLicenceKeepsOnlyTheSecuritySuite(t *testing.T) {
	f := newFixture(t, func(f *fixture, dir string) ([]byte, error) {
		publish(t, dir, "security-only", []string{"entitled-security"}, now.Add(24*time.Hour))
		return []byte(origin), nil
	})
	oldFile := filepath.Join(f.e.RepoDir, "olivares-entitled.repo")
	if err := os.WriteFile(oldFile, []byte("[olivares-entitled-stable]\nbaseurl=old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := refresh(context.Background(), f.e); err != nil {
		t.Fatal(err)
	}
	text := repoText(t, f)
	if strings.Contains(text, "entitled-stable") || !strings.Contains(text, "[olivares-entitled-security]") {
		t.Fatalf("an expired licence still has the feature suite, or lost the security one:\n%s", text)
	}
}

func TestRefreshLeavesTheOldFileWhenTheProductIssuesNothing(t *testing.T) {
	inv := invocation
	cases := map[string]func(f *fixture, dir string) ([]byte, error){
		"not bound": func(f *fixture, dir string) ([]byte, error) {
			if err := dnfrefresh.Publish(dir, dnfrefresh.NotIssued(invocation, &inv, dnfrefresh.OutcomeNotBound, "", now)); err != nil {
				t.Fatal(err)
			}
			return nil, errors.New("exit status 1")
		},
		"refused with a code": func(f *fixture, dir string) ([]byte, error) {
			if err := dnfrefresh.Publish(dir, dnfrefresh.NotIssued(invocation, &inv, dnfrefresh.OutcomeRefused, "licence_revoked", now)); err != nil {
				t.Fatal(err)
			}
			return nil, errors.New("exit status 1")
		},
		"the product died before it wrote": func(f *fixture, dir string) ([]byte, error) {
			return nil, errors.New("signal: killed")
		},
		"the handoff is another invocation's": func(f *fixture, dir string) ([]byte, error) {
			other := "ffffffffffffffffffffffffffffffff"
			doc := dnfrefresh.NotIssued(invocation, &other, dnfrefresh.OutcomeBusy, "", now)
			if err := dnfrefresh.Publish(dir, doc); err != nil {
				t.Fatal(err)
			}
			return nil, nil
		},
	}
	for name, product := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, product)
			old := filepath.Join(f.e.RepoDir, "olivares-entitled.repo")
			if err := os.WriteFile(old, []byte("old\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			err := refresh(context.Background(), f.e)
			if err == nil {
				t.Fatal("refresh reported success without an issued credential")
			}
			if data, _ := os.ReadFile(old); string(data) != "old\n" {
				t.Fatalf("the old repository file was replaced: %q", data)
			}
		})
	}
}

func TestRefreshNamesTheOutcomeAndCode(t *testing.T) {
	inv := invocation
	f := newFixture(t, func(f *fixture, dir string) ([]byte, error) {
		if err := dnfrefresh.Publish(dir, dnfrefresh.NotIssued(invocation, &inv, dnfrefresh.OutcomeRefused, "licence_revoked", now)); err != nil {
			t.Fatal(err)
		}
		return nil, errors.New("exit status 1")
	})
	err := refresh(context.Background(), f.e)
	if err == nil || !strings.Contains(err.Error(), "refused") || !strings.Contains(err.Error(), "licence_revoked") {
		t.Fatalf("error %v does not name the outcome and the code", err)
	}
}

func TestRefreshRefusesToRunOutsideItsUnit(t *testing.T) {
	for _, inv := range []string{"", "not-an-id", strings.ToUpper(invocation)} {
		f := newFixture(t, func(f *fixture, dir string) ([]byte, error) {
			t.Fatal("the product ran without a unit invocation")
			return nil, nil
		})
		f.e.Invocation = inv
		if err := refresh(context.Background(), f.e); err == nil {
			t.Errorf("refresh accepted invocation %q", inv)
		}
	}
}

func TestRefreshWritesNothingWhenTheReportedEndpointIsNotHTTPS(t *testing.T) {
	for _, stdout := range []string{
		`{"endpoint":"http://licenses.example.test"}`,
		`{"endpoint":"https://u:p@licenses.example.test"}`,
		`{"status":"issued"}`,
		`not json`,
		``,
	} {
		f := newFixture(t, func(f *fixture, dir string) ([]byte, error) {
			publish(t, dir, "current", []string{"entitled-security", "entitled-stable"}, now.Add(24*time.Hour))
			return []byte(stdout), nil
		})
		if err := refresh(context.Background(), f.e); err == nil {
			t.Errorf("refresh accepted product output %q", stdout)
		}
		if _, err := os.Stat(filepath.Join(f.e.RepoDir, "olivares-entitled.repo")); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("a repository file exists after output %q: %v", stdout, err)
		}
	}
}

func TestRefreshRefusesAHandoffDirectoryItCannotHandOver(t *testing.T) {
	f := newFixture(t, func(f *fixture, dir string) ([]byte, error) {
		t.Fatal("the product ran although the handoff directory could not be handed over")
		return nil, nil
	})
	f.e.Chown = func(string, int, int) error { return errors.New("operation not permitted") }
	if err := refresh(context.Background(), f.e); err == nil {
		t.Fatal("refresh went on after the chown failed")
	}
}

func TestRunUsage(t *testing.T) {
	var out, errb bytes.Buffer
	for _, args := range [][]string{nil, {"status"}, {"refresh", "--force"}} {
		if code := run(context.Background(), args, &out, &errb); code != 2 {
			t.Errorf("run(%v) = %d, want 2", args, code)
		}
	}
}

func containsEnv(environ []string, want string) bool {
	for _, kv := range environ {
		if kv == want {
			return true
		}
	}
	return false
}
