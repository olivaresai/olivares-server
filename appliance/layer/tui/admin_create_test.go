// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package tui

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/olivaresai/olivares/appliance/layer/helpers/helperschema"
	"github.com/olivaresai/olivares/appliance/layer/hostusers"
	"github.com/olivaresai/olivares/appliance/layer/portal/auth"
)

type creationFixture struct{ login string }

func (f *creationFixture) CreateAdministrator(_ context.Context, login string) (Human, error) {
	f.login = login
	return Human{Login: login, UID: 1000}, nil
}

func TestRunCreatesOperatorChosenAdministrator(t *testing.T) {
	creator := &creationFixture{}
	console := NewConsole(auth.State{}).WithAdministratorCreator(creator)
	var out, diagnostics bytes.Buffer
	code := console.Run(strings.NewReader("c\nalice\ncreate\nq\n"), &out, &diagnostics)
	if code != 0 {
		t.Fatalf("creation flow exited %d: %s", code, diagnostics.String())
	}
	if creator.login != "alice" {
		t.Fatalf("created login %q, want operator-chosen alice", creator.login)
	}
	if !strings.Contains(out.String(), "Administrator alice created") || !strings.Contains(out.String(), "sign in") {
		t.Fatalf("the visible path does not finish at ordinary sign-in:\n%s", out.String())
	}
}

type helperFixture struct{ calls int }

func (h *helperFixture) Call(context.Context, string, helperschema.Request) (helperschema.Response, error) {
	h.calls++
	return helperschema.Response{Result: helperschema.ResultRefused}, nil
}

func TestCreationRequiresTheInstallerDeferralMarker(t *testing.T) {
	helper := &helperFixture{}
	creator := NativeAdministratorCreation{Creator: hostusers.CreateTask{Helper: helper}, Accounts: SystemAccounts()}
	if _, err := creator.CreateAdministrator(t.Context(), "alice"); err == nil {
		t.Fatal("creation ran without the installer's deferral")
	}
	if helper.calls != 0 {
		t.Fatal("the helper was called without the deferral marker")
	}
	marker := t.TempDir() + "/defer-administrator"
	if err := os.WriteFile(marker, []byte("defer-administrator\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	creator.Marker = marker
	_, err := creator.CreateAdministrator(t.Context(), "alice")
	if helper.calls == 0 {
		t.Fatal("the marked first-boot path did not reach the fixed helper")
	}
	if err == nil || !strings.Contains(err.Error(), "not-performed") {
		t.Fatalf("a refused helper answer is not named in the error: %v", err)
	}
}

func TestCreationRefusesAReservedLoginBeforeTheHelper(t *testing.T) {
	marker := t.TempDir() + "/defer-administrator"
	if err := os.WriteFile(marker, []byte("defer-administrator\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	helper := &helperFixture{}
	creator := NativeAdministratorCreation{Creator: hostusers.CreateTask{Helper: helper}, Accounts: SystemAccounts(), Marker: marker}
	_, err := creator.CreateAdministrator(t.Context(), "olivares")
	if err == nil || !strings.Contains(err.Error(), "olivares is reserved") {
		t.Fatalf("the product's reserved account name was not refused readably: %v", err)
	}
	if helper.calls != 0 {
		t.Fatal("a reserved login reached the fixed helper")
	}
}

type refusingCreator struct{}

func (refusingCreator) CreateAdministrator(context.Context, string) (Human, error) {
	return Human{}, errors.New("the installer did not defer administrator creation")
}

func TestRunNamesWhyAdministratorCreationWasRefused(t *testing.T) {
	console := NewConsole(auth.State{}).WithAdministratorCreator(refusingCreator{})
	var out, diagnostics bytes.Buffer
	if code := console.Run(strings.NewReader("c\nalice\ncreate\nq\n"), &out, &diagnostics); code != 0 {
		t.Fatalf("creation flow exited %d: %s", code, diagnostics.String())
	}
	const cause = "the installer did not defer administrator creation"
	if !strings.Contains(out.String(), "Administrator creation was refused: "+cause) {
		t.Fatalf("tty1 does not name why creation was refused:\n%s", out.String())
	}
	if !strings.Contains(diagnostics.String(), "administrator creation refused: "+cause) {
		t.Fatalf("the journal does not record why creation was refused: %q", diagnostics.String())
	}
}
