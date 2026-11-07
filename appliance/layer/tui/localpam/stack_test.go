// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

//go:build linux && cgo && olivares_pam && pamstack

package localpam

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

// The container job's fixture accounts: an administrator the job created with no usable credential,
// and one it locked. The case sets the administrator's credential itself, from fresh randomness, on
// chpasswd's standard input, so no credential is in an argument, a file name, the environment or a log.
const (
	fixtureAdmin  = "olivares-fixture"
	fixtureLocked = "locked-fixture"
)

// answer places line on the standard input the service's own terminal conversation reads.
func answer(t *testing.T, line string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.WriteString(line + "\n"); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	if err := syscall.Dup3(int(r.Fd()), 0, 0); err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
}

func TestLocalPAM_ThePasswordServiceChangesTheCredential(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("the container job runs this case as root, as the repair console runs")
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	credential := hex.EncodeToString(raw)
	answer(t, credential+"\n"+credential)
	if err := (Stack{}).ChangePassword("passwd", fixtureAdmin); err != nil {
		t.Fatalf("the distribution password service refused the native change: %v", err)
	}
	transaction, err := Stack{}.Start("login", fixtureAdmin)
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Close()
	answer(t, credential)
	if err := transaction.Authenticate(); err != nil {
		t.Fatalf("the recovered credential did not sign in: %v", err)
	}
	if err := transaction.Account(); err != nil {
		t.Fatalf("the recovered account was refused: %v", err)
	}
}

func TestLocalPAM_TheLoginServiceChecksTheCredentialAndTheAccount(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("the container job runs this case as root, as the repair console runs")
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	credential := hex.EncodeToString(raw)
	set := exec.Command("chpasswd")
	set.Stdin = strings.NewReader(fixtureAdmin + ":" + credential + "\n")
	if err := set.Run(); err != nil {
		t.Fatalf("control: the fixture's credential could not be set: %v", err)
	}
	check := func(login, typed string) (auth, account error) {
		t.Helper()
		transaction, err := Stack{}.Start("login", login)
		if err != nil {
			t.Fatalf("the login service could not be opened for %s: %v", login, err)
		}
		defer transaction.Close()
		answer(t, typed)
		if auth = transaction.Authenticate(); auth != nil {
			return auth, nil
		}
		return nil, transaction.Account()
	}
	if auth, account := check(fixtureAdmin, credential); auth != nil || account != nil {
		t.Fatalf("the right credential: auth %v, account %v", auth, account)
	}
	if auth, _ := check(fixtureAdmin, credential+"x"); auth == nil {
		t.Fatal("a wrong credential was accepted")
	}
	if auth, _ := check(fixtureAdmin, ""); auth == nil {
		t.Fatal("an empty credential was accepted")
	}
	if auth, account := check(fixtureLocked, credential); auth == nil && account == nil {
		t.Fatal("a locked account was admitted")
	}
	if !Built {
		t.Fatal("the adapter under test is the refusing one")
	}
}

// capture runs f with the process's standard output and standard error on pipes, restored after,
// and returns what each received.
func capture(t *testing.T, f func()) (stdout, stderr string) {
	t.Helper()
	read := func(fd int) (restore func() string) {
		saved, err := syscall.Dup(fd)
		if err != nil {
			t.Fatal(err)
		}
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := syscall.Dup3(int(w.Fd()), fd, 0); err != nil {
			t.Fatal(err)
		}
		_ = w.Close()
		return func() string {
			_ = syscall.Dup3(saved, fd, 0)
			_ = syscall.Close(saved)
			data, _ := io.ReadAll(r)
			_ = r.Close()
			return string(data)
		}
	}
	restoreOut, restoreErr := read(1), read(2)
	f()
	return restoreOut(), restoreErr()
}

// The operator sees the password service's prompts on tty1: they go to standard output, which the
// console's unit gives to the terminal, never to standard error, which it gives to the journal.
func TestLocalPAM_TheConversationPromptsOnTheTerminal(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("the container job runs this case as root, as the repair console runs")
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	credential := hex.EncodeToString(raw)
	answer(t, credential+"\n"+credential)
	var err error
	stdout, stderr := capture(t, func() { err = (Stack{}).ChangePassword("passwd", fixtureAdmin) })
	if err != nil {
		t.Fatalf("the distribution password service refused the change: %v", err)
	}
	if !strings.Contains(stdout, "New password:") || !strings.Contains(stdout, "Retype new password:") {
		t.Fatalf("the prompts did not reach the terminal; standard output %q, standard error %q", stdout, stderr)
	}
	if strings.Contains(stderr, "password:") || strings.Contains(stdout+stderr, credential) {
		t.Fatalf("a prompt went to the journal or the credential was echoed; standard output %q, standard error %q", stdout, stderr)
	}
}

// An answer longer than the conversation's buffer is refused, never cut down into a credential.
func TestLocalPAM_AnOverlongAnswerIsRefused(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("the container job runs this case as root, as the repair console runs")
	}
	raw := make([]byte, 300)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	long := hex.EncodeToString(raw)
	answer(t, long+"\n"+long)
	if err := (Stack{}).ChangePassword("passwd", fixtureAdmin); err == nil {
		t.Fatal("a 600-character answer was taken: it was cut down into the credential")
	}
}

// A NUL typed in an answer would cut the credential at it: the answer is refused instead.
func TestLocalPAM_AnAnswerHoldingANulIsRefused(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("the container job runs this case as root, as the repair console runs")
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	withNul := hex.EncodeToString(raw) + "\x00" + hex.EncodeToString(raw[:4])
	answer(t, withNul+"\n"+withNul)
	if err := (Stack{}).ChangePassword("passwd", fixtureAdmin); err == nil {
		t.Fatal("an answer holding a NUL was taken: it was cut down into the credential")
	}
}

// A secret is never read from a character device whose echo cannot be turned off.
func TestLocalPAM_ASecretIsNotReadFromADeviceItCannotQuieten(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("the container job runs this case as root, as the repair console runs")
	}
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Dup3(int(null.Fd()), 0, 0); err != nil {
		t.Fatal(err)
	}
	_ = null.Close()
	if err := (Stack{}).ChangePassword("passwd", fixtureAdmin); err == nil {
		t.Fatal("a credential was taken from a device the conversation could not quieten")
	}
}
