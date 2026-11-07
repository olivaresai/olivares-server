// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

//go:build linux && cgo && olivares_pam && pamstack

package localpam

import (
	"bufio"
	"fmt"
	"os"
	"syscall"
	"testing"
	"time"
)

// An abandoned prompt does not hold tty1: the conversation gives up after its deadline.
func TestLocalPAM_AnUnansweredPromptEndsAtTheDeadline(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("the container job runs this case as root, as the repair console runs")
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close() // held open and never written: the operator walked away
	if err := syscall.Dup3(int(r.Fd()), 0, 0); err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	saved := conversationTimeout
	conversationTimeout = 2 * time.Second
	defer func() { conversationTimeout = saved }()
	start := time.Now()
	if err := (Stack{}).ChangePassword("passwd", fixtureAdmin); err == nil {
		t.Fatal("an unanswered prompt changed the credential")
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("the unanswered prompt held the console for %s", elapsed)
	}
}

// The conversation on a real terminal, as tty1 is: the container job runs this case under a
// pseudo-terminal in its cooked modes, with the pseudo-terminal as the controlling terminal. In mode
// "prompt" it types each answer the moment its prompt appears, Enter as a carriage return, and the
// change must go through; in mode "together" it sends both answers behind the first prompt, and the
// second, typed before its prompt, must not be taken. In mode "abandoned" it types part of the secret
// without Enter and lets the deadline pass; after the refusal it sends ^R and then q, and neither the
// reprinted line nor the next line read may hold what was typed.
func TestLocalPAM_TheConversationOnATerminal(t *testing.T) {
	switch os.Getenv("LOCALPAM_TERMINAL_JOB") {
	case "prompt":
		if err := (Stack{}).ChangePassword("passwd", fixtureAdmin); err != nil {
			t.Fatalf("the password service refused the change typed on a terminal: %v", err)
		}
	case "together":
		saved := conversationTimeout
		conversationTimeout = 2 * time.Second
		defer func() { conversationTimeout = saved }()
		if err := (Stack{}).ChangePassword("passwd", fixtureAdmin); err == nil {
			t.Fatal("an answer typed before its prompt was taken")
		}
	case "abandoned":
		saved := conversationTimeout
		conversationTimeout = 2 * time.Second
		defer func() { conversationTimeout = saved }()
		if err := (Stack{}).ChangePassword("passwd", fixtureAdmin); err == nil {
			t.Fatal("an abandoned prompt changed the credential")
		}
		fmt.Println("ABANDONED-REFUSED")
		next, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if next != "q\n" {
			t.Fatalf("the next line read after the refusal is %d bytes, not q: it holds what was typed at the prompt", len(next))
		}
	default:
		t.Skip("the container job runs this case under a pseudo-terminal it answers")
	}
}
