// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

// Package localpam opens transactions on the host's own sign-in services for the repair console on
// tty1. The conversation is the adapter's own, on the console's terminal: prompts and the services'
// messages go to standard output, answers come from standard input (a secret one with echo off), so
// the operator's credential goes from the keyboard to the host's services in a C buffer that is wiped,
// never as a Go value, and nothing typed is logged. Each answer waits at most conversationTimeout.
//
// The adapter needs the host's sign-in library, so it is built only with cgo and the olivares_pam
// build tag, on Linux; the repair console's package build sets both. Built without them, Start
// refuses every transaction and the console signs nobody in: its ordinary acts stay refused, which
// is the direction a missing adapter must fail in. Its behavior against a real stack is measured
// by a container job and on the appliance image, never here.
package localpam

import "errors"

// Stack is the adapter. Its zero value is ready to use.
type Stack struct{}

// ErrNotBuilt refuses every transaction of a binary built without the adapter.
var ErrNotBuilt = errors.New("this binary was built without the host's sign-in library, so nobody signs in")

// errRefused is every refusal of a built adapter, whichever step refused.
var errRefused = errors.New("the host's sign-in service refused")

// consoleTerminal is the terminal the transactions name, as the host's login names a virtual console.
const consoleTerminal = "tty1"
