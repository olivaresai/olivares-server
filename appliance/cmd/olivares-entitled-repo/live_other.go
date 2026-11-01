// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

//go:build !linux

package main

// live is an empty environment off Linux, where the command only has to build: it has no invocation
// id, so refresh refuses before it touches anything.
func live() env { return env{} }
