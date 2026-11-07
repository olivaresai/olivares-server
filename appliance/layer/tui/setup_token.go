// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package tui

import (
	"errors"
	"os"
)

// setupTokenShown starts the one answer that carries the token; the console clears the screen after it.
const setupTokenShown = "One-time setup token: "

// SetupToken reads the current one-time setup token only after the operator's local confirmation.
type SetupToken func() (string, error)

// WithSetupToken returns the console reading its setup token through r, never at startup.
func (c Console) WithSetupToken(r SetupToken) Console {
	c.setupToken = r
	return c
}

// ShowSetupToken displays the token only to a signed-in operator who typed show. An absent file
// answers "spent or absent"; any other read error answers one fixed "could not be read" sentence, so
// a permission or policy fault is never reported as a finished setup. Neither prints token material
// or error details.
func (c Console) ShowSetupToken(answer string) string {
	if !c.qualified() {
		return "setup token: " + signInRequired
	}
	if answer != "show" {
		return "Nothing was shown."
	}
	if c.setupToken == nil {
		return "setup token: no local token reader is configured."
	}
	token, err := c.setupToken()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "setup token: the token could not be read."
	}
	if err != nil || token == "" {
		return "setup token: no active one-time token is available; setup may already be complete."
	}
	return setupTokenShown + token + "\nUse it at the setup address shown above. It is single-use."
}
