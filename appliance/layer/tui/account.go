// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package tui

import (
	"context"
	"time"
)

// Human is the administrator the host layer created and recorded in its host record: the login
// and the uid it was created with.
type Human struct {
	Login string
	UID   uint32
}

// HostRecord reads the host layer's host record, which names the human its host layer created.
type HostRecord interface {
	RecordedHuman() (Human, error)
}

// AccountRecovery is the host layer's own account-recovery entry on this console, set-admin-password, which
// sets the credential of the human the host layer recorded. Its conversation and its checks are the host layer's.
type AccountRecovery interface {
	SetAdminCredential(ctx context.Context, human Human) error
}

// recoveryTimeout bounds the host layer's entry, which holds the terminal while it asks.
const recoveryTimeout = 10 * time.Minute

// WithHostRecord returns the console reading the host layer's host record through r.
func (c Console) WithHostRecord(r HostRecord) Console {
	c.record = r
	return c
}

// WithAccountRecovery returns the console handing account recovery to the host layer's entry e.
func (c Console) WithAccountRecovery(e AccountRecovery) Console {
	c.recovery = e
	return c
}

// AccountRecovery hands the first credential of the human the host layer recorded to the host layer's own entry, and
// states what happened. The operator names nobody: the target is the recorded human, and only when
// the host's account of that login is the one the host layer created. It never creates a human, which is the host layer's
// restore-human entry, and it grants no act on this console: Run ends any sign-in before it, and
// the next ordinary act needs a new sign-in with the new credential. Every refusal changes nothing.
func (c Console) AccountRecovery() string {
	const refused = "account recovery: refused: "
	if !c.authority.attestedOnTty1() {
		return refused + "this entry runs only in the repair console's own process on tty1, so nothing was changed."
	}
	if c.record == nil {
		return refused + "the host layer's host record is not readable by this version, so no human is named and nothing was changed."
	}
	human, err := c.record.RecordedHuman()
	if err != nil {
		return refused + "the host layer's host record is absent, unreadable or corrupt, so no human is named and nothing was changed."
	}
	if !loginShape(human.Login) || human.Login == "root" || human.UID == 0 {
		return refused + "the host layer's host record does not name a human its host layer created, so nothing was changed."
	}
	if c.authority.Accounts == nil {
		return refused + "this host's accounts cannot be read, so nothing was changed."
	}
	uid, _, err := c.authority.Accounts.Lookup(human.Login)
	if err != nil {
		return refused + "the human the host layer recorded, " + human.Login + ", does not exist on this host; bringing it back is " +
			"the host layer's own restore-human entry, and this console created nothing."
	}
	if uid != human.UID {
		return refused + "the account named " + human.Login + " is not the human the host layer recorded, so nothing was changed."
	}
	if c.recovery == nil {
		return refused + "the host layer's account-recovery entry is not composed with this console in this version, so nothing was changed."
	}
	ctx, cancel := context.WithTimeout(context.Background(), recoveryTimeout)
	defer cancel()
	if err := c.recovery.SetAdminCredential(ctx, human); err != nil {
		return "account recovery: the host layer's entry refused or did not finish for " + human.Login +
			", so its credential is unchanged or unknown; read the host layer's own state before trying again."
	}
	return "account recovery: the host layer's entry set-admin-password set the credential of " + human.Login +
		", the human the host layer recorded. It grants nothing here: sign in with that credential (s) for an ordinary act."
}
