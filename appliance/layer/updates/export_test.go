// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package updates

// DigestWithSteps is the digest the plan would carry if its two sealed steps were the given bytes: the test's way of
// forging a plan whose own digest agrees with its files.
func DigestWithSteps(p Plan, update, recovery []byte) string {
	p.update, p.recovery = update, recovery
	return p.digest()
}
