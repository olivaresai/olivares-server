// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

//go:build !linux

package entitled

import "io/fs"

// ownerUID reports no owner off Linux, so ReadHandoff refuses every handoff there.
func ownerUID(fs.FileInfo) (int, bool) { return 0, false }
