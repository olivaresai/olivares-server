// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package tui

import (
	"context"

	"github.com/olivaresai/olivares/appliance/layer/tui/localpam"
)

// NativeAccountRecovery resets the recorded administrator's credential with the distribution's PAM service.
type NativeAccountRecovery struct {
	Stack localpam.Stack
}

// SetAdminCredential uses the passwd service's native terminal conversation, never a subprocess.
func (r NativeAccountRecovery) SetAdminCredential(ctx context.Context, human Human) error {
	_ = ctx
	return r.Stack.ChangePassword("passwd", human.Login)
}
