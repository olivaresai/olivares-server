// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package updates

import (
	"context"

	"github.com/olivaresai/olivares/appliance/layer/hostops"
)

// Recover replays only the retained inverse package transaction, under a new
// exact-act authorization. It neither undoes other package transactions nor
// restores application data, configuration or package scriptlet side effects.
// The installed version must still equal the update's exact target. A returned
// revert is measured only after RPM reports the retained previous version.
func (x RPM) Recover(ctx context.Context, p Plan) (hostops.Observation, error) {
	return x.replay(ctx, p, true)
}
