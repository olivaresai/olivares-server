// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package hostops

import "github.com/olivaresai/olivares/appliance/layer/portal/audit"

// SpoolAudit uses the portal's existing durable audit spool, including the
// exact target and intent for refused operations that have no operation record.
type SpoolAudit struct{ Spool *audit.Spool }

func (a SpoolAudit) Append(e ActEvent) error {
	if a.Spool == nil {
		return refuse("audit")
	}
	_, err := a.Spool.Append(audit.Record{Mode: e.Caller.Mode, Surface: e.Surface, Actor: e.Caller.Actor, Verb: e.TaskID, Outcome: e.Outcome, OperationID: e.OperationID, Target: e.Target, PlanDigest: e.Digest})
	return err
}
