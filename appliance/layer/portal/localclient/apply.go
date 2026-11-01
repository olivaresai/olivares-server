// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package localclient

import "github.com/olivaresai/olivares/appliance/layer/hostops"

// Apply sends exactly once. The operation ID remains available for explicit
// status lookup after an unverified response; this client never retries.
func (c *Client) Apply(req hostops.ApplyRequest) (hostops.Record, int, error) {
	var r hostops.Record
	status, err := c.call("task.apply", req, &r)
	if err == nil && (r.OperationID != req.OperationID || r.Module != req.Module || r.Verb != req.Verb || r.PlanDigest != req.Confirmation || (status == 202) != (r.State == hostops.StateRunning)) {
		_ = c.Close()
		return hostops.Record{}, 0, &Failure{Code: "response_unverified", Reason: "record_malformed", Sent: true}
	}
	return r, status, err
}
