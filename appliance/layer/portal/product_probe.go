// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package portal

import (
	"errors"
	"syscall"

	"github.com/olivaresai/olivares/appliance/layer/portal/auth"
)

// MeasureProduct uses the existing fixed, verified native client. An answer is
// reachability only; even a refusal keeps PAM closed while the product answers.
// Failed trust or a timeout is unmeasured, never evidence that the product is down.
func (p *productClient) MeasureProduct() auth.ProductMeasurement {
	if p == nil || p.http == nil {
		return auth.ProductMeasurement{}
	}
	response, err := p.http.Get(p.endpoint + "/livez")
	if err != nil {
		return auth.ProductMeasurement{Measured: errors.Is(err, syscall.ECONNREFUSED)}
	}
	defer response.Body.Close()
	return auth.ProductMeasurement{Measured: true, Answers: true}
}
