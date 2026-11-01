// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package updatepage

import (
	"encoding/json"
	"slices"
	"strings"
	"time"
	"unicode"
)

// maxLicenceBody bounds the product's licence answer the page takes: its status is a few hundred bytes.
const maxLicenceBody = 32 << 10

// maxShown bounds a licence text value the page shows, in characters.
const maxShown = 128

// Licence is the product's licence status reduced to what the page shows.
type Licence struct {
	// Read is true when the product answered with a status this package knows.
	Read bool
	// Edition is the build edition, "community" or "enterprise" (the Business and Enterprise build).
	Edition string
	// Status is none, invalid, valid, expired or perpetual.
	Status         string
	Licensee, Plan string
	ExpiresAt      *time.Time
	// ManagedExternally is true when a boot override outranks the installed file.
	ManagedExternally bool
}

// Installed is true when the product reported a licence it holds: any status but none and invalid.
func (l Licence) Installed() bool {
	return l.Read && l.Status != "none" && l.Status != "invalid"
}

// DecodeLicence reads the product's GET /v1/console/license answer. It returns false for anything
// that is not a status of a known edition and lifecycle, so a changed or foreign answer is shown as
// unread and never as a guess.
func DecodeLicence(body []byte) (Licence, bool) {
	var in struct {
		Edition           string     `json:"edition"`
		Status            string     `json:"status"`
		Licensee          string     `json:"licensee"`
		Plan              string     `json:"plan"`
		ExpiresAt         *time.Time `json:"expires_at"`
		ManagedExternally bool       `json:"managed_externally"`
	}
	if len(body) == 0 || len(body) > maxLicenceBody || json.Unmarshal(body, &in) != nil {
		return Licence{}, false
	}
	if !slices.Contains([]string{"community", "enterprise"}, in.Edition) ||
		!slices.Contains([]string{"none", "invalid", "valid", "expired", "perpetual"}, in.Status) {
		return Licence{}, false
	}
	return Licence{Read: true, Edition: in.Edition, Status: in.Status, Licensee: shown(in.Licensee), Plan: shown(in.Plan),
		ExpiresAt: in.ExpiresAt, ManagedExternally: in.ManagedExternally}, true
}

// shown drops control and format characters (a right-to-left override among them) and keeps at most maxShown characters of a text the licence carries.
func shown(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
			return -1
		}
		return r
	}, s)
	if r := []rune(s); len(r) > maxShown {
		s = string(r[:maxShown])
	}
	return s
}
