// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package entitled

import (
	"bytes"
	"errors"
)

// The two editions are two packages of one product; the package manager is the only thing that changes which one a
// host holds. The image ships Community. Business is never in the image: its package, which conflicts with
// Community's and provides it, comes from the entitled channel once a licence earns it.
const (
	CommunityPackage = "olivares"
	BusinessPackage  = "olivares-business"
)

// FeatureSuite is the entitled suite only a current licence earns (the licensing service's class table gives an
// expired licence the security suite alone). Render writes one repository section per suite, so the section is the
// one record of what the licence earns now.
const FeatureSuite = "entitled-stable"

// Swap is one package transaction: From leaves and To arrives, in the same transaction, so the host never holds
// both and never holds neither.
type Swap struct{ From, To string }

// HasFeatureSuite reports whether a repository file written by Render has the feature suite's section. Only a line
// that is exactly the section header counts: a value, a comment or a longer id does not.
func HasFeatureSuite(repo []byte) bool {
	want := []byte("[olivares-" + FeatureSuite + "]")
	for _, line := range bytes.Split(repo, []byte("\n")) {
		if bytes.Equal(line, want) {
			return true
		}
	}
	return false
}

// Wanted decides whether the installed edition must change. licensed is whether a licence is installed, feature
// whether the entitled repository has the feature suite, and community and business which packages the host holds.
//
// A licence that earns the feature suite puts Business on a Community host. No licence puts Community on a
// Business host: the repository file is only a leftover then. Anything else leaves the host as it is: an expired
// licence keeps the edition it has and gets security updates only, and a licence whose channel has not been
// refreshed yet changes nothing until it has. A host that holds both packages or neither is refused, as the
// transaction would not mean what it says.
func Wanted(licensed, feature, community, business bool) (Swap, bool, error) {
	switch {
	case community == business:
		return Swap{}, false, errors.New("entitled: the host must hold exactly one of " + CommunityPackage + " and " + BusinessPackage)
	case licensed && feature && community:
		return Swap{From: CommunityPackage, To: BusinessPackage}, true, nil
	case !licensed && business:
		return Swap{From: BusinessPackage, To: CommunityPackage}, true, nil
	}
	return Swap{}, false, nil
}
