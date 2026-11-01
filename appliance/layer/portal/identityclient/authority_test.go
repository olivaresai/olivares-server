// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package identityclient

import (
	"context"
	"github.com/olivaresai/olivares/appliance/layer/hostusers"
	"strings"
	"testing"
)

func TestAuthorityResolverRequiresCapturedOriginalPeer(t *testing.T) {
	resolve := NewAuthorityResolver()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, canceled} {
		if authority, err := resolve(ctx, 1602); err == nil || authority != nil {
			t.Fatal("missing/canceled context admitted")
		}
	}
	if authority, err := resolve(context.Background(), 0); err == nil || authority != nil {
		t.Fatal("UID0 admitted")
	}
	authority, err := resolve(context.Background(), 1602)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = authority.Authorize(context.Background(), hostusers.Descriptors()[0], "system", strings.Repeat("a", 64)); err == nil {
		t.Fatal("claimed UID replaced original held socket")
	}
}
