// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package base

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// First boot may search a home but not list it: the enforcing image grants search on user_home_dir_t and refuses read
// (#2810). A home it can only search, here mode 0111, still yields the account's authorized keys.
func TestCloudInitHost_FindsAHomesKeysWithoutListingTheHome(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a mode 0111 directory; the refusal measured here is the non-root one")
	}
	s, in := networkHost(t)
	if err := os.Remove(filepath.Join(s.Host.Root, "root/.ssh/authorized_keys")); err != nil {
		t.Fatal(err)
	}
	place(t, s.Host.Root, "home/appliance-admin/.ssh/authorized_keys", strings.Join(in.Answers.SSHAuthorizedKeys, "\n")+"\n")
	home := filepath.Join(s.Host.Root, "home/appliance-admin")
	if err := os.Chmod(home, 0o111); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(home, 0o700) })
	if _, err := s.Apply(context.Background(), in); err != nil {
		t.Fatalf("keys in a search-only home: %v", err)
	}
}

// A file in /home is not an account: its path has no .ssh under it, and the scan goes on to the real homes.
func TestCloudInitHost_SkipsAFileInHome(t *testing.T) {
	s, in := networkHost(t)
	if err := os.Remove(filepath.Join(s.Host.Root, "root/.ssh/authorized_keys")); err != nil {
		t.Fatal(err)
	}
	place(t, s.Host.Root, "home/README", "not an account\n")
	place(t, s.Host.Root, "home/appliance-admin/.ssh/authorized_keys", strings.Join(in.Answers.SSHAuthorizedKeys, "\n")+"\n")
	if _, err := s.Apply(context.Background(), in); err != nil {
		t.Fatalf("a file next to a home: %v", err)
	}
}
