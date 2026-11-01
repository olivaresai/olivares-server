// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package console

import (
	"bytes"
	"encoding/json"
	"github.com/olivaresai/olivares/appliance/layer/hostops"
	"strings"
	"testing"
)

func TestCLI_StorageMountAndUnmountUseTheExactFilesystemAndExistingApply(t *testing.T) {
	const uuid = "617359a8-818f-4d2d-a901-cc4b7b2911a1"
	for _, op := range []string{"mount", "unmount"} {
		t.Run(op, func(t *testing.T) {
			s := &userSession{state: hostops.StateSucceeded}
			var out, log bytes.Buffer
			args := []string{"storage", op, uuid}
			dial := func() (Session, error) { return s, nil }
			if code := Run(t.Context(), append(append([]string{}, args...), "--plan"), nil, &out, &log, dial); code != 0 || s.applied != 0 {
				t.Fatalf("storage plan: exit=%d output=%s", code, log.String())
			}
			if code := Run(t.Context(), append(args, "--confirm", strings.Repeat("a", 64), "--operation-id", strings.Repeat("1", 32), "--output", "json"), nil, &out, &log, dial); code != 0 || s.applied != 1 || s.req.Module != "storage" || s.req.Verb != op {
				t.Fatalf("storage apply: exit=%d request=%+v", code, s.req)
			}
			var inputs map[string]string
			if json.Unmarshal(s.req.Inputs, &inputs) != nil || len(inputs) != 1 || inputs["filesystem_uuid"] != uuid {
				t.Fatal("wrong volume", string(s.req.Inputs))
			}
		})
	}
}
func TestCLI_StorageCannotSupplyADevicePathForceOrAuthority(t *testing.T) {
	for _, args := range [][]string{
		{"storage", "mount", "/dev/sdb", "--plan"},
		{"storage", "unmount", "617359a8-818f-4d2d-a901-cc4b7b2911a1", "--force", "--confirm", strings.Repeat("a", 64)},
		{"storage", "mount", "617359a8-818f-4d2d-a901-cc4b7b2911a1", "--actor", "fran", "--plan"},
	} {
		var out, log bytes.Buffer
		dials := 0
		code := Run(t.Context(), args, nil, &out, &log, func() (Session, error) { dials++; return &userSession{}, nil })
		if code != 1 || dials != 0 {
			t.Fatalf("unsafe storage command: exit=%d dials=%d args=%v", code, dials, args)
		}
	}
}
