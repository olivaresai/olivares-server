// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

//go:build !linux

package optionalapps

import (
	"context"
	"errors"
	"io/fs"
)

func LinuxRun(context.Context, []string, int64) ([]byte, error) {
	return nil, errors.New("consumer_unavailable")
}
func ownedByHelper(fs.FileInfo) bool { return false }
