// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package hostusers

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
)

// DeferralMarker is the installer-owned proof that no usable administrator existed at inspection.
const DeferralMarker = "/etc/olivares-appliance/defer-administrator"

// UserdbRecord is the systemd-userdb record of the host administrator, written by the helper.
type UserdbRecord string

// Save preserves an existing record or writes the measured login and numeric UID atomically.
func (path UserdbRecord) Save(login, uidText string) error {
	uid, err := strconv.ParseUint(uidText, 10, 32)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(string(path))
	switch {
	case err == nil:
		var current struct {
			UserName string `json:"userName"`
			UID      uint32 `json:"uid"`
		}
		if json.Unmarshal(data, &current) != nil || current.UserName != login || current.UID != uint32(uid) {
			return errors.New("a different administrator is already recorded")
		}
		return nil
	case !errors.Is(err, os.ErrNotExist):
		return err
	}
	if err := os.MkdirAll(filepath.Dir(string(path)), 0o700); err != nil {
		return err
	}
	data, _ = json.Marshal(struct {
		UserName string `json:"userName"`
		UID      uint32 `json:"uid"`
	}{login, uint32(uid)})
	temporary := string(path) + ".new"
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	succeeded := false
	defer func() {
		if !succeeded {
			_ = file.Close()
			_ = os.Remove(temporary)
		}
	}()
	if _, err := file.Write(append(data, '\n')); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, string(path)); err != nil {
		return err
	}
	if err := os.Remove(DeferralMarker); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	succeeded = true
	return nil
}
