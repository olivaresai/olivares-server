// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package tui

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/olivaresai/olivares/appliance/layer/helpers/helperschema"
	"github.com/olivaresai/olivares/appliance/layer/hostops"
	"github.com/olivaresai/olivares/appliance/layer/hostusers"
)

// AdministratorCreator is the host layer's operator-chosen administrator-creation entry.
type AdministratorCreator interface {
	CreateAdministrator(ctx context.Context, login string) (Human, error)
}

// WithAdministratorCreator returns the console offering the host layer's creation entry.
func (c Console) WithAdministratorCreator(creator AdministratorCreator) Console {
	c.creator = creator
	return c
}

// NativeAdministratorCreation composes the fixed host-user helper, account measurement and PAM credential path.
type NativeAdministratorCreation struct {
	Creator  hostusers.CreateTask
	Accounts Accounts
	Record   UserDBHostRecord
	Marker   string
	Recovery NativeAccountRecovery
	Random   io.Reader
}

// CreateAdministrator asks the fixed helper for the operator-named account and sets its credential with PAM.
func (c NativeAdministratorCreation) CreateAdministrator(ctx context.Context, login string) (Human, error) {
	if !loginShape(login) || login == "root" || c.Accounts == nil {
		return Human{}, errors.New("administrator creation refused")
	}
	inputs, _ := json.Marshal(hostusers.Request{Account: login, Home: "/home/" + login, Group: "wheel"})
	if _, err := hostusers.Decode(inputs); err != nil {
		return Human{}, fmt.Errorf("%s is reserved or not a valid account name: choose another login", login)
	}
	if c.Record != "" {
		_, err := c.Record.RecordedHuman()
		if !errors.Is(err, os.ErrNotExist) {
			return Human{}, errors.New("administrator record present or unreadable")
		}
	}
	markerPath := c.Marker
	if markerPath == "" {
		markerPath = hostusers.DeferralMarker
	}
	marker, err := os.Lstat(markerPath)
	if err != nil || !marker.Mode().IsRegular() || marker.Mode().Perm() != 0o600 {
		return Human{}, errors.New("the installer did not defer administrator creation")
	}
	operation, err := helperschema.NewOperationID(operationRandom(c.Random))
	if err != nil {
		return Human{}, err
	}
	cmd := hostops.Command{OperationID: operation, TaskID: "host-user.create", Module: "host-user", Verb: "create", Target: "system"}
	observation := c.Creator.Apply(ctx, cmd, inputs)
	if observation.P1 != "performed" {
		return Human{}, fmt.Errorf("the host-user helper answered %s", observation.P1)
	}
	uid, groups, err := c.Accounts.Lookup(login)
	if err != nil || !administrator(uid, groups) {
		return Human{}, errors.New("the created account is not an administrator")
	}
	return Human{Login: login, UID: uid}, c.Recovery.SetAdminCredential(ctx, Human{Login: login, UID: uid})
}

// operationRandom supplies the operation-ID source without storing authority in the request.
func operationRandom(r io.Reader) io.Reader {
	if r == nil {
		return rand.Reader
	}
	return r
}
