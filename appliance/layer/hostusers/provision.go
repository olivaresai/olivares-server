// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

// Package hostusers creates OS accounts. Product identities and workspaces are
// separate; no password or arbitrary executable is accepted by this module.
package hostusers

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/olivaresai/olivares/appliance/layer/hostops"
)

type Request struct {
	Account string `json:"account"`
	Home    string `json:"home"`
	Group   string `json:"group"`
}
type Account struct{ Name, UID, GID, Home string }
type Home struct {
	Exists, Directory, Private bool
	UID, GID                   string
}

// Host is the privileged helper's OS seam. An appliance caller must reach it
// through the existing attested helper admission, never by promoting its UID.
type Host interface {
	Account(context.Context, string) (Account, bool, error)
	Group(context.Context, string) (string, error)
	Home(context.Context, string) (Home, error)
	Run(context.Context, string, []string) error
}
type Provisioner struct {
	Host              Host
	Record            UserdbRecord
	SupplementalGroup string
}

func Decode(input json.RawMessage) (Request, error) {
	var r Request
	if hostops.DecodeClosed(input, &r) != nil {
		return Request{}, errors.New("input_refused")
	}
	if r.Home == "" {
		r.Home = "/home/" + r.Account
	}
	if !name(r.Account) || !name(r.Group) || r.Home != "/home/"+r.Account || reserved(r.Account) || r.Group == "root" {
		return Request{}, errors.New("input_refused")
	}
	return r, nil
}
func name(s string) bool {
	if len(s) == 0 || len(s) > 32 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}
func reserved(s string) bool {
	return strings.HasPrefix(s, "olivares") || s == "root" || s == "nobody" || s == "daemon" || s == "bin" || s == "sys" || s == "sync"
}
func id(s string) bool {
	n, err := strconv.ParseUint(s, 10, 32)
	return err == nil && n > 0 && n < 1<<32-1 && strconv.FormatUint(n, 10) == s
}

func (x Provisioner) preflight(ctx context.Context, r Request) (string, error) {
	if x.Host == nil {
		return "", errors.New("consumer_unavailable")
	}
	_, exists, err := x.Host.Account(ctx, r.Account)
	if err != nil || exists {
		return "", errors.New("account_exists_or_unavailable")
	}
	gid, err := x.Host.Group(ctx, r.Group)
	if err != nil || !id(gid) {
		return "", errors.New("group_unavailable")
	}
	home, err := x.Host.Home(ctx, r.Home)
	if err != nil || home.Exists {
		return "", errors.New("home_unavailable")
	}
	return gid, nil
}
func (x Provisioner) Prepare(ctx context.Context, input json.RawMessage) (string, error) {
	r, err := Decode(input)
	if err != nil {
		return "", err
	}
	if _, err := x.preflight(ctx, r); err != nil {
		return "", err
	}
	return "system", nil
}

// Apply uses useradd's documented create-home, explicit existing group, private
// umask and locked-password default. It never returns command output or retries.
func (x Provisioner) Apply(ctx context.Context, cmd hostops.Command, input json.RawMessage) hostops.Observation {
	return x.apply(ctx, cmd, input, "")
}

func (x Provisioner) apply(ctx context.Context, cmd hostops.Command, input json.RawMessage, expectedGID string) hostops.Observation {
	r, err := Decode(input)
	if err != nil {
		return hostops.Observation{P1: "not-performed"}
	}
	gid, err := x.preflight(ctx, r)
	if err != nil || expectedGID != "" && gid != expectedGID {
		return hostops.Observation{P1: "not-performed"}
	}
	if ctx.Err() != nil {
		return hostops.Observation{P1: "not-performed"}
	}
	err = x.Host.Run(ctx, "/usr/sbin/useradd", []string{"--create-home", "--home-dir", r.Home, "--gid", gid, "--no-user-group", "--shell", "/bin/bash", "--key", "UMASK=077", "--key", "HOME_MODE=0700", "--", r.Account})
	if err == nil && x.SupplementalGroup != "" {
		err = x.Host.Run(ctx, "/usr/sbin/usermod", []string{"--append", "--groups", x.SupplementalGroup, "--", r.Account})
	}
	if err != nil {
		// A failed step saves no administrator record and keeps the installer's deferral marker.
		x.Record = ""
	}
	obs := x.measure(ctx, r, gid)
	if err != nil {
		if obs.P1 == "performed" || obs.MeasuredChange {
			return hostops.Observation{P1: "partial", MeasuredChange: true}
		}
		return hostops.Observation{P1: "unknown"}
	}
	return obs
}

// Recover only measures. It never repeats useradd or removes an account/home.
func (x Provisioner) Recover(ctx context.Context, input json.RawMessage) hostops.Observation {
	r, err := Decode(input)
	if err != nil || x.Host == nil {
		return hostops.Observation{P1: "unknown"}
	}
	gid, err := x.Host.Group(ctx, r.Group)
	if err != nil || !id(gid) {
		return hostops.Observation{P1: "unknown"}
	}
	return x.measure(ctx, r, gid)
}
func (x Provisioner) measure(ctx context.Context, r Request, gid string) hostops.Observation {
	a, exists, err := x.Host.Account(ctx, r.Account)
	if err != nil {
		return hostops.Observation{P1: "unknown"}
	}
	h, homeErr := x.Host.Home(ctx, r.Home)
	if exists && a.Name == r.Account && id(a.UID) && a.GID == gid && a.Home == r.Home && homeErr == nil && h.Exists && h.Directory && h.Private && h.UID == a.UID && h.GID == gid {
		if x.Record != "" {
			if err := x.Record.Save(r.Account, a.UID); err != nil {
				return hostops.Observation{P1: "partial", MeasuredChange: true}
			}
		}
		return hostops.Observation{P1: "performed", MeasuredChange: true, Postconditions: []string{"OS account " + r.Account + " has home " + r.Home + " and primary GID " + gid, "Home is a private directory owned by UID " + a.UID + " and GID " + gid}}
	}
	if exists || homeErr == nil && h.Exists {
		return hostops.Observation{P1: "partial", MeasuredChange: true}
	}
	return hostops.Observation{P1: "unknown"}
}
