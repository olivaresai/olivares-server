// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package hostusers_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/olivaresai/olivares/appliance/layer/hostops"
	"github.com/olivaresai/olivares/appliance/layer/hostusers"
)

type host struct {
	account                    hostusers.Account
	exists, homeExists, unsafe bool
	path                       string
	args                       []string
	fail, unmeasured           bool
}

func (h *host) Account(context.Context, string) (hostusers.Account, bool, error) {
	return h.account, h.exists, nil
}
func (h *host) Group(context.Context, string) (string, error) { return "1001", nil }
func (h *host) Home(context.Context, string) (hostusers.Home, error) {
	if h.unsafe {
		return hostusers.Home{}, errors.New("unsafe home")
	}
	return hostusers.Home{Exists: h.homeExists, Directory: h.homeExists, UID: "1002", GID: "1001", Private: true}, nil
}
func (h *host) Run(_ context.Context, path string, args []string) error {
	h.path, h.args = path, args
	if !h.unmeasured {
		h.exists, h.homeExists = true, true
		h.account = hostusers.Account{Name: "alice", UID: "1002", GID: "1001", Home: "/home/alice"}
	}
	if h.fail {
		return errors.New("command failed with sensitive stderr")
	}
	return nil
}
func TestHostUser_CreateMeasuresFixedUseraddAndHome(t *testing.T) {
	h := &host{}
	x := hostusers.Provisioner{Host: h}
	input := json.RawMessage(`{"account":"alice","home":"/home/alice","group":"staff"}`)
	if target, err := x.Prepare(context.Background(), input); err != nil || target != "system" {
		t.Fatalf("prepare: %s %v", target, err)
	}
	obs := x.Apply(context.Background(), hostops.Command{}, input)
	want := []string{"--create-home", "--home-dir", "/home/alice", "--gid", "1001", "--no-user-group", "--shell", "/bin/bash", "--key", "UMASK=077", "--key", "HOME_MODE=0700", "--", "alice"}
	if obs.P1 != "performed" || len(obs.Postconditions) == 0 || h.path != "/usr/sbin/useradd" || !reflect.DeepEqual(h.args, want) {
		t.Fatalf("observation %+v command %s %v", obs, h.path, h.args)
	}
	if _, err := x.Prepare(context.Background(), input); err == nil {
		t.Fatal("duplicate allowed")
	}
	if got := x.Recover(context.Background(), input); got.P1 != "performed" || len(got.Postconditions) == 0 {
		t.Fatalf("recovery: %+v", got)
	}
}
func TestHostUser_RefusesPathsReservedAccountsAndExistingHomes(t *testing.T) {
	for _, input := range []string{
		`{"account":"root","home":"/home/root","group":"staff"}`,
		`{"account":"alice","home":"/etc/alice","group":"staff"}`,
		`{"account":"alice","home":"/home/../etc","group":"staff"}`,
		`{"account":"-alice","home":"/home/-alice","group":"staff"}`,
		`{"account":"alice","home":"/home/alice","group":"root"}`,
		`{"account":"alice","home":"/home/alice","group":"staff","shell":"/bin/sh"}`,
	} {
		h := &host{}
		x := hostusers.Provisioner{Host: h}
		if _, err := x.Prepare(context.Background(), json.RawMessage(input)); err == nil {
			t.Fatalf("accepted %s", input)
		}
		if obs := x.Apply(context.Background(), hostops.Command{}, json.RawMessage(input)); obs.P1 != "not-performed" || h.path != "" {
			t.Fatalf("effect: %+v", obs)
		}
	}
	for _, h := range []*host{{homeExists: true}, {unsafe: true}} {
		x := hostusers.Provisioner{Host: h}
		if _, err := x.Prepare(context.Background(), json.RawMessage(`{"account":"alice","home":"/home/alice","group":"staff"}`)); err == nil {
			t.Fatal("existing or unsafe home accepted")
		}
	}
}
func TestHostUser_FailedOrUnmeasuredEffectIsNeverSuccess(t *testing.T) {
	for _, h := range []*host{{fail: true}, {unmeasured: true}, {fail: true, unmeasured: true}} {
		x := hostusers.Provisioner{Host: h}
		obs := x.Apply(context.Background(), hostops.Command{}, json.RawMessage(`{"account":"alice","home":"/home/alice","group":"staff"}`))
		if obs.P1 == "performed" {
			t.Fatalf("false success: %+v", obs)
		}
	}
}
