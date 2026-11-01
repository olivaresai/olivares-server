// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/olivaresai/olivares/appliance/layer/firewall"
	"github.com/olivaresai/olivares/appliance/layer/firewall/policy"
	"github.com/olivaresai/olivares/appliance/layer/helpers/helperschema"
	"github.com/olivaresai/olivares/appliance/layer/optionalapps"
)

type observedNFT struct {
	firewall.NFT
	err error
}

func (n *observedNFT) Load(ctx context.Context, ruleset []byte) error {
	n.err = n.NFT.Load(ctx, ruleset)
	return n.err
}

func TestBootLoadJournalsNativeLoadFailure(t *testing.T) {
	for _, tc := range []struct {
		name, script, want string
	}{
		{"netlink", "printf '%s' 'netlink: Error: Could not process rule: Operation not permitted /private/sentinel' >&2\nexit 1", "exit status 1; stderr reports Operation not permitted"},
		{"syntax", "printf '%s' '/dev/stdin:1:1: Error: syntax error\nprivate-sentinel ruleset' >&2\nexit 1", "exit status 1; stderr reports syntax error"},
		{"unknown", "printf '%s' 'private-sentinel\nsecret ruleset' >&2\nexit 42", "exit status 42; stderr prefix 31 bytes (raw text withheld)"},
		{"large", "printf '%s' '" + strings.Repeat("private-sentinel", 1000) + "' >&2\nexit 1", "exit status 1; stderr prefix 4096 bytes (raw text withheld)"},
		{"signal", "kill -TERM $$", "signal: terminated"},
		{"stdout", "printf '%s' '" + strings.Repeat("x", 64*1024+1) + "'\nexit 0", "execution or output failure (details withheld)"},
	} {
		for _, confirmed := range []bool{false, true} {
			mode := "install"
			if confirmed {
				mode = "boot"
			}
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				dir := t.TempDir()
				program := filepath.Join(dir, "nft")
				// The real NFT adapter must pass its fixed argv and rendered stdin.
				script := "#!/bin/sh\n[ \"$#\" -eq 2 ] && [ \"$1\" = '-f' ] && [ \"$2\" = '-' ] || exit 99\n" +
					"IFS= read -r first\n[ \"$first\" = 'table inet olivares' ] || exit 98\n" +
					"while IFS= read -r line; do :; done\n" + tc.script + "\n"
				if err := os.WriteFile(program, []byte(script), 0700); err != nil {
					t.Fatal(err)
				}
				kernel := &observedNFT{NFT: firewall.NFT{Program: program}}
				o := &firewall.Owner{StateDir: dir, RunDir: dir, Kernel: kernel, Lock: beforeNetworkRuntime{}}
				initial := firewall.Initial(firewall.Selection{}, 22, nil)
				if confirmed {
					data, err := policy.Canonical(initial)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(dir, "confirmed.json"), data, 0600); err != nil {
						t.Fatal(err)
					}
				}
				var log bytes.Buffer
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				status := bootLoadWith(ctx, &log, o, func(context.Context, io.Writer) (policy.Document, bool, string) {
					if confirmed {
						t.Error("boot ignored the confirmed policy")
					}
					return initial, true, ""
				})
				if status != 1 {
					t.Fatalf("exit=%d, want 1", status)
				}
				if tc.name == "stdout" {
					if kernel.err == nil || kernel.err.Error() != "the program's output exceeds its bound" {
						t.Fatalf("stdout fixture did not overflow: %v", kernel.err)
					}
				} else {
					var child *exec.ExitError
					if !errors.As(kernel.err, &child) || !strings.HasPrefix(tc.want, child.ProcessState.String()) {
						t.Fatalf("child fixture did not reach the intended failure: %v", kernel.err)
					}
				}
				want := "firewall boot load: load_failed: nft did not load the table; the kernel keeps its previous one\n"
				if !strings.Contains(log.String(), want) || !strings.Contains(log.String(), "firewall boot load: nft -f -: "+tc.want) {
					t.Fatalf("missing refusal or native diagnostic: %q", log.String())
				}
				if strings.Contains(log.String(), "sentinel") || strings.Contains(log.String(), "/private/") || strings.Contains(log.String(), "ruleset") || strings.ContainsAny(log.String(), "\r\x1b") || log.Len() > 640 {
					t.Fatal("unsafe or unbounded journal")
				}
			})
		}
	}
}

func TestBootLoadJournalsNativeStartFailure(t *testing.T) {
	dir := t.TempDir()
	program := filepath.Join(dir, "absent-private-sentinel")
	kernel := &observedNFT{NFT: firewall.NFT{Program: program}}
	o := &firewall.Owner{StateDir: dir, RunDir: dir, Kernel: kernel, Lock: beforeNetworkRuntime{}}
	var log bytes.Buffer
	status := bootLoadWith(context.Background(), &log, o, func(context.Context, io.Writer) (policy.Document, bool, string) {
		return firewall.Initial(firewall.Selection{}, 22, nil), true, ""
	})
	if !errors.Is(kernel.err, os.ErrNotExist) {
		t.Fatalf("native execution did not report the missing program: %v", kernel.err)
	}
	want := "firewall boot load: nft -f -: executable unavailable\n" +
		"firewall boot load: load_failed: nft did not load the table; the kernel keeps its previous one\n"
	if status != 1 || log.String() != want {
		t.Fatalf("exit=%d journal=%q", status, log.String())
	}
}

func TestMain_OnlyTheTwoBootModesTakeAnArgument(t *testing.T) {
	for args, want := range map[string]runMode{
		"":                    modeServe,
		"--boot-load":         modeBootLoad,
		"--guard":             modeGuard,
		"--boot-load --guard": modeServe,
		"--guard --guard":     modeServe,
		"--help":              modeServe,
		"boot-load":           modeServe,
		"--boot-load=1":       modeServe,
	} {
		if got := modeOf(strings.Fields(args)); got != want {
			t.Errorf("%q runs mode %d, want %d", args, got, want)
		}
	}
}

func TestHelper_ActsWaitForTheirAdoption(t *testing.T) {
	ctx := context.Background()
	id := strings.Repeat("ab", 16)
	opened := 0
	open := func() (*firewall.Owner, error) { opened++; return nil, errors.New("no host in this test") }
	h := helperWith(false, optionalapps.FirewallApps(), open)
	if h.Name != firewall.HelperName || h.NewRequest == nil || len(h.Rules) == 0 {
		t.Fatalf("the helper is %+v", h)
	}
	if _, ok := h.NewRequest().(*firewall.Request); !ok {
		t.Fatal("the helper's document is not the firewall request")
	}
	for _, op := range []string{"apply", "confirm", "revert"} {
		resp := h.Perform(ctx, helperschema.Peer{}, &firewall.Request{Op: op, OperationID: id})
		if resp.Result != helperschema.ResultRefused || resp.Code != firewall.CodeActNotAdopted {
			t.Errorf("%s before adoption: %+v", op, resp)
		}
	}
	if opened != 0 {
		t.Fatal("an act reached the owner before its adoption")
	}
	// status is a read: it reaches the owner, and an owner that cannot open is a failure.
	if resp := h.Perform(ctx, helperschema.Peer{}, &firewall.Request{Op: "status"}); resp.Result != helperschema.ResultFailed || opened != 1 {
		t.Errorf("status: %+v, opened %d", resp, opened)
	}
	adopted := helperWith(true, optionalapps.FirewallApps(), open)
	if resp := adopted.Perform(ctx, helperschema.Peer{}, &firewall.Request{Op: "revert", OperationID: id}); resp.Result != helperschema.ResultFailed || opened != 2 {
		t.Errorf("an adopted act: %+v, opened %d", resp, opened)
	}
}

// appDocument is a valid policy that carries the given rows for the application.
func appDocument(rows []policy.AppRow) *policy.Document {
	return &policy.Document{SchemaVersion: policy.SchemaVersion, SSHPort: 22, DHCPv6ClientInterfaces: []string{}, Apps: rows,
		Portal: policy.Portal{Enabled: true, Listen: policy.ListenManagement, ManagementInterfaces: []string{"eth0"}}}
}

// The Appliance Console composes the network act (firewall.app-row) and sends the helper apply and
// confirm: the helper the binary serves must let them reach the owner, or the adopted act could never
// perform. It is the helper main builds, not a copy: the same constant and the product's own table of
// the application's rows.
func TestHelper_TheServedHelperLetsTheConsolesActsReachTheOwner(t *testing.T) {
	opened := 0
	open := func() (*firewall.Owner, error) { opened++; return nil, errors.New("no host in this test") }
	served := helperWith(actAdopted, optionalapps.FirewallApps(), open)
	id := strings.Repeat("cd", 16)
	add := &firewall.Request{Op: "apply", OperationID: id, App: optionalapps.Slug, Candidate: appDocument(optionalapps.FirewallRows())}
	remove := &firewall.Request{Op: "apply", OperationID: id, App: optionalapps.Slug, Candidate: appDocument([]policy.AppRow{})}
	for name, req := range map[string]*firewall.Request{"apply of the rows": add, "apply of their removal": remove,
		"confirm": {Op: "confirm", OperationID: id}, "revert": {Op: "revert", OperationID: id}} {
		before := opened
		resp := served.Perform(context.Background(), helperschema.Peer{}, req)
		if resp.Code == firewall.CodeActNotAdopted || resp.Code == firewall.CodeAppRowNotOwnAct || opened != before+1 {
			t.Errorf("%s: %+v, opened %d times, want it to reach the owner", name, resp, opened-before)
		}
	}
}

// The adopted act is the application's own act and nothing wider: a console process that asks the
// helper for a whole policy, for an application the product does not know, or for a port, an interface
// or a bridge the manifest does not give reaches no owner. Each variant differs from the accepted
// document in the one thing it names.
func TestHelper_AnApplyIsOnlyTheApplicationsOwnActWithItsManifestRows(t *testing.T) {
	opened := 0
	open := func() (*firewall.Owner, error) { opened++; return nil, errors.New("no host in this test") }
	served := helperWith(actAdopted, optionalapps.FirewallApps(), open)
	id := strings.Repeat("ef", 16)
	rows := func(change func(*policy.AppRow)) []policy.AppRow {
		out := optionalapps.FirewallRows()
		change(&out[0])
		return out
	}
	other := optionalapps.FirewallRows()
	for i := range other {
		other[i].App = "notes"
	}
	whole := appDocument([]policy.AppRow{})
	whole.SSHPort = 2222
	for name, c := range map[string]struct {
		req  *firewall.Request
		code string
	}{
		"a whole policy with no application":  {&firewall.Request{Op: "apply", OperationID: id, Candidate: whole}, firewall.CodeActNotAdopted},
		"an application the product lacks":    {&firewall.Request{Op: "apply", OperationID: id, App: "notes", Candidate: appDocument(other)}, firewall.CodeActNotAdopted},
		"a bridge of the console's choosing":  {&firewall.Request{Op: "apply", OperationID: id, App: optionalapps.Slug, Candidate: appDocument(rows(func(r *policy.AppRow) { r.Bridge = "eth0" }))}, firewall.CodeAppRowNotOwnAct},
		"a port the manifest does not give":   {&firewall.Request{Op: "apply", OperationID: id, App: optionalapps.Slug, Candidate: appDocument(rows(func(r *policy.AppRow) { r.Port = "2222/tcp" }))}, firewall.CodeAppRowNotOwnAct},
		"an interface the manifest lacks":     {&firewall.Request{Op: "apply", OperationID: id, App: optionalapps.Slug, Candidate: appDocument(rows(func(r *policy.AppRow) { r.Interfaces = []string{"eth0"} }))}, firewall.CodeAppRowNotOwnAct},
		"only some of the manifest's rows":    {&firewall.Request{Op: "apply", OperationID: id, App: optionalapps.Slug, Candidate: appDocument(optionalapps.FirewallRows()[:1])}, firewall.CodeAppRowNotOwnAct},
		"the rows and one the manifest lacks": {&firewall.Request{Op: "apply", OperationID: id, App: optionalapps.Slug, Candidate: appDocument(append(optionalapps.FirewallRows(), policy.AppRow{App: optionalapps.Slug, Port: "9000/tcp", Interfaces: []string{"*"}}))}, firewall.CodeAppRowNotOwnAct},
	} {
		resp := served.Perform(context.Background(), helperschema.Peer{}, c.req)
		if resp.Result != helperschema.ResultRefused || resp.Code != c.code || opened != 0 {
			t.Errorf("%s: %+v, opened %d times, want refused %s with the owner not reached", name, resp, opened, c.code)
		}
	}
}
