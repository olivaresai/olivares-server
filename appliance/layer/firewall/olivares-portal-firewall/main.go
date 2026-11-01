// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

// olivares-portal-firewall is the host firewall's one owner program, in three fixed modes.
//
// With no argument it serves one connection of olivares-helper-firewall.socket
// (/run/olivares-helpers/firewall.sock, Accept=yes), as root with CAP_NET_ADMIN alone: it reads
// one document, {"op", "operation_id", "candidate", "app", "revert_after_s"}, takes no path,
// admits the invoker the kernel attests for the connection, and answers status, apply, confirm
// or revert through the owner. The acts reach it from the Appliance Console only, which composes
// the product's act authorization for the network verb (hostops.Acts: current authority, the
// operator's confirmation of the plan and the audit record) around the one act it adopts,
// firewall.app-row, whose task asks this helper for apply and confirm; the repair console on tty1
// may also revert a window. Without the console's composition an act is refused with
// act_not_adopted and the owner is not reached.
//
// With --boot-load (olivares-firewall.service, before network-pre.target) it loads the last
// confirmed policy, taking the network lock once the network runtime has created it. With none confirmed, it confirms the first one only once first boot has
// completed generate-product-config, so the published console selection is final: that
// selection, the SSH port sshd reports and the DHCPv6 client links. Earlier it loads nothing.
//
// With --guard (olivares-firewall-guard.service) it reverts every unconfirmed window at its
// deadline, once a second.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"syscall"
	"time"

	"github.com/olivaresai/olivares/appliance/layer/base"
	"github.com/olivaresai/olivares/appliance/layer/firewall"
	"github.com/olivaresai/olivares/appliance/layer/firewall/policy"
	"github.com/olivaresai/olivares/appliance/layer/helpers/helperschema"
	"github.com/olivaresai/olivares/appliance/layer/helpers/invocation"
	"github.com/olivaresai/olivares/appliance/layer/netguard"
	"github.com/olivaresai/olivares/appliance/layer/optionalapps"
	"github.com/olivaresai/olivares/appliance/layer/portal"
)

// actAdopted records whether the product's act authorization for the network verb is composed
// with this helper: its consumer, which verifies the act the product issued for this operation
// and journals it. The Appliance Console's firewall.app-row task is that consumer (localsession
// composes it around hostops.Acts), and it is the only sender of apply and confirm, so the
// constant is true. Were it false, apply, confirm and revert would be refused with
// act_not_adopted, whoever asks, and the owner not reached. status is a read and is unaffected.
// The boot modes are the owner's own units, not acts.
const actAdopted = true

type runMode int

const (
	modeServe runMode = iota
	modeBootLoad
	modeGuard
)

// modeOf selects the mode: exactly --boot-load or exactly --guard; anything else is the helper,
// whose seam refuses every argument but --help.
func modeOf(args []string) runMode {
	if len(args) == 1 {
		switch args[0] {
		case "--boot-load":
			return modeBootLoad
		case "--guard":
			return modeGuard
		}
	}
	return modeServe
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	var code int
	switch modeOf(os.Args[1:]) {
	case modeBootLoad:
		code = bootLoad(ctx, os.Stderr)
	case modeGuard:
		code = guard(ctx, os.Stderr)
	default:
		code = invocation.Serve(ctx, helperWith(actAdopted, optionalapps.FirewallApps(), ownerOnHost), invocation.Linux{}, os.Args[1:], 0, os.Stdin, os.Stdout, os.Stderr)
	}
	stop()
	os.Exit(code)
}

// ownRowsOnly keeps the one adopted act what the console composed: an application's own act, whose rows
// are the ones its manifest gives, or none. The helper checks it itself, so that a console process that
// asks for a whole policy, or for a port or a bridge of its choosing, reaches no table with no act,
// confirmation or audit record behind it. A refusal is returned, or nil when the document is that act.
func ownRowsOnly(req *firewall.Request, apps map[string][]policy.AppRow) *helperschema.Response {
	want, known := apps[req.App]
	if req.App == "" || !known || req.Candidate == nil {
		return &helperschema.Response{Result: helperschema.ResultRefused, Code: firewall.CodeActNotAdopted,
			Detail: "only an installed application's own act is adopted; nothing was asked"}
	}
	var rows []string
	for _, row := range req.Candidate.Apps {
		if row.App == req.App {
			rows = append(rows, rowKey(row))
		}
	}
	var table []string
	for _, row := range want {
		table = append(table, rowKey(row))
	}
	slices.Sort(rows)
	slices.Sort(table)
	if len(rows) != 0 && !slices.Equal(rows, table) {
		return &helperschema.Response{Result: helperschema.ResultRefused, Code: firewall.CodeAppRowNotOwnAct,
			Detail: "the application's rows are not the ones its manifest gives; nothing was asked"}
	}
	return nil
}

// rowKey names a row by everything the policy renders from it.
func rowKey(r policy.AppRow) string {
	interfaces := slices.Sorted(slices.Values(r.Interfaces))
	return fmt.Sprintf("%s|%s|%q|%s", r.App, r.Port, interfaces, r.Bridge)
}

// helperWith is the helper with the adoption given, so that both sides of it can be measured. apps is
// each application's rows as its manifest gives them: an apply is accepted only as one application's
// own act with exactly those rows, or with none (their removal).
func helperWith(adopted bool, apps map[string][]policy.AppRow, open func() (*firewall.Owner, error)) invocation.Helper {
	return invocation.Helper{
		Name:       firewall.HelperName,
		Rules:      firewall.Rules(),
		NewRequest: func() helperschema.Request { return &firewall.Request{} },
		Perform: func(ctx context.Context, _ helperschema.Peer, request helperschema.Request) helperschema.Response {
			req, ok := request.(*firewall.Request)
			if !ok {
				return helperschema.Response{Result: helperschema.ResultRefused, Code: helperschema.CodeInputRefused, Detail: "not a document of this helper"}
			}
			if req.Op != firewall.OpStatus && !adopted {
				return helperschema.Response{Result: helperschema.ResultRefused, Code: firewall.CodeActNotAdopted,
					Detail: "the act authorization for the network verb is not composed with this helper; nothing was asked"}
			}
			if req.Op == firewall.OpApply {
				if refused := ownRowsOnly(req, apps); refused != nil {
					return *refused
				}
			}
			o, err := open()
			if err != nil {
				return helperschema.Response{Result: helperschema.ResultFailed, Code: helperschema.CodeEffectFailed,
					Detail: "the firewall owner's lock or clock is unavailable; nothing was asked"}
			}
			return firewall.Answer(ctx, o, req)
		},
	}
}

// ownerOnHost is the owner over this host: its state, nft, the network lock the NetworkManager
// plane's initializer creates and this boot's clock.
func ownerOnHost() (*firewall.Owner, error) { return owner(false) }

// owner is ownerOnHost. early is the boot load's: before the network runtime's initializer has
// created the lock's directory, no other owner can hold the lock, and the load takes none.
func owner(early bool) (*firewall.Owner, error) {
	var lock firewall.Lock
	if _, err := os.Lstat(filepath.Dir(netguard.NetworkLockPath)); early && errors.Is(err, os.ErrNotExist) {
		lock = beforeNetworkRuntime{}
	} else {
		fileLock, err := netguard.NewFileLock()
		if err != nil {
			return nil, err
		}
		lock = fileLock
	}
	clock, err := netguard.NewBootClock()
	if err != nil {
		return nil, err
	}
	return &firewall.Owner{StateDir: firewall.StateDir, RunDir: firewall.RunDir, Kernel: firewall.NFT{}, Lock: lock, Clock: clock}, nil
}

// beforeNetworkRuntime is the network lock before it exists in this boot: nothing holds it.
type beforeNetworkRuntime struct{}

func (beforeNetworkRuntime) Acquire() (func(), error) { return func() {}, nil }

// lockAttempts bounds how long a boot load waits, between attempts and never while holding the
// lock, for another holder of the network lock.
const lockAttempts = 20

func bootLoad(ctx context.Context, log io.Writer) int {
	o, err := owner(true)
	if err != nil {
		_, _ = fmt.Fprintf(log, "firewall boot load: the owner cannot start: %v\n", err)
		return 2
	}
	return bootLoadWith(ctx, log, o, initialPolicy)
}

func bootLoadWith(ctx context.Context, log io.Writer, o *firewall.Owner,
	initialPolicy func(context.Context, io.Writer) (policy.Document, bool, string)) int {
	logf := func(format string, a ...any) { _, _ = fmt.Fprintf(log, "firewall boot load: "+format+"\n", a...) }
	var m firewall.Measurement
	var err error
	for attempt := 1; ; attempt++ {
		m, err = o.BootLoad(ctx)
		if code(err) != firewall.CodeTargetLocked || attempt == lockAttempts {
			break
		}
		select {
		case <-ctx.Done():
			return 2
		case <-time.After(250 * time.Millisecond):
		}
	}
	if code(err) == firewall.CodeNoConfirmedPolicy {
		initial, final, reason := initialPolicy(ctx, log)
		if !final {
			logf("%s; nothing is loaded and no service is exposed beyond loopback", reason)
			return 0
		}
		if reason != "" {
			logf("%s; nothing is loaded and no service is exposed beyond loopback", reason)
			return 1
		}
		m, err = o.Install(ctx, initial)
	}
	if err != nil {
		var diagnostic interface{ Diagnostic() string }
		if errors.As(err, &diagnostic) && diagnostic.Diagnostic() != "" {
			logf("%s", diagnostic.Diagnostic())
		}
		logf("%v", err)
		return 1
	}
	logf("loaded and measured %s in boot %s", m.PolicyDigest, m.BootID)
	return 0
}

// initialPolicy derives the first confirmed policy. final is false while first boot has not
// completed generate-product-config, whose published selection the console row follows; reason
// is then why, and also why a final selection gave no policy.
func initialPolicy(ctx context.Context, log io.Writer) (initial policy.Document, final bool, reason string) {
	record, found, err := base.Store{Dir: base.StateDir}.Load()
	if err != nil || !found || !slices.ContainsFunc(record.Completed, func(c base.Completed) bool { return c.Stage == base.StageProductConfig }) {
		return policy.Document{}, false, "no policy was confirmed and first boot has not published the console selection yet"
	}
	selection, why := portal.ReadSelection(portal.SelectionFile)
	if why != "" {
		return policy.Document{}, true, why
	}
	port, err := firewall.SSHPort(ctx, firewall.Exec)
	if err != nil {
		var diagnostic interface{ Diagnostic() string }
		if errors.As(err, &diagnostic) {
			_, _ = fmt.Fprintln(log, "firewall boot load:", diagnostic.Diagnostic())
		}
		return policy.Document{}, true, "the operator's SSH port is unmeasured: " + err.Error()
	}
	links, err := firewall.ClientInterfaces(firewall.SysClassNet)
	if err != nil {
		return policy.Document{}, true, "the DHCPv6 client links are unmeasured: " + err.Error()
	}
	enabled := selection.Enabled != nil && *selection.Enabled
	return firewall.Initial(firewall.Selection{Enabled: enabled, Listen: selection.Listen, ManagementInterfaces: selection.ManagementInterfaces}, port, links), true, ""
}

func guard(ctx context.Context, log io.Writer) int {
	o, err := ownerOnHost()
	if err != nil {
		_, _ = fmt.Fprintf(log, "firewall guard: the owner cannot start: %v\n", err)
		return 2
	}
	o.Guard(ctx, time.Second, func(closed []firewall.Window, err error) {
		for _, w := range closed {
			_, _ = fmt.Fprintf(log, "firewall guard: window %s %s (%s), operation_id %s\n", w.CandidateDigest, w.State, w.Reason, w.OperationID)
		}
		if err != nil {
			_, _ = fmt.Fprintf(log, "firewall guard: %v\n", err)
		}
	})
	return 0
}

// code is a refusal's closed code, or "".
func code(err error) string {
	var refusal *firewall.Refusal
	if errors.As(err, &refusal) {
		return refusal.Code
	}
	return ""
}
