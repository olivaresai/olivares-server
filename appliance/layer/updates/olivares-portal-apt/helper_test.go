// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/olivaresai/olivares/appliance/layer/helpers/helperschema"
	"github.com/olivaresai/olivares/appliance/layer/updates"
)

// peerKernel attests one connection's peer: account, unit, and the controlling terminal's
// device number (0 for none).
type peerKernel struct {
	uid     uint32
	account string
	unit    string
	ttyNr   int
}

func (k peerKernel) PeerCred(int) (int, uint32, error) { return 4242, k.uid, nil }
func (k peerKernel) PeerPidfd(int) (int, error)        { return 9, nil }
func (k peerKernel) PidOf(int) (int, error)            { return 4242, nil }
func (k peerKernel) Cgroup(int) (string, error) {
	return "0::/system.slice/" + k.unit + "\n", nil
}
func (k peerKernel) Stat(int) (string, error) {
	return "4242 (client) S 1 4242 4242 " + strconv.Itoa(k.ttyNr) + " -1 4194560 0 0 0 0", nil
}
func (k peerKernel) AccountOf(uint32) (string, error) { return k.account, nil }
func (k peerKernel) Alive(int) error                  { return nil }
func (k peerKernel) Close(int)                        {}

var portal = peerKernel{uid: 998, account: "olivares-portal", unit: "olivares-portal.service"}

const operationID = "0123456789abcdef0123456789abcdef"

// emptyDirectory is a helper-owned operation directory with no retained plan, as on a fresh image,
// and a native runner that fails the test if the helper reaches for a package program.
func emptyDirectory(t *testing.T) updates.RPM {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return updates.RPM{Root: root, Run: func(_ context.Context, argv []string, _ int64) ([]byte, error) {
		t.Errorf("the helper ran %v", argv)
		return nil, errors.New("not expected")
	}}
}

func TestAptHelper_AdmitsTheAttestedConsoleAndPerformsNothingOnAnEmptyDirectory(t *testing.T) {
	h := helper(emptyDirectory(t))
	serve := func(k peerKernel, args []string, document string) (int, helperschema.Response) {
		var out, log bytes.Buffer
		code := invocationServe(h, k, args, document, &out, &log)
		var response helperschema.Response
		if out.Len() > 0 {
			if err := json.Unmarshal(out.Bytes(), &response); err != nil {
				t.Fatalf("answer %q: %v", out.String(), err)
			}
		}
		return code, response
	}

	// The console's status read reaches the module and, with no retained plan, is refused with the
	// module's own closed code: the console then composes no package task.
	code, response := serve(portal, nil, `{"op":"status","operation_id":"","native_plan":""}`)
	if code != 1 || response.Result != helperschema.ResultRefused || response.Code != helperschema.CodeInputRefused {
		t.Fatalf("status with no plan: exit %d, %+v", code, response)
	}

	update := `{"op":"update","operation_id":"` + operationID + `","native_plan":"` + strings.Repeat("c", 64) + `"}`
	recoverDocument := strings.Replace(update, `"update"`, `"recover"`, 1)
	for name, tc := range map[string]struct {
		k        peerKernel
		args     []string
		document string
		code     string
	}{
		"an SSH root session":                     {peerKernel{uid: 0, account: "root", unit: "sshd.service"}, nil, `{"op":"status"}`, helperschema.CodeNotAdmitted},
		"the tty1 repair console":                 {peerKernel{uid: 0, account: "root", unit: "olivares-repair-console.service", ttyNr: 4<<8 | 1}, nil, update, helperschema.CodeNotAdmitted},
		"the network guard":                       {peerKernel{uid: 997, account: "olivares-net-guard", unit: "olivares-net-guard.service"}, nil, `{"op":"status"}`, helperschema.CodeNotAdmitted},
		"the console's update, no plan retained":  {portal, nil, update, helperschema.CodeInputRefused},
		"the console's recover, no plan retained": {portal, nil, recoverDocument, helperschema.CodeInputRefused},
		"a path in the document":                  {portal, nil, `{"op":"status","path":"/tmp/next.rpm"}`, helperschema.CodeInputRefused},
		"an unknown operation":                    {portal, nil, `{"op":"install"}`, helperschema.CodeInputRefused},
	} {
		t.Run(name, func(t *testing.T) {
			var out, log bytes.Buffer
			if exit := invocationServe(h, tc.k, tc.args, tc.document, &out, &log); exit != 1 || !strings.Contains(out.String(), `"code":"`+tc.code+`"`) {
				t.Fatalf("exit %d, want a refusal %s: %s", exit, tc.code, out.String())
			}
		})
	}

	// An argument is a usage failure before any document is read.
	if code, _ := serve(portal, []string{"--root", "/"}, `{"op":"status"}`); code != 2 {
		t.Fatalf("an argument exited %d, want 2", code)
	}
}

// The program opens the directory systemd creates for it: the unit's StateDirectory is the program's
// directory under /var/lib, private to root.
func TestAptHelper_OpensTheDirectoryItsUnitCreates(t *testing.T) {
	unit, err := os.ReadFile(filepath.Join("..", "units", "olivares-helper-apt@.service"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(unit)
	if want := "\nStateDirectory=" + filepath.Base(stateDirectory) + "\n"; !strings.Contains(text, want) {
		t.Errorf("the unit does not create %s: want the line %q", stateDirectory, strings.TrimSpace(want))
	}
	if filepath.Dir(stateDirectory) != "/var/lib" || !strings.Contains(text, "\nStateDirectoryMode=0700\n") {
		t.Errorf("the state directory %s is not private under /var/lib", stateDirectory)
	}
}
