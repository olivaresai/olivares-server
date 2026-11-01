// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/olivaresai/olivares/appliance/layer/helpers/helperschema"
	"github.com/olivaresai/olivares/appliance/layer/helpers/invocation"
	"github.com/olivaresai/olivares/appliance/layer/optionalapps"
)

// kernel describes one peer to the seam: the Appliance Console's service, or another process.
type kernel struct {
	uid    uint32
	cgroup string
}

func (k kernel) PeerCred(int) (int, uint32, error) { return 77, k.uid, nil }
func (k kernel) PeerPidfd(int) (int, error)        { return 9, nil }
func (k kernel) PidOf(int) (int, error)            { return 77, nil }
func (k kernel) Cgroup(int) (string, error)        { return k.cgroup, nil }
func (k kernel) Stat(int) (string, error) {
	return "77 (olivares-portal) S 1 77 77 0 77 4194560 0 0 0 0 0 0 0 0 20 0 1 0 1 0 0\n", nil
}
func (k kernel) AccountOf(uid uint32) (string, error) {
	if uid == 0 {
		return "root", nil
	}
	return map[uint32]string{998: "olivares-portal", 1000: "operator"}[uid], nil
}
func (k kernel) Alive(int) error { return nil }
func (k kernel) Close(int)       {}

var (
	portal   = kernel{uid: 998, cgroup: "0::/system.slice/olivares-portal.service\n"}
	operator = kernel{uid: 1000, cgroup: "0::/system.slice/olivares-other.service\n"}
)

// appDir is a private app directory, as the unit's StateDirectory provides it.
func appDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// manifestDigest is the digest of the manifest file the module embeds.
func manifestDigest(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "nginx-proxy-manager.json"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// serve runs one connection through the apps helper over a Docker whose inventories are empty:
// the app is not installed. It returns the exit code, the answer and every Docker argument vector.
func serve(t *testing.T, k invocation.Kernel, document string) (int, helperschema.Response, [][]string) {
	t.Helper()
	dir := appDir(t)
	var calls [][]string
	open := func() (optionalapps.Compose, error) {
		root, err := os.OpenRoot(dir)
		if err != nil {
			return optionalapps.Compose{}, err
		}
		return optionalapps.Compose{Root: root,
			Run: func(_ context.Context, argv []string, _ int64) ([]byte, error) {
				calls = append(calls, argv)
				return nil, nil
			},
			PortAvailable: func(context.Context, string) error { return nil }}, nil
	}
	var out, log bytes.Buffer
	code := invocation.Serve(context.Background(), helper(open), k, nil, 3, strings.NewReader(document), &out, &log)
	var response helperschema.Response
	if out.Len() > 0 {
		if err := json.Unmarshal(out.Bytes(), &response); err != nil {
			t.Fatalf("the answer is not one document: %q", out.String())
		}
	}
	return code, response, calls
}

func statusDocument(t *testing.T) string {
	return `{"op":"status","manifest":"` + manifestDigest(t) + `"}`
}

// actDocument is the document the Appliance Console sends for op, written out as the helper reads
// it: the operation id, the manifest it expects and the state it measured before asking.
func actDocument(t *testing.T, op string) string {
	t.Helper()
	installed, running := op != "install", op == "stop"
	container := ""
	if installed {
		container = strings.Repeat("c", 64)
	}
	return fmt.Sprintf(`{"op":%q,"operation_id":%q,"manifest":%q,"expected":{"container_id":%q,"installed":%t,"running":%t}}`,
		op, strings.Repeat("ab", 16), manifestDigest(t), container, installed, running)
}

// installDocument is the document for install.
func installDocument(t *testing.T) string { return actDocument(t, "install") }

func TestAppsHelper_AnswersTheMeasuredStateToTheApplianceConsole(t *testing.T) {
	code, response, calls := serve(t, portal, statusDocument(t))
	if code != invocation.ExitDone || response.Result != helperschema.ResultAnswered {
		t.Fatalf("status: exit %d, %+v", code, response)
	}
	var status struct {
		Manifest string `json:"manifest"`
		State    struct {
			Installed bool `json:"installed"`
			Running   bool `json:"running"`
		} `json:"state"`
	}
	if err := json.Unmarshal(response.Bundle, &status); err != nil || status.Manifest != manifestDigest(t) || status.State.Installed || status.State.Running {
		t.Fatalf("status bundle %s (%v), want the manifest digest and an app that is not installed", response.Bundle, err)
	}
	if len(calls) == 0 {
		t.Fatal("status measured nothing from Docker")
	}
	for _, argv := range calls {
		if len(argv) < 6 || argv[0] != "/usr/bin/docker" || argv[2] != "unix:///var/run/docker.sock" || argv[3] != "--config" {
			t.Errorf("Docker was asked with %v, want the fixed client, the local socket and the helper's own config", argv)
		}
		if argv[5] != "container" && argv[5] != "compose" {
			t.Errorf("status ran a Docker %s command; a read lists containers only", argv[5])
		}
		for _, arg := range argv[5:] {
			if arg == "up" || arg == "down" || arg == "pull" || arg == "start" || arg == "stop" {
				t.Errorf("status ran %v", argv)
			}
		}
	}
}

// With the guest proof recorded, the helper admits the console's lifecycle acts and they reach Docker through
// the executor: none is refused as unproven or as not admitted. The act itself is measured by the executor's
// own tests, and the proof by appliance/test/guestproof.
func TestAppsHelper_ALifecycleActFromTheApplianceConsoleReachesTheExecutor(t *testing.T) {
	for _, op := range []string{"install", "start", "stop", "uninstall"} {
		_, response, calls := serve(t, portal, actDocument(t, op))
		if response.Code == helperschema.CodePidfdUnproven || response.Code == helperschema.CodeNotAdmitted {
			t.Errorf("%s: %+v, want it admitted and past the seam", op, response)
		}
		if len(calls) == 0 {
			t.Errorf("%s: the act never reached Docker", op)
		}
	}
}

func TestAppsHelper_AdmitsTheApplianceConsoleAlone(t *testing.T) {
	for name, k := range map[string]kernel{"an operator's account in another unit": operator, "root in another unit": {uid: 0, cgroup: "0::/system.slice/olivares-other.service\n"}} {
		for _, document := range []string{statusDocument(t), installDocument(t)} {
			code, response, calls := serve(t, k, document)
			if code != invocation.ExitRefused || response.Code != helperschema.CodeNotAdmitted || len(calls) != 0 {
				t.Errorf("%s: exit %d, %+v, Docker %v, want refused %s and no Docker call", name, code, response, calls, helperschema.CodeNotAdmitted)
			}
		}
	}
}

func TestAppsHelper_RefusesADocumentThatNamesWhatTheModuleFixes(t *testing.T) {
	for name, document := range map[string]string{
		"an image":         `{"op":"status","manifest":"` + manifestDigest(t) + `","image":"docker.io/evil/x"}`,
		"a folder":         `{"op":"status","manifest":"` + manifestDigest(t) + `","path":"/"}`,
		"another app":      `{"op":"status","manifest":"` + manifestDigest(t) + `","app":"x"}`,
		"another manifest": `{"op":"status","manifest":"` + strings.Repeat("0", 64) + `"}`,
		"an unknown op":    `{"op":"exec","manifest":"` + manifestDigest(t) + `"}`,
	} {
		code, response, calls := serve(t, portal, document)
		if code != invocation.ExitRefused || response.Result != helperschema.ResultRefused || len(calls) != 0 {
			t.Errorf("%s: exit %d, %+v, Docker %v, want a refusal that asks Docker nothing", name, code, response, calls)
		}
	}
}

func TestAppsHelper_FailsWithoutAnAppDirectoryAndTouchesNothing(t *testing.T) {
	open := func() (optionalapps.Compose, error) { return optionalapps.Compose{}, errors.New("no directory") }
	var out, log bytes.Buffer
	code := invocation.Serve(context.Background(), helper(open), portal, nil, 3, strings.NewReader(statusDocument(t)), &out, &log)
	var response helperschema.Response
	if err := json.Unmarshal(out.Bytes(), &response); err != nil || code != invocation.ExitFailure || response.Result != helperschema.ResultFailed {
		t.Fatalf("exit %d, %q (%v), want a failed answer", code, out.String(), err)
	}
}
