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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	previousNEVRA = "olv-example-1.0-1.el10.noarch"
	nextNEVRA     = "olv-example-1.1-1.el10.noarch"
)

// native answers the few rpm queries Prepare asks, by the file's name; the host has the previous version.
func native(signed bool) func(context.Context, []string, int64) ([]byte, error) {
	return func(_ context.Context, argv []string, _ int64) ([]byte, error) {
		last := argv[len(argv)-1]
		switch {
		case argv[0] == "/usr/bin/rpmkeys" && !signed:
			return nil, errors.New("unsigned")
		case argv[0] == "/usr/bin/rpmkeys", argv[1] == "-U":
			return nil, nil
		case argv[1] == "-qa":
			return []byte("bash\nolv-example\n"), nil
		case argv[1] == "-q":
			return []byte(previousNEVRA + "\n"), nil
		case strings.Contains(strings.Join(argv, " "), "--provides"):
			return []byte("olv-example = 1.1-1.el10\n"), nil
		case strings.Contains(strings.Join(argv, " "), "OBSOLETENAME"):
			return nil, nil
		case strings.HasSuffix(last, "previous.rpm"):
			return []byte(previousNEVRA + "\n"), nil
		}
		return []byte(nextNEVRA + "\n"), nil
	}
}

func directories(t *testing.T) (state, delivery string) {
	t.Helper()
	state, delivery = t.TempDir(), t.TempDir()
	for _, dir := range []string{state, delivery} {
		if err := os.Chmod(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	artifacts := map[string]map[string]string{"previous": {"Name": "olv-example", "NEVRA": previousNEVRA, "Repository": "baseos"}, "next": {"Name": "olv-example", "NEVRA": nextNEVRA, "Repository": "appstream"}}
	document := map[string]any{"schema": "olivares-package-delivery/v1"}
	for kind, artifact := range artifacts {
		data := []byte("delivered " + kind)
		sum := sha256.Sum256(data)
		artifact["SHA256"] = hex.EncodeToString(sum[:])
		document[kind] = artifact
		if err := os.WriteFile(filepath.Join(delivery, kind+".rpm"), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	data, _ := json.Marshal(document)
	if err := os.WriteFile(filepath.Join(delivery, "delivery.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	return state, delivery
}

func TestRun_RetainsThePlanAndNamesIt(t *testing.T) {
	state, delivery := directories(t)
	var out, diagnostic bytes.Buffer
	if code := run(t.Context(), state, delivery, native(true), &out, &diagnostic); code != 0 || diagnostic.Len() != 0 {
		t.Fatalf("rc=%d %s", code, diagnostic.String())
	}
	if _, err := os.Stat(filepath.Join(state, "plan.json")); err != nil {
		t.Fatal("no plan.json:", err)
	}
	if !strings.Contains(out.String(), previousNEVRA+" to "+nextNEVRA) {
		t.Fatalf("the plan is not named: %q", out.String())
	}
}

func TestRun_SaysWhyItRefusedAndLeavesNoPlan(t *testing.T) {
	state, delivery := directories(t)
	var out, diagnostic bytes.Buffer
	if code := run(t.Context(), state, delivery, native(false), &out, &diagnostic); code != 1 || out.Len() != 0 || !strings.Contains(diagnostic.String(), "artifact_signature_refused") {
		t.Fatalf("rc=%d out=%q diagnostic=%q", code, out.String(), diagnostic.String())
	}
	if entries, _ := os.ReadDir(state); len(entries) != 0 {
		t.Fatal("a refusal left files in the plan directory")
	}
}

func TestRun_AMissingDirectoryIsNamed(t *testing.T) {
	state, _ := directories(t)
	var out, diagnostic bytes.Buffer
	if code := run(t.Context(), state, filepath.Join(state, "absent"), native(true), &out, &diagnostic); code != 1 || !strings.Contains(diagnostic.String(), "delivery directory") {
		t.Fatalf("rc=%d %q", code, diagnostic.String())
	}
}
