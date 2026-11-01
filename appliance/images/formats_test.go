// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package images

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// twoGiB is the exclusive GitHub release asset bound; larger payloads route to R2.
const twoGiB = int64(2) << 30

type formatsDeclaration struct {
	Product string `json:"product"`
	Vendor  string `json:"vendor"`
	Arch    string `json:"arch"`
	Base    struct {
		Distribution string `json:"distribution"`
		Version      string `json:"version"`
		Minor        string `json:"minor"`
	} `json:"base"`
	ReleaseAssetMaxBytes int64  `json:"release_asset_max_bytes"`
	ReleaseAssetLimit    string `json:"release_asset_limit"`
	SourceBundle         map[string]struct {
		Split        bool  `json:"split"`
		SplitPartMax int64 `json:"split_part_max_bytes"`
	} `json:"source_bundle"`
	Artifacts []struct {
		Edition      string `json:"edition"`
		Format       string `json:"format"`
		File         string `json:"file"`
		Script       string `json:"script"`
		Manifest     string `json:"manifest"`
		MaxBytes     int64  `json:"max_bytes"`
		Split        bool   `json:"split"`
		SplitPartMax int64  `json:"split_part_max_bytes"`
		Expected     int64  `json:"expected_bytes_about"`
	} `json:"artifacts"`
}

// formatsPolicy parses the formats declaration, which is written in the JSON subset its
// shell assembly also reads, the way the layer's package manifest is (appliance/layer/base
// /package_test.go): one document, read by the gate and by the program it gates.
func formatsPolicy(t *testing.T) formatsDeclaration {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot, "appliance/images/formats/formats.json"))
	if err != nil {
		t.Fatalf("the recipe declares no formats: %v", err)
	}
	var body bytes.Buffer
	lines := bufio.NewScanner(bytes.NewReader(data))
	for lines.Scan() {
		if !strings.HasPrefix(strings.TrimSpace(lines.Text()), "//") {
			body.WriteString(lines.Text() + "\n")
		}
	}
	var declaration formatsDeclaration
	if err := json.Unmarshal(body.Bytes(), &declaration); err != nil {
		t.Fatalf("the formats declaration is not the JSON its assembly reads: %v", err)
	}
	return declaration
}

// TestFormats_DeclareIsoQcow2Ova — the recipe delivers three formats and no more — the hybrid
// installer ISO, the qcow2 disk and the OVA — to each declared edition: the server edition,
// and the desktop edition the same recipe builds beside it. Each artifact has its assembly
// script, each writes its manifest, and the Taskfile exposes them under one target.
func TestFormats_DeclareIsoQcow2Ova(t *testing.T) {
	declaration := formatsPolicy(t)

	want := "iso qcow2 ova"
	byEdition := map[string][]string{}
	for _, artifact := range declaration.Artifacts {
		byEdition[artifact.Edition] = append(byEdition[artifact.Edition], artifact.Format)
		if artifact.File == "" || artifact.Manifest != artifact.File+".manifest.json" {
			t.Errorf("edition %s format %s does not name its artifact and the manifest beside it: %q %q",
				artifact.Edition, artifact.Format, artifact.File, artifact.Manifest)
		}
		if !strings.Contains(artifact.File, "-"+artifact.Edition+"-") {
			t.Errorf("edition %s's artifact %q does not name its edition", artifact.Edition, artifact.File)
		}
		script := filepath.Join(repoRoot, "appliance/images/formats", artifact.Script)
		info, err := os.Stat(script)
		if err != nil {
			t.Errorf("edition %s format %s has no assembly script: %v", artifact.Edition, artifact.Format, err)
			continue
		}
		if info.Mode().Perm()&0o111 == 0 {
			t.Errorf("edition %s format %s cannot run its assembly script: mode %v", artifact.Edition,
				artifact.Format, info.Mode().Perm())
		}
	}
	if len(byEdition) != 2 || strings.Join(byEdition["server"], " ") != want ||
		strings.Join(byEdition["desktop"], " ") != want {
		t.Fatalf("each declared edition (found %d) delivers exactly %q; the declaration holds %v",
			len(byEdition), want, byEdition)
	}

	// The OVA is a vmdk inside an OVF envelope with its own manifest: the format the design
	// names for the hypervisors that import one file.
	ova := read(t, "appliance/images/formats/ova.sh")
	for _, required := range []string{"streamOptimized", ".ovf", ".mf", "tar"} {
		if !strings.Contains(ova, required) {
			t.Errorf("the OVA assembly does not use %q", required)
		}
	}

	taskfile := read(t, "appliance/Taskfile.yml")
	for _, required := range []string{
		"appliance:build:",
		"appliance:boot:",
		"EDITION",
		"ARCH",
		"FORMAT",
	} {
		if !strings.Contains(taskfile, required) {
			t.Errorf("the Taskfile does not expose the recipe: %q is missing", required)
		}
	}
}

// TestRelease_SourceBundleDeclaresItsSplitPerEdition — every declared edition says whether its corresponding source bundle
// is written as parts (release_outputs.py reads it); a split edition's part fits a GitHub release asset, and an edition
// that is not split carries no part size.
func TestRelease_SourceBundleDeclaresItsSplitPerEdition(t *testing.T) {
	declaration := formatsPolicy(t)

	editions := map[string]bool{}
	for _, artifact := range declaration.Artifacts {
		editions[artifact.Edition] = true
	}
	for edition := range editions {
		if _, ok := declaration.SourceBundle[edition]; !ok {
			t.Errorf("edition %s declares no source bundle", edition)
		}
	}
	for edition, bundle := range declaration.SourceBundle {
		switch {
		case !editions[edition]:
			t.Errorf("the source bundle names edition %s, which delivers no artifact", edition)
		case bundle.Split && (bundle.SplitPartMax <= 0 || bundle.SplitPartMax >= twoGiB):
			t.Errorf("edition %s's source bundle is split into parts of %d bytes, which do not fit a release asset below %d",
				edition, bundle.SplitPartMax, twoGiB)
		case !bundle.Split && bundle.SplitPartMax != 0:
			t.Errorf("edition %s's source bundle is not split but declares parts of %d bytes", edition, bundle.SplitPartMax)
		}
	}
	if declaration.SourceBundle["server"].Split {
		t.Error("the server source bundle is one file below the single-PUT bound and is not split")
	}
	if !declaration.SourceBundle["desktop"].Split {
		t.Error("the desktop source bundle is 5363483534 bytes in the 2026-10 lab run, over the single-PUT bound: it is split")
	}
}

// TestRelease_EachArtifactFitsItsTransport — assembly allows the R2 payload range while
// the publisher keeps GitHub's smaller asset cutoff.
func TestRelease_EachArtifactFitsItsTransport(t *testing.T) {
	declaration := formatsPolicy(t)

	if declaration.ReleaseAssetMaxBytes != twoGiB {
		t.Errorf("the declared release ceiling is %d bytes, the measured limit is %d", declaration.ReleaseAssetMaxBytes, twoGiB)
	}
	if !strings.Contains(strings.ToLower(declaration.ReleaseAssetLimit), "release") {
		t.Errorf("the ceiling does not say where it comes from: %q", declaration.ReleaseAssetLimit)
	}

	for _, artifact := range declaration.Artifacts {
		switch {
		case artifact.Split:
			if artifact.SplitPartMax <= 0 || artifact.SplitPartMax > twoGiB {
				t.Errorf("format %s is declared split but no part fits the ceiling: %d", artifact.Format, artifact.SplitPartMax)
			}
		case artifact.MaxBytes <= twoGiB || artifact.MaxBytes >= 5363466240:
			t.Errorf("format %s declares a ceiling of %d bytes, which does not fit the R2 transport bound of %d", artifact.Format, artifact.MaxBytes, int64(5363466240))
		}
		if artifact.Expected <= 0 || artifact.Expected > artifact.MaxBytes {
			t.Errorf("format %s does not predict a size under its own ceiling: %d of %d", artifact.Format, artifact.Expected, artifact.MaxBytes)
		}
		script := read(t, filepath.Join("appliance/images/formats", artifact.Script))
		if !strings.Contains(script, "enforce_release_ceiling") {
			t.Errorf("format %s does not enforce the ceiling it declares", artifact.Format)
		}
	}

	common := read(t, "appliance/images/formats/common.sh")
	if !strings.Contains(common, "enforce_release_ceiling()") {
		t.Error("the shared assembly does not define the ceiling gate")
	}
	if !strings.Contains(common, "max_bytes") {
		t.Error("the ceiling gate does not read the declared ceiling")
	}
}
