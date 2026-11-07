// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package base

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

const repoRoot = "../../.."

type nfpmContent struct {
	Src      string `json:"src"`
	Dst      string `json:"dst"`
	Type     string `json:"type"`
	Packager string `json:"packager"`
	FileInfo struct {
		Mode uint32 `json:"mode"`
	} `json:"file_info"`
}

// readManifest parses the nfpm document after its leading comment lines. The document is
// the JSON subset of YAML, so this is the data nfpm reads.
func readManifest(t *testing.T) (manifest struct {
	Name       string        `json:"name"`
	Recommends []string      `json:"recommends"`
	Depends    []string      `json:"depends"`
	Contents   []nfpmContent `json:"contents"`
	Scripts    struct {
		Postinstall string `json:"postinstall"`
		Preremove   string `json:"preremove"`
		Postremove  string `json:"postremove"`
	} `json:"scripts"`
}) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot, "packaging/nfpm/olivares-appliance-base.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	lines := bufio.NewScanner(bytes.NewReader(data))
	for lines.Scan() {
		if !strings.HasPrefix(lines.Text(), "#") {
			body.WriteString(lines.Text() + "\n")
		}
	}
	if err := json.Unmarshal(body.Bytes(), &manifest); err != nil {
		t.Fatalf("the manifest is not the JSON subset this test and nfpm share: %v", err)
	}
	return manifest
}

// productOwned lists the paths the product's package installs (every nfpm dst in
// packaging/nfpm/packages.json) and those its postinstall creates.
func productOwned(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot, "packaging/nfpm/packages.json"))
	if err != nil {
		t.Fatal(err)
	}
	owned := []string{"/usr/bin/olivares", "/etc/olivares", "/var/lib/olivares", "/usr/lib/olivares"}
	var recipes struct {
		Nfpms []struct {
			Contents []nfpmContent `json:"contents"`
		} `json:"nfpms"`
	}
	if err := json.Unmarshal(data, &recipes); err != nil {
		t.Fatal(err)
	}
	if len(recipes.Nfpms) != 2 {
		t.Fatalf("native recipe inventory: got %d, want 2", len(recipes.Nfpms))
	}
	for _, recipe := range recipes.Nfpms {
		for _, content := range recipe.Contents {
			owned = append(owned, content.Dst)
		}
	}
	return owned
}

func TestPackage_ProductDevelopmentRPMRequiresScriptletInterpreter(t *testing.T) {
	raw := readRepo(t, "appliance/images/kiwi/product-dev.nfpm.yaml")
	raw = raw[strings.Index(raw, "{"):]
	var manifest struct {
		Overrides map[string]struct {
			Depends []string `json:"depends"`
		} `json:"overrides"`
	}
	if err := json.Unmarshal([]byte(raw), &manifest); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(manifest.Overrides["rpm"].Depends, "/bin/sh") {
		t.Fatal("the appliance development RPM may run its postinstall before bash is installed")
	}
}

func TestPackage_NativeDebDeclaresApparmorForPostinstall(t *testing.T) {
	var recipes struct {
		Nfpms []struct {
			ID        string `json:"id"`
			Overrides map[string]struct {
				Depends []string `json:"depends"`
			} `json:"overrides"`
		} `json:"nfpms"`
	}
	if err := json.Unmarshal([]byte(readRepo(t, "packaging/nfpm/packages.json")), &recipes); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, recipe := range recipes.Nfpms {
		if recipe.ID != "olivares-nfpm" {
			continue
		}
		found = true
		if !slices.Contains(recipe.Overrides["deb"].Depends, "apparmor") {
			t.Fatal("the deb postinst refuses without apparmor_parser: declare apparmor as a deb dependency")
		}
		for _, format := range []string{"rpm", "apk"} {
			if slices.Contains(recipe.Overrides[format].Depends, "apparmor") {
				t.Fatalf("the %s package declares apparmor; only the deb postinst requires it", format)
			}
		}
	}
	if !found {
		t.Fatal("packages.json has no olivares-nfpm recipe")
	}
}

func TestPackage_ManifestInstallsTheUnitAndBinariesAndOwnsNoProductFile(t *testing.T) {
	manifest := readManifest(t)
	if manifest.Name != "olivares-appliance-base" || len(manifest.Depends) != 0 {
		t.Fatalf("package %q depends on %v", manifest.Name, manifest.Depends)
	}
	want := map[string]struct {
		mode uint32
		typ  string
	}{
		"/usr/bin/appliance-firstboot":                                           {0o755, ""},
		"/usr/bin/appliance-answers":                                             {0o755, ""},
		"/usr/lib/systemd/system/olivares-appliance-firstboot.service":           {0o644, ""},
		"/usr/lib/systemd/system/olivares-appliance-readiness.service":           {0o644, ""},
		"/usr/lib/systemd/system/olivares-console-certificate.service":           {0o644, ""},
		"/usr/lib/systemd/system/olivares.service.d/50-console-certificate.conf": {0o644, ""},
		"/etc/issue.d/olivares-appliance.issue":                                  {0o644, "config|noreplace"},
		"/etc/profile.d/olivares-shell.sh":                                       {0o644, "config|noreplace"},
		StateDir:                                                                 {0o700, "dir"},
	}
	installed := map[string]nfpmContent{}
	for _, c := range manifest.Contents {
		installed[c.Dst] = c
		if c.Src != "" && !strings.HasPrefix(c.Src, "bin/") {
			if _, err := os.Stat(filepath.Join(repoRoot, c.Src)); err != nil {
				t.Fatalf("%s installs a missing source: %v", c.Dst, err)
			}
		}
	}
	for dst, w := range want {
		c, ok := installed[dst]
		if !ok || c.FileInfo.Mode != w.mode || c.Type != w.typ {
			t.Fatalf("%s: installed %+v, want mode %o type %q", dst, c, w.mode, w.typ)
		}
	}
	for _, script := range []string{manifest.Scripts.Postinstall, manifest.Scripts.Preremove} {
		if _, err := os.Stat(filepath.Join(repoRoot, script)); script == "" || err != nil {
			t.Fatalf("maintainer script %q: %v", script, err)
		}
	}

	unit, err := os.ReadFile(filepath.Join(repoRoot, installed["/usr/lib/systemd/system/olivares-appliance-firstboot.service"].Src))
	if err != nil {
		t.Fatal(err)
	}
	for _, directive := range []string{
		"ConditionPathExists=!" + filepath.Join(StateDir, readyFile),
		"ExecStart=/usr/bin/appliance-firstboot apply",
		"StateDirectory=olivares-appliance",
		"ImportCredential=olivares.appliance.answers",
	} {
		if !strings.Contains(string(unit), "\n"+directive+"\n") {
			t.Fatalf("the first-boot unit lacks %q", directive)
		}
	}

	owned := productOwned(t)
	if !strings.Contains(strings.Join(owned, "\n"), "/usr/lib/systemd/system/olivares.service") {
		t.Fatalf("the product's package paths were not read: %v", owned)
	}
	for dst := range installed {
		for _, p := range owned {
			if dst == p || strings.HasPrefix(dst, p+"/") || strings.HasPrefix(p, dst+"/") {
				t.Fatalf("%s overlaps the product package's %s", dst, p)
			}
		}
	}
}

// recipeContents returns the contents of each nfpm recipe in a document: one for a single
// recipe (the JSON subset of YAML after its comment lines), one per entry of "nfpms".
func recipeContents(t *testing.T, path string) [][]nfpmContent {
	t.Helper()
	var body strings.Builder
	for line := range strings.SplitSeq(readRepo(t, path), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "#") {
			body.WriteString(line + "\n")
		}
	}
	var document struct {
		Contents []nfpmContent `json:"contents"`
		Nfpms    []struct {
			Contents []nfpmContent `json:"contents"`
		} `json:"nfpms"`
	}
	if err := json.Unmarshal([]byte(body.String()), &document); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	if len(document.Nfpms) == 0 {
		return [][]nfpmContent{document.Contents}
	}
	var recipes [][]nfpmContent
	for _, r := range document.Nfpms {
		recipes = append(recipes, r.Contents)
	}
	return recipes
}

func TestPackage_SessionImageShipsWithItsContainerfile(t *testing.T) {
	// session-image builds from the recipe directory; an image whose packages carry the
	// command without the recipe fails its build at the FROM check.
	const command, recipe = "/usr/libexec/olivares/session-image", "/usr/share/olivares/session-image/Containerfile"
	const source = "packaging/container/session/Containerfile"
	base := recipeContents(t, "packaging/nfpm/olivares-appliance-base.yaml")[0]
	if !slices.ContainsFunc(base, func(c nfpmContent) bool { return c.Dst == command }) {
		t.Fatalf("the base package no longer ships %s; update this check", command)
	}
	// An appliance installs the base package with the product package: the development
	// package until the release builds the image, the release package after.
	for _, product := range []string{"appliance/images/kiwi/product-dev.nfpm.yaml", "packaging/nfpm/packages.json"} {
		for i, contents := range recipeContents(t, product) {
			set := append(slices.Clone(base), contents...)
			at := slices.IndexFunc(set, func(c nfpmContent) bool { return c.Dst == recipe })
			if at < 0 {
				t.Fatalf("%s recipe %d with the base package ships %s without %s", product, i, command, recipe)
			}
			if set[at].Src != source || set[at].Packager != "" {
				t.Fatalf("%s recipe %d: %s from %+v, want %s for every packager", product, i, recipe, set[at], source)
			}
		}
	}
}

func TestPackage_PostinstallHelpersAreShippedInPackagesAndFixtureImages(t *testing.T) {
	const postinstall = "packaging/nfpm/postinstall.sh"
	// Absolute shell-script paths in the maintainer script are package payload; the fixture
	// images install the product from its development package, so they get them the same way.
	var helpers []string
	paths := regexp.MustCompile(`(?:^|[[:space:]"'])(/[a-zA-Z0-9_./-]+\.sh)(?:[[:space:]"']|$)`)
	for line := range strings.SplitSeq(readRepo(t, postinstall), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "#") {
			for _, match := range paths.FindAllStringSubmatch(line, -1) {
				path := match[1]
				if !slices.Contains(helpers, path) {
					helpers = append(helpers, path)
				}
			}
		}
	}
	if len(helpers) == 0 {
		t.Fatal("no postinstall helper paths found")
	}
	type recipe struct {
		Name     string            `json:"name"`
		ID       string            `json:"id"`
		Formats  []string          `json:"formats"`
		Contents []nfpmContent     `json:"contents"`
		Scripts  map[string]string `json:"scripts"`
	}
	var configs []string
	for _, pattern := range []string{"*.json", "*.yaml"} {
		files, err := filepath.Glob(filepath.Join(repoRoot, "packaging/nfpm", pattern))
		if err != nil {
			t.Fatal(err)
		}
		configs = append(configs, files...)
	}
	configs = append(configs, filepath.Join(repoRoot, "appliance/images/kiwi/product-dev.nfpm.yaml"))
	checked := 0
	for _, config := range configs {
		data, err := os.ReadFile(config)
		if err != nil {
			t.Fatal(err)
		}
		var body strings.Builder
		for line := range strings.SplitSeq(string(data), "\n") {
			if !strings.HasPrefix(strings.TrimSpace(line), "#") {
				body.WriteString(line + "\n")
			}
		}
		var document struct {
			recipe
			Nfpms []recipe `json:"nfpms"`
		}
		if err := json.Unmarshal([]byte(body.String()), &document); err != nil {
			t.Fatalf("%s: %v", config, err)
		}
		recipes := document.Nfpms
		if len(recipes) == 0 {
			recipes = []recipe{document.recipe}
		}
		for _, r := range recipes {
			if r.Scripts["postinstall"] != postinstall {
				continue
			}
			checked++
			if len(r.Formats) == 0 {
				r.Formats = []string{"deb", "rpm"}
			}
			for _, helper := range helpers {
				for _, format := range r.Formats {
					found := false
					for _, content := range r.Contents {
						if content.Dst == helper && (content.Packager == "" || content.Packager == format) {
							found = content.Type == "" && content.FileInfo.Mode == 0o755 && content.Src != ""
							if found {
								readRepo(t, content.Src)
							}
							break
						}
					}
					if !found {
						t.Errorf("%s %s %s: postinstall helper %s is not shipped 0755", config, r.ID, format, helper)
					}
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no package uses the product postinstall script")
	}
	// The workflow is the composed build's file; the composed build asserts it is present.
	if _, err := os.Stat(filepath.Join(repoRoot, ".github/workflows/appliance-a1.yml")); errors.Is(err, fs.ErrNotExist) {
		t.Skip("the image workflow belongs to the composed build")
	} else if err != nil {
		t.Fatal(err)
	}
	workflow := readRepo(t, ".github/workflows/appliance-a1.yml")
	for _, fixture := range []struct{ job, format string }{{"fixture", "deb"}, {"fixture-almalinux", "rpm"}} {
		t.Run(fixture.job, func(t *testing.T) {
			_, job, ok := strings.Cut(workflow, "\n  "+fixture.job+":\n")
			if !ok {
				t.Fatal("fixture workflow job is absent")
			}
			job, _, _ = strings.Cut(job, "\n  fixture-almalinux:\n")
			for _, want := range []string{
				"--config appliance/images/kiwi/product-dev.nfpm.yaml --packager " + fixture.format + " --target dist/olivares." + fixture.format + "\n",
				" dist/olivares." + fixture.format + " ",
			} {
				if !strings.Contains(job, want) {
					t.Errorf("the %s job does not package and stage the product package: no %q", fixture.job, want)
				}
			}
		})
	}
}

func readRepo(t *testing.T, path string) string {
	t.Helper()
	if path == "" {
		t.Fatal("no path declared")
	}
	data, err := os.ReadFile(filepath.Join(repoRoot, path))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestPackage_ShipsTheDropInDirectoryRecommendsSSHAndKeepsEnablementAcrossReinstall(t *testing.T) {
	manifest := readManifest(t)
	dropIn := false
	for _, c := range manifest.Contents {
		if c.Dst == "/etc/systemd/system/olivares.service.d" {
			dropIn = c.Type == "dir" && c.FileInfo.Mode == 0o755
		}
	}
	if !dropIn {
		t.Fatal("the drop-in directory is not shipped 0755: the unit's UMask=0077 would create it 0700")
	}
	for _, want := range []string{"olivares", "cloud-init", "openssh-server"} {
		if !slices.Contains(manifest.Recommends, want) {
			t.Fatalf("recommends %v lacks %s", manifest.Recommends, want)
		}
	}
	postinstall := readRepo(t, manifest.Scripts.Postinstall)
	preremove := readRepo(t, manifest.Scripts.Preremove)
	postremove := readRepo(t, manifest.Scripts.Postremove)
	const marker = "/var/lib/olivares-appliance/.firstboot-enabled-at-removal"
	if !strings.Contains(preremove, marker) || !strings.Contains(postinstall, marker) {
		t.Fatal("a reinstallation after removal does not restore the first-boot unit's enablement")
	}
	if !strings.Contains(postremove, "systemctl daemon-reload") {
		t.Fatal("no daemon-reload after the unit files are removed")
	}
	banner := readRepo(t, "appliance/layer/base/units/tty1-banner.txt")
	// agetty's \4 is the address of the interface its console is on, which is loopback on tty1: the person is
	// told to open an address nobody else can reach. The address lines are written from the host's addresses.
	if !strings.Contains(banner, "headless server") || strings.Contains(banner, `\4`) || strings.Contains(banner, "127.0.0.1") {
		t.Fatal("the static banner must say this is a headless server and name no address: the refresh writes them")
	}
}

func TestPackage_VisibleHostNameIsOlivaresServer(t *testing.T) {
	banner := readRepo(t, "appliance/layer/base/units/tty1-banner.txt")
	if first := strings.SplitN(banner, "\n", 2)[0]; first != `Olivares Server \n` {
		t.Fatalf("banner starts with %q, want Olivares Server and the host name", first)
	}
	for path, want := range map[string]string{
		firstBootUnitPath: "Olivares Server first boot",
		readinessUnitPath: "Olivares Server first-boot readiness",
	} {
		unit := parseUnit(readRepo(t, path))
		if got := unit["Description"]; len(got) != 1 || got[0] != want {
			t.Errorf("%s descriptions %q, want %q", path, got, want)
		}
	}
}

// The maintainer scripts run under dpkg's action words and rpm's instance counts alike: the
// harness beside them drives each through installation, upgrade, removal and reinstallation
// under both conventions and both /bin/sh the targets use.
func TestPackage_MaintainerScriptsBehaveAlikeUnderDpkgAndRpmArguments(t *testing.T) {
	out, err := exec.Command("bash", "package/maintainer-scripts-test.sh").CombinedOutput()
	if err != nil {
		t.Fatalf("the maintainer scripts do not hold under both conventions: %v\n%s", err, out)
	}
}

// The base package is built for both of its targets from the one manifest: rpm for the AlmaLinux
// image, deb for Debian as an installation target.
func TestPackage_TheBaseTaskBuildsAnRpmAndADebFromTheOneManifest(t *testing.T) {
	_, task, ok := strings.Cut(readRepo(t, "appliance/Taskfile.yml"), "\n  appliance:package:base:\n")
	if !ok {
		t.Fatal("appliance/Taskfile.yml has no appliance:package:base task")
	}
	if end := strings.Index(task, "\n\n"); end >= 0 {
		task = task[:end]
	}
	for _, packager := range []string{"rpm", "deb"} {
		want := "--config packaging/nfpm/olivares-appliance-base.yaml --packager " + packager +
			" --target dist/olivares-appliance-base." + packager
		if strings.Count(task, want) != 1 {
			t.Errorf("appliance:package:base does not build the %s once: want %q in\n%s", packager, want, task)
		}
	}
}

func TestFixture_BaseImageIsPinnedByDigest(t *testing.T) {
	for _, line := range strings.Split(readRepo(t, "appliance/layer/base/fixture/Containerfile"), "\n") {
		if strings.HasPrefix(line, "FROM ") {
			if !regexp.MustCompile(`^FROM debian:13@sha256:[0-9a-f]{64}$`).MatchString(line) {
				t.Fatalf("base image not pinned by digest: %q", line)
			}
			return
		}
	}
	t.Fatal("no FROM line")
}

// Each fixture family builds from its own image, pinned by digest, and installs with its own
// package tools: Debian 13 with apt-get and dpkg, AlmaLinux 10 with dnf and rpm. Neither runs the
// other's.
func TestFixture_EachFamilyIsPinnedByDigestAndUsesOnlyItsOwnPackageTools(t *testing.T) {
	for _, family := range []struct {
		file, from   string
		own, foreign []string
	}{
		{"Containerfile", `^FROM debian:13@sha256:[0-9a-f]{64}$`, []string{"apt-get install", "dpkg -i "}, []string{"dnf", "rpm "}},
		{"almalinux/Containerfile", `^FROM almalinux:10@sha256:[0-9a-f]{64}$`, []string{"dnf -y", "rpm -i "}, []string{"apt-get", "dpkg"}},
	} {
		var froms, instructions []string
		for _, line := range strings.Split(readRepo(t, "appliance/layer/base/fixture/"+family.file), "\n") {
			if strings.HasPrefix(line, "#") {
				continue
			}
			if strings.HasPrefix(line, "FROM ") {
				froms = append(froms, line)
			}
			instructions = append(instructions, line)
		}
		if len(froms) != 1 || !regexp.MustCompile(family.from).MatchString(froms[0]) {
			t.Errorf("%s: FROM lines %q, want one matching %s", family.file, froms, family.from)
		}
		text := strings.Join(instructions, "\n")
		for _, tool := range family.own {
			if !strings.Contains(text, tool) {
				t.Errorf("%s does not use %q", family.file, tool)
			}
		}
		for _, tool := range family.foreign {
			if strings.Contains(text, tool) {
				t.Errorf("%s runs %q, the other family's tool", family.file, tool)
			}
		}
	}
}

// Each fixture installs the base package with every dependency it declares already satisfied,
// as a package manager would: the distribution's packages from the family's own repositories,
// and the product from its development package (appliance/images/kiwi/product-dev.nfpm.yaml) in
// the same transaction as the base package, never as loose files no package owns. The product
// package carries VERSION verbatim, as the base package does, so its version satisfies the base
// package's "olivares >= VERSION", and declares the release package's depends and deb-only files,
// which the fixture satisfies too (apparmor, for the deb postinstall's profile load).
func TestFixture_EachFamilySatisfiesEveryDependencyOfTheBasePackage(t *testing.T) {
	for _, file := range []string{"packaging/nfpm/olivares-appliance-base.yaml", "appliance/images/kiwi/product-dev.nfpm.yaml"} {
		raw := readRepo(t, file)
		var schema struct {
			VersionSchema string `json:"version_schema"`
		}
		if err := json.Unmarshal([]byte(raw[strings.Index(raw, "{"):]), &schema); err != nil {
			t.Fatal(err)
		}
		if schema.VersionSchema != "none" {
			t.Errorf("%s: version_schema %q, want none: nfpm's default makes 0.0.0-fixture 0.0.0~fixture, "+
				"which is below the base package's olivares >= 0.0.0-fixture", file, schema.VersionSchema)
		}
	}
	type nfpm struct {
		PackageName string        `json:"package_name"`
		Contents    []nfpmContent `json:"contents"`
		Overrides   map[string]struct {
			Depends []string `json:"depends"`
		} `json:"overrides"`
	}
	read := func(file string) (m nfpm) {
		raw := readRepo(t, file)
		if err := json.Unmarshal([]byte(raw[strings.Index(raw, "{"):]), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	manifest, product := read("packaging/nfpm/olivares-appliance-base.yaml"), read("appliance/images/kiwi/product-dev.nfpm.yaml")
	// The development product package declares what the release package declares per format: the same
	// depends, and the deb-only AppArmor profile that the product's postinstall loads.
	var releases struct{ Nfpms []nfpm }
	if err := json.Unmarshal([]byte(readRepo(t, "packaging/nfpm/packages.json")), &releases); err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(releases.Nfpms, func(n nfpm) bool { return n.PackageName == "olivares" })
	if i < 0 {
		t.Fatal("packaging/nfpm/packages.json defines no olivares package")
	}
	release := releases.Nfpms[i]
	for format, want := range release.Overrides {
		if got := product.Overrides[format].Depends; !slices.Equal(got, want.Depends) {
			t.Errorf("product-dev.nfpm.yaml: %s depends %q, the release package's are %q", format, got, want.Depends)
		}
	}
	for _, content := range release.Contents {
		if content.Packager == "deb" && !slices.ContainsFunc(product.Contents, func(c nfpmContent) bool {
			return c.Dst == content.Dst && c.Src == content.Src && (c.Packager == "" || c.Packager == "deb")
		}) {
			t.Errorf("product-dev.nfpm.yaml does not ship the release deb's %s from %s", content.Dst, content.Src)
		}
	}
	for _, family := range []struct{ format, file, system, install string }{
		{"deb", "Containerfile", `apt-get install -y --no-install-recommends ([^\\\n]*)`, `RUN dpkg -i ([^&\n]*)`},
		{"rpm", "almalinux/Containerfile", `(?s)dnf -y [^\n]*? install (.*?)&& dnf clean all`, `RUN rpm -i ([^&\n]*)`},
	} {
		container := readRepo(t, "appliance/layer/base/fixture/"+family.file)
		system := regexp.MustCompile(family.system).FindStringSubmatch(container)
		install := regexp.MustCompile(family.install).FindStringSubmatch(container)
		if system == nil || install == nil {
			t.Fatalf("%s: no system package list or no package install", family.file)
		}
		packages := strings.Fields(strings.ReplaceAll(system[1], "\\", " "))
		staged := strings.Fields(install[1])
		if !slices.Contains(staged, "/tmp/olivares-appliance-base."+family.format) {
			t.Errorf("%s: %q does not install the base package", family.file, install[0])
		}
		depends := manifest.Overrides[family.format].Depends
		if len(depends) == 0 {
			t.Fatalf("the %s base package declares no depends", family.format)
		}
		depends = append(slices.Clone(depends), product.Overrides[family.format].Depends...)
		for _, depend := range depends {
			name, _, _ := strings.Cut(depend, " ")
			switch {
			case name == "olivares":
				if !slices.Contains(staged, "/tmp/olivares."+family.format) {
					t.Errorf("%s: %q installs the base package without the product package it depends on", family.file, install[0])
				}
			case strings.HasPrefix(name, "/"):
				// A file dependency (the RPM's /bin/sh), which the family's base image provides.
			case !slices.Contains(packages, name):
				t.Errorf("%s does not install %s, a dependency of the %s base or product package", family.file, name, family.format)
			}
		}
	}
}

// The battery removes the base package with the booted family's own tool, chosen by the
// container's /etc/os-release: dpkg on Debian, rpm on AlmaLinux. Nowhere else does it remove it.
func TestFixture_TheBatteryRemovesTheBasePackageWithTheFamilysOwnTool(t *testing.T) {
	battery := readRepo(t, "appliance/layer/base/fixture/firstboot-battery.sh")
	_, body, ok := strings.Cut(battery, "\nremove_base() {\n")
	if !ok {
		t.Fatal("the battery has no remove_base function")
	}
	body, _, _ = strings.Cut(body, "\n}\n")
	for _, want := range []string{"/etc/os-release", "debian)", "dpkg --remove olivares-appliance-base", "almalinux)",
		"rpm --erase olivares-appliance-base"} {
		if !strings.Contains(body, want) {
			t.Errorf("remove_base lacks %q", want)
		}
	}
	if strings.Count(battery, "dpkg --remove") != 1 || strings.Count(battery, "rpm --erase") != 1 {
		t.Error("the battery removes the base package outside remove_base")
	}
}

// A scenario keeps its evidence in files, so boot retires the previous scenario's container before it starts the
// next. With four still running, the Debian fixture's fifth (restart) ended at once with exit 255 and no output on
// a shared runner. The battery's own boot runs here with only the docker command replaced by a log of its calls.
func TestFixture_TheBatteryRunsOneSystemdContainerAtATime(t *testing.T) {
	battery := readRepo(t, "appliance/layer/base/fixture/firstboot-battery.sh")
	_, boot, ok := strings.Cut(battery, "\nboot() {\n")
	if !ok {
		t.Fatal("the battery has no boot function")
	}
	boot, _, _ = strings.Cut(boot, "\n}\n")
	dockerLog := filepath.Join(t.TempDir(), "docker.log")
	script := "boot() {\n" + boot + "\n}\n" +
		"containers=(); hostname=h; image_id=i; boot_command=true\n" +
		"docker() { printf '%s\\n' \"$*\" >> \"$DOCKER_LOG\"; }\n" +
		"boot first; boot second; boot third\n"
	cmd := exec.Command("bash", "-euo", "pipefail", "-c", script)
	cmd.Env = append(os.Environ(), "DOCKER_LOG="+dockerLog)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("the battery's boot failed: %v\n%s", err, out)
	}
	calls, err := os.ReadFile(dockerLog)
	if err != nil {
		t.Fatal(err)
	}
	running, peak := map[string]bool{}, 0
	for _, line := range strings.Split(strings.TrimSpace(string(calls)), "\n") {
		words := strings.Fields(line)
		switch words[0] {
		case "run":
			i := slices.Index(words, "--name")
			if i < 0 || i+1 >= len(words) {
				t.Fatalf("a docker run without a container name: %s", line)
			}
			running[words[i+1]] = true
			peak = max(peak, len(running))
		case "rm":
			for _, name := range words[2:] {
				delete(running, name)
			}
		}
	}
	if peak != 1 {
		t.Errorf("%d scenario containers ran at once, want 1; docker calls:\n%s", peak, calls)
	}
}
