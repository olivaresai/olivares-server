// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package entitled

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/olivaresai/olivares/core/license/dnfrefresh"
)

const (
	testCycle      = "0123456789abcdef0123456789abcdef"
	testContext    = "fedcba9876543210fedcba9876543210"
	testCredential = "oad1." + "eyJhIjoxfQ" + "." + "c2lnbmF0dXJl" // synthetic: base64 of {"a":1} and of "signature", joined so the secrets sweep does not read one literal
)

var (
	testNow   = time.Date(2026, 10, 16, 18, 0, 0, 0, time.UTC)
	allSuites = []string{"entitled-security", "entitled-stable"}
	secSuites = []string{"entitled-security"}
)

func issuedDoc(t *testing.T, class string, suites []string, exp time.Time) dnfrefresh.Document {
	t.Helper()
	inv := testCycle
	return dnfrefresh.Issued(testCycle, &inv, dnfrefresh.Answer{
		Class: class, Set: "biz", Suites: suites, Context: testContext, Credential: testCredential, Exp: exp.Unix(),
	}, testNow)
}

func TestRenderCurrentWritesBothSuitesWithTheCredential(t *testing.T) {
	doc := issuedDoc(t, "current", allSuites, testNow.Add(24*time.Hour))
	got, err := Render("https://licenses.example.test", doc, testNow)
	if err != nil {
		t.Fatal(err)
	}
	text := string(got)
	for _, want := range []string{
		"[olivares-entitled-stable]",
		"[olivares-entitled-security]",
		"baseurl=https://licenses.example.test/dnf/v1/ctx/" + testContext + "/entitled-stable\n",
		"baseurl=https://licenses.example.test/dnf/v1/ctx/" + testContext + "/entitled-security\n",
		"username=olivares-dnf\n",
		"password=" + testCredential + "\n",
		"type=rpm-md\n",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("repository file lacks %q:\n%s", want, text)
		}
	}
	// Both signature checks stay on, on their own: in DNF 4 gpgcheck checks the packages and repo_gpgcheck the metadata.
	// pkg_gpgcheck is DNF 5's; DNF 4 ignores it, so a file that names it checks no package.
	lines := strings.Split(text, "\n")
	for _, check := range []string{"gpgcheck=1", "repo_gpgcheck=1"} {
		n := 0
		for _, line := range lines {
			if line == check {
				n++
			}
		}
		if n != 2 {
			t.Errorf("%s appears %d times, want once per suite", check, n)
		}
	}
	if strings.Contains(text, "pkg_gpgcheck") {
		t.Error("the file names pkg_gpgcheck, which DNF 4 ignores")
	}
	// The trust anchor is the preinstalled key by path, in every section, never a URL the service names.
	if n := strings.Count(text, "gpgkey="+GPGKey+"\n"); n != 2 || strings.Count(text, "gpgkey=") != 2 {
		t.Errorf("gpgkey=%s appears %d times, want once per suite and no other key", GPGKey, n)
	}
	if strings.Contains(text, "gpgcheck=0") || strings.Contains(text, "sslverify=0") {
		t.Errorf("repository file weakens a check:\n%s", text)
	}
}

// An expired licence is answered with the security-only class: the feature suite must disappear from the
// file, so `dnf upgrade` can no longer take feature updates while security updates continue.
func TestRenderSecurityOnlyWritesNoFeatureSuite(t *testing.T) {
	for _, class := range []string{"security-only", "security-unresolved"} {
		doc := issuedDoc(t, class, secSuites, testNow.Add(24*time.Hour))
		got, err := Render("https://licenses.example.test", doc, testNow)
		if err != nil {
			t.Fatalf("%s: %v", class, err)
		}
		text := string(got)
		if strings.Contains(text, "entitled-stable") {
			t.Errorf("%s: the feature suite is still in the file:\n%s", class, text)
		}
		if !strings.Contains(text, "[olivares-entitled-security]") {
			t.Errorf("%s: the security suite is missing:\n%s", class, text)
		}
	}
}

func TestRenderRefusesWhatIsNotAUsableIssuedHandoff(t *testing.T) {
	inv := testCycle
	notIssued := dnfrefresh.NotIssued(testCycle, &inv, dnfrefresh.OutcomeRefused, "licence_revoked", testNow)
	cases := []struct {
		name string
		doc  dnfrefresh.Document
		now  time.Time
	}{
		{"not issued", notIssued, testNow},
		{"expired", issuedDoc(t, "current", allSuites, testNow.Add(time.Hour)), testNow.Add(2 * time.Hour)},
		{"expires now", issuedDoc(t, "current", allSuites, testNow), testNow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Render("https://licenses.example.test", tc.doc, tc.now)
			if err == nil || got != nil {
				t.Fatalf("Render = %q, %v; want a refusal", got, err)
			}
			if strings.Contains(err.Error(), testCredential) {
				t.Fatalf("the refusal carries the credential: %v", err)
			}
		})
	}
}

func TestRenderRefusesAnOriginThatIsNotOne(t *testing.T) {
	doc := issuedDoc(t, "current", allSuites, testNow.Add(time.Hour))
	if _, err := Render("http://licenses.example.test", doc, testNow); err == nil {
		t.Fatal("Render accepted a plain http origin: the credential would cross the network in clear")
	}
}

func TestOrigin(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"https://licenses.example.test", "https://licenses.example.test", true},
		{"https://licenses.example.test:8443", "https://licenses.example.test:8443", true},
		{"https://licenses.example.test/", "https://licenses.example.test", true},
		{"http://licenses.example.test", "", false},
		{"https://user:pw@licenses.example.test", "", false},
		{"https://licenses.example.test/dnf", "", false},
		{"https://licenses.example.test?x=1", "", false},
		{"https://licenses.example.test#frag", "", false},
		{"https://", "", false},
		{"licenses.example.test", "", false},
		{"", "", false},
		{"https://licenses.example.test\n[evil]", "", false},
		// dnf splits baseurl on commas and expands $variables; Go decodes %xx escapes into Host and accepts other bytes.
		{"https://a.example.test,https://b.example.test", "", false},
		{"https://a$releasever.example.test", "", false},
		{"https://licenses.example.t%65st", "", false},
		{"https://licenses.exämple.test", "", false},
		{"https://[::1]:8443", "", false},
		{"https://-licenses.example.test", "", false},
		{"https://licenses.example.test:", "", false},
		{"https://licenses.example.test:123456", "", false},
	}
	for _, tc := range cases {
		got, err := Origin(tc.in)
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("Origin(%q) = %q, %v; want %q ok=%v", tc.in, got, err, tc.want, tc.ok)
		}
	}
}

func handoffDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "handoff")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// The directory is a umask-free 0700 of the running user, as the product's own writer requires.
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestReadHandoffReturnsTheDocumentTheProductWrote(t *testing.T) {
	dir := handoffDir(t)
	want := issuedDoc(t, "current", allSuites, testNow.Add(time.Hour))
	if err := dnfrefresh.Publish(dir, want); err != nil {
		t.Fatal(err)
	}
	got, err := ReadHandoff(dir, testCycle, testCycle, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	if got.Outcome != dnfrefresh.OutcomeIssued || *got.Context != testContext || *got.Credential != testCredential || *got.Class != "current" {
		t.Fatalf("ReadHandoff returned %+v", got)
	}
}

func TestReadHandoffReturnsANotIssuedDocumentSoTheCallerCanNameTheOutcome(t *testing.T) {
	dir := handoffDir(t)
	inv := testCycle
	if err := dnfrefresh.Publish(dir, dnfrefresh.NotIssued(testCycle, &inv, dnfrefresh.OutcomeNotBound, "", testNow)); err != nil {
		t.Fatal(err)
	}
	got, err := ReadHandoff(dir, testCycle, testCycle, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	if got.Outcome != dnfrefresh.OutcomeNotBound {
		t.Fatalf("outcome %q, want not_bound", got.Outcome)
	}
}

func TestReadHandoffRefusals(t *testing.T) {
	publish := func(t *testing.T, doc dnfrefresh.Document) string {
		dir := handoffDir(t)
		if err := dnfrefresh.Publish(dir, doc); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	good := func(t *testing.T) dnfrefresh.Document {
		return issuedDoc(t, "current", allSuites, testNow.Add(time.Hour))
	}
	otherInv := "ffffffffffffffffffffffffffffffff"
	cases := []struct {
		name string
		run  func(t *testing.T) error
	}{
		{"another user owns the directory", func(t *testing.T) error {
			_, err := ReadHandoff(publish(t, good(t)), testCycle, testCycle, os.Getuid()+1)
			return err
		}},
		{"the directory is group readable", func(t *testing.T) error {
			dir := publish(t, good(t))
			if err := os.Chmod(dir, 0o750); err != nil {
				t.Fatal(err)
			}
			_, err := ReadHandoff(dir, testCycle, testCycle, os.Getuid())
			return err
		}},
		{"the directory is a symbolic link", func(t *testing.T) error {
			dir := publish(t, good(t))
			link := filepath.Join(t.TempDir(), "link")
			if err := os.Symlink(dir, link); err != nil {
				t.Fatal(err)
			}
			_, err := ReadHandoff(link, testCycle, testCycle, os.Getuid())
			return err
		}},
		// The target stays inside the directory: a link out of it is refused by os.Root before our check runs.
		{"the file is a symbolic link to another file of the directory", func(t *testing.T) error {
			dir := publish(t, good(t))
			if err := os.Rename(filepath.Join(dir, testCycle+".json"), filepath.Join(dir, "real.json")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("real.json", filepath.Join(dir, testCycle+".json")); err != nil {
				t.Fatal(err)
			}
			_, err := ReadHandoff(dir, testCycle, testCycle, os.Getuid())
			return err
		}},
		{"the file is readable by its group", func(t *testing.T) error {
			dir := publish(t, good(t))
			if err := os.Chmod(filepath.Join(dir, testCycle+".json"), 0o640); err != nil {
				t.Fatal(err)
			}
			_, err := ReadHandoff(dir, testCycle, testCycle, os.Getuid())
			return err
		}},
		{"the file is readable by everyone", func(t *testing.T) error {
			dir := publish(t, good(t))
			if err := os.Chmod(filepath.Join(dir, testCycle+".json"), 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := ReadHandoff(dir, testCycle, testCycle, os.Getuid())
			return err
		}},
		{"a directory stands where the file should be", func(t *testing.T) error {
			dir := handoffDir(t)
			if err := os.Mkdir(filepath.Join(dir, testCycle+".json"), 0o700); err != nil {
				t.Fatal(err)
			}
			_, err := ReadHandoff(dir, testCycle, testCycle, os.Getuid())
			return err
		}},
		{"the handoff names another invocation", func(t *testing.T) error {
			doc := good(t)
			doc.Invocation = &otherInv
			_, err := ReadHandoff(publish(t, doc), testCycle, testCycle, os.Getuid())
			return err
		}},
		{"the handoff has no invocation, as a run by hand produces", func(t *testing.T) error {
			doc := good(t)
			doc.Invocation = nil
			_, err := ReadHandoff(publish(t, doc), testCycle, testCycle, os.Getuid())
			return err
		}},
		{"our own invocation is not a 128-bit id", func(t *testing.T) error {
			_, err := ReadHandoff(publish(t, good(t)), testCycle, "", os.Getuid())
			return err
		}},
		{"the cycle is not a 128-bit id", func(t *testing.T) error {
			_, err := ReadHandoff(publish(t, good(t)), "../../etc/passwd", testCycle, os.Getuid())
			return err
		}},
		{"the file is not the document's canonical bytes", func(t *testing.T) error {
			dir := publish(t, good(t))
			data, err := os.ReadFile(filepath.Join(dir, testCycle+".json"))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, testCycle+".json"), append(data, " \n"...), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err = ReadHandoff(dir, testCycle, testCycle, os.Getuid())
			return err
		}},
		{"the file has a field outside the schema", func(t *testing.T) error {
			dir := publish(t, good(t))
			data, err := os.ReadFile(filepath.Join(dir, testCycle+".json"))
			if err != nil {
				t.Fatal(err)
			}
			forged := strings.Replace(string(data), `"at":`, `"extra":true,"at":`, 1)
			if err := os.WriteFile(filepath.Join(dir, testCycle+".json"), []byte(forged), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err = ReadHandoff(dir, testCycle, testCycle, os.Getuid())
			return err
		}},
		{"the file is larger than the product writes", func(t *testing.T) error {
			dir := publish(t, good(t))
			if err := os.WriteFile(filepath.Join(dir, testCycle+".json"), []byte(strings.Repeat("x", dnfrefresh.MaxHandoffBytes+1)), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := ReadHandoff(dir, testCycle, testCycle, os.Getuid())
			return err
		}},
		{"the handoff of another cycle is not there", func(t *testing.T) error {
			dir := publish(t, good(t))
			_, err := ReadHandoff(dir, "11111111111111111111111111111111", testCycle, os.Getuid())
			return err
		}},
		{"the file names another cycle than its own name", func(t *testing.T) error {
			doc := good(t)
			doc.Cycle = "11111111111111111111111111111111"
			dir := publish(t, doc)
			if err := os.Rename(filepath.Join(dir, doc.Cycle+".json"), filepath.Join(dir, testCycle+".json")); err != nil {
				t.Fatal(err)
			}
			_, err := ReadHandoff(dir, testCycle, testCycle, os.Getuid())
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.run(t)
			if err == nil {
				t.Fatal("ReadHandoff accepted it")
			}
			if strings.Contains(err.Error(), testCredential) {
				t.Fatalf("the refusal carries the credential: %v", err)
			}
		})
	}
}

func TestInstallWritesMode0600AndReplacesTheOldFileWhole(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, RepoFile)
	if err := os.WriteFile(path, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Install(dir, []byte("new\n")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "new\n" {
		t.Fatalf("file = %q, %v", data, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, want 0600: the file carries a credential", info.Mode().Perm())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("directory holds %d entries after the replace, want only %s", len(entries), RepoFile)
	}
}

func TestInstallLeavesTheOldFileWhenTheDirectoryIsGone(t *testing.T) {
	if err := Install(filepath.Join(t.TempDir(), "missing"), []byte("new\n")); err == nil {
		t.Fatal("Install reported success for a directory that does not exist")
	}
}

func TestInstallWritesThroughNoSymbolicLinkAtTheTarget(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(dir, RepoFile)); err != nil {
		t.Fatal(err)
	}
	if err := Install(dir, []byte("new\n")); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(victim); string(data) != "keep\n" {
		t.Fatalf("Install wrote through the symbolic link: victim = %q", data)
	}
}
