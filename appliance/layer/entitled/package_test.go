// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package entitled

import (
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/olivaresai/olivares/core/license/dnfrefresh"
)

// licenseFile is where the product keeps an installed licence (cmd/olivares licenseFileName under
// the data directory the product's unit names): the file whose presence starts the refresh.
const licenseFile = "/var/lib/olivares/license.key"

const (
	binaryDst = "/usr/libexec/olivares/olivares-entitled-repo"
	unitDir   = "/usr/lib/systemd/system/"
)

// credentialLifetime is the download credential's: dnfrefresh accepts exp at most 86400 s plus skew away.
const credentialLifetime = 24 * time.Hour

type content struct {
	Src      string `json:"src"`
	Dst      string `json:"dst"`
	FileInfo struct {
		Mode  uint32 `json:"mode"`
		Owner string `json:"owner"`
	} `json:"file_info"`
}

func shipped(t *testing.T) map[string]content {
	t.Helper()
	data, err := os.ReadFile("../../../packaging/nfpm/olivares-appliance-portal.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	var m struct {
		Contents []content `json:"contents"`
	}
	if err := json.Unmarshal([]byte(strings.Join(lines, "\n")), &m); err != nil {
		t.Fatal(err)
	}
	out := map[string]content{}
	for _, c := range m.Contents {
		out[c.Dst] = c
	}
	return out
}

// directives returns each key of a unit file with its values, in order, whatever the section.
func directives(t *testing.T, file string) map[string][]string {
	t.Helper()
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("%s: line %q is not a directive", file, line)
		}
		out[key] = append(out[key], value)
	}
	return out
}

func one(t *testing.T, d map[string][]string, key string) string {
	t.Helper()
	if len(d[key]) != 1 {
		t.Fatalf("%s appears %d times, want once", key, len(d[key]))
	}
	return d[key][0]
}

func TestPackageShipsTheCommandAndEveryUnitFromThisModule(t *testing.T) {
	got := shipped(t)
	want := map[string]struct {
		src  string
		mode uint32
	}{
		binaryDst: {"bin/olivares-entitled-repo", 0o755},
	}
	for _, unit := range []string{"olivares-entitled-repo.service", "olivares-entitled-repo.timer", "olivares-entitled-repo.path", "olivares-edition.service", "olivares-appliance-update.service", "olivares-appliance-rollback.service"} {
		want[unitDir+unit] = struct {
			src  string
			mode uint32
		}{"appliance/layer/entitled/units/" + unit, 0o644}
	}
	for dst, w := range want {
		c, ok := got[dst]
		if !ok || c.Src != w.src || c.FileInfo.Mode != w.mode || (c.FileInfo.Owner != "" && c.FileInfo.Owner != "root") {
			t.Errorf("%s: package has %+v, want source %s mode %o", dst, c, w.src, w.mode)
		}
		if strings.HasPrefix(w.src, "appliance/") {
			if _, err := os.Stat(filepath.Join("../../..", w.src)); err != nil {
				t.Errorf("%s ships a missing source: %v", dst, err)
			}
		}
	}
}

func TestBuildScriptBuildsTheCommand(t *testing.T) {
	data, err := os.ReadFile("../../../scripts/build-appliance-portal.sh")
	if err != nil {
		t.Fatal(err)
	}
	// An entry of the build loop's list: followed by a continuation, or by the `; do` that ends the list.
	if !regexp.MustCompile(`(?m)^\tappliance/cmd/olivares-entitled-repo( \\|; do)$`).Match(data) {
		t.Fatal("the portal payload build does not build bin/olivares-entitled-repo, which the package ships")
	}
}

func TestRefreshServiceRunsTheCommandOnlyWithALicenceAndHandsOffInTheProductsDirectory(t *testing.T) {
	d := directives(t, "units/olivares-entitled-repo.service")
	if got := one(t, d, "ExecStart"); got != binaryDst+" refresh" {
		t.Errorf("ExecStart=%s", got)
	}
	if got := one(t, d, "ConditionPathExists"); got != licenseFile {
		t.Errorf("ConditionPathExists=%s, want the product's licence file %s", got, licenseFile)
	}
	// The product publishes into dnfrefresh.HandoffDir and nowhere else: the unit must create that directory, 0700.
	if got, want := one(t, d, "RuntimeDirectory"), path.Base(dnfrefresh.HandoffDir); got != want || path.Dir(dnfrefresh.HandoffDir) != "/run" {
		t.Errorf("RuntimeDirectory=%s does not make the product's handoff directory %s", got, dnfrefresh.HandoffDir)
	}
	if got := one(t, d, "RuntimeDirectoryMode"); got != "0700" {
		t.Errorf("RuntimeDirectoryMode=%s, want 0700", got)
	}
	if got := one(t, d, "Type"); got != "oneshot" {
		t.Errorf("Type=%s", got)
	}
	// It writes the repository directory and the product's state (the connect state the product updates) and nothing else.
	if got := one(t, d, "ReadWritePaths"); got != "/etc/yum.repos.d /var/lib/olivares" {
		t.Errorf("ReadWritePaths=%s", got)
	}
	if got := one(t, d, "ProtectSystem"); got != "strict" {
		t.Errorf("ProtectSystem=%s", got)
	}
	caps := strings.Fields(one(t, d, "CapabilityBoundingSet"))
	slices.Sort(caps)
	if want := []string{"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_SETGID", "CAP_SETUID"}; !slices.Equal(caps, want) {
		t.Errorf("CapabilityBoundingSet=%v, want exactly %v", caps, want)
	}
	for key, want := range map[string]string{"NoNewPrivileges": "yes", "PrivateTmp": "yes", "PrivateDevices": "yes", "ProtectHome": "yes",
		"RestrictSUIDSGID": "yes", "MemoryDenyWriteExecute": "yes", "UMask": "0077", "AmbientCapabilities": ""} {
		if got := one(t, d, key); got != want {
			t.Errorf("%s=%q, want %q", key, got, want)
		}
	}
	for _, family := range strings.Fields(one(t, d, "RestrictAddressFamilies")) {
		if !slices.Contains([]string{"AF_UNIX", "AF_INET", "AF_INET6"}, family) {
			t.Errorf("RestrictAddressFamilies allows %s", family)
		}
	}
	if _, ok := d["WantedBy"]; ok {
		t.Error("the service has an [Install] section: only its timer and path unit start it")
	}
}

func TestTimerRenewsWellInsideTheCredentialsLifetimeAndPathUnitStartsItOnActivation(t *testing.T) {
	timer := directives(t, "units/olivares-entitled-repo.timer")
	// Both units start the edition step, which pulls in the refresh first: a renewed credential or a changed licence
	// is followed by the edition the licence earns, and the timer is the retry for a channel that was not ready.
	if got := one(t, timer, "Unit"); got != "olivares-edition.service" {
		t.Errorf("timer Unit=%s", got)
	}
	// systemd spells minutes "min"; the spans used here are whole hours and minutes.
	span := func(key string) time.Duration {
		d, err := time.ParseDuration(strings.Replace(one(t, timer, key), "min", "m", 1))
		if err != nil {
			t.Fatalf("%s: %v", key, err)
		}
		return d
	}
	every, delay := span("OnUnitInactiveSec"), span("RandomizedDelaySec")
	// At least three attempts must fit in the lifetime, delay included.
	if every+delay > credentialLifetime/3 {
		t.Errorf("a refresh every %s (+%s) leaves fewer than three attempts in the credential's %s", every, delay, credentialLifetime)
	}
	if got := one(t, timer, "WantedBy"); got != "timers.target" {
		t.Errorf("timer WantedBy=%s", got)
	}
	p := directives(t, "units/olivares-entitled-repo.path")
	if got := one(t, p, "PathChanged"); got != "/var/lib/olivares/public/license.changed" {
		t.Errorf("PathChanged=%s, want the public licence notification", got)
	}
	if got := one(t, p, "Unit"); got != "olivares-edition.service" {
		t.Errorf("path Unit=%s", got)
	}
}

func TestEditionServiceRunsAfterAFreshRefreshAndMayWriteWhatAPackageTransactionWrites(t *testing.T) {
	d := directives(t, "units/olivares-edition.service")
	if got := one(t, d, "ExecStart"); got != binaryDst+" edition" {
		t.Errorf("ExecStart=%s", got)
	}
	if got := one(t, d, "Type"); got != "oneshot" {
		t.Errorf("Type=%s", got)
	}
	// Requires= starts the refresh when this unit is started and fails this one if the refresh fails; a refresh the
	// licence condition skipped (no licence) counts as success, which is how the step runs on deactivation.
	if got := one(t, d, "Requires"); got != "olivares-entitled-repo.service" {
		t.Errorf("Requires=%s", got)
	}
	if !strings.Contains(one(t, d, "After"), "olivares-entitled-repo.service") {
		t.Errorf("After=%s does not order the edition after the refresh", one(t, d, "After"))
	}
	// It must run without a licence: that is the deactivation. Neither a condition nor an assert on the licence file.
	for _, key := range []string{"ConditionPathExists", "AssertPathExists"} {
		if _, ok := d[key]; ok {
			t.Errorf("%s: the step has to run without a licence to return the host to Community", key)
		}
	}
	// A package transaction writes the package database, /usr and the unit files, and runs scriptlets as root: the
	// refresh unit's sandbox (read-only system, a few paths, four capabilities) cannot hold it. If a sandbox that can
	// hold a transaction is ever designed, it replaces this list on purpose.
	for _, key := range []string{"ProtectSystem", "ReadWritePaths", "CapabilityBoundingSet", "NoNewPrivileges", "MemoryDenyWriteExecute"} {
		if _, ok := d[key]; ok {
			t.Errorf("%s is set: a package transaction does not run inside the refresh unit's sandbox", key)
		}
	}
	// A licence file that is absent because its volume is not mounted yet must never read as a removed licence.
	if got := one(t, d, "RequiresMountsFor"); got != "/var/lib/olivares" {
		t.Errorf("RequiresMountsFor=%s, want the product's data directory", got)
	}
	// dnf is given ten minutes after SIGTERM (stopGrace in the command); systemd must wait longer before it kills the group.
	if got := one(t, d, "TimeoutStopSec"); got != "15min" {
		t.Errorf("TimeoutStopSec=%s, want 15min, above the ten minutes dnf is given to unwind", got)
	}
	// SIGTERM goes to the command alone, which passes it on to dnf; the default group kill would signal dnf itself.
	if got := one(t, d, "KillMode"); got != "mixed" {
		t.Errorf("KillMode=%s, want mixed", got)
	}
	if got := one(t, d, "TimeoutStartSec"); got != "1h" {
		t.Errorf("TimeoutStartSec=%s, want the update unit's 1h", got)
	}
	if _, ok := d["WantedBy"]; ok {
		t.Error("the edition service has an [Install] section: only the path unit and the timer start it")
	}
}

func TestUpdateRenewsTheCredentialFirstAndUpgradesOnlyOlivaresPackagesThroughDnf4(t *testing.T) {
	d := directives(t, "units/olivares-appliance-update.service")
	if got := one(t, d, "Requires"); got != "olivares-entitled-repo.service" {
		t.Errorf("Requires=%s", got)
	}
	if !strings.Contains(one(t, d, "After"), "olivares-entitled-repo.service") {
		t.Errorf("After=%s does not order the update after the credential refresh", one(t, d, "After"))
	}
	if got := one(t, d, "ExecStart"); got != binaryDst+" update" {
		t.Errorf("ExecStart=%s, want the transaction owner that snapshots before DNF", got)
	}
	// ConditionPathExists would skip the unit and report success; an assert fails the start and says why.
	if got := one(t, d, "AssertPathExists"); got != licenseFile {
		t.Errorf("AssertPathExists=%s, want the product's licence file %s", got, licenseFile)
	}
	if _, ok := d["ConditionPathExists"]; ok {
		t.Error("the update skips silently without a licence: use AssertPathExists")
	}
	// The update stops the product before dnf and starts it after: a stop must reach the command, which asks dnf to
	// unwind and starts the product again, not dnf directly with a kill 90 seconds later.
	if got := one(t, d, "KillMode"); got != "mixed" {
		t.Errorf("KillMode=%s, want mixed", got)
	}
	if got := one(t, d, "TimeoutStopSec"); got != "15min" {
		t.Errorf("TimeoutStopSec=%s, want 15min, above the ten minutes dnf is given to unwind", got)
	}
	if _, ok := d["WantedBy"]; ok {
		t.Error("the update has an [Install] section: nothing starts it by itself")
	}
}

func TestImagePresetEnablesTheTimerAndThePathUnit(t *testing.T) {
	data, err := os.ReadFile("../../images/kiwi/almalinux10-server-amd64/etc/systemd/system-preset/10-olivares-appliance.preset")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(data), "\n")
	for _, want := range []string{"enable olivares-entitled-repo.timer", "enable olivares-entitled-repo.path"} {
		if !slices.Contains(lines, want) {
			t.Errorf("the image preset lacks %q", want)
		}
	}
	for _, line := range lines {
		if strings.Contains(line, "olivares-appliance-update") || line == "enable olivares-entitled-repo.service" || strings.Contains(line, "olivares-edition") {
			t.Errorf("the image preset enables %q: only the timer and the path unit start a refresh, and nothing starts an update", line)
		}
	}
}
