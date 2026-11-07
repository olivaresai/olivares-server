// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package optionalapps

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/olivaresai/olivares/appliance/layer/firewall/policy"
)

// The app's firewall rows come from its manifest and nowhere else: one for each port it publishes
// beyond loopback, answering on every interface, with the bridge its container network is made
// with. The admin listener on loopback gets no row, and the rows are a valid policy.
func TestFirewallRows_AreThePublishedPortsAndTheBridgeOfTheManifest(t *testing.T) {
	rows := FirewallRows()
	want := []policy.AppRow{
		{App: "nginx-proxy-manager", Port: "80/tcp", Interfaces: []string{"*"}, Bridge: "olv-npm"},
		{App: "nginx-proxy-manager", Port: "443/tcp", Interfaces: []string{"*"}, Bridge: "olv-npm"},
	}
	if !slices.EqualFunc(rows, want, func(a, b policy.AppRow) bool {
		return a.App == b.App && a.Port == b.Port && slices.Equal(a.Interfaces, b.Interfaces) && a.Bridge == b.Bridge
	}) {
		t.Fatalf("the rows are %+v, want %+v", rows, want)
	}
	m, err := manifest()
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Networks["default"].DriverOpts["com.docker.network.bridge.name"]; got != "olv-npm" {
		t.Errorf("the manifest's network is made with bridge %q, want the rows' olv-npm", got)
	}
	if m.Networks["default"].Driver != "bridge" {
		t.Errorf("the manifest's network driver is %q, want bridge", m.Networks["default"].Driver)
	}
	d := policy.Document{SchemaVersion: policy.SchemaVersion, SSHPort: 22, Portal: policy.Portal{Listen: policy.ListenLocal},
		DHCPv6ClientInterfaces: []string{}, Apps: rows}
	if err := d.Validate(); err != nil {
		t.Errorf("the rows are not a valid policy: %v", err)
	}
	for _, row := range rows {
		if row.Port == "81/tcp" {
			t.Errorf("the loopback admin listener has a row: %+v", row)
		}
	}
}

// The app's folders reach a confined container only if the runtime relabels them, and the runtime
// relabels a bind mount only from the short form with the z option: Compose sends the long form with
// create_host_path false through the mount API, which cannot (measured on AlmaLinux 10.2 with Docker
// 29.9.1 and Compose 5.6.0: the folder kept the helper's type and the container, confined as
// container_t, could not write it). So every volume asks for the relabel, and none asks for the
// other form.
func TestManifest_VolumesAskTheRuntimeToRelabelThem(t *testing.T) {
	var m struct {
		Services map[string]struct {
			Volumes []struct {
				Source string         `json:"source"`
				Bind   map[string]any `json:"bind"`
			} `json:"volumes"`
		} `json:"services"`
	}
	if err := json.Unmarshal(nginxProxyManager, &m); err != nil {
		t.Fatal(err)
	}
	volumes := m.Services["app"].Volumes
	if len(volumes) != 2 {
		t.Fatalf("the app has %d volumes, want its data and certificates", len(volumes))
	}
	for _, v := range volumes {
		if v.Bind["selinux"] != "z" {
			t.Errorf("%s: bind options %v, want selinux z", v.Source, v.Bind)
		}
		if _, set := v.Bind["create_host_path"]; set {
			t.Errorf("%s: create_host_path sends the mount through the API that cannot relabel it", v.Source)
		}
	}
}

func TestCloudflaredRequiresAProtectedTokenAndPublishesNoInboundPort(t *testing.T) {
	h := newDockerHost(t)
	h.app = Cloudflared
	x := h.executor()
	x.App = Cloudflared
	before, err := x.Apply(context.Background(), "install")
	if err == nil || before.P1 != "not-performed" || len(h.effects) != 0 {
		t.Fatalf("missing token allowed a native effect: %+v %v %v", before, err, h.effects)
	}
	m, err := manifestFor(Cloudflared)
	if err != nil {
		t.Fatal(err)
	}
	app := m.Services["app"]
	if len(app.Ports) != 0 || app.NetworkMode != "host" || !slices.Contains(app.Command, "--token-file") || !slices.Contains(app.Command, "127.0.0.1:20241") || len(app.Volumes) != 2 || !app.Volumes[0].ReadOnly || !app.Volumes[1].ReadOnly {
		t.Fatalf("tunnel must use a file token without inbound ports: %+v", app)
	}
	for _, mode := range []os.FileMode{0644, 0600} {
		if err := h.root.WriteFile("tunnel-token", []byte(strings.Repeat("fixture", 2)), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(h.root.Name(), "tunnel-token"), mode); err != nil {
			t.Fatal(err)
		}
		if mode == 0600 {
			result, err := x.Apply(context.Background(), "install")
			if err == nil || result.P1 != "not-performed" || len(h.effects) != 0 {
				t.Fatalf("missing origin CA allowed effect: %+v %v", result, err)
			}
			if err := h.root.WriteFile("origin-ca.pem", []byte("fixture public certificate"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		result, err := x.Apply(context.Background(), "install")
		if mode == 0644 {
			if err == nil || len(h.effects) != 0 {
				t.Fatalf("unprotected token allowed effect: %+v %v", result, err)
			}
		} else if err != nil || result.P1 != "performed" || len(h.probes) != 0 {
			t.Fatalf("protected token tunnel install: %+v %v probes=%v", result, err, h.probes)
		}
	}
	for _, row := range FirewallApps()[Cloudflared] {
		t.Fatalf("outbound tunnel requested an inbound firewall row: %+v", row)
	}
}
