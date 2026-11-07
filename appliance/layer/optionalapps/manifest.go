// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

// Package optionalapps owns the optional apps' lifecycle: the host operation
// descriptors, the olivares-portal-apps helper's document and rules, the Compose
// executor that helper runs and the portal-side task that asks it. The apps
// are Nginx Proxy Manager and Cloudflare Tunnel.
package optionalapps

import (
	_ "embed"
	"encoding/json"
	"net/netip"
	"strconv"

	"github.com/olivaresai/olivares/appliance/layer/firewall/policy"
)

// This is the official NPM Compose setup, pinned by registry manifest digest.
// The admin listener is loopback-only pending a protected product route.
// JSON is also a YAML document; the native Compose parser validates it before
// any pull or installation. No caller supplies a Compose file or image.
//
//go:embed nginx-proxy-manager.json
var nginxProxyManager []byte

//go:embed cloudflared.json
var cloudflared []byte

// Cloudflared is the outbound-only named tunnel app.
const Cloudflared = "cloudflared"

func manifestBytes(app string) []byte {
	switch app {
	case "", Slug:
		return nginxProxyManager
	case Cloudflared:
		return cloudflared
	}
	return nil
}

type composeManifest struct {
	Name     string             `json:"name"`
	Services map[string]service `json:"services"`
	Networks map[string]network `json:"networks"`
}
type network struct {
	Driver     string            `json:"driver"`
	DriverOpts map[string]string `json:"driver_opts"`
}
type service struct {
	Image         string    `json:"image"`
	ContainerName string    `json:"container_name"`
	Restart       string    `json:"restart"`
	Command       []string  `json:"command"`
	NetworkMode   string    `json:"network_mode"`
	ReadOnly      bool      `json:"read_only"`
	CapDrop       []string  `json:"cap_drop"`
	SecurityOpt   []string  `json:"security_opt"`
	User          string    `json:"user"`
	Ports         []binding `json:"ports"`
	Volumes       []volume  `json:"volumes"`
}
type binding struct {
	Target    uint16 `json:"target"`
	Published string `json:"published"`
	HostIP    string `json:"host_ip"`
	Protocol  string `json:"protocol"`
}
type volume struct {
	Type, Source, Target string
	ReadOnly             bool `json:"read_only"`
}

func manifest() (composeManifest, error) {
	return manifestFor(Slug)
}

func manifestFor(app string) (composeManifest, error) {
	var m composeManifest
	err := json.Unmarshal(manifestBytes(app), &m)
	return m, err
}
func portKey(p binding) string { return strconv.Itoa(int(p.Target)) + "/" + p.Protocol }

// Slug is the app's name in the firewall policy and in its own act.
const Slug = "nginx-proxy-manager"

// bridgeOption is the Docker network option that names the Linux bridge of a network.
const bridgeOption = "com.docker.network.bridge.name"

// FirewallRows are the rows the app's firewall act adds, from the manifest alone: one for each port it
// publishes beyond loopback, answering on every interface, each with the bridge its container network
// is made with, so that the policy forwards the published ports and the app's egress. The admin
// listener, published on loopback, gets none.
func FirewallRows() []policy.AppRow {
	m, err := manifest()
	if err != nil {
		return nil
	}
	rows := []policy.AppRow{}
	for _, p := range m.Services["app"].Ports {
		if address, err := netip.ParseAddr(p.HostIP); err != nil || !address.IsLoopback() {
			rows = append(rows, policy.AppRow{App: Slug, Port: p.Published + "/" + p.Protocol, Interfaces: []string{policy.EveryInterface},
				Bridge: m.Networks["default"].DriverOpts[bridgeOption]})
		}
	}
	return rows
}

// FirewallApps is the rows of each optional app by its slug: the one table that the console's app-row
// act and the firewall helper's check of that act both read.
func FirewallApps() map[string][]policy.AppRow {
	return map[string][]policy.AppRow{Slug: FirewallRows(), Cloudflared: {}}
}
