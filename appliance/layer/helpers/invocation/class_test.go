// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package invocation

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/olivaresai/olivares/appliance/layer/helpers/helperschema"
)

// moduleUnits is the directory in which each module helper's module ships its socket and its
// template.
var moduleUnits = map[string]string{
	helperschema.HelperUnits:    filepath.Join("..", "..", "services", "units"),
	helperschema.HelperStorage:  filepath.Join("..", "..", "storage", "units"),
	helperschema.HelperFirewall: filepath.Join("..", "..", "firewall", "units"),
	helperschema.HelperApt:      filepath.Join("..", "..", "updates", "units"),
	helperschema.HelperApps:     filepath.Join("..", "..", "optionalapps", "units"),
}

// packageActCapabilities is what the host-package helper's act holds (bounding and ambient, which
// NoNewPrivileges makes the same set: without the ambient copy a scriptlet that changes user cannot
// set its user ID). Each is rpm's own and measured on AlmaLinux 10 (rpm 4.19.1.1) under the real
// unit, with a package whose upgrade fails, or silently loses a mode, when it is dropped:
// CAP_CHOWN (chown of a file owned by another account), CAP_DAC_OVERRIDE (replacing a file whose
// mode denies root), CAP_FOWNER (chmod of a file another account owns), CAP_FSETID (a setgid file
// keeps its bit), CAP_SETFCAP (a file with capabilities), and CAP_SETUID with CAP_SETGID (a scriptlet
// that runs a command as another account).
const packageActCapabilities = "CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_FSETID CAP_SETFCAP CAP_SETGID CAP_SETUID"

// moduleConfinement is what each module helper's template states of its network, its capabilities
// and its filesystem, exactly, as its module needs; nil is a directive the template does not state.
// Services and package-status reads run with no network and no capability. The storage helper
// retains CHOWN/FOWNER only for the verified backup mount root, with no raw disk-write or SYS_ADMIN capability. The firewall owner loads the
// host's own table: it runs in the host's network namespace, with netlink, and holds CAP_NET_ADMIN
// alone, which the kernel requires of an nftables sender, root included. The apps helper probes the
// app's published ports by binding them in the host's network namespace, so it holds
// CAP_NET_BIND_SERVICE alone and the IPv4 family beside the Docker daemon's Unix socket. The package
// helper's act is rpm -U of a retained, signature-verified file, which writes anywhere under / (so no
// ProtectSystem) and may install a set-id file (so no RestrictSUIDSGID), with the capabilities above.
var moduleConfinement = map[string]map[string][]string{
	helperschema.HelperUnits: {"Service.PrivateNetwork": {"yes"}, "Service.RestrictAddressFamilies": {"AF_UNIX"},
		"Service.CapabilityBoundingSet": {""}, "Service.AmbientCapabilities": {""}, "Service.ProtectSystem": {"strict"}, "Service.RestrictSUIDSGID": {"yes"}},
	helperschema.HelperStorage: {"Service.PrivateNetwork": {"yes"}, "Service.RestrictAddressFamilies": {"AF_UNIX"},
		"Service.CapabilityBoundingSet": {"CAP_CHOWN CAP_FOWNER"}, "Service.AmbientCapabilities": {""}, "Service.ProtectSystem": {"strict"}, "Service.RestrictSUIDSGID": {"yes"}},
	helperschema.HelperFirewall: {"Service.PrivateNetwork": nil, "Service.RestrictAddressFamilies": {"AF_UNIX AF_NETLINK"},
		"Service.CapabilityBoundingSet": {"CAP_NET_ADMIN"}, "Service.AmbientCapabilities": {""}, "Service.ProtectSystem": {"strict"}, "Service.RestrictSUIDSGID": {"yes"}},
	helperschema.HelperApt: {"Service.PrivateNetwork": {"yes"}, "Service.RestrictAddressFamilies": {"AF_UNIX"},
		"Service.CapabilityBoundingSet": {packageActCapabilities}, "Service.AmbientCapabilities": {packageActCapabilities},
		"Service.ProtectSystem": {"no"}, "Service.RestrictSUIDSGID": nil},
	helperschema.HelperApps: {"Service.PrivateNetwork": nil, "Service.RestrictAddressFamilies": {"AF_UNIX AF_INET"},
		"Service.CapabilityBoundingSet": {"CAP_NET_BIND_SERVICE"}, "Service.AmbientCapabilities": {""}, "Service.ProtectSystem": {"strict"},
		"Service.RestrictSUIDSGID": {"yes"}, "Service.IPAddressDeny": {"any"}, "Service.PrivateDevices": {"yes"}},
}

func TestHelperUnits_ModuleHelpersListenForTheApplianceConsoleUnderTheirModule(t *testing.T) {
	if len(moduleUnits) != len(helperschema.ModuleHelpers()) || len(moduleConfinement) != len(helperschema.ModuleHelpers()) {
		t.Fatalf("the inventory names %d module directories and %d confinements for %d module helpers",
			len(moduleUnits), len(moduleConfinement), len(helperschema.ModuleHelpers()))
	}
	for _, name := range helperschema.ModuleHelpers() {
		t.Run(name, func(t *testing.T) {
			dir, ok := moduleUnits[name]
			if !ok {
				t.Fatalf("no module ships the units of %s", name)
			}
			socket := unitDirectives(t, filepath.Join(dir, "olivares-helper-"+name+".socket"))
			service := unitDirectives(t, filepath.Join(dir, "olivares-helper-"+name+"@.service"))
			// The node is root's with the Appliance Console's group, so the console can connect;
			// connecting is necessary, never sufficient: the seam admits the console's process.
			for key, want := range map[string]string{
				"Socket.ListenStream": filepath.Join(helperschema.SocketDir, name+".sock"),
				"Socket.Accept":       "yes",
				"Socket.SocketUser":   "root",
				"Socket.SocketGroup":  helperschema.Portal.Account,
				"Socket.SocketMode":   "0660",
				"Install.WantedBy":    "sockets.target",
			} {
				if !slices.Equal(socket[key], []string{want}) {
					t.Errorf("socket %s=%v, want %s", key, socket[key], want)
				}
			}
			for key, want := range map[string]string{
				"Service.ExecStart":       libexec + "/olivares-portal-" + name,
				"Service.User":            helperschema.Account(name),
				"Service.StandardInput":   "socket",
				"Service.StandardOutput":  "socket",
				"Service.NoNewPrivileges": "yes",
			} {
				if !slices.Equal(service[key], []string{want}) {
					t.Errorf("service %s=%v, want %q", key, service[key], want)
				}
			}
			confinement, ok := moduleConfinement[name]
			if !ok {
				t.Fatalf("no confinement is stated for %s", name)
			}
			for key, want := range confinement {
				if !slices.Equal(service[key], want) {
					t.Errorf("service %s=%q, want exactly %q", key, service[key], want)
				}
			}
			for key, values := range service {
				if strings.HasPrefix(key, "Install.") {
					t.Errorf("the template has an [Install] section (%s)", key)
				}
				if strings.HasPrefix(key, "Service.Exec") {
					for _, value := range values {
						if strings.Contains(value, " ") || strings.IndexAny(value, "+!@-:") == 0 {
							t.Errorf("%s=%s: the helper takes no argument and no privilege prefix", key, value)
						}
					}
				}
			}
			var writable []string
			if name == helperschema.HelperStorage {
				writable = []string{"/mnt/olivares-backups"}
			}
			if !slices.Equal(service["Service.ReadWritePaths"], writable) {
				t.Errorf("service ReadWritePaths=%v, want exactly %v", service["Service.ReadWritePaths"], writable)
			}
			for _, key := range []string{"Service.BindPaths", "Service.Environment", "Service.EnvironmentFile",
				"Service.DynamicUser", "Service.Group", "Service.SupplementaryGroups"} {
				if len(service[key]) > 0 {
					t.Errorf("service %s=%v: nothing but the template decides the helper's inputs and account", key, service[key])
				}
			}
			// The module ships its units; the root helpers' directory holds none of them.
			for _, file := range []string{"olivares-helper-" + name + ".socket", "olivares-helper-" + name + "@.service"} {
				if _, err := os.Stat(filepath.Join("..", "units", file)); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("%s is in the root helpers' directory (%v)", file, err)
				}
			}
		})
	}

	// The console's group is the module class's alone: no root helper's socket names it.
	for _, name := range helperschema.Helpers() {
		socket := unitDirectives(t, rootUnit(name, "olivares-helper-"+name+".socket"))
		if slices.Contains(socket["Socket.SocketGroup"], helperschema.Portal.Account) || !slices.Equal(socket["Socket.SocketMode"], []string{"0600"}) {
			t.Errorf("the root helper %s's socket is group %v mode %v, want root's alone", name, socket["Socket.SocketGroup"], socket["Socket.SocketMode"])
		}
	}
}
