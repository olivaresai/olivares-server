// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package optionalapps

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/olivaresai/olivares/appliance/layer/hostops"
)

// Compose belongs to the fixed attested helper, under the existing host target
// lock and exact-act authority. Root is its private persistent app directory;
// its data directories are not an operation journal. Run and PortAvailable are
// the native OS seams. This source does not install a runtime or expose a task.
type Compose struct {
	Root          *os.Root
	Run           func(context.Context, []string, int64) ([]byte, error)
	PortAvailable func(context.Context, string) error
}

// State measures only the retained native container, not application readiness,
// certificate issuance, browser sign-in or a working reverse proxy.
type State struct {
	ContainerID string `json:"container_id"`
	Installed   bool   `json:"installed"`
	Running     bool   `json:"running"`
}
type nativeState struct {
	ID, Image, Status, Restart string
	Labels                     map[string]string
	Running                    bool
	Mounts                     []nativeMount
	Ports                      map[string][]nativePort
}
type nativeMount struct {
	Type, Source, Destination string
	RW                        bool
}
type nativePort struct {
	HostIP   string `json:"HostIp"`
	HostPort string
}

// Read makes no native effect. Absence is established by successful empty
// native inventories; a failed daemon read is never treated as uninstalled.
func (x Compose) Read(ctx context.Context) (State, error) {
	if err := x.available(ctx); err != nil {
		return State{}, err
	}
	if err := x.inputs(); err != nil {
		return State{}, err
	}
	m, err := manifest()
	if err != nil {
		return State{}, errors.New("input_refused")
	}
	app := m.Services["app"]
	named, err := x.ids(ctx, "name=^/"+app.ContainerName+"$")
	if err != nil {
		return State{}, err
	}
	project, err := x.ids(ctx, "label=com.docker.compose.project="+m.Name)
	if err != nil {
		return State{}, err
	}
	if len(named) > 1 || !slices.Equal(named, project) {
		return State{}, errors.New("container_identity_changed")
	}
	if len(named) == 0 {
		return State{}, nil
	}
	format := `{"ID":{{json .Id}},"Image":{{json .Config.Image}},"Labels":{{json .Config.Labels}},"Running":{{json .State.Running}},"Status":{{json .State.Status}},"Restart":{{json .HostConfig.RestartPolicy.Name}},"Mounts":[{{range $i,$m := .Mounts}}{{if $i}},{{end}}{"Type":{{json $m.Type}},"Source":{{json $m.Source}},"Destination":{{json $m.Destination}},"RW":{{json $m.RW}}}{{end}}],"Ports":{{json .HostConfig.PortBindings}}}`
	data, err := x.call(ctx, "container", "inspect", "--format", format, named[0])
	var native nativeState
	if err != nil || hostops.DecodeClosed(data, &native) != nil || native.ID != named[0] || native.Image != app.Image || native.Labels["com.docker.compose.project"] != m.Name || native.Labels["com.docker.compose.service"] != "app" || native.Restart != app.Restart || !slices.Contains([]string{"running", "exited", "created"}, native.Status) || native.Running != (native.Status == "running") {
		return State{}, errors.New("container_identity_changed")
	}
	if len(native.Mounts) != len(app.Volumes) || len(native.Ports) != len(app.Ports) {
		return State{}, errors.New("container_identity_changed")
	}
	for _, v := range app.Volumes {
		matches := 0
		for _, mount := range native.Mounts {
			if mount.Type == v.Type && mount.Source == filepath.Join(x.Root.Name(), v.Source) && mount.Destination == v.Target && mount.RW {
				matches++
			}
		}
		if matches != 1 {
			return State{}, errors.New("container_identity_changed")
		}
	}
	for _, p := range app.Ports {
		ports := native.Ports[portKey(p)]
		if len(ports) != 1 || ports[0].HostIP != p.HostIP || ports[0].HostPort != p.Published {
			return State{}, errors.New("container_identity_changed")
		}
	}
	return State{ContainerID: native.ID, Installed: true, Running: native.Running}, nil
}

// Apply issues the fixed native lifecycle once, after fresh ownership and port
// checks. Install explicitly pulls the pinned artifact before starting it.
// Stop/uninstall never remove data, volumes or images. Duplicate operation IDs
// and durable outcomes still belong to the existing hostops caller, not here.
func (x Compose) Apply(ctx context.Context, op string) (hostops.Observation, error) {
	return x.apply(ctx, op, nil)
}

func (x Compose) apply(ctx context.Context, op string, expected *State) (hostops.Observation, error) {
	refuse := func(err error) (hostops.Observation, error) { return hostops.Observation{P1: "not-performed"}, err }
	if !slices.Contains(lifecycleOps, op) {
		return refuse(errors.New("input_refused"))
	}
	before, err := x.Read(ctx)
	if err != nil {
		return refuse(err)
	}
	if expected != nil && before != *expected {
		return refuse(errors.New("container_identity_changed"))
	}
	if (op == "install" && before.Installed) || (op != "install" && !before.Installed) || (op == "start" && before.Running) || (op == "stop" && !before.Running) {
		return refuse(errors.New("already_in_expected_state"))
	}
	m, err := manifest()
	if err != nil {
		return refuse(errors.New("input_refused"))
	}
	if op == "install" || op == "start" {
		if x.PortAvailable == nil {
			return refuse(errors.New("consumer_unavailable"))
		}
		for _, p := range m.Services["app"].Ports {
			if x.PortAvailable(ctx, net.JoinHostPort(p.HostIP, p.Published)) != nil {
				return refuse(errors.New("port_conflict"))
			}
		}
	}
	prepared := false
	if op == "install" {
		prepared, err = x.prepare()
		if err != nil {
			return hostops.Observation{P1: "failed", MeasuredChange: prepared}, err
		}
	} else {
		for _, name := range []string{"compose.yaml", "empty.env", "data", "letsencrypt"} {
			if _, err = x.Root.Lstat(name); err != nil {
				return refuse(errors.New("retained_input_unavailable"))
			}
		}
	}
	var command []string
	switch op {
	case "install":
		_, err = x.compose(ctx, m.Name, "config", "--quiet")
		if err == nil {
			_, err = x.compose(ctx, m.Name, "pull", "--quiet", "app")
		}
		command = []string{"up", "--detach", "--no-build", "--pull", "never", "app"}
	case "start":
		command = []string{"start", "app"}
	case "stop":
		command = []string{"stop", "--timeout", "20", "app"}
	case "uninstall":
		command = []string{"down", "--timeout", "20"}
	}
	if err == nil {
		_, err = x.compose(ctx, m.Name, command...)
	}
	after, readErr := x.Read(ctx)
	if readErr != nil || (before.Installed && after.Installed && before.ContainerID != after.ContainerID) {
		return hostops.Observation{P1: "unknown"}, errors.New("container_measurement_unavailable")
	}
	changed := prepared || before != after
	if err != nil {
		return hostops.Observation{P1: "failed", MeasuredChange: changed}, errors.New("optional_app_command_failed")
	}
	wantInstalled, wantRunning := op != "uninstall", op == "install" || op == "start"
	if after.Installed != wantInstalled || after.Running != wantRunning || x.inputs() != nil {
		return hostops.Observation{P1: "partial", MeasuredChange: changed}, errors.New("optional_app_postcondition_missing")
	}
	for _, name := range []string{"data", "letsencrypt"} {
		if info, err := x.Root.Lstat(name); err != nil || !info.IsDir() {
			return hostops.Observation{P1: "partial", MeasuredChange: changed}, errors.New("optional_app_postcondition_missing")
		}
	}
	return hostops.Observation{P1: "performed", MeasuredChange: changed, Postconditions: []string{"app=nginx-proxy-manager", "container_installed=" + strconv.FormatBool(after.Installed), "container_running=" + strconv.FormatBool(after.Running), "data_directories_retained=true"}}, nil
}

func (x Compose) available(ctx context.Context) error {
	if x.Root == nil || x.Run == nil || ctx.Err() != nil {
		return errors.New("consumer_unavailable")
	}
	info, err := x.Root.Stat(".")
	path := x.Root.Name()
	native, nativeErr := os.Lstat(path)
	resolved, resolveErr := filepath.EvalSymlinks(path)
	if err != nil || !info.IsDir() || !ownedByHelper(info) || info.Mode().Perm()&0077 != 0 || !filepath.IsAbs(path) || filepath.Clean(path) != path || nativeErr != nil || resolveErr != nil || resolved != path || !os.SameFile(info, native) {
		return errors.New("retained_input_unavailable")
	}
	return nil
}
func (x Compose) inputs() error {
	for name, expected := range map[string][]byte{"compose.yaml": nginxProxyManager, "empty.env": nil} {
		info, err := x.Root.Lstat(name)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() || !ownedByHelper(info) || info.Mode().Perm()&0077 != 0 || info.Size() > 16<<10 {
			return errors.New("retained_input_unavailable")
		}
		data, err := x.Root.ReadFile(name)
		if err != nil || !bytes.Equal(data, expected) {
			return errors.New("retained_input_changed")
		}
	}
	for _, name := range []string{"docker-config", "data", "letsencrypt"} {
		info, err := x.Root.Lstat(name)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.IsDir() {
			return errors.New("retained_input_unavailable")
		}
		// The official container can chown its data directories. The helper's
		// private parent still protects them; its own Docker account dir must
		// remain empty and helper-owned. Account file contents are never read.
		if name == "docker-config" {
			if !ownedByHelper(info) || info.Mode().Perm()&0077 != 0 {
				return errors.New("retained_input_unavailable")
			}
			f, err := x.Root.Open(name)
			if err != nil {
				return errors.New("retained_input_unavailable")
			}
			entries, readErr := f.ReadDir(1)
			_ = f.Close()
			if len(entries) != 0 || !errors.Is(readErr, io.EOF) {
				return errors.New("docker_account_config_refused")
			}
		}
	}
	return nil
}
func (x Compose) prepare() (bool, error) {
	changed := false
	for _, name := range []string{"docker-config", "data", "letsencrypt"} {
		err := x.Root.Mkdir(name, 0700)
		if err == nil {
			changed = true
		} else if !errors.Is(err, os.ErrExist) {
			return changed, errors.New("retained_input_unavailable")
		}
	}
	for name, data := range map[string][]byte{"compose.yaml": nginxProxyManager, "empty.env": nil} {
		if _, err := x.Root.Lstat(name); err == nil {
			continue
		}
		f, err := x.Root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return changed, errors.New("retained_input_unavailable")
		}
		changed = true
		_, writeErr := f.Write(data)
		syncErr := f.Sync()
		closeErr := f.Close()
		if writeErr != nil || syncErr != nil || closeErr != nil {
			return changed, errors.New("retained_input_unavailable")
		}
	}
	f, err := x.Root.Open(".")
	if err != nil {
		return changed, errors.New("retained_input_unavailable")
	}
	syncErr := f.Sync()
	closeErr := f.Close()
	if syncErr != nil || closeErr != nil {
		return changed, errors.New("retained_input_unavailable")
	}
	return changed, x.inputs()
}
func (x Compose) ids(ctx context.Context, filter string) ([]string, error) {
	data, err := x.call(ctx, "container", "ls", "--all", "--no-trunc", "--quiet", "--filter", filter)
	if err != nil {
		return nil, errors.New("container_measurement_unavailable")
	}
	ids := strings.Fields(string(data))
	for _, id := range ids {
		if _, err := hex.DecodeString(id); err != nil || len(id) != 64 || strings.ToLower(id) != id {
			return nil, errors.New("container_measurement_unavailable")
		}
	}
	slices.Sort(ids)
	return ids, nil
}
func (x Compose) compose(ctx context.Context, project string, args ...string) ([]byte, error) {
	prefix := []string{"compose", "--ansi", "never", "--project-name", project, "--project-directory", x.Root.Name(), "--file", filepath.Join(x.Root.Name(), "compose.yaml"), "--env-file", filepath.Join(x.Root.Name(), "empty.env")}
	return x.call(ctx, append(prefix, args...)...)
}
func (x Compose) call(ctx context.Context, args ...string) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, errors.New("consumer_unavailable")
	}
	argv := []string{"/usr/bin/docker", "--host", "unix:///var/run/docker.sock", "--config", filepath.Join(x.Root.Name(), "docker-config")}
	data, err := x.Run(ctx, append(argv, args...), 16<<10)
	if len(data) > 16<<10 {
		return nil, errors.New("native_output_limit")
	}
	return data, err
}

// PortAvailable is a native bind probe, not a reservation or a firewall claim.
// A later race is still a failed native action, never a successful installation.
func PortAvailable(ctx context.Context, address string) error {
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp4", address)
	if err != nil {
		return errors.New("port_conflict")
	}
	return listener.Close()
}
