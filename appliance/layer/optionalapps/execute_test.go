// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package optionalapps

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"text/template"
)

type dockerHost struct {
	root      *os.Root
	installed bool
	running   bool
	effects   []string
	fail      string
	lostRead  bool
	foreign   string
	portBusy  bool
	probes    []string
}

func newDockerHost(t *testing.T) *dockerHost {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return &dockerHost{root: root}
}

func (h *dockerHost) executor() Compose {
	return Compose{Root: h.root, Run: h.run, PortAvailable: h.port}
}

func (h *dockerHost) port(_ context.Context, address string) error {
	h.probes = append(h.probes, address)
	if h.fail == "preparation" && address == "127.0.0.1:81" {
		return h.root.WriteFile("letsencrypt", []byte("fixture preparation obstruction"), 0600)
	}
	if h.portBusy {
		return errors.New("port in use")
	}
	return nil
}

func (h *dockerHost) run(_ context.Context, argv []string, limit int64) ([]byte, error) {
	prefix := []string{"/usr/bin/docker", "--host", "unix:///var/run/docker.sock", "--config", filepath.Join(h.root.Name(), "docker-config")}
	if len(argv) < len(prefix)+1 || !slices.Equal(argv[:len(prefix)], prefix) || limit > 16<<10 {
		return nil, errors.New("not the fixed local native Docker command")
	}
	args := argv[len(prefix):]
	if args[0] == "container" {
		if h.lostRead && len(h.effects) > 0 {
			return nil, errors.New("daemon answer lost")
		}
		if args[1] == "ls" {
			if h.foreign == "extra project service" && slices.Contains(args, "label=com.docker.compose.project=olivares-nginx-proxy-manager") {
				return []byte(strings.Repeat("c", 64) + "\n" + strings.Repeat("d", 64) + "\n"), nil
			}
			if h.installed {
				return []byte(strings.Repeat("c", 64) + "\n"), nil
			}
			return nil, nil
		}
		if args[1] == "inspect" {
			m, err := manifest()
			if err != nil {
				return nil, err
			}
			app := m.Services["app"]
			state := nativeState{ID: strings.Repeat("c", 64), Image: app.Image, Labels: map[string]string{"com.docker.compose.project": m.Name, "com.docker.compose.service": "app"}, Running: h.running, Status: "exited", Restart: "unless-stopped", Ports: map[string][]nativePort{}}
			if h.running {
				state.Status = "running"
			}
			for _, v := range app.Volumes {
				state.Mounts = append(state.Mounts, nativeMount{Type: "bind", Source: filepath.Join(h.root.Name(), v.Source), Destination: v.Target, RW: true})
			}
			for _, p := range app.Ports {
				state.Ports[portKey(p)] = []nativePort{{HostIP: p.HostIP, HostPort: p.Published}}
			}
			switch h.foreign {
			case "other image":
				state.Image = "docker.io/unknown/image:latest"
			case "other project":
				state.Labels["com.docker.compose.project"] = "other"
			case "other mount":
				state.Mounts[0].Source = "/somebody-elses-data"
			case "public admin port":
				state.Ports["81/tcp"][0].HostIP = "0.0.0.0"
			}
			// Docker's inspector falls back to its raw native JSON map when a
			// typed field (such as Id) differs. Exercise the actual Go template,
			// rather than fabricating the helper's selected JSON response.
			raw := map[string]any{
				"Id":         state.ID,
				"Config":     map[string]any{"Image": state.Image, "Labels": state.Labels, "Env": []string{"fixture-secret-must-not-appear"}},
				"State":      map[string]any{"Running": state.Running, "Status": state.Status},
				"HostConfig": map[string]any{"RestartPolicy": map[string]any{"Name": state.Restart}, "PortBindings": state.Ports},
				"Mounts":     state.Mounts,
			}
			if len(args) != 5 || args[2] != "--format" || args[4] != state.ID {
				return nil, errors.New("inspection was not bound to the measured native ID")
			}
			tmpl, err := template.New("native inspect").Option("missingkey=error").Funcs(template.FuncMap{"json": func(v any) (string, error) {
				data, err := json.Marshal(v)
				return string(data), err
			}}).Parse(args[3])
			if err != nil {
				return nil, err
			}
			var out bytes.Buffer
			if err := tmpl.Execute(&out, raw); err != nil {
				return nil, err
			}
			if strings.Contains(out.String(), "fixture-secret-must-not-appear") {
				return nil, errors.New("inspection exposed the container environment")
			}
			return out.Bytes(), nil
		}
		return nil, errors.New("unexpected inventory read")
	}
	if args[0] != "compose" {
		return nil, errors.New("unexpected native operation")
	}
	for _, value := range []string{"--file", filepath.Join(h.root.Name(), "compose.yaml"), "--project-directory", h.root.Name(), "--project-name", "olivares-nginx-proxy-manager", "--env-file", filepath.Join(h.root.Name(), "empty.env")} {
		if !slices.Contains(args, value) {
			return nil, errors.New("native project input was not fixed")
		}
	}
	for _, forbidden := range []string{"--volumes", "--rmi", "--remove-orphans", "--build", "--force-recreate"} {
		if slices.Contains(args, forbidden) {
			return nil, errors.New("destructive or unpinned native flag")
		}
	}
	command := ""
	for _, c := range []string{"config", "pull", "up", "start", "stop", "down"} {
		if slices.Contains(args, c) {
			command = c
		}
	}
	if command == "config" {
		data, err := h.root.ReadFile("compose.yaml")
		if err != nil || !strings.Contains(string(data), "docker.io/jc21/nginx-proxy-manager@sha256:4393e642e233e5efd5adeb7f10918d4aaea71c9ed875b94190273fc8e87f9594") || strings.Contains(string(data), "latest") {
			return nil, errors.New("official image was not pinned")
		}
		return nil, nil
	}
	h.effects = append(h.effects, command)
	if h.fail == command {
		return nil, errors.New("native command failed")
	}
	switch command {
	case "pull":
	case "up":
		if !slices.Contains(args, "never") || !slices.Contains(args, "--no-build") {
			return nil, errors.New("up could acquire another image")
		}
		h.installed, h.running = true, true
	case "start":
		h.running = true
	case "stop":
		h.running = false
	case "down":
		h.installed, h.running = false, false
	default:
		return nil, errors.New("unexpected native command")
	}
	return nil, nil
}

func TestCompose_NPMNativeLifecycleRetainsDataAcrossReopen(t *testing.T) {
	h := newDockerHost(t)
	x := h.executor()
	before, err := x.Read(t.Context())
	if err != nil || before.Installed || len(h.effects) != 0 {
		t.Fatalf("optional app was enabled by reading: %+v %v", before, err)
	}
	observation, err := x.Apply(t.Context(), "install")
	if err != nil || observation.P1 != "performed" || !slices.Equal(h.effects, []string{"pull", "up"}) {
		t.Fatalf("install: %+v %v effects=%v", observation, err, h.effects)
	}
	if !slices.Equal(h.probes, []string{"0.0.0.0:80", "0.0.0.0:443", "127.0.0.1:81"}) {
		t.Fatal("unexpected published port scope", h.probes)
	}
	for name, content := range map[string]string{"data/database.sqlite": "persistent fixture database", "letsencrypt/account.json": "persistent fixture ACME account"} {
		if err := h.root.WriteFile(name, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(h.root.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	x.Root = root
	for _, op := range []string{"stop", "start", "uninstall"} {
		observation, err := x.Apply(t.Context(), op)
		if err != nil || observation.P1 != "performed" {
			t.Fatalf("%s: %+v %v", op, observation, err)
		}
	}
	if !slices.Equal(h.effects, []string{"pull", "up", "stop", "start", "down"}) {
		t.Fatal("an operation was implicitly retried", h.effects)
	}
	for _, name := range []string{"data/database.sqlite", "letsencrypt/account.json"} {
		if data, err := root.ReadFile(name); err != nil || !strings.HasPrefix(string(data), "persistent fixture") {
			t.Fatalf("uninstall lost persistent data: %s %v", name, err)
		}
	}
	t.Logf("fake native effects=%v; real private data reopened and retained", h.effects)
}

func TestCompose_PortForeignStateAndModifiedInputsRefuseBeforeNativeEffects(t *testing.T) {
	for _, cause := range []string{"port conflict", "other image", "other project", "other mount", "public admin port", "extra project service", "edited compose file", "Docker account config", "linked data", "unsupported operation"} {
		t.Run(cause, func(t *testing.T) {
			h := newDockerHost(t)
			x := h.executor()
			op := "install"
			switch cause {
			case "port conflict":
				h.portBusy = true
			case "other image", "other project", "other mount", "public admin port", "extra project service":
				h.installed, h.running, h.foreign = true, true, cause
				op = "uninstall"
			case "edited compose file":
				_ = h.root.WriteFile("compose.yaml", []byte("foreign configuration"), 0600)
			case "Docker account config":
				_ = h.root.Mkdir("docker-config", 0700)
				_ = h.root.WriteFile("docker-config/config.json", []byte("fixture account must not be read"), 0600)
			case "linked data":
				_ = h.root.Symlink(t.TempDir(), "data")
			case "unsupported operation":
				op = "purge"
			}
			observation, err := x.Apply(t.Context(), op)
			if err == nil || observation.P1 != "not-performed" || len(h.effects) != 0 {
				t.Fatalf("unsafe input reached native effects: %+v %v effects=%v", observation, err, h.effects)
			}
		})
	}
}

func TestCompose_NativeFailureAndLostMeasurementsDoNotClaimSuccessOrRetry(t *testing.T) {
	for _, cause := range []string{"pull", "up", "lost answer", "preparation"} {
		t.Run(cause, func(t *testing.T) {
			h := newDockerHost(t)
			h.fail = cause
			h.lostRead = cause == "lost answer"
			observation, err := h.executor().Apply(t.Context(), "install")
			want := "failed"
			if h.lostRead {
				want = "unknown"
			}
			if cause == "preparation" {
				if _, dirErr := h.root.Lstat("data"); dirErr != nil || !observation.MeasuredChange || len(h.effects) != 0 {
					t.Fatalf("partial preparation was not reported: %+v %v directory=%v effects=%v", observation, err, dirErr, h.effects)
				}
			}
			if err == nil || observation.P1 != want || len(h.effects) > 2 {
				t.Fatalf("%s: %+v %v effects=%v", cause, observation, err, h.effects)
			}
		})
	}
}
