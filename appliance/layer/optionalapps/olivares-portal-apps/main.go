// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

// olivares-portal-apps installs, starts, stops and uninstalls the appliance's optional apps for an
// invoker the kernel attests, and answers their state.
//
// Its socket unit, olivares-helper-apps.socket, listens on /run/olivares-helpers/apps.sock with
// Accept=yes and starts one instance per connection, as root, with the connection as its standard
// input and output. It reads one document, {"op": "status" | "install" | "start" | "stop" |
// "uninstall", ...}, takes no argument and no path, admits the Appliance Console alone from the
// connection, and runs the app's fixed Compose project with the local Docker daemon: the app is selected only by an embedded manifest digest (Nginx Proxy Manager or
// Cloudflare Tunnel), with a fixed image and private state directory. A document names
// no image, folder, port or Docker account. Until the appliance's kernel is proven to give each
// instance its peer's pidfd, every lifecycle act is refused with pidfd_unproven; status is not.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/olivaresai/olivares/appliance/layer/helpers/helperschema"
	"github.com/olivaresai/olivares/appliance/layer/helpers/invocation"
	"github.com/olivaresai/olivares/appliance/layer/optionalapps"
)

// appDirectory is the app's private persistent directory: the unit's StateDirectory, root's alone.
const appDirectory = "/var/lib/olivares-apps/nginx-proxy-manager"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	code := invocation.Serve(ctx, helper(appliance), invocation.Linux{}, os.Args[1:], 0, os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

// appliance opens the installed host's Compose executor: the app directory, the local Docker
// daemon and the native bind probe.
func appliance() (optionalapps.Compose, error) {
	root, err := os.OpenRoot(appDirectory)
	if err != nil {
		return optionalapps.Compose{}, err
	}
	return optionalapps.Compose{Root: root, Run: optionalapps.LinuxRun, PortAvailable: optionalapps.PortAvailable}, nil
}

// helper is the apps helper over open, which returns the executor for one connection.
func helper(open func() (optionalapps.Compose, error)) invocation.Helper {
	return invocation.Helper{
		Name:       helperschema.HelperApps,
		Rules:      optionalapps.Rules(),
		NewRequest: func() helperschema.Request { return &optionalapps.LifecycleRequest{} },
		Perform: func(ctx context.Context, _ helperschema.Peer, request helperschema.Request) helperschema.Response {
			req, ok := request.(*optionalapps.LifecycleRequest)
			if !ok {
				return helperschema.Response{Result: helperschema.ResultRefused, Code: helperschema.CodeInputRefused, Detail: "not a document of this helper"}
			}
			app, valid := optionalapps.AppForManifest(req.Manifest)
			if !valid {
				return helperschema.Response{Result: helperschema.ResultRefused, Code: helperschema.CodeInputRefused}
			}
			var x optionalapps.Compose
			var err error
			if app == optionalapps.Cloudflared {
				var root *os.Root
				root, err = os.OpenRoot("/var/lib/olivares-apps/cloudflared")
				x = optionalapps.Compose{App: app, Root: root, Run: optionalapps.LinuxRun, PortAvailable: optionalapps.PortAvailable}
			} else {
				x, err = open()
			}
			if err != nil {
				fmt.Fprintln(os.Stderr, "olivares-portal-apps: the app directory cannot be opened:", err)
				return helperschema.Response{Result: helperschema.ResultFailed, Code: helperschema.CodeEffectFailed, Detail: "the app directory cannot be opened; nothing was done"}
			}
			defer x.Root.Close()
			response := optionalapps.LifecycleAnswer(ctx, x, req)
			if response.Detail != "" {
				fmt.Fprintln(os.Stderr, "olivares-portal-apps:", req.Op, response.Result+":", response.Detail)
			}
			return response
		},
	}
}
