// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package console

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/olivaresai/olivares/appliance/layer/services"
)

// runConfirmedResource uses one confirmation grammar for service units, data
// filesystems, the fixed optional app, an optional app's firewall rows and
// prepared host package. All reuse the local Apply transport.
func runConfirmedResource(ctx context.Context, args []string, out, diagnostic io.Writer, dial Dial) int {
	refuse := func() int {
		_, _ = fmt.Fprintln(diagnostic, "input_refused")
		return 1
	}
	if len(args) < 2 {
		return refuse()
	}
	key := "unit"
	start := 3
	values := map[string]string{}
	switch args[0] {
	case "service":
		if len(args) < 3 || args[2] == "" || !services.IsAct(args[1]) {
			return refuse()
		}
		values[key] = args[2]
	case "storage":
		if len(args) < 3 || (args[1] != "mount" && args[1] != "unmount") {
			return refuse()
		}
		key = "filesystem_uuid"
		uuid := args[2]
		if len(uuid) != 36 || uuid[8] != '-' || uuid[13] != '-' || uuid[18] != '-' || uuid[23] != '-' || !validID(strings.ReplaceAll(uuid, "-", "")) {
			return refuse()
		}
		values[key] = args[2]
	case "nginx-proxy-manager":
		if args[1] != "install" && args[1] != "start" && args[1] != "stop" && args[1] != "uninstall" {
			return refuse()
		}
		start = 2
	case "host-package":
		if args[1] != "update" && args[1] != "recover" {
			return refuse()
		}
		start = 2
	case "firewall":
		if len(args) < 4 || args[1] != "app-row" || !simpleName(args[2]) || args[3] != "add" && args[3] != "remove" {
			return refuse()
		}
		values["app"], values["change"] = args[2], args[3]
		start = 4
	default:
		return refuse()
	}
	var confirm, operation string
	asJSON, planOnly := false, false
	seen := map[string]bool{}
	for i := start; i < len(args); i++ {
		flag := args[i]
		if seen[flag] {
			return refuse()
		}
		seen[flag] = true
		if flag == "--plan" {
			planOnly = true
			continue
		}
		if i+1 >= len(args) {
			return refuse()
		}
		i++
		switch flag {
		case "--confirm":
			confirm = args[i]
		case "--operation-id":
			operation = args[i]
		case "--output":
			if args[i] != "json" {
				return refuse()
			}
			asJSON = true
		case "--revert-after":
			// The window the owner holds an unconfirmed load for: whole seconds, 60 to 600.
			if n, err := strconv.Atoi(args[i]); args[0] != "firewall" || err != nil || n < 60 || n > 600 || strconv.Itoa(n) != args[i] {
				return refuse()
			}
			values["revert_after_s"] = args[i]
		case "--lines":
			// How many entries a logs act reads: whole numbers, 1 to the helper's bound.
			if n, err := strconv.Atoi(args[i]); args[0] != "service" || args[1] != services.OpLogs || err != nil || n < 1 || n > services.MaxLogLines || strconv.Itoa(n) != args[i] {
				return refuse()
			}
			values["lines"] = args[i]
		default:
			return refuse()
		}
	}
	if confirm == "" && !planOnly || confirm != "" && (!validDigest(confirm) || planOnly) || operation != "" && (!validID(operation) || confirm == "") || asJSON && confirm == "" {
		return refuse()
	}
	return runConfirmedTask(ctx, args[0], args[1], values, confirm, operation, asJSON, out, diagnostic, dial)
}
