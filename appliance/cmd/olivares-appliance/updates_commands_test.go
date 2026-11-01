// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package main

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/olivaresai/olivares/appliance/layer/hostops/console"
	"github.com/olivaresai/olivares/appliance/layer/services"
	"github.com/olivaresai/olivares/appliance/layer/updatepage"
)

// The Updates page sends the administrator to a command for every act, and no command it names may be
// one the console refuses. Each is an `olivares-appliance service` command on a unit the page reports,
// whose verb the class table admits, run here through the CLI's own refusals with a console that offers
// the apply: a command without --plan or --confirm shows the act's plan and names the command that
// confirms it, and sends nothing. The page names no other program.
func TestUpdatesPage_NoCommandItNamesIsOneTheConsoleRefuses(t *testing.T) {
	commands := updatepage.Commands()
	if len(commands) == 0 {
		t.Fatal("the page names no command")
	}
	watched := updatepage.WatchedUnits()
	for _, command := range commands {
		words := strings.Fields(strings.ReplaceAll(command, "<n>", "20"))
		if len(words) < 4 || words[0] != "olivares-appliance" || words[1] != "service" {
			t.Errorf("%q: the page names a program that is not the console's command line", command)
			continue
		}
		verb, unit := words[2], words[3]
		if !services.IsAct(verb) || !slices.Contains(watched, unit) || services.Check(verb, unit) != nil {
			t.Errorf("%q is not an act the class table admits on a unit the page reports", command)
		}
		s := &restartingSession{}
		var out, diagnostic bytes.Buffer
		code, handled := runService(t.Context(), words[1:], &out, &diagnostic,
			func() (console.Session, error) { return s, nil },
			func() (moduleSession, error) { return hostReads(), nil })
		confirm := "Confirm: " + strings.Join(words, " ") + " --confirm " + strings.Repeat("a", 64)
		if !handled || code != 0 || slices.Contains(words, "--plan") || s.applied != 0 || len(s.plans) != 1 || !strings.Contains(out.String(), confirm) {
			t.Errorf("%q is named by the page and refused, performed or not confirmable: handled %t, exit %d, plans %v, stdout %q, stderr %q", command, handled, code, s.plans, out.String(), diagnostic.String())
		}
	}
}
