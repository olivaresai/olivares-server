// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/olivaresai/olivares/appliance/layer/hostops/console"
	"github.com/olivaresai/olivares/appliance/layer/portal/localsession"
	"github.com/olivaresai/olivares/appliance/layer/services"
)

// anyUnit is a local API that has read every unit: services.status answers whichever unit is asked.
type anyUnit struct{ *reads }

func (a anyUnit) Read(query, unit string, offset int, surface string) (localsession.ModuleAnswer, error) {
	if query != localsession.QueryServicesStatus {
		return a.reads.Read(query, unit, offset, surface)
	}
	class := services.Classify(unit)
	return localsession.ModuleAnswer{Query: query, Total: 1, Unit: &localsession.UnitStatus{Unit: unit, Class: string(class), Consequence: class.Consequence(),
		Allowed: []string{"status"}, LoadState: "loaded", ActiveState: "active", SubState: "running"}}, nil
}

var pageCommand = regexp.MustCompile(`olivares-appliance service [a-z]+ [A-Za-z0-9:_.@\\-]+(?: --lines [0-9]+)?`)

// The Services page prints the command that plans or reads each unit's acts, and no command it names
// may be one the console refuses: each is run through the CLI's own refusals, as the Updates page's
// commands are. A command that is not a read plans an act and sends nothing.
func TestServicesPage_NoCommandItNamesIsOneTheConsoleRefuses(t *testing.T) {
	var units []services.Listed
	for _, name := range []string{"olivares.service", "sshd.service", "chronyd.service", "dnf-automatic-install.timer", "dnf-automatic-install.service",
		"olivares-appliance-update.service", "dbus.service", "olivares-app-example.service"} {
		units = append(units, services.Listed{Unit: services.Unit{Name: name, LoadState: "loaded", ActiveState: "active", SubState: "running"}})
	}
	rec := httptest.NewRecorder()
	services.Page(services.Snapshot{Measured: true, Inventory: services.Inventory{Units: units}}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/services", nil))
	commands := pageCommand.FindAllString(rec.Body.String(), -1)
	acts := 0
	for _, command := range commands {
		words := strings.Fields(command)
		s := &restartingSession{}
		var out, diagnostic bytes.Buffer
		code, handled := runService(t.Context(), words[1:], &out, &diagnostic,
			func() (console.Session, error) { return s, nil },
			func() (moduleSession, error) { return anyUnit{hostReads()}, nil })
		if !handled || code != 0 || diagnostic.Len() != 0 || s.applied != 0 {
			t.Errorf("%q is named by the page and refused: handled %t, exit %d, stdout %q, stderr %q", command, handled, code, out.String(), diagnostic.String())
		}
		if services.IsAct(words[2]) {
			acts++
			if len(s.plans) != 1 || !strings.Contains(out.String(), "Confirm: "+command+" --confirm") {
				t.Errorf("%q plans %v and does not name the command that confirms it:\n%s", command, s.plans, out.String())
			}
		}
	}
	// Every act the class table admits on a listed unit has its command on the page.
	for _, u := range units {
		class := services.Classify(u.Name)
		for _, op := range services.Ops() {
			if services.IsEffect(op) && class.Allows(op) && !slices.Contains(commands, "olivares-appliance service "+op+" "+u.Name) {
				t.Errorf("the page does not name %s %s, which the class table admits", op, u.Name)
			}
		}
	}
	if acts == 0 {
		t.Fatal("the page names no act")
	}
}
