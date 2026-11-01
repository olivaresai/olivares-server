// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

// Package updatepage is the Appliance Console's Updates and activation page: the product's licence
// and edition as the product reports them, the state of the entitled channel and of the two update
// units, and the policy of the AlmaLinux operating system updates, with the command that performs each act.
//
// The page has no source of its own. The licence is the product's answer to GET /v1/console/license,
// the unit states are the console's last completed read of the units helper, and the policy is the
// image's: security updates only, applied by dnf-automatic in its nightly window. It performs no read
// and no act, and it starts no helper. The one form it can carry posts a licence to the console, which
// relays it to the product's own licence API under the caller's session; the product decides.
package updatepage

import (
	"html/template"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode"
)

// Unit is one unit's state as the units helper's inventory lists it.
type Unit struct{ Name, Active, Sub string }

// Snapshot is what the page renders.
type Snapshot struct {
	// SignInStatement is the sign-in mode statement every page shows.
	SignInStatement string
	// Licence is the product's answer; the zero value is unread.
	Licence Licence
	// Units are the console's last read of the watched units, in any order and with any other
	// units the inventory lists; UnitsMeasured is false until an inventory was read.
	Units         []Unit
	UnitsMeasured bool
	// UnitsTruncated is true when the inventory was cut at its bound: a unit it does not list may exist.
	UnitsTruncated bool
	// CSRF is the product's token for this browser session. Without it the page offers no form: it
	// names the command line instead.
	CSRF string
	// Result is the console's sentence about the activation it just relayed.
	Result string
}

// act is one act of a watched unit: a verb of the services module and its title.
type act struct{ Title, Op string }

// watched is the closed list of units the page reports, in the order it shows them, and the acts of
// each that it names a command for. The entitled channel's refresh service is read only: the licence
// path unit and the timer own it.
var watched = []struct {
	Name, Role string
	Acts       []act
}{
	{"olivares-entitled-repo.service", "Entitled channel refresh", nil},
	{"olivares-appliance-update.service", "Product update", []act{{"Start the product update", "start"}, {"Read its log", "logs"}}},
	// enable and disable only decide whether the timer starts at boot; stopping and starting it now are their own acts.
	{"dnf-automatic-install.timer", "Automatic OS security updates", []act{
		{"Stop the timer (until it is started or the host boots)", "stop"}, {"Start the timer now", "start"},
		{"Do not start the timer at boot", "disable"}, {"Start the timer at every boot", "enable"},
	}},
	{"dnf-automatic-install.service", "OS security update run", []act{{"Apply the OS security updates now", "start"}, {"Read its log", "logs"}}},
}

// actRow is one act the page names, with the command that performs it on the appliance, as root.
type actRow struct{ Unit, Op, Title, Command string }

// command names the console's own command for an act: `olivares-appliance service` plans it and,
// with the plan's digest, performs it as the act of the services module, with its receipt. The class
// table names every unit of the list above, so the command line does not refuse these acts.
func command(op, unit string) string {
	if op == "logs" {
		return "olivares-appliance service logs " + unit + " --lines <n>"
	}
	return "olivares-appliance service " + op + " " + unit
}

// acts returns every act the page names.
func acts() []actRow {
	var out []actRow
	for _, w := range watched {
		out = append(out, rowActs(w.Name, w.Acts)...)
	}
	return out
}

func rowActs(unit string, list []act) []actRow {
	var out []actRow
	for _, a := range list {
		out = append(out, actRow{Unit: unit, Op: a.Op, Title: a.Title, Command: command(a.Op, unit)})
	}
	return out
}

// Commands returns the command line of every act the page names, in the order it shows them.
func Commands() []string {
	var out []string
	for _, a := range acts() {
		out = append(out, a.Command)
	}
	return out
}

// WatchedUnits returns the names of the units the page reports.
func WatchedUnits() []string {
	names := make([]string, 0, len(watched))
	for _, w := range watched {
		names = append(names, w.Name)
	}
	return names
}

type unitRow struct {
	Name, Role, State string
	Acts              []actRow
}

type view struct {
	SignInStatement, CSRF, Result string
	Licence                       Licence
	EditionLabel, ExpiresOn       string
	Next                          string
	Units                         []unitRow
	UnitsMeasured                 bool
}

func (s Snapshot) view() view {
	v := view{SignInStatement: s.SignInStatement, CSRF: s.CSRF, Result: s.Result, Licence: s.Licence, UnitsMeasured: s.UnitsMeasured}
	l := s.Licence
	if l.Read {
		v.EditionLabel = "Community build"
		if l.Edition == "enterprise" {
			v.EditionLabel = "Business build"
		}
		if l.ExpiresAt != nil {
			v.ExpiresOn = l.ExpiresAt.UTC().Format(time.DateOnly)
		}
		v.Next = next(l)
	}
	byName := map[string]Unit{}
	for _, u := range s.Units {
		byName[u.Name] = u
	}
	for _, w := range watched {
		row := unitRow{Name: w.Name, Role: w.Role, State: "unmeasured", Acts: rowActs(w.Name, w.Acts)}
		if s.UnitsMeasured {
			u, listed := byName[w.Name]
			switch {
			case listed:
				row.State = word(u.Active) + " (" + word(u.Sub) + ")"
			case s.UnitsTruncated:
				// The inventory was cut: the unit may be loaded beyond the cut.
			case strings.HasSuffix(w.Name, ".timer"):
				row.State = "not loaded: off, or not installed"
			default:
				row.State = "not loaded: idle, or not installed"
			}
		}
		v.Units = append(v.Units, row)
	}
	return v
}

// word keeps a state word to what a state word is: the service manager's lowercase names.
func word(s string) string {
	if s == "" || len(s) > 32 || strings.IndexFunc(s, func(r rune) bool { return !(unicode.IsLower(r) || r == '-') }) >= 0 {
		return "unmeasured"
	}
	return s
}

// next is the one sentence that says what the licence's state asks of the administrator.
func next(l Licence) string {
	business := l.Edition == "enterprise"
	switch {
	case l.ManagedExternally:
		return "The licence is managed outside this console (a boot override), so it cannot be changed here."
	case l.Status == "none":
		return "No licence is installed. Activate a Business licence to make the Business packages available from the entitled channel."
	case l.Status == "invalid":
		return "The installed licence does not verify. Activate a valid one."
	case l.Status == "expired" && business:
		return "The licence expired: the entitled channel offers security updates only until a current licence is activated."
	case l.Status == "expired":
		return "The licence expired: activate a current one."
	case business:
		return "The Business build is running."
	}
	return "The licence is active and this is the Community build. Apply the product update to switch to the Business build."
}

var page = template.Must(template.New("updates").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Updates and activation</title>
</head>
<body>
<h1>Updates and activation</h1>
<p>{{.SignInStatement}}</p>
{{with .Result}}<p role="status">{{.}}</p>
{{end}}<h2>Edition and licence</h2>
{{if .Licence.Read}}<dl>
<dt>Edition</dt><dd>{{.EditionLabel}}</dd>
<dt>Licence</dt><dd>{{.Licence.Status}}</dd>
{{with .Licence.Licensee}}<dt>Licensee</dt><dd>{{.}}</dd>
{{end}}{{with .Licence.Plan}}<dt>Plan</dt><dd>{{.}}</dd>
{{end}}{{with .ExpiresOn}}<dt>Expires</dt><dd>{{.}}</dd>
{{end}}</dl>
<p>{{.Next}}</p>
{{else}}<p>The licence is unread: the product did not answer, refused this session, or sent an answer this page does not know. The product console on port 8443 and <code>olivares license status</code> report it.</p>
{{end}}{{if .CSRF}}<form method="post" action="/updates/licence" enctype="application/x-www-form-urlencoded">
<input type="hidden" name="csrf_token" value="{{.CSRF}}">
<p><label>Licence <textarea name="license" rows="6" cols="72" required autocomplete="off" spellcheck="false"></textarea></label></p>
<p><button type="submit">Activate licence</button></p>
</form>
<p>The console passes the licence to the product's own licence API under your sign-in; the product verifies it and decides. Nothing else on this page changes the appliance.</p>
{{else}}<p>To activate a licence from the command line: <code>olivares license install &lt;file&gt;</code>, or <code>olivares license connect</code>. The form appears when this console holds a browser session that the product confirms.</p>
{{end}}<h2>Product updates</h2>
<p>The Olivares packages (the product, the appliance layer and the SELinux policy) come from the entitled channel, signed, and are never applied without an administrator's act: the automatic AlmaLinux run leaves them out, even a security fix of theirs. Once a licence is installed the channel is refreshed at once and every six hours.</p>
<h2>AlmaLinux updates</h2>
<p>By default the appliance applies security updates only, from the AlmaLinux repositories, automatically through dnf-automatic: the Olivares packages are left out of that run (see Product updates), and so are the other kinds of AlmaLinux update. It reboots after them only when a reboot is needed, and only in the nightly window: the schedule of <code>dnf-automatic-install.timer</code> (03:00 by default; <code>systemctl list-timers dnf-automatic-install.timer</code> shows it now). A night the host was off is not made up when it boots, so a reboot never lands outside the window: the next night takes it, or apply the updates now with the command below: it reboots the host about a minute after the run when an update needs it, as the nightly run does.</p>
<h2>State</h2>
<p>Acts on units are not carried by this page: each is one operation with its own act authorization, plan and confirmation, which the console's command line carries. Run a command below on the appliance: it shows the plan and the command that confirms it with the plan's digest, and the confirmed act has a receipt of its own; in the log command, replace <code>&lt;n&gt;</code> with the number of lines you want. A service that is not loaded is idle or not installed: the service manager unloads a service that finished without failing and keeps a failed one. A timer that is not loaded is off or not installed.</p>
<table>
<thead><tr><th>Unit</th><th>State</th><th>What it is</th><th>Commands</th></tr></thead>
<tbody>
{{range .Units}}<tr><td>{{.Name}}</td><td>{{.State}}</td><td>{{.Role}}</td><td>{{range .Acts}}{{.Title}}: <code>{{.Command}}</code><br>
{{else}}none{{end}}</td></tr>
{{end}}</tbody>
</table>
</body>
</html>
`))

// Page serves the Updates and activation page for s, GET and HEAD only.
func Page(s Snapshot) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		Write(w, http.StatusOK, s)
	})
}

// Write answers with the page for s and status code. The console uses it for the answer to a relayed
// activation, which is the page again with the outcome on top.
func Write(w http.ResponseWriter, status int, s Snapshot) {
	var out strings.Builder
	if err := page.Execute(&out, s.view()); err != nil {
		http.Error(w, "page unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, out.String())
}

// Unconfirmed is the sentence for an install the product answered with success while the licence read
// back afterwards shows none: the page says what it saw and does not call the licence installed.
const Unconfirmed = "The product accepted the licence, but the licence below does not show it yet. Reload this page; if it still does not show, run olivares license status on the appliance."

// Outcome is the sentence for the product's answer to a relayed activation: status is the code the page
// is answered with, and unanswered is true when the product gave none. It names the status and never
// repeats the product's own text, which may carry what the caller sent.
func Outcome(status int, unanswered bool) string {
	switch {
	case unanswered, status >= http.StatusInternalServerError && status != http.StatusNotImplemented:
		// A product that failed after it was asked may have written the licence first.
		return "The product did not complete the request, so the licence may or may not have been installed. The licence below is what it holds now."
	case status == http.StatusOK:
		return "The licence is installed. The entitled channel is refreshed now; apply the product update below to take the Business packages."
	case status == http.StatusUnauthorized:
		return "Sign in again: the product no longer knows this session."
	case status == http.StatusForbidden:
		return "The product refused (403): a step-up sign-in is required, this page's token is stale (reload the page), or this account may not install a licence. Sign in again with your authenticator code, or use the product console on port 8443."
	case status == http.StatusConflict:
		return "The licence is managed outside this console (a boot override), so it was not changed."
	case status == http.StatusBadRequest, status == http.StatusUnprocessableEntity:
		return "The product did not accept this licence: it does not verify or is not a licence."
	case status == http.StatusNotImplemented:
		return "The licence service is not available on this product."
	}
	return "The product did not install the licence."
}
