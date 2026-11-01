// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package storage

import (
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"
)

var pageFuncs = template.FuncMap{
	"space": func(n uint64) string { return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30)) },
	"actionAllowed": func(inv Inventory, op, digest string) bool {
		_, err := SelectAction(inv, op, digest)
		return err == nil
	},
	"tailSpace": func(d Disk) uint64 {
		if d.Filesystem != nil && len(d.Partitions) == 0 {
			return 0
		}
		var end uint64
		for _, p := range d.Partitions {
			if p.Offset > d.Size || p.Size > d.Size-p.Offset {
				return 0
			}
			if p.Offset+p.Size > end {
				end = p.Offset + p.Size
			}
		}
		return d.Size - end
	},

	"join": strings.Join,
	"consumers": func(list []Consumer) string {
		if len(list) == 0 {
			return "none"
		}
		out := make([]string, 0, len(list))
		for _, c := range list {
			out = append(out, c.Kind+" "+c.Name)
		}
		return strings.Join(out, ", ")
	},
	"operations": func(list []Operation) string {
		if len(list) == 0 {
			return "none reported"
		}
		out := make([]string, 0, len(list))
		for _, o := range list {
			s := o.Name + " " + o.Type
			if len(o.Modes) > 0 {
				s += " (" + strings.Join(o.Modes, ", ") + ")"
			}
			if o.Disabled != "" {
				s += " [disabled: " + o.Disabled + "]"
			}
			out = append(out, s)
		}
		return strings.Join(out, ", ")
	},
	"filesystem": func(fs *Filesystem) string {
		if fs == nil {
			return "none"
		}
		s := fs.Type
		if fs.Label != "" {
			s += " label " + fs.Label
		}
		if len(fs.MountPoints) > 0 {
			s += " mounted at " + strings.Join(fs.MountPoints, ", ")
		}
		return s
	},
	"identity": func(id Identity) string {
		switch {
		case id.Kind == "":
			return "none (" + id.Missing + "): no plan can name this disk"
		case id.Ambiguous:
			return id.Kind + " by " + id.Source + ", shared with another disk: no plan can name this disk"
		case id.BootID != "":
			return id.Kind + " by " + id.Source + " " + id.Value + ", valid in boot " + id.BootID + " only"
		}
		return id.Kind + " by " + id.Source + " " + id.Value
	},
}

var storagePage = template.Must(template.New("storage").Funcs(pageFuncs).Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>:root{color-scheme:light dark}body{font:1rem/1.5 system-ui,sans-serif;max-width:72rem;margin:auto;padding:1rem;background:Canvas;color:CanvasText}h1,h2{line-height:1.2}li{overflow-wrap:anywhere}form{display:inline-block;margin:.4rem .6rem .4rem 0}button{font:inherit;max-width:100%;white-space:normal;min-height:44px;padding:.6rem 1rem;cursor:pointer}a:focus-visible,button:focus-visible{outline:3px solid Highlight;outline-offset:3px}.table-scroll{overflow-x:auto}table{border-collapse:collapse}th,td{text-align:left;padding:.6rem;border-bottom:1px solid GrayText}.notice{padding:1rem;border:1px solid GrayText;border-radius:.5rem;overflow-wrap:anywhere}input{font:inherit}</style>
<title>Storage — Appliance Console</title>
</head>
<body><main>
<h1>Storage</h1>
<p>{{.SignIn}}</p>
{{if .Actions.CSRF}}<p>Choose a backup disk or grow the data volume after enlarging this appliance's disk. Each change needs your confirmation.</p>{{else}}<p>Read-only inventory of disks, partitions, filesystems, swap and LVM. Nothing on this page changes the appliance; storage changes require a signed-in system administrator. An LVM metadata backup or a snapshot is not a data backup.</p>{{end}}
{{if .Actions.Result}}<p class="notice" role="status">{{.Actions.Result}}</p>{{end}}
{{if .Actions.CSRF}}{{with .Actions.Plan}}<section class="notice" aria-labelledby="confirm-heading"><h2 id="confirm-heading">Confirm {{if eq .Op "backup"}}backup disk{{else}}data growth{{end}}</h2>
<p>{{if eq .Op "backup"}}{{if .RegistrationOnly}}The disk is prepared. Finish saving it as the backup target.{{else}}This erases all data on {{.DiskName}} and formats it for backups.{{end}}{{else}}Grow the data volume on {{.DiskName}} to use the additional disk space without restarting.{{end}}</p>
<form method="post" action="/storage/action"><input type="hidden" name="csrf_token" value="{{$.Actions.CSRF}}"><input type="hidden" name="stage" value="apply"><input type="hidden" name="op" value="{{.Op}}"><input type="hidden" name="disk_digest" value="{{.DiskDigest}}"><input type="hidden" name="operation_id" value="{{.OperationID}}"><input type="hidden" name="confirmation" value="{{.Confirmation}}"><button type="submit">{{if .RegistrationOnly}}Finish backup setup{{else}}Confirm {{if eq .Op "backup"}}use of {{.DiskName}} for backups{{else}}growth of {{.DiskName}}{{end}}{{end}}</button></form><a href="/storage">Cancel</a></section>{{end}}{{end}}
<p>Command: olivares-appliance storage list --plan</p>
{{if .Have}}<p>Inventory read at {{.ReadAt}}.</p>
{{with .Inventory}}{{range .Disks}}<h2>{{.Device}}</h2>
<p>{{if .System}}System disk. {{end}}Disk {{space .Size}}; unpartitioned {{space (tailSpace .)}}.{{range .Partitions}}{{if .Filesystem}}{{if eq .Filesystem.Type "btrfs"}} Data volume: {{if .Filesystem.Size}}{{space .Filesystem.Size}}{{else}}unmeasured{{end}}.{{end}}{{end}}{{end}}</p>
{{if $.Actions.CSRF}}{{if actionAllowed $.Inventory "backup" .Identity.Digest}}<form method="post" action="/storage/action" aria-label="Use {{.Device}} for backups"><input type="hidden" name="csrf_token" value="{{$.Actions.CSRF}}"><input type="hidden" name="stage" value="plan"><input type="hidden" name="op" value="backup"><input type="hidden" name="disk_digest" value="{{.Identity.Digest}}"><button type="submit">Use for backups</button></form>{{end}}
{{if actionAllowed $.Inventory "grow" .Identity.Digest}}<form method="post" action="/storage/action" aria-label="Grow data on {{.Device}}"><input type="hidden" name="csrf_token" value="{{$.Actions.CSRF}}"><input type="hidden" name="stage" value="plan"><input type="hidden" name="op" value="grow"><input type="hidden" name="disk_digest" value="{{.Identity.Digest}}"><button type="submit">Grow now</button></form>{{end}}{{end}}
<details><summary>Disk details</summary><ul>
<li>Size: {{.Size}} bytes{{if .Model}}; model {{.Model}}{{end}}{{if .BackingFile}}; backing file shown by UDisks2: {{.BackingFile}}{{end}}</li>
<li>Identity: {{identity .Identity}}</li>
<li>Target: {{if .Target}}{{.Target}}{{else}}none{{end}}</li>
<li>System disk: {{if .System}}yes ({{join .SystemReasons ", "}}){{else}}no{{end}}; UDisks2 system hint: {{.HintSystem}}</li>
<li>Partition table: {{if .PartitionTable}}{{.PartitionTable}}{{else}}none{{end}}; filesystem: {{filesystem .Filesystem}}</li>
<li>Consumers: {{consumers .Consumers}}</li>
<li>Operations the host reports: {{operations .Operations}}</li>
</ul>
{{if .Partitions}}<div class="table-scroll" tabindex="0" role="region" aria-label="Partitions on {{.Device}}"><table><caption>Partitions on {{.Device}}</caption>
<tr><th>Partition</th><th>Number</th><th>Size (bytes)</th><th>Filesystem</th><th>Consumers</th><th>Operations the host reports</th></tr>
{{range .Partitions}}<tr><td>{{.Device}}</td><td>{{.Number}}</td><td>{{.Size}}</td><td>{{filesystem .Filesystem}}</td><td>{{consumers .Consumers}}</td><td>{{operations .Operations}}</td></tr>
{{end}}</table></div>
{{end}}</details>{{end}}<details><summary>Advanced volumes</summary><h2>LVM</h2>
<p>LVM: {{.LVM.State}}{{if .LVM.Reason}} ({{.LVM.Reason}}){{end}}</p>
{{range .LVM.VolumeGroups}}<h3>Volume group {{.Name}}</h3>
<p>Size {{.Size}} bytes, free {{.Free}} bytes; physical volumes: {{join .PhysicalVolumes ", "}}{{if .Missing}}; missing: {{join .Missing ", "}}{{end}}</p>
<ul>
{{range .LogicalVolumes}}<li>{{.Name}}: {{.Size}} bytes{{if .Device}}, {{.Device}}{{end}}, {{if .Active}}active{{else}}inactive{{end}}; filesystem: {{filesystem .Filesystem}}; consumers: {{consumers .Consumers}}</li>
{{end}}</ul>
{{end}}<p>Boot {{.BootID}}</p></details>
{{end}}{{else}}<p>The storage inventory is unmeasured: no read of the storage helper has completed. The socket olivares-helper-storage.socket must be active and UDisks2 with its LVM2 module installed.</p>
{{end}}<p><a href="/">Appliance status</a></p>
</main></body>
</html>
`))

// ActionsView contains only authorized form data, never authority of its own.
type ActionsView struct {
	CSRF, Result string
	Plan         *ActionPlanView
}

// ActionPlanView is the disk and intent the operator must confirm.
type ActionPlanView struct {
	Op, DiskDigest, DiskName, OperationID, Confirmation string
	RegistrationOnly                                    bool
}

type pageView struct {
	Actions   ActionsView
	SignIn    string
	Have      bool
	ReadAt    string
	Inventory Inventory
}

// SnapshotPage serves the Storage page for GET and HEAD from one inventory the caller already read,
// with the time it was read, or unmeasured when have is false: the console's read model, which
// reads the storage helper itself and never for a request. The page starts no read and waits on
// nothing; one that has never been read is answered 200 and says it is unmeasured. It shows each
// disk with its identity, target, system mark, consumers and the operations the host reports, its
// partitions, and the LVM part. Every other method is 405. The page has no form.
func SnapshotPage(signIn string, inv Inventory, readAt time.Time, have bool) http.Handler {
	return ActionPage(signIn, inv, readAt, have, ActionsView{})
}

// ActionPage renders the same inventory, with forms only when the protected caller supplies a CSRF token.
func ActionPage(signIn string, inv Inventory, readAt time.Time, have bool, actions ActionsView) http.Handler {
	view := pageView{SignIn: signIn, Have: have, Inventory: inv, Actions: actions}
	if have {
		view.ReadAt = readAt.UTC().Format(time.RFC3339)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = storagePage.Execute(w, view)
	})
}
