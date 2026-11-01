// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package portal

import (
	"net/http"

	"github.com/olivaresai/olivares/appliance/layer/portal/localsession"
	"github.com/olivaresai/olivares/appliance/layer/services"
	"github.com/olivaresai/olivares/appliance/layer/storage"
)

// serveServices serves the services module's page to a caller on this host: a snapshot of s's last
// completed units read, taken from memory at the request, with every act disabled and its
// equivalent command. The page reads nothing else and asks no helper; services.Page refuses every
// method but GET and HEAD. The page names units, so a caller on another host is answered 404, as
// for any detail it may not read.
func serveServices(s Status) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !loopbackPeer(r.RemoteAddr) {
			http.NotFound(w, r)
			return
		}
		snapshot := services.Snapshot{SignInStatement: s.SignIn.Statement()}
		if s.Pages != nil {
			var stamp localsession.Stamp
			snapshot.Inventory, stamp, snapshot.Measured = s.Pages.Units()
			snapshot.ReadAt = stamp.ReadAt
		}
		services.Page(snapshot).ServeHTTP(w, r)
	}
}

// serveStorage serves the storage module's page to a caller on this host from s's last completed
// inventory read, taken from memory at the request. The page names disks, partitions and mount
// points, so a caller on another host is answered 404. storage.SnapshotPage refuses every method
// but GET and HEAD and starts no read.
func serveStorage(s Status) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !loopbackPeer(r.RemoteAddr) {
			http.NotFound(w, r)
			return
		}
		var (
			inventory storage.Inventory
			stamp     localsession.Stamp
			ok        bool
		)
		if s.Pages != nil {
			inventory, stamp, ok = s.Pages.Storage()
		}
		storage.SnapshotPage(s.SignIn.Statement(), inventory, stamp.ReadAt, ok).ServeHTTP(w, r)
	}
}
