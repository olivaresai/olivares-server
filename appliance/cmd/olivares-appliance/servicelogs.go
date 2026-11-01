// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"slices"

	"github.com/olivaresai/olivares/appliance/layer/hostops/console"
	"github.com/olivaresai/olivares/appliance/layer/portal/localsession"
	"github.com/olivaresai/olivares/appliance/layer/services"
)

// runLogs performs a confirmed logs act and prints what it read. The act is the console's like any
// other: a plan, the operator's confirmation of its digest, a durable receipt that keeps only how many
// entries were read. The entries wait in the console's hold under the operation id of the act, so the
// id is the operator's own (--operation-id) or minted here, sent with the act and used to collect them.
// With --output json the receipt is the first line and the entries are the second, one document.
func runLogs(ctx context.Context, args []string, out, diagnostic io.Writer, dial console.Dial, read readDial) int {
	args, id, err := withOperationID(args)
	if err != nil {
		_, _ = fmt.Fprintln(diagnostic, "session_lost")
		return 2
	}
	var receipt bytes.Buffer
	code := console.Run(ctx, args, nil, &receipt, diagnostic, dial)
	if _, err := out.Write(receipt.Bytes()); err != nil {
		return 2
	}
	if code != 0 {
		return code
	}
	logs, err := collectLogs(read, id, args[2])
	if err != nil {
		reportRead(diagnostic, err)
		_, _ = fmt.Fprintln(diagnostic, "The act ran and its receipt is above; its entries could not be collected.")
		return 2
	}
	if i := slices.Index(args, "--output"); i >= 0 && i+1 < len(args) && args[i+1] == "json" {
		if err := json.NewEncoder(out).Encode(logs); err != nil {
			_, _ = fmt.Fprintln(diagnostic, "The act ran and its receipt is above; its entries could not be written.")
			return 2
		}
		return 0
	}
	_, _ = fmt.Fprintf(out, "Entries of %s, newest last:\n", printable(logs.Unit))
	for _, e := range logs.Entries {
		_, _ = fmt.Fprintf(out, "%s %s %s\n", printable(e.Timestamp), printable(e.Priority), printable(e.Message))
	}
	if logs.Truncated {
		_, _ = fmt.Fprintln(out, "The unit has more entries than fit one answer: these are the newest.")
	}
	return 0
}

// withOperationID returns args with an --operation-id, and that id: the one args carry, else a fresh one.
func withOperationID(args []string) ([]string, string, error) {
	if i := slices.Index(args, "--operation-id"); i >= 0 && i+1 < len(args) {
		return args, args[i+1], nil
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, "", err
	}
	text := hex.EncodeToString(id[:])
	return append(slices.Clone(args), "--operation-id", text), text, nil
}

// collected is what a logs act read, as the console held it.
type collected struct {
	Unit      string           `json:"unit"`
	Truncated bool             `json:"truncated"`
	Entries   []services.Entry `json:"entries"`
}

// collectLogs reads every page of the entries the act of id read on unit, all from the one hold. A page that
// disagrees with the first, one that does not move on, a unit that is not the act's and a total the pages do not
// add up to mean the read could not run: a short list is never printed as the journal.
func collectLogs(read readDial, id, unit string) (collected, error) {
	session, err := read()
	if err != nil {
		return collected{}, err
	}
	defer session.Close()
	var all localsession.ModuleAnswer
	for next, pages := 0, 0; ; pages++ {
		if pages >= maxPages {
			return collected{}, errReadChanged
		}
		page, err := session.ReadLogs(id, next, "cli")
		if err != nil {
			return collected{}, err
		}
		if pages == 0 {
			all = page
		} else if page.LogUnit != all.LogUnit || page.Total != all.Total || page.Truncated != all.Truncated {
			return collected{}, errReadChanged
		} else {
			all.Entries = append(all.Entries, page.Entries...)
		}
		if page.Next == 0 {
			break
		}
		if page.Next <= next {
			return collected{}, errReadChanged
		}
		next = page.Next
	}
	if all.LogUnit != unit || len(all.Entries) != all.Total {
		return collected{}, errReadChanged
	}
	if all.Entries == nil {
		all.Entries = []services.Entry{}
	}
	return collected{Unit: all.LogUnit, Truncated: all.Truncated, Entries: all.Entries}, nil
}
