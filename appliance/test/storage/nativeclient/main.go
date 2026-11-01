// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

// nativeclient is a disposable-guest-only fixture. PID1 runs it as the trusted
// portal to exercise the real helper protocol. It supplies no product identity;
// this mechanism proof is separate from the real authenticated console journey.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/olivaresai/olivares/appliance/layer/hostops"
	"github.com/olivaresai/olivares/appliance/layer/portal/helperclient"
	"github.com/olivaresai/olivares/appliance/layer/storage"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) != 2 {
		return fmt.Errorf("expected inventory, guard-root, backup, grow or wait-write")
	}
	mode := os.Args[1]
	if mode == "wait-write" {
		fmt.Println("WRITER_WAITING")
		until := time.Now().Add(90 * time.Second)
		for time.Now().Before(until) {
			entries, err := os.ReadDir("/mnt/olivares-backups")
			if err == nil {
				for _, entry := range entries {
					if !entry.IsDir() || len(entry.Name()) != 36 {
						continue
					}
					path := filepath.Join("/mnt/olivares-backups", entry.Name(), "native-proof")
					if err = os.WriteFile(path, []byte("disposable native storage proof\n"), 0600); err == nil {
						fmt.Println("WRITER_PASS")
						return nil
					}
				}
			}
			time.Sleep(200 * time.Millisecond)
		}
		return fmt.Errorf("engine domain could not write into late-mounted backup volume")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	client := helperclient.Client{}
	inv, err := storage.HelperReader(client.Call)(ctx)
	if err != nil {
		return err
	}
	if mode == "inventory" {
		return json.NewEncoder(os.Stdout).Encode(inv)
	}
	op := mode
	if mode == "guard-root" {
		op = "backup"
	}
	var selected *storage.Disk
	for i := range inv.Disks {
		d := &inv.Disks[i]
		if mode == "grow" || mode == "guard-root" {
			if _, err := storage.SelectAction(inv, "grow", d.Identity.Digest); err == nil {
				selected = d
			}
		} else if mode == "backup" && d.Size == 20<<30 {
			if _, err := storage.SelectAction(inv, "backup", d.Identity.Digest); err == nil {
				selected = d
			}
		}
	}
	if selected == nil {
		return fmt.Errorf("no eligible proof disk")
	}
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		return err
	}
	answer, err := client.Call(ctx, storage.HelperName, &storage.ActionRequest{Op: op, OperationID: hex.EncodeToString(random[:]), Identity: selected.Identity})
	if err != nil {
		return err
	}
	if mode == "guard-root" {
		if answer.Result != "refused" {
			return fmt.Errorf("system backup request was not refused: %s", answer.Result)
		}
		fmt.Println("ROOT_BACKUP_REFUSED")
		return nil
	}
	data, err := json.Marshal(answer)
	if err != nil {
		return err
	}
	var result struct {
		OperationID    string              `json:"operation_id"`
		IdentityDigest string              `json:"identity_digest"`
		Op             string              `json:"op"`
		Observation    hostops.Observation `json:"observation"`
	}
	if err = json.Unmarshal(answer.Bundle, &result); err != nil {
		return err
	}
	if answer.Result != "performed" || result.Observation.P1 != "performed" || result.Op != op || result.OperationID != hex.EncodeToString(random[:]) || result.IdentityDigest != selected.Identity.Digest {
		return fmt.Errorf("native action did not complete: %s", data)
	}
	fmt.Println(string(data))
	return nil
}
