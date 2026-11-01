// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

// olivares-portal-storage answers the host's storage inventory to an invoker the kernel attests.
//
// Its socket unit, olivares-helper-storage.socket, listens on /run/olivares-helpers/storage.sock
// with Accept=yes and starts one instance per connection, as root, with the connection as its
// standard input and output. It reads one document, {"op": "inventory"}, takes no argument and
// no path, admits the Appliance Console alone from the connection, and answers the inventory:
// disks, partitions, filesystems, swap and LVM as UDisks2 and the kernel report them, the system
// disk, every consumer and the operations the host reports. It enables UDisks2's LVM2 module
// before it reads. Confirmed backup and root-growth requests are separate
// mutating subcommands admitted only for the attested Appliance Console.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/olivaresai/olivares/appliance/layer/helpers/helperschema"
	"github.com/olivaresai/olivares/appliance/layer/helpers/invocation"
	"github.com/olivaresai/olivares/appliance/layer/storage"
)

// readTimeout bounds one inventory read, within the unit's RuntimeMaxSec.
const readTimeout = 20 * time.Second

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	if len(os.Args) == 3 && (os.Args[1] == "--prepare-grow" || os.Args[1] == "--grow-condition") {
		var err error
		if os.Args[1] == "--grow-condition" {
			err = storage.GrowthCondition(os.Args[2])
		} else {
			err = storage.PrepareGrowth(ctx, os.Args[2])
		}
		stop()
		if err != nil {
			_, _ = os.Stderr.WriteString("storage growth preparation refused: " + err.Error() + "\n")
			os.Exit(1)
		}
		return
	}
	code := invocation.Serve(ctx, helper(readHost, applyHost), invocation.Linux{}, os.Args[1:], 0, os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

// readHost reads the installed host's inventory through UDisks2 on the system bus and the
// kernel.
func readHost(ctx context.Context) (storage.Inventory, error) {
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	bus, err := storage.DialSystemBus(ctx)
	if err != nil {
		return storage.Inventory{}, err
	}
	defer bus.Close()
	return storage.Read(ctx, bus, storage.LinuxKernel{})
}

func applyHost(ctx context.Context, r *storage.ActionRequest) helperschema.Response {
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	bus, err := storage.DialSystemBus(ctx)
	if err != nil {
		return helperschema.Response{Result: helperschema.ResultFailed, Code: helperschema.CodeConsumerUnavailable}
	}
	defer bus.Close()
	return storage.ActionAnswer(ctx, storage.NativeExecutor(bus), r)
}
