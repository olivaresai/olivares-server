#!/bin/bash
# SPDX-FileCopyrightText: 2026 Olivares.AI
# SPDX-License-Identifier: AGPL-3.0-only
# Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.
#
# Guest fixture of the helper seam's proof, never shipped. It runs as the Appliance Console's account in
# olivares-portal.service (the invoker the helpers admit) and forks until one child holds the pid P, the
# pid of a client that has exited: the process the helper's connection was opened by is gone and another
# process of the admitted unit now has its number. P and the directory come from the environment.
for ((i = 0; i < 30000; i++)); do
	sleep 3000 &
	p=$!
	if [ "$p" = "$P" ]; then
		echo hit > "$GUESTPROOF_DIR/hit"
		wait
		exit 0
	fi
	kill "$p"
	wait "$p" 2> /dev/null
done
echo miss > "$GUESTPROOF_DIR/hit"
