#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Olivares.AI
# SPDX-License-Identifier: AGPL-3.0-only
# Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.
#
# pid1-denial.sh — whether SELinux denied PID 1 anything during a boot. PID 1 (init_t) sets up the credentials of a unit in
# "(sd-mkdcreds)", binds the socket files, and watches the files its path units name; a denial of any of them stops a
# unit before its program runs (status 243, step CREDENTIALS) or silently leaves a watch incomplete.
#
# pid1_was_denied_nothing JOURNAL — succeeds only when JOURNAL was read and holds no avc denial whose source is init_t.
# grep exits 0 on a denial and 2 on a file it could not read; neither is "no denial".
pid1_was_denied_nothing() {
  LC_ALL=C grep -Eaq 'avc: +denied.*scontext=[^ ]*:init_t:' "$1"
  [ $? -eq 1 ]
}
