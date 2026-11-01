#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Olivares.AI
# SPDX-License-Identifier: AGPL-3.0-only
# Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.
#
# cpu-model.sh — the CPU model a test guest boots on. AlmaLinux 10 is built for x86-64-v3, so on qemu's default model
# (qemu64) its glibc stops init: "Fatal glibc error: CPU does not support x86-64-v2" (the regression). KVM hands the guest
# the host's CPU; TCG emulates every feature it has.
#
# cpu_model ACCEL — prints max for tcg and host for kvm; the callers accept no other accelerator.
cpu_model() {
  if [ "$1" = tcg ]; then
    printf 'max'
  else
    printf 'host'
  fi
}
