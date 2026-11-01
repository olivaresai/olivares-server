#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Olivares.AI
# SPDX-License-Identifier: AGPL-3.0-only
# Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.
#
# battery-selftest.sh — what the boot battery and the unattended first-boot probe promise
# BEFORE either of them boots anything.
#
# It runs on any machine: it starts no virtual machine, needs no /dev/kvm and no QEMU, and
# every assertion is about the scripts themselves. That is the point — the battery's first
# promise is that it REFUSES when it cannot measure, and a refusal is exactly what can be
# tested where there is nothing to boot. Each named assertion has a negative control: the
# same assertion fed counterfeit evidence must fail.
#
# usage: battery-selftest.sh [EVIDENCE_DIR]
#   exit 0  every assertion held and every negative control failed
#   exit 1  an assertion failed or a negative control passed
#   exit 2  an assertion could not be measured here (a missing tool). Never a pass.
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
battery="$here/boot-battery.sh"
probe="$here/nocloud-probe.sh"
hosted="$here/network/run-hosted.sh"
cpu_lib="$here/lib/cpu-model.sh"
predicates="$here/lib/firstboot-predicates.sh"
delivered="$here/../layer/base/fixture/firstboot-battery.sh"
banner="$here/../layer/base/units/tty1-banner.txt"
evidence=${1:-${TMPDIR:-/tmp}/appliance-boot-selftest}
failures=0
unmeasured=0

mkdir -p "$evidence"

say() { printf '%s\n' "$*"; }
check() {
  local name=$1
  shift
  if "$@"; then say "PASS $name"; else say "FAIL $name"; failures=$((failures + 1)); fi
}
control() {
  local name=$1
  shift
  if "$@" >/dev/null 2>&1; then
    say "FAIL control:$name accepted counterfeit evidence"
    failures=$((failures + 1))
  else
    say "PASS control:$name"
  fi
}
unable() { say "UNMEASURED $*"; unmeasured=$((unmeasured + 1)); }

# ---- the assertions ---------------------------------------------------------------------
parses() { bash -n "$1" 2>/dev/null; }

# refuses_naming SCRIPT WORD ENV... — the script refuses (exit 2) and its output names WORD.
refuses_naming() {
  local script=$1 word=$2
  shift 2
  local out status
  out=$(env "$@" bash "$script" --check-preflight "$evidence/artifacts" 2>&1)
  status=$?
  printf '%s\n' "$out" > "$evidence/preflight.$(basename "$script").txt"
  [ "$status" -eq 2 ] && printf '%s' "$out" | grep -Fq -- "$word"
}

# quiet_about SCRIPT WORD ENV... — the same refusal does NOT name WORD.
quiet_about() {
  local script=$1 word=$2
  shift 2
  local out status
  out=$(env "$@" bash "$script" --check-preflight "$evidence/artifacts" 2>&1)
  status=$?
  [ "$status" -eq 2 ] && ! printf '%s' "$out" | grep -Fq -- "$word"
}

lists_cases() {
  local want=$1
  [ "$(bash "$battery" --list-cases 2>/dev/null | head -3 | tr '\n' ' ')" = "$want " ]
}
names_case() { bash "$battery" --list-cases 2>/dev/null | grep -qx -- "$1"; }

# no_call_recorded FILE — the emulator spy was never run.
no_call_recorded() { [ ! -e "$1" ]; }

# refusal_ran_the_spy — the preflight refuses with an emulator spy on the command path; it
# prints the spy's log, which must not exist.
refusal_ran_the_spy() {
  local spy="$evidence/qemu-spy" log="$evidence/qemu-spy.log"
  rm -f "$log"
  printf '#!/bin/sh\necho called >> %s\n' "$log" > "$spy"
  chmod 0755 "$spy"
  env APPLIANCE_KVM_DEVICE="$evidence/no-such-kvm" APPLIANCE_QEMU="$spy" \
    bash "$battery" --check-preflight "$evidence/artifacts" >/dev/null 2>&1
  printf '%s\n' "$log"
}

holds() { grep -Fq -- "$2" "$1"; }
sources_delivered() { grep -Fq -- 'layer/base/fixture/firstboot-battery.sh' "$1"; }

defines_predicates() {
  local extracted="$evidence/extracted.sh"
  ( set -e; . "$predicates"; firstboot_predicates_extract > "$extracted" ) 2>/dev/null || return 1
  local name
  for name in check control record_is completed_are no_setup_token is holds same; do
    grep -Eq "^${name}\(\)" "$extracted" || return 1
  done
  ! grep -q 'docker' "$extracted"
}

predicate_answers_both_ways() {
  local record="$evidence/state.json"
  printf '%s\n' '{"state":"refused","stage":"prepare-setup-delivery","completed":[]}' > "$record"
  ( . "$predicates"; firstboot_predicates_load; record_is "$record" refused prepare-setup-delivery ) 2>/dev/null
}
predicate_refuses_a_counterfeit() {
  local record="$evidence/state-counterfeit.json"
  printf '%s\n' '{"state":"ready","stage":"measure-readiness","completed":[]}' > "$record"
  ( . "$predicates"; firstboot_predicates_load; record_is "$record" refused prepare-setup-delivery ) 2>/dev/null
}

# A battery reads its console label from the delivered banner through lib/console-label.sh, and keeps no literal of
# its own; the helper gives the banner's first line without agetty's host name escape.
reads_the_delivered_banner() {
  grep -Fq 'lib/console-label.sh' "$1" && grep -Fq 'appliance/layer/base/units/tty1-banner.txt' "$1" \
    && grep -Eq 'console_label=\$\(banner_label ' "$1" && ! grep -Eq "console_label=['\"][^'\"]" "$1"
}
label_is_the_banner_line() {
  local want got
  want=$(head -n 1 "$banner" | sed 's/[[:space:]]*\\n[[:space:]]*$//')
  got=$( . "$here/lib/console-label.sh"; banner_label "$1" )
  [ -n "$want" ] && [ "$got" = "$want" ]
}

# gives_model LIB ACCEL MODEL — LIB's cpu_model gives a guest under ACCEL the CPU model MODEL.
gives_model() { [ "$( ( . "$1" && cpu_model "$2" ) 2>/dev/null)" = "$3" ]; }
# passes_cpu_model SCRIPT LIB — outside comments, SCRIPT sources LIB (relative to its own directory) and gives qemu its
# CPU model for the accelerator it chose.
passes_cpu_model() {
  local code
  code=$(grep -v '^[[:space:]]*#' "$1")
  grep -Fq ". \"\$here/$2\"" <<<"$code" && grep -Fq -- '-cpu "$(cpu_model "$accel")"' <<<"$code"
}

counterfeit_file() {
  local out
  out=$(mktemp "$evidence/counterfeit.XXXXXX")
  printf '%s\n' "$1" > "$out"
  printf '%s\n' "$out"
}

# ---- what the battery promises ----------------------------------------------------------
check battery_parses parses "$battery"
control battery_parses parses "$(counterfeit_file 'if then fi')"

check battery_lists_the_three_firmware_cases lists_cases "bios uefi uefi-secureboot"
control battery_lists_the_three_firmware_cases lists_cases "bios uefi tcg"
check battery_names_the_installer_case names_case iso-install
control battery_names_the_installer_case names_case install-by-hand

check battery_refuses_without_kvm \
  refuses_naming "$battery" "$evidence/no-such-kvm" APPLIANCE_KVM_DEVICE="$evidence/no-such-kvm"
control battery_refuses_without_kvm \
  refuses_naming "$(counterfeit_file 'exit 2')" "$evidence/no-such-kvm" APPLIANCE_KVM_DEVICE="$evidence/no-such-kvm"

check battery_does_not_start_qemu_when_it_refuses no_call_recorded "$(refusal_ran_the_spy)"
control battery_does_not_start_qemu_when_it_refuses no_call_recorded "$(counterfeit_file called)"

check battery_under_tcg_refuses_for_the_missing_emulator_only \
  refuses_naming "$battery" "$evidence/no-such-qemu" \
  APPLIANCE_BOOT_ACCEL=tcg APPLIANCE_QEMU="$evidence/no-such-qemu" APPLIANCE_KVM_DEVICE="$evidence/no-such-kvm"
check battery_under_tcg_does_not_blame_kvm \
  quiet_about "$battery" "$evidence/no-such-kvm" \
  APPLIANCE_BOOT_ACCEL=tcg APPLIANCE_QEMU="$evidence/no-such-qemu" APPLIANCE_KVM_DEVICE="$evidence/no-such-kvm"
control battery_under_tcg_does_not_blame_kvm \
  quiet_about "$(counterfeit_file "printf '%s\\n' \"$evidence/no-such-kvm\"; exit 2")" "$evidence/no-such-kvm"

# AlmaLinux 10 needs x86-64-v3, which qemu's default CPU model lacks: KVM guests get the host's CPU, TCG guests max,
# from one library every guest launcher sources.
check cpu_model_gives_kvm_guests_the_host_cpu gives_model "$cpu_lib" kvm host
control cpu_model_gives_kvm_guests_the_host_cpu gives_model "$(counterfeit_file 'cpu_model() { printf qemu64; }')" kvm host
check cpu_model_gives_tcg_guests_the_max_cpu gives_model "$cpu_lib" tcg max
control cpu_model_gives_tcg_guests_the_max_cpu gives_model "$(counterfeit_file 'cpu_model() { printf host; }')" tcg max
check battery_passes_the_cpu_model_to_qemu passes_cpu_model "$battery" lib/cpu-model.sh
control battery_passes_the_cpu_model_to_qemu passes_cpu_model \
  "$(counterfeit_file "$(printf '. "$here/lib/cpu-model.sh"\n# -cpu "$(cpu_model "$accel")"')")" lib/cpu-model.sh
check probe_passes_the_cpu_model_to_qemu passes_cpu_model "$probe" lib/cpu-model.sh
check hosted_guest_passes_the_cpu_model_to_qemu passes_cpu_model "$hosted" ../lib/cpu-model.sh

check battery_reads_the_console_label_of_the_delivered_banner reads_the_delivered_banner "$battery"
control battery_reads_the_console_label_of_the_delivered_banner reads_the_delivered_banner \
  "$(counterfeit_file "readonly console_label='Olivares AI appliance'")"
check the_console_label_is_the_delivered_banner_line label_is_the_banner_line "$banner"
control the_console_label_is_the_delivered_banner_line label_is_the_banner_line \
  "$(counterfeit_file 'Olivares AI appliance \n')"
check battery_asserts_the_boot_target holds "$battery" multi-user.target
control battery_asserts_the_boot_target holds "$(counterfeit_file 'reached the login prompt')" multi-user.target
check battery_asserts_secure_boot_was_on holds "$battery" "SecureBoot enabled"
control battery_asserts_secure_boot_was_on holds "$(counterfeit_file 'secure boot assumed')" "SecureBoot enabled"

# ---- what the unattended first-boot probe promises ---------------------------------------
check probe_parses parses "$probe"
check probe_reads_the_console_label_of_the_delivered_banner reads_the_delivered_banner "$probe"
control probe_reads_the_console_label_of_the_delivered_banner reads_the_delivered_banner \
  "$(counterfeit_file "holds \"\$console\" 'Olivares AI appliance'")"
control probe_parses parses "$(counterfeit_file 'while do done')"
check probe_refuses_without_kvm \
  refuses_naming "$probe" "$evidence/no-such-kvm" APPLIANCE_KVM_DEVICE="$evidence/no-such-kvm"
check probe_seeds_from_the_delivered_carrier_fixture holds "$probe" answers/carriers/testdata/nocloud
control probe_seeds_from_the_delivered_carrier_fixture holds "$(counterfeit_file 'a seed of its own')" answers/carriers/testdata/nocloud

# The probe delivers the seed's own document as the systemd credential first boot imports, so PID 1 sets one up on the
# image, and refuses a boot journal that holds an SELinux denial of PID 1 (the helper that sets the credential up, the
# socket files it binds, the files its path units watch).
check probe_delivers_the_answers_as_a_systemd_credential holds "$probe" \
  'io.systemd.credential.binary:olivares.appliance.answers=$answers_credential'
control probe_delivers_the_answers_as_a_systemd_credential holds "$(counterfeit_file 'a seed only')" \
  'io.systemd.credential.binary:olivares.appliance.answers=$answers_credential'

# pid1_clean JOURNAL — lib/pid1-denial.sh finds no avc denial of PID 1 (init_t) in JOURNAL and could read it.
pid1_clean() { ( . "$here/lib/pid1-denial.sh"; pid1_was_denied_nothing "$1" ) 2>/dev/null; }
check pid1_denial_check_accepts_a_clean_journal pid1_clean \
  "$(counterfeit_file 'systemd[1]: Started olivares-portal.service.')"
check pid1_denial_check_ignores_other_domains pid1_clean \
  "$(counterfeit_file 'audit: type=1400 audit(1.0:3): avc:  denied  { read } for  pid=9 comm="cloud-init" scontext=system_u:system_r:cloud_init_t:s0 tcontext=system_u:object_r:etc_t:s0 tclass=file permissive=0')"
control pid1_denial_check_refuses_a_credential_setup_denial pid1_clean \
  "$(counterfeit_file 'audit: type=1400 audit(1.0:2): avc:  denied  { add_name } for  pid=1157 comm="(sd-mkdcreds)" scontext=system_u:system_r:init_t:s0 tcontext=system_u:object_r:olivares_firstboot_cred_t:s0 tclass=dir permissive=0')"
control pid1_denial_check_refuses_a_socket_denial pid1_clean \
  "$(counterfeit_file 'audit: type=1400 audit(1.0:4): avc:  denied  { write } for  pid=1 comm="systemd" name="local.sock" scontext=system_u:system_r:init_t:s0 tcontext=system_u:object_r:olivares_portal_api_sock_t:s0 tclass=sock_file permissive=0')"
control pid1_denial_check_refuses_a_journal_it_cannot_read pid1_clean "$evidence/no-such-journal"
check probe_runs_the_pid1_denial_check holds "$probe" 'check pid1_was_denied_nothing_during_first_boot pid1_was_denied_nothing'
control probe_runs_the_pid1_denial_check holds "$(counterfeit_file 'control only')" 'check pid1_was_denied_nothing_during_first_boot pid1_was_denied_nothing'
check probe_asserts_first_boot_read_the_credential holds "$probe" 'check first_boot_read_the_systemd_credential_carrier'
control probe_asserts_first_boot_read_the_credential holds "$(counterfeit_file 'control only')" 'check first_boot_read_the_systemd_credential_carrier'
check probe_asserts_cloud_init_wrote_the_carrier holds "$probe" 'check cloud_init_wrote_the_nocloud_carrier'
control probe_asserts_cloud_init_wrote_the_carrier holds "$(counterfeit_file 'control only')" 'check cloud_init_wrote_the_nocloud_carrier'

check probe_reuses_the_delivered_first_boot_battery sources_delivered "$predicates"
control probe_reuses_the_delivered_first_boot_battery sources_delivered "$(counterfeit_file 'record_is() { :; }')"
if [ ! -r "$delivered" ]; then
  unable "the delivered first-boot battery is not at $delivered"
elif ! command -v jq >/dev/null 2>&1; then
  unable "jq is not available, so the reused predicates cannot be exercised here"
else
  check reused_predicates_are_the_delivered_ones defines_predicates
  check reused_predicate_reads_a_refusal predicate_answers_both_ways
  control reused_predicate_reads_a_refusal predicate_refuses_a_counterfeit
fi

say "failed: $failures; unmeasured: $unmeasured"
[ "$failures" -gt 0 ] && exit 1
[ "$unmeasured" -gt 0 ] && exit 2
exit 0
