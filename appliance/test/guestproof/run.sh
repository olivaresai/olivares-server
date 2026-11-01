#!/bin/bash
# SPDX-FileCopyrightText: 2026 Olivares.AI
# SPDX-License-Identifier: AGPL-3.0-only
# Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.
#
# The helper seam's guest proof. Disposable AlmaLinux guest only, as root, never the host and never shipped:
# it replaces the helper binary, writes runtime units and lowers kernel.pid_max.
#
# It measures, on the guest's own kernel and service manager and with the real units of the units helper
# (Accept=yes, one instance per connection), what README.md's helper section says the appliance must prove
# before a per-connection instance performs a mutating subcommand:
#
#   1. each instance receives its peer's pidfd: with the helper built before the proof (guestProven false) an
#      admitted invoker, the Appliance Console's own unit and account, is refused pidfd_unproven only after the
#      instance admitted it from the pidfd (its journal says "attested"), and a stranger is not_admitted;
#   2. a recycled pid is refused: a client opens a connection and exits, a process of the same admitted unit
#      then holds the client's pid number, and the instance, which looks only now, attests nobody
#      (no_connection_identity), where a reader of /proc by pid number would have named the admitted unit;
#   3. with the helper built after the proof (guestProven true) the admitted invoker's act is performed, and
#      the acts the services module adopts run end to end through the console's act path: the real
#      olivares-appliance command line, the console's local session (a stand-in only for the product's identity
#      owner), the real helper and the service manager.
#
# The control helper, olivares-portal-units.unproven, is ./layer/helpers/olivares-portal-units built from the same tree with
# `const guestProven = false` in layer/helpers/invocation/serve.go and nothing else changed; the other binaries are built
# with CGO_ENABLED=0 GOOS=linux: ./layer/helpers/olivares-portal-units, ./cmd/olivares-appliance, ./test/guestproof/console.
#
# usage: GUESTPROOF_DISPOSABLE=1 run.sh   (files in $GUESTPROOF_DIR, default /var/tmp/guestproof: ask.py recycle.sh olivares-appliance
#                  guestproof-console olivares-portal-units.unproven [olivares-portal-units] units/*: the real units of the units
#                  helper, of the console's local socket and of the update, and the console's sysusers and tmpfiles files)
# Every measurement is one line "PROOF <name> PASS|FAIL <detail>"; the last line is the count; exit 1 on a FAIL.
set -u
export LC_ALL=C
S=${GUESTPROOF_DIR:-/var/tmp/guestproof}
SOCK=/run/olivares-helpers/units.sock
LIBEXEC=/usr/libexec/olivares
G=/run/guestproof
passes=0
fails=0

[ "${GUESTPROOF_DISPOSABLE:-}" = 1 ] || { echo "run.sh replaces binaries, truncates files and lowers kernel.pid_max: set GUESTPROOF_DISPOSABLE=1 in a disposable guest" >&2; exit 2; }
for f in ask.py recycle.sh olivares-appliance guestproof-console olivares-portal-units olivares-portal-units.unproven \
	units/olivares-helper-units.socket 'units/olivares-helper-units@.service' units/olivares-portal-local.socket units/olivares-appliance-update.service; do
	[ -e "$S/$f" ] || { echo "PROOF files-are-staged FAIL $S/$f is missing" ; exit 2; }
done

proof() {
	printf 'PROOF %s %s %s\n' "$1" "$2" "$3"
	if [ "$2" = PASS ]; then passes=$((passes + 1)); else fails=$((fails + 1)); fi
}
expect() { if [ "$2" = "$3" ]; then proof "$1" PASS "$2"; else proof "$1" FAIL "got '$2', want '$3'"; fi; }
contains() { if printf '%s' "$2" | grep -qE -- "$3"; then proof "$1" PASS "$3"; else proof "$1" FAIL "no match for '$3' in: $(printf '%s' "$2" | tr '\n' ' ' | cut -c1-400)"; fi; }
lacks() { if printf '%s' "$2" | grep -qE -- "$3"; then proof "$1" FAIL "unexpected '$3' in: $(printf '%s' "$2" | tr '\n' ' ' | cut -c1-400)"; else proof "$1" PASS "no '$3'"; fi; }
mark() { sleep 1; date +%s; } # a second apart from the step before, so the journal window holds this step alone
opid() { python3 -c 'import os;print(os.urandom(16).hex())'; }
field() { python3 -c 'import json,sys;print(json.loads(sys.stdin.readline()).get(sys.argv[1],""))' "$1"; }
helper_log() { journalctl -u 'olivares-helper-units@*.service' --since "@$1" --no-pager -o cat 2> /dev/null; }
unit_log() { journalctl -u "$1" --since "@$2" --no-pager -o cat 2> /dev/null; }
portal_run() { systemd-run --quiet --wait --pipe --collect --unit=olivares-portal.service --uid=olivares-portal --gid=olivares-portal "$@"; }
start_doc() { printf '{"op":"start","unit":"dnf-automatic-install.service","operation_id":"%s"}' "$1"; }

# A rerun starts from a clean guest: the runtime units and state of an earlier run are removed first.
systemctl stop olivares-portal-local.socket olivares-portal.service guestproof-root.service guestproof-stranger.service 2> /dev/null
rm -f /run/systemd/system/olivares-portal.service /etc/systemd/system/olivares-portal-local.socket
rm -rf /var/lib/olivares-portal "$G"
rm -f "$LIBEXEC/guestproof-console" "$LIBEXEC/olivares-portal-units" /usr/local/bin/olivares-appliance
systemctl daemon-reload

# --- the guest, its units and the helper's real unit files ---------------------------------------------------
echo "# guest: kernel $(uname -r), $(rpm -q systemd), $(rpm -q kernel | tail -1), SELinux $(getenforce)"
kmajor=$(uname -r | cut -d. -f1)
kminor=$(uname -r | cut -d. -f2)
if [ "$kmajor" -gt 6 ] || { [ "$kmajor" -eq 6 ] && [ "$kminor" -ge 5 ]; }; then
	proof kernel-offers-so-peerpidfd PASS "$(uname -r) (SO_PEERPIDFD is Linux 6.5 and later)"
else
	proof kernel-offers-so-peerpidfd FAIL "$(uname -r)"
fi
# The console's accounts and the directories it keeps are the appliance's own sysusers and tmpfiles files.
install -d /etc/sysusers.d /etc/tmpfiles.d
install -m 0644 "$S"/units/sysusers.d/*.conf /etc/sysusers.d/
install -m 0644 "$S"/units/tmpfiles.d/*.conf /etc/tmpfiles.d/
systemd-sysusers
systemd-tmpfiles --create
if journalctl -n 1 --no-pager > /dev/null 2>&1; then proof journal-is-readable PASS "the journal answers"; else proof journal-is-readable FAIL "no journal: every check of an absent line would pass"; fi
id olivares-portal > /dev/null 2>&1 || proof console-account-exists FAIL "sysusers did not create olivares-portal"
install -d -m 0755 "$LIBEXEC"
install -m 0644 "$S/units/olivares-helper-units.socket" "$S/units/olivares-helper-units@.service" /etc/systemd/system/
# The instance's wait for the proof's go-ahead: a script, because a unit line would expand $i and the instance's
# PrivateTmp hides /var/tmp.
printf 'i=0; while [ ! -e %s/go ] && [ "$i" -lt 900 ]; do sleep 0.1; i=$((i+1)); done\n' "$G" > "$LIBEXEC/guestproof-waitgo"
rpm -q dnf-automatic > /dev/null 2>&1 || dnf -y -q install dnf-automatic > /dev/null 2>&1
if [ ! -e /usr/lib/systemd/system/dnf-automatic-install.service ]; then
	printf '[Service]\nType=oneshot\nExecStart=/bin/true\n' > /etc/systemd/system/dnf-automatic-install.service
	printf '[Timer]\nOnCalendar=*-*-* 03:00:00\n[Install]\nWantedBy=timers.target\n' > /etc/systemd/system/dnf-automatic-install.timer
	echo "# dnf-automatic is not installable here: stub units of the same names"
else
	echo "# dnf-automatic: $(rpm -q dnf-automatic), its own unit files"
fi
# The units' bodies are replaced by a line in the journal: what is measured is the act, not a package manager run.
install -d /run/systemd/system/dnf-automatic-install.service.d /run/systemd/system/olivares-appliance-update.service.d
# The run prints 120 lines of 280 bytes before its marker, so that the default 100-line logs read is larger than a frame.
printf 'i=0; while [ "$i" -lt 120 ]; do echo "guestproof-filler $i $(printf %%0280d 0)"; i=$((i+1)); done; echo guestproof dnf run\n' > "$LIBEXEC/guestproof-dnf-run"
printf '[Service]\nExecStart=\nExecStart=/bin/sh %s/guestproof-dnf-run\n' "$LIBEXEC" > /run/systemd/system/dnf-automatic-install.service.d/proof.conf
install -m 0644 "$S/units/olivares-appliance-update.service" /etc/systemd/system/
# The update unit keeps its own dependencies and assertion: the channel's refresh it requires is a stub that
# prints a line, and the licence file it asserts is present and empty.
install -d /var/lib/olivares
: > /var/lib/olivares/license.key
printf '[Service]\nType=oneshot\nExecStart=/usr/bin/echo guestproof entitled-repo refresh\n' > /etc/systemd/system/olivares-entitled-repo.service
printf '[Service]\nExecStart=\nExecStart=/usr/bin/echo guestproof update run\n' > /run/systemd/system/olivares-appliance-update.service.d/proof.conf
systemctl daemon-reload
install_helper() {
	install -m 0755 "$1" "$LIBEXEC/olivares-portal-units"
	restorecon -F "$LIBEXEC/olivares-portal-units" 2> /dev/null
	systemctl restart olivares-helper-units.socket
}
systemctl start olivares-helper-units.socket
expect socket-is-per-connection "$(systemctl show -p Accept --value olivares-helper-units.socket)" yes
old_pid_max=$(sysctl -n kernel.pid_max)

# Who is not the Appliance Console is refused whoever it is: root in another system unit and the console's own
# account in another unit are attested and not admitted, and root in a login session, which no system unit
# names, has no connection identity for a mutating subcommand.
stranger_checks() { # stranger_checks PREFIX
	local answer
	answer=$(systemd-run --quiet --wait --pipe --collect --unit=guestproof-root.service /usr/bin/python3 "$S/ask.py" "$SOCK" "$(start_doc "$(opid)")")
	expect "$1-root-in-another-unit-is-not-admitted" "$(printf '%s' "$answer" | field code)" not_admitted
	answer=$(systemd-run --quiet --wait --pipe --collect --unit=guestproof-stranger.service --uid=olivares-portal --gid=olivares-portal /usr/bin/python3 "$S/ask.py" "$SOCK" "$(start_doc "$(opid)")")
	expect "$1-portal-account-in-another-unit-is-not-admitted" "$(printf '%s' "$answer" | field code)" not_admitted
	answer=$(/usr/bin/python3 "$S/ask.py" "$SOCK" "$(start_doc "$(opid)")")
	expect "$1-root-in-a-login-session-has-no-identity" "$(printf '%s' "$answer" | field code)" no_connection_identity
}

# --- a connection whose client has exited, with or without its pid recycled -----------------------------------
recycle_case() { # recycle_case NAME yes|no
	local name=$1 recycle=$2 id T P tries naive log
	for tries in 1 2 3; do
		rm -rf "$G"
		install -d -m 0777 "$G"
		install -d /run/systemd/system/olivares-helper-units@.service.d
		printf '[Service]\nExecStartPre=/bin/sh %s/guestproof-waitgo\n' "$LIBEXEC" > /run/systemd/system/olivares-helper-units@.service.d/delay.conf
		systemctl daemon-reload
		sysctl -qw kernel.pid_max=2000
		id=$(opid)
		T=$(mark)
		systemd-run --quiet --wait --collect --unit=olivares-portal.service --uid=olivares-portal --gid=olivares-portal \
			-E GUESTPROOF_PIDFILE="$G/client.pid" /usr/bin/python3 "$S/ask.py" "$SOCK" "$(start_doc "$id")" --leave
		P=$(cat "$G/client.pid")
		if [ "$recycle" = yes ]; then
			systemd-run --quiet --no-block --collect --unit=olivares-portal.service --uid=olivares-portal --gid=olivares-portal \
				-E P="$P" -E GUESTPROOF_DIR="$G" /bin/bash "$S/recycle.sh"
			for _ in $(seq 1 300); do [ -e "$G/hit" ] && break; sleep 0.2; done
			[ "$(cat "$G/hit" 2> /dev/null)" = hit ] || { systemctl stop olivares-portal.service 2> /dev/null; continue; }
		fi
		break
	done
	naive=$(cat "/proc/$P/cgroup" 2> /dev/null)
	if [ "$recycle" = yes ]; then
		contains "$name-pid-names-the-admitted-unit-now" "$naive" 'olivares-portal\.service'
	else
		expect "$name-pid-names-nobody-now" "$naive" ""
	fi
	touch "$G/go"
	for _ in $(seq 1 100); do
		log=$(helper_log "$T")
		printf '%s' "$log" | grep -q 'refused\|admitted' && break
		sleep 0.2
	done
	contains "$name-instance-attests-nobody" "$log" 'attested false: start refused: no_connection_identity'
	lacks "$name-no-act-was-run" "$(unit_log dnf-automatic-install.service "$T")" 'guestproof dnf run'
	systemctl stop olivares-portal.service 2> /dev/null
	rm -f /run/systemd/system/olivares-helper-units@.service.d/delay.conf
	systemctl daemon-reload
	sysctl -qw kernel.pid_max="$old_pid_max"
}

# --- the helper as the repository has it before the proof ----------------------------------------------------
install_helper "$S/olivares-portal-units.unproven"
T=$(mark)
read_answer=$(portal_run /usr/bin/python3 "$S/ask.py" "$SOCK" '{"op":"list"}')
expect control-read-is-answered "$(printf '%s' "$read_answer" | field result)" answered
id=$(opid)
answer=$(portal_run /usr/bin/python3 "$S/ask.py" "$SOCK" "$(start_doc "$id")")
expect control-admitted-invoker-is-refused-only-as-unproven "$(printf '%s' "$answer" | field code)" pidfd_unproven
log=$(helper_log "$T")
contains control-instance-admitted-it-from-the-pidfd "$log" "peer uid [0-9]+ unit \"olivares-portal.service\" tty \"\" attested: start admitted, operation_id $id"
contains control-refusal-came-after-admission "$log" "start refused: pidfd_unproven, operation_id $id"
stranger_checks control
recycle_case control-exited-client no
recycle_case control-recycled-pid yes

# --- the helper after the proof ------------------------------------------------------------------------------
{
	install_helper "$S/olivares-portal-units"
	T=$(mark)
	id=$(opid)
	answer=$(portal_run /usr/bin/python3 "$S/ask.py" "$SOCK" "$(start_doc "$id")")
	expect admitted-invoker-act-is-performed "$(printf '%s' "$answer" | field result)" performed
	lacks admitted-invoker-is-not-refused-as-unproven "$answer" pidfd_unproven
	contains act-ran-in-the-service-manager "$(unit_log dnf-automatic-install.service "$T")" 'guestproof dnf run'
	stranger_checks final
	recycle_case exited-client no
	recycle_case recycled-pid yes

	# the adopted acts, end to end: the real command line, the console's local session, the real helper
	install -m 0755 "$S/guestproof-console" "$LIBEXEC/guestproof-console" || proof console-binary-installed FAIL "install failed"
	install -m 0755 "$S/olivares-appliance" /usr/local/bin/olivares-appliance || proof cli-binary-installed FAIL "install failed"
	restorecon -F "$LIBEXEC/guestproof-console" /usr/local/bin/olivares-appliance 2> /dev/null
	# The command line checks, without opening them, that the console's TLS files were delivered; this fixture has
	# no web listener, so empty placeholders stand in for them.
	install -d -m 0755 /etc/olivares-portal
	: > /etc/olivares-portal/tls.crt
	: > /etc/olivares-portal/tls.key
	install -m 0644 "$S/units/olivares-portal-local.socket" /etc/systemd/system/
	printf '[Service]\nUser=olivares-portal\nGroup=olivares-portal\nSupplementaryGroups=olivares-appliance olivares-lifecycle\nStateDirectory=olivares-portal olivares-portal/operations olivares-portal/audit\nStateDirectoryMode=0700\nExecStart=%s/guestproof-console /var/lib/olivares-portal/operations /var/lib/olivares-portal/audit\n' "$LIBEXEC" > /run/systemd/system/olivares-portal.service
	systemctl daemon-reload
	systemctl start olivares-portal-local.socket
	cli() { /usr/local/bin/olivares-appliance "$@" 2>&1; }
	act() { # act NAME unit verb [args...]: plan, then confirm the plan's digest; leaves the confirmed output in ACT_OUT
		local name=$1 unit=$2 verb=$3 plan digest
		shift 3
		plan=$(cli service "$verb" "$unit" "$@")
		digest=$(printf '%s\n' "$plan" | sed -n 's/^Plan: //p')
		contains "$name-plan-names-its-confirming-command" "$plan" "Confirm: olivares-appliance service $verb $unit.* --confirm $digest"
		ACT_OUT=$(cli service "$verb" "$unit" "$@" --confirm "$digest")
		expect "$name-exit-code" "$?" 0
	}
	T=$(mark)
	act start-update-service olivares-appliance-update.service start
	contains start-update-service-receipt "$ACT_OUT" '[0-9a-f]{32}  unit:olivares-appliance-update.service  succeeded'
	contains start-update-service-ran "$(unit_log olivares-appliance-update.service "$T")" 'guestproof update run'
	T=$(mark)
	act start-dnf-service dnf-automatic-install.service start
	contains start-dnf-service-receipt "$ACT_OUT" '[0-9a-f]{32}  unit:dnf-automatic-install.service  succeeded'
	contains start-dnf-service-ran "$(unit_log dnf-automatic-install.service "$T")" 'guestproof dnf run'
	systemctl enable --now dnf-automatic-install.timer > /dev/null 2>&1
	expect stop-timer-pre-state "$(systemctl is-active dnf-automatic-install.timer)" active
	act stop-timer dnf-automatic-install.timer stop
	expect stop-timer-measured "$(systemctl is-active dnf-automatic-install.timer)" inactive
	expect start-timer-pre-state "$(systemctl is-active dnf-automatic-install.timer)" inactive
	act start-timer dnf-automatic-install.timer start
	expect start-timer-measured "$(systemctl is-active dnf-automatic-install.timer)" active
	expect disable-timer-pre-state "$(systemctl is-enabled dnf-automatic-install.timer)" enabled
	act disable-timer dnf-automatic-install.timer disable
	expect disable-timer-measured "$(systemctl is-enabled dnf-automatic-install.timer)" disabled
	expect enable-timer-pre-state "$(systemctl is-enabled dnf-automatic-install.timer)" disabled
	act enable-timer dnf-automatic-install.timer enable
	expect enable-timer-measured "$(systemctl is-enabled dnf-automatic-install.timer)" enabled
	# The default read of 100 entries is more than a frame: the console must take the whole answer and print every entry.
	act logs-dnf-service dnf-automatic-install.service logs
	contains logs-dnf-service-prints-its-entries "$ACT_OUT" 'Entries of dnf-automatic-install.service, newest last:'
	contains logs-dnf-service-entries-are-the-journal "$ACT_OUT" 'guestproof dnf run$'
	expect logs-dnf-service-prints-every-entry-it-read "$(printf '%s\n' "$ACT_OUT" | sed -n '/^Entries of /,$p' | tail -n +2 | grep -c .)" 100
	if [ "${#ACT_OUT}" -gt 16384 ]; then proof logs-answer-is-larger-than-a-frame PASS "${#ACT_OUT} bytes printed"; else proof logs-answer-is-larger-than-a-frame FAIL "only ${#ACT_OUT} bytes: the case does not test a large answer"; fi
	# a confirmation is for one plan and one act, and a replay of an operation does not run it twice
	plan=$(cli service start dnf-automatic-install.service)
	stop_digest=$(cli service stop dnf-automatic-install.timer | sed -n 's/^Plan: //p')
	T=$(mark)
	out=$(cli service start dnf-automatic-install.service --confirm "$stop_digest")
	rc=$?
	expect another-acts-digest-is-refused-exit-code "$rc" 1
	contains another-acts-digest-is-refused-by-the-console "$out" '(mode_refused|plan_changed|input_refused)'
	lacks another-acts-digest-ran-nothing "$(unit_log dnf-automatic-install.service "$T")" 'guestproof dnf run'
	digest=$(printf '%s\n' "$plan" | sed -n 's/^Plan: //p')
	id=$(opid)
	T=$(mark)
	cli service start dnf-automatic-install.service --confirm "$digest" --operation-id "$id" > /dev/null
	expect first-run-of-an-operation-exit-code "$?" 0
	cli service start dnf-automatic-install.service --confirm "$digest" --operation-id "$id" > /dev/null
	expect replay-of-an-operation-exit-code "$?" 0
	expect replayed-operation-ran-once "$(unit_log dnf-automatic-install.service "$T" | grep -c 'guestproof dnf run')" 1
	out=$(cli service stop dbus.service --confirm "$digest")
	rc=$?
	expect protected-unit-is-refused-by-the-class-table-exit-code "$rc" 1
	expect protected-unit-is-refused-before-dialing "$(printf '%s' "$out" | head -1)" unit_protected
	contains durable-receipts-were-kept "$(ls /var/lib/olivares-portal/operations 2> /dev/null | tr '\n' ' ')" '[0-9a-f]{32}'
	contains audit-spool-was-written "$(cat /var/lib/olivares-portal/audit/* 2> /dev/null | head -c 2000)" 'service'
	# The journal is sensitive: what a logs act read is in the console's memory and nowhere on disk.
	expect journal-text-is-not-kept-in-the-operation-records-or-the-audit-spool "$(grep -rl 'guestproof-filler\|guestproof dnf run' /var/lib/olivares-portal 2> /dev/null | tr '\n' ' ')" ""
	systemctl stop olivares-portal-local.socket olivares-portal.service 2> /dev/null
}
echo "PROOF-SUMMARY pass=$passes fail=$fails"
[ "$fails" -eq 0 ]
