#!/bin/bash
# SPDX-FileCopyrightText: 2026 Olivares.AI
# SPDX-License-Identifier: AGPL-3.0-only
# Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.
# The administrator's shell in a built image root (the regression): the aliases both images share, vi -> vim and
# every tool the issue names. The recipe runs this as its admin-shell phase over the KIWI target directory,
# so a defect in the installed profile or in the package set fails the build. The issue scopes the appliance
# to login shells, so a fresh root without ~/.bashrc is measured through /etc/profile. Exit 2 means the image
# could not be measured (no root, no privilege, no working chroot) or could not be left as it was found, 1 a
# measured failure, 0 all checks passed.
set -u

target=${1:?usage: admin-shell-battery.sh TARGET_DIR}
# KIWI builds the root at <target-dir>/build/image-root (kiwi/tasks/system_build.py); nothing moves it.
root=$target/build/image-root
if [ ! -x "$root/bin/bash" ] || [ ! -d "$root/etc" ]; then
    echo "admin-shell: no image root under $target" >&2
    exit 2
fi
if [ "$(id -u)" -eq 0 ]; then
    root_cmd=()
elif sudo -n true 2>/dev/null; then
    root_cmd=(sudo -n)
else
    echo "admin-shell: chrooting the image needs root or passwordless sudo" >&2
    exit 2
fi
chroot_cmd=("${root_cmd[@]}" chroot)
# Prove the chroot runs before checking anything: without CAP_SYS_CHROOT every check would fail as an
# ordinary defect although nothing was measured.
if ! "${chroot_cmd[@]}" "$root" /bin/true 2>/dev/null; then
    echo "admin-shell: cannot chroot $root; no measurement" >&2
    exit 2
fi
# ps (procps-ng) refuses to run without /proc, and a chroot does not bring one (the regression). Mount it in the root
# for the checks and unmount it on every exit the shell controls; a kill nothing can trap (SIGKILL) can still
# leave it, and the recipe stops at this phase's failure, so no later phase ever handles a mounted root. A /proc
# that was already mounted is not this run's to unmount, so mountpoint is asked without privilege: a wrong answer
# only fails loud (a phantom mount fails the ps check) or layers this run's own mount, which this run unmounts.
proc=$root/proc
mounted_proc=
unmount_proc() {
    local status=$?
    [ -n "$mounted_proc" ] || return "$status"
    mounted_proc=
    if ! "${root_cmd[@]}" umount "$proc"; then
        echo "admin-shell: cannot unmount $proc; the image root is left mounted" >&2
        # A measured failure keeps its verdict: only a passing run is turned into a refusal by a root
        # the battery could not put back as it found it.
        if [ "$status" -eq 0 ]; then
            status=2
        fi
    fi
    exit "$status"
}
trap unmount_proc EXIT
trap 'exit 2' INT TERM HUP
if ! mountpoint -q "$proc"; then
    # Marked before the mount, cleared when it fails: a signal bash defers until the mount returns must
    # still find the root marked, or the EXIT trap would leave this run's mount standing.
    mounted_proc=1
    if ! "${root_cmd[@]}" mount -t proc proc "$proc"; then
        mounted_proc=
        echo "admin-shell: cannot mount /proc in $root; no measurement" >&2
        exit 2
    fi
fi

shared_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd) || {
    echo "admin-shell: cannot locate the repository" >&2
    exit 2
}
shared=$shared_root/packaging/container/bashrc.sh
if [ ! -r "$shared" ]; then
    echo "admin-shell: cannot read $shared" >&2
    exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
    echo "admin-shell: sha256sum is required to compare the profile" >&2
    exit 2
fi
path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
fail=0
ok() { printf 'ok   %s\n' "$1"; }
bad() { printf 'FAIL %s\n' "$1" >&2; fail=1; }
want() { case $1 in *"$2"*) ok "$3" ;; *) bad "$3" ;; esac; }

inside() { # COMMAND [TERM [HOME]]
    "${chroot_cmd[@]}" "$root" /usr/bin/env -i PATH="$path" TERM="${2:-xterm}" HOME="${3:-/root}" \
        /bin/bash -c "$1"
}
interactive() { # LOGIN(-l or empty) TERM HOME COMMAND
    local login=()
    [ -n "$1" ] && login=(-l)
    "${chroot_cmd[@]}" "$root" /usr/bin/env -i PATH="$path" TERM="$2" HOME="$3" \
        /bin/bash "${login[@]}" -ic "$4" </dev/null
}

# One file, byte for byte, is the Docker image's rc file and the appliance's profile drop-in. A missing
# or unreadable file must fail, never compare two empty strings and pass.
profile=$root/etc/profile.d/olivares-shell.sh
installed_hash=
[ -f "$profile" ] && installed_hash=$(sha256sum < "$profile" 2>/dev/null)
shared_hash=$(sha256sum < "$shared" 2>/dev/null)
if [ -n "$installed_hash" ] && [ "$installed_hash" = "$shared_hash" ]; then
    ok "/etc/profile.d/olivares-shell.sh is packaging/container/bashrc.sh"
else
    bad "/etc/profile.d/olivares-shell.sh differs from packaging/container/bashrc.sh"
fi
if syntax=$("${chroot_cmd[@]}" "$root" /bin/bash -n /etc/profile.d/olivares-shell.sh 2>&1); then
    ok "the installed profile parses"
else
    bad "the installed profile does not parse: $syntax"
fi

aliases=(
    "ll='ls -alF'" "l='ls -CF'" "la='ls -A'" "lt='ls -altrh'" "ls='ls --color=auto'"
    "o='less'" "..='cd ..'" "...='cd ../..'" "cd..='cd ..'" "md='mkdir -p'" "rd='rmdir'"
    "rehash='hash -r'" "dir='ls -l'" "ls-l='ls -l'" "vi='vim'"
    "grep='grep --color=auto'" "egrep='grep -E --color=auto'" "fgrep='grep -F --color=auto'"
)
# The issue scopes the appliance to login shells: a fresh KIWI root has no ~/.bashrc for a non-login
# interactive shell to read /etc/bashrc from, so /etc/profile is the state that ships.
if listing=$(interactive -l xterm /root 'alias; type ll; type vi' 2>/dev/null); then
    for entry in "${aliases[@]}"; do
        want "$listing" "alias $entry" "login shell: alias $entry"
    done
    want "$listing" "ll is aliased to" "login shell: type ll"
    want "$listing" "vi is aliased to" "login shell: type vi"
else
    bad "login shell: bash did not start"
fi

if home=$(interactive -l xterm /var/lib/olivares/home 'printf "HOME=%s\n" "$HOME"' 2>/dev/null); then
    want "$home" "HOME=/root" "root HOME is /root, as on the Docker image"
else
    bad "root HOME: bash did not start"
fi

if dumb=$(interactive -l dumb /root 'alias; type vi' 2>/dev/null); then
    case $dumb in
        *"alias ls="*) bad "dumb terminal: ls keeps a colour alias" ;;
        *) ok "dumb terminal: ls has no colour alias" ;;
    esac
    want "$dumb" "alias grep='grep --color=auto'" "dumb terminal: grep keeps SLES's colour alias"
    want "$dumb" "alias vi='vim'" "dumb terminal: vi is vim"
else
    bad "dumb terminal: bash did not start"
fi

if completion=$(interactive -l xterm /root 'type _init_completion' 2>/dev/null); then
    want "$completion" "_init_completion is a function" "bash-completion defines _init_completion"
else
    bad "bash-completion: _init_completion is not defined"
fi

tool() { # NAME COMMAND OUTPUT-PATTERN
    local out
    if out=$(inside "set -e; $2" 2>&1) && printf '%s\n' "$out" | grep -Eq "$3"; then
        ok "$1"
    else
        bad "$1: $2: ${out:-no output}"
    fi
}
tool "vi runs VIM" 'vi --version | head -1' '^VIM - Vi IMproved'
tool "vim" 'vim --version | head -1' '^VIM - Vi IMproved'
tool "ifconfig (net-tools)" 'ifconfig --version' 'net-tools'
tool "netstat (net-tools)" 'netstat --version' 'net-tools'
tool "which" 'which --version' 'GNU which'
tool "tree" 'tree --version' '^tree v'
tool "lsof" 'lsof -v 2>&1 | grep revision' 'revision'
tool "tcpdump" 'tcpdump --version 2>&1 | head -1' 'tcpdump version'
tool "rsync" 'rsync --version | head -1' '^rsync '
tool "ps (procps-ng)" 'ps --version' 'procps-ng'
tool "less" 'less --version | head -1' '^less '
tool "man" 'man --version' '^man '
tool "man page of man-db" 'man -w man' '/man1/man'
tool "man-pages" 'man -w intro' '/man1/intro\.1'

if [ "$fail" -ne 0 ]; then
    echo "admin-shell: failed checks in $root" >&2
    exit 1
fi
printf 'admin-shell: all checks passed in %s\n' "$root"
