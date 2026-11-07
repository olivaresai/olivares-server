#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Olivares.AI
# SPDX-License-Identifier: AGPL-3.0-only
"""Drive KIWI's installer and prove confirmation precedes every write, or explicitly requested unattended mode.

Exit 0: the installed system printed its label (qemu-exit.txt: "ended: hand-over"). Exit 1: a guest ran and did not finish
the install (ended: deadline, exited or refused), the appliance's failure. Exit 2: no guest could be run here (a medium
xorriso cannot read, no QEMU), which measures nothing."""
import argparse
import hashlib
import os
import select
import subprocess
import sys
import tempfile
import time

LABEL = "Olivares Server"
FAILED, UNMEASURED = 1, 2


def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("iso")
    parser.add_argument("target")
    parser.add_argument("log")
    parser.add_argument("--unattended", action="store_true")
    parser.add_argument("--deadline", type=int, default=600, help="seconds the guest may take")
    parser.add_argument("--other-disk", help="an unselected disk that must remain unchanged")
    args = parser.parse_args()
    exit_record = os.path.join(os.path.dirname(args.log), "qemu-exit.txt")
    with tempfile.TemporaryDirectory(prefix="install-driver-") as work:
        try:
            for name in ("linux", "initrd"):
                subprocess.run(["xorriso", "-osirrox", "on", "-indev", args.iso,
                                "-extract", "/boot/x86_64/loader/" + name, os.path.join(work, name)],
                               check=True, capture_output=True, timeout=60)
            info = subprocess.run(["xorriso", "-indev", args.iso, "-pvd_info"], check=True,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=60).stdout
            volume = next(line.split(":", 1)[1].strip().strip("'") for line in info.splitlines()
                          if line.strip().lower().startswith("volume id"))
        except (OSError, subprocess.SubprocessError, StopIteration) as err:
            print("the installer medium cannot be read here: %r" % err, file=sys.stderr)
            return UNMEASURED
        append = f"root=install:CDLABEL={volume} console=ttyS0,115200n8 net.ifnames=0 loglevel=3"
        if args.unattended:
            append += " rd.kiwi.oem.installdevice=/dev/vda rd.kiwi.oem.unattended=true"
        cmd = ["qemu-system-x86_64", "-machine", "q35,accel=kvm", "-cpu", "host", "-smp", "2", "-m", "2048",
               "-drive", f"file={args.target},if=virtio,format=qcow2",
               "-drive", f"if=none,id=medium,format=raw,readonly=on,file={args.iso}",
               "-device", "ide-cd,drive=medium", "-kernel", os.path.join(work, "linux"),
               "-initrd", os.path.join(work, "initrd"), "-append", append,
               "-display", "none", "-serial", "stdio", "-monitor", "none", "-no-reboot"]
        if args.other_disk:
            cmd[11:11] = ["-drive", f"file={args.other_disk},if=virtio,format=qcow2"]
        before = tuple(digest(path) for path in (args.target, args.other_disk) if path)
        try:
            proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        except OSError as err:
            print("no guest can be started here: %r" % err, file=sys.stderr)
            return UNMEASURED
        log = open(args.log, "wb")
        buf = b""
        start = time.time()
        deadline = start + args.deadline
        stage = 0
        ended = "deadline"
        try:
            while time.time() < deadline:
                ready, _, _ = select.select([proc.stdout], [], [], 2)
                if ready:
                    chunk = os.read(proc.stdout.fileno(), 65536)
                    if not chunk:
                        ended = "exited"
                        break
                    buf += chunk
                    log.write(chunk)
                    log.flush()
                    if len(buf) > 262144:
                        buf = buf[-131072:]
                if args.unattended and (b"Select Installation Disk" in buf or b"Destroying ALL data" in buf):
                    raise SystemExit("explicit unattended mode asked a question")
                if not args.unattended and stage == 0 and b"Select Installation Disk" in buf:
                    proc.stdin.write(b"\n")
                    proc.stdin.flush()
                    stage = 1
                elif not args.unattended and stage == 0 and b"Destroying ALL data" in buf:
                    stage = 1
                if not args.unattended and stage == 1 and b"Destroying ALL data" in buf:
                    if tuple(digest(path) for path in (args.target, args.other_disk) if path) != before:
                        raise SystemExit("a disk changed before the erasure confirmation")
                    proc.stdin.write(b"y\n")
                    proc.stdin.flush()
                    stage = 2
                elif LABEL.encode() in buf:
                    if args.other_disk and digest(args.other_disk) != before[1]:
                        raise SystemExit("the unselected disk changed during installation")
                    print(("unattended" if args.unattended else "confirmed") + " install reached " + LABEL)
                    ended = "hand-over"
                    return 0
                if proc.poll() is not None:
                    ended = "exited"
                    break
            print("installer did not reach the installed system (%s)" % ended, file=sys.stderr)
            return FAILED
        except SystemExit:
            ended = "refused"
            raise
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            log.close()
            with open(exit_record, "w") as evidence:
                evidence.write("ended: %s\nseconds: %d\n" % (ended, time.time() - start))


if __name__ == "__main__":
    sys.exit(main())
