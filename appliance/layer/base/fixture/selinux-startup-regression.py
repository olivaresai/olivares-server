#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Olivares.AI
# SPDX-License-Identifier: AGPL-3.0-only
"""Compare old and corrected startup confinement in one enforcing AlmaLinux guest.

Usage: selinux-startup-regression.py PARENT_UNITS CHANGED_UNITS EVIDENCE
The real firstboot binary must be present and the olivares policy absent.
Derived units keep the shipped service sandbox, but run readonly status, use a
private fixture StateDirectory, and omit ordering/Ready conditions. This proves
pre-exec refusal only; unchanged installed apply units prove normal firstboot.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def run(argv):
    return subprocess.run(argv, capture_output=True, text=True, timeout=35)


def witness():
    paths = ("/var/lib/olivares-appliance/state.json", "/var/lib/olivares-appliance/ready",
             "/etc/olivares/olivares.env", "/etc/olivares-portal/selection.json")
    return {p: hashlib.sha256(Path(p).read_bytes()).hexdigest() if Path(p).is_file() else None
            for p in paths}


parent, changed, evidence = map(Path, sys.argv[1:])
evidence.mkdir(parents=True, exist_ok=False)
before = None
units, results, cleanup_errors = [], [], []
failure = "native regression did not finish"
try:
    enforcing = run(["getenforce"])
    if enforcing.returncode or enforcing.stdout.strip() != "Enforcing":
        raise RuntimeError("this regression needs enforcing SELinux")
    modules = run(["semodule", "--list-modules=standard"])
    if modules.returncode or any(line.split()[:1] == ["olivares"] for line in modules.stdout.splitlines()):
        raise RuntimeError("this regression needs the olivares policy absent")
    if Path("/var/lib/olivares-firstboot-policy-test").exists():
        raise RuntimeError("the private fixture directory already exists")
    before = witness()
    for revision, source in (("parent", parent), ("changed", changed)):
        for phase in ("firstboot", "readiness"):
            original = (source / ("olivares-appliance-" + phase + ".service")).read_text()
            service = original.split("[Service]\n", 1)[1].split("[Install]", 1)[0]
            directives = [line.strip() for line in service.splitlines() if not line.lstrip().startswith("#")]
            if [line for line in directives if line.startswith("Exec")] != ["ExecStart=/usr/bin/appliance-firstboot apply"]:
                raise RuntimeError("unexpected execution command in the shipped sandbox")
            if [line for line in directives if line.startswith("StateDirectory=")] != ["StateDirectory=olivares-appliance"]:
                raise RuntimeError("unexpected state directory in the shipped sandbox")
            service = "\n".join(
                "ExecStart=/usr/bin/appliance-firstboot status" if line.strip() == "ExecStart=/usr/bin/appliance-firstboot apply"
                else "StateDirectory=olivares-firstboot-policy-test" if line.strip() == "StateDirectory=olivares-appliance"
                else line for line in service.splitlines()) + "\n"
            name = "olivares-policy-test-" + revision + "-" + phase + ".service"
            path = Path("/run/systemd/system") / name
            with path.open("x") as output:
                output.write("[Unit]\nDescription=Readonly firstboot confinement regression\n[Service]\n" +
                             service + "\nStandardOutput=null\nStandardError=null\nTimeoutStartSec=30s\n")
            units.append((name, path))
            if run(["systemctl", "daemon-reload"]).returncode:
                raise RuntimeError("cannot load the native regression unit")
            start = run(["systemctl", "start", name])
            (evidence / (name + ".start.log")).write_text(start.stdout + start.stderr)
            journal = run(["journalctl", "-b", "-u", name, "--no-pager", "-n", "20", "-o", "cat"])
            if journal.returncode:
                raise RuntimeError("cannot retain the native startup refusal")
            (evidence / (name + ".journal.log")).write_text(journal.stdout + journal.stderr)
            observed = run(["systemctl", "show", "-p", "Result", "-p", "ExecMainCode",
                            "-p", "ExecMainStatus", name])
            if observed.returncode:
                raise RuntimeError("cannot observe the native unit result")
            fields = dict(line.split("=", 1) for line in observed.stdout.splitlines())
            blocked = (start.returncode != 0 and fields.get("Result") == "exit-code" and
                       fields.get("ExecMainCode") == "1" and fields.get("ExecMainStatus") == "229")
            reached_status = fields.get("ExecMainCode") == "1" and fields.get("ExecMainStatus") in ("0", "1", "2")
            results.append({"revision": revision, "phase": phase, "observed": fields,
                            "start_exit": start.returncode,
                            "required_context_regression": "GREEN" if blocked else "RED" if reached_status else "INCONCLUSIVE"})
            if not blocked and not reached_status:
                raise RuntimeError("inconclusive failure before readonly status")
    if [r["required_context_regression"] for r in results] != ["RED", "RED", "GREEN", "GREEN"]:
        raise RuntimeError("expected parent RED then corrected GREEN for both native units")
    if witness() != before:
        raise RuntimeError("readonly regression changed a product effect witness")
    failure = None
except Exception as error:
    failure = str(error)
finally:
    for name, path in units:
        for action in (["systemctl", "stop", name], path):
            try:
                if isinstance(action, Path):
                    action.unlink()
                elif run(action).returncode:
                    cleanup_errors.append("cannot stop " + name)
            except Exception as error:
                cleanup_errors.append(str(error))
    try:
        if units and run(["systemctl", "daemon-reload"]).returncode:
            cleanup_errors.append("cannot reload after removing native test units")
        directory = Path("/var/lib/olivares-firstboot-policy-test")
        if units and directory.exists():
            directory.rmdir()
        unchanged = before is not None and witness() == before
        if before is not None and not unchanged:
            cleanup_errors.append("cleanup changed a product effect witness")
    except Exception as error:
        unchanged = False
        cleanup_errors.append(str(error))
    (evidence / "result.json").write_text(json.dumps({"cases": results,
        "status": "FAIL" if failure or cleanup_errors else "PASS", "failure": failure,
        "cleanup_errors": cleanup_errors, "effect_witness_unchanged": unchanged,
        "scope": "readonly native pre-exec confinement; installed apply still required"}, indent=2) + "\n")
if failure or cleanup_errors:
    raise SystemExit(failure or "; ".join(cleanup_errors))
