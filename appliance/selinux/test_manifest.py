# SPDX-FileCopyrightText: 2026 Olivares.AI
# SPDX-License-Identifier: AGPL-3.0-only
"""manifest.tsv lists the accesses the enforcing image must show. Each grant must be held by the rows of access.tsv it
names, on the label it expects; each deny must be a denied.tsv row that no row of access.tsv grants. So deleting a
row a grant needs, or granting what a deny forbids, fails here before any image is built. Every row and denial of
the local API is in the manifest.

Run: python3 -m unittest discover -s appliance/selinux -p 'test_*.py'
"""
import os
import re
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TREE = os.path.normpath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, HERE)

import compare_rules  # noqa: E402
import generate  # noqa: E402
import test_local_api  # noqa: E402
import test_network  # noqa: E402

MANIFEST_COLUMNS = ("id", "source", "domain", "path", "class", "perms", "expected_label", "label_basis", "rows",
                    "kind", "reason")


def _raise(error):
    raise error


def named_like(root, program):
    """Paths under root, git and node_modules apart, with a file or directory name that starts with program. It walks
    the files, so it reads the same tree in a checkout, in the archived tree the enterprise CI builds and in a source
    archive, and untracked files count. A root or a directory it cannot read raises: an empty answer must mean that
    the walk saw the whole tree."""
    found = []
    for top, dirs, files in os.walk(root, onerror=_raise):
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules")]
        found += [os.path.join(top, n) for n in dirs + files if n.startswith(program)]
    return sorted(found)


def entered(rows, login, entry_type):
    """The domains the rows make login enter by executing entry_type: interface calls and type_transition rows."""
    out = []
    for r in rows:
        if r["kind"] == "interface" and r["perms"] == "unconfined_run_to":
            _, transitions, _, _ = compare_rules.interface_rules(r)
            out += [new for s, t, c, _, new in transitions if (s, t, c) == (login, entry_type, "process")]
        elif r["kind"] == "type_transition" and (r["source"], r["target"], r["class"]) == (login, entry_type, "process"):
            out.append(r["perms"].split(" ", 1)[0])
    return out


def login_failures(m, rows):
    """entry: a login (domain) running the program (path) runs in the expected context, made by the interface row
    and admitted by the portal's rows after it; no-entry: a copy labeled bin_t keeps the login's context, and no row
    lets the portal read /proc of the login's domain; transition: sesearch shows exactly one transition to the type."""
    by_id = {r["id"]: r for r in rows}
    login, want = m["domain"], m["expected_label"].split(":")[2] if m["expected_label"].count(":") >= 3 else ""
    if m["kind"] == "transition":
        call = by_id.get(m["rows"].split(";")[0])
        found = []
        for rid in m["rows"].split(";"):
            step = by_id.get(rid)
            if step:
                found += entered(rows, login, step["target"])
        want = set(m["expected_label"].split())
        if (len(want) == 1 and found != [m["expected_label"]]) or (len(want) > 1 and set(found) != want):
            return [f"{m['id']}: {login} has {len(found)} transitions on {call['target'] if call else '?'}:process, "
                    f"not one to {m['expected_label']}"]
        return []
    if m["kind"] == "no-entry":
        out = []
        if want != login or entered(rows, login, "bin_t"):
            out.append(f"{m['id']}: a copy labeled bin_t does not stay in {login}")
        out += [f"{m['id']}: row {r['id']} lets the portal read /proc of {login}, so it would admit the copy"
                for r in rows if r["kind"] == "allow" and r["source"] == "olivares_portal_t" and r["target"] == login]
        return out
    ids = m["rows"].split(";")
    call = by_id.get(ids[0])
    if call is None or call["kind"] != "interface" or want not in entered([call], login, call["target"]):
        return [f"{m['id']}: row {ids[0]} does not enter {want} from {login} on {m['path']}"]
    out = []
    for rid in ids[1:]:
        r = by_id.get(rid)
        if r is None or (r["kind"], r["source"], r["target"], r["condition"]) != ("allow", "olivares_portal_t", want, ""):
            out.append(f"{m['id']}: row {rid} is not the portal's unconditional read of /proc of {want}")
    return out


def manifest_failures(manifest, rows, denied):
    failures, seen = [], set()
    by_id = {r["id"]: r for r in rows}
    denied_by_id = {d["id"]: d for d in denied}
    for m in manifest:
        if m["id"] in seen:
            failures.append(f"{m['id']}: repeated manifest id")
        seen.add(m["id"])
        wanted = set(m["perms"].split())
        if m["kind"] == "grant":
            held = set()
            for rid in m["rows"].split(";"):
                r = by_id.get(rid)
                if r is None:
                    failures.append(f"{m['id']}: row {rid} is not in access.tsv")
                    continue
                if (r["kind"], r["source"], r["target"], r["class"], r["condition"]) != (
                        "allow", m["domain"], m["expected_label"], m["class"], ""):
                    failures.append(f"{m['id']}: row {rid} is not an unconditional allow of {m['domain']} on "
                                    f"{m['expected_label']}:{m['class']}")
                    continue
                held |= set(r["perms"].split())
            if wanted - held:
                failures.append(f"{m['id']}: {m['path']} needs {' '.join(sorted(wanted - held))} on "
                                f"{m['expected_label']}:{m['class']}, which its rows do not hold")
        elif m["kind"] == "deny":
            d = denied_by_id.get(m["rows"])
            if d is None or (d["source"], d["target"], d["class"], d["perm"]) != (
                    m["domain"], m["expected_label"], m["class"], m["perms"]):
                failures.append(f"{m['id']}: denied.tsv has no row {m['rows']} for {m['domain']} "
                                f"{m['perms']} on {m['expected_label']}:{m['class']}")
            for r in rows:
                if (r["kind"] == "allow" and r["source"] == m["domain"] and r["target"] == m["expected_label"]
                        and r["class"] == m["class"] and wanted & set(r["perms"].split())):
                    failures.append(f"{m['id']}: row {r['id']} grants what {m['rows']} denies")
        elif m["kind"] in ("entry", "no-entry", "transition"):
            failures += login_failures(m, rows)
        elif m["kind"] == "role":
            # The expected context's role must hold the domain, or the kernel refuses every exec that computes it
            # (security_compute_sid invalid_context): a role row, not an allow, makes it valid.
            parts = m["expected_label"].split(":")
            r = by_id.get(m["rows"])
            if len(parts) < 4 or parts[2] != m["domain"] or r is None or (r["kind"], r["source"], r["target"]) != (
                    "role", parts[1], m["domain"]):
                failures.append(f"{m['id']}: row {m['rows']} does not authorize {m['domain']} for the role of "
                                f"{m['expected_label']}")
        else:
            failures.append(f"{m['id']}: kind {m['kind']!r} is not grant, deny, entry, no-entry, transition or role")
    return failures


def entry_failures(manifest, rows):
    """The entries for the operator's login: for each interface row, an entry for an SSH root login and one for an
    olivares-admins login, a no-entry for a copy of the program labeled bin_t, and the one transition sesearch shows."""
    failures = []
    for r in (r for r in rows if r["kind"] == "interface" and r["perms"] == "unconfined_run_to"):
        entries = [m for m in manifest if m["kind"] == "entry" and m["rows"].split(";")[0] == r["id"]]
        for who in ("root", "olivares-admins"):
            if not any(who in m["reason"] for m in entries):
                failures.append(f"{r['id']}: no entry entry for an SSH {who} login")
        if not any(m["kind"] == "no-entry" for m in manifest):
            failures.append(f"{r['id']}: no no-entry entry for a copy of the program labeled bin_t")
        if not any(m["kind"] == "transition" and m["rows"] == r["id"] for m in manifest):
            failures.append(f"{r['id']}: no transition entry for sesearch")
    return failures


def repository():
    manifest = generate.read_table(os.path.join(HERE, "manifest.tsv"), MANIFEST_COLUMNS)
    rows = generate.read_table(os.path.join(HERE, "access.tsv"), generate.ACCESS_COLUMNS)
    denied = compare_rules.read_denied(os.path.join(HERE, "denied.tsv"))
    return manifest, rows, denied


EXPECTED_COLUMNS = ("deny", "source", "target", "class", "perm", "name", "reason")


def expected_denial_failures(expected, rows, denied):
    """Each denial the qualification expects is a denied.tsv row's access that no row of access.tsv grants: the
    expected list can name a refused access, never open one or excuse an access no rule refuses."""
    failures = []
    denied_by_id = {d["id"]: d for d in denied}
    for e in expected:
        d = denied_by_id.get(e["deny"])
        if d is None or (d["source"], d["target"], d["class"]) != (e["source"], e["target"], e["class"]) or \
                e["perm"] not in d["perm"].split():
            failures.append(f"{e['deny']}: denied.tsv refuses no {e['perm']} of {e['source']} on "
                            f"{e['target']}:{e['class']}")
        for r in rows:
            if (r["kind"] == "allow" and (r["source"], r["target"], r["class"]) == (e["source"], e["target"], e["class"])
                    and e["perm"] in r["perms"].split()):
                failures.append(f"{e['deny']}: row {r['id']} grants the expected denial {e['perm']}")
    return failures


def expected_denials():
    return generate.read_table(os.path.join(HERE, "expected-denials.tsv"), EXPECTED_COLUMNS)


class Manifest(unittest.TestCase):
    def test_engine_commands_are_not_visible_to_tools(self):
        _, rows, _ = repository()
        engine = entered(rows, "olivares_t", "bin_t")
        tool = entered(rows, "olivares_tool_t", "bin_t")
        self.assertEqual(engine, ["olivares_engine_cmd_t"])
        self.assertEqual(tool, ["olivares_cmd_t"])
        self.assertEqual(manifest_failures(*repository()), [])
        atoms = {a[1:5] for a in compare_rules.row_atoms(rows) if a[0] == "allow"}
        for target in (engine[0], "olivares_gitpub_t", "olivares_git_import_t"):
            for source in ("olivares_tool_t", tool[0]):
                self.assertNotIn((source, target, "file", "read"), atoms)
                self.assertNotIn((source, target, "dir", "search"), atoms)
        self.assertIn(("olivares_tool_t", tool[0], "file", "read"), atoms)
        self.assertIn((tool[0], "olivares_t", "fifo_file", "write"), atoms)
        self.assertIn(("olivares_t", engine[0], "process", "signal"), atoms)
        self.assertIn(("olivares_t", tool[0], "process", "signal"), atoms)
        self.assertIn(("olivares_t", tool[0], "process", "sigkill"), atoms)

    def test_every_entry_is_held_or_refused_by_the_tables(self):
        self.assertEqual(manifest_failures(*repository()), [])

    def test_each_grant_fails_without_each_of_its_rows(self):
        manifest, rows, denied = repository()
        for m in (m for m in manifest if m["kind"] == "grant"):
            for rid in m["rows"].split(";"):
                with self.subTest(entry=m["id"], row=rid):
                    failures = manifest_failures([m], [r for r in rows if r["id"] != rid], denied)
                    self.assertTrue(failures)

    def test_a_row_granting_a_denied_access_fails(self):
        manifest, rows, denied = repository()
        deny = next(m for m in manifest if m["kind"] == "deny")
        extra = dict(rows[0], id="X-01", kind="allow", source=deny["domain"], target=deny["expected_label"],
                     condition="", via="")
        extra["class"], extra["perms"] = deny["class"], deny["perms"]
        self.assertIn(f"{deny['id']}: row X-01 grants what {deny['rows']} denies",
                      manifest_failures([deny], rows + [extra], denied))

    def test_first_boot_reads_cloud_init_and_userdb_state_and_executes_neither(self):
        manifest, _, _ = repository()
        paths = {(m["path"], m["kind"]) for m in manifest if m["domain"] == "olivares_firstboot_t"}
        for path in ("/usr/bin/cloud-init", "/var/lib/cloud/data/status.json", "/var/lib/cloud/data/result.json",
                     "/etc/cloud/cloud-init.disabled", "/run/cloud-init/disabled", "/proc/cmdline",
                     "/etc/userdb/olivares.user", "/run/userdb/olivares.user", "/run/host/userdb/olivares.user",
                     "/usr/lib/userdb/olivares.user"):
            with self.subTest(path=path):
                self.assertIn((path, "grant"), paths)
        self.assertIn(("/usr/bin/cloud-init", "deny"), paths)
        self.assertIn(("/usr/bin/id", "deny"), paths)

    def test_first_boot_stats_every_cloud_init_unit_link_it_names(self):
        """A local host owner refuses cloud-init when a link of cloudInitUnitLinks (adapters.go) exists. First boot
        stats each one without following it; a link the policy does not let it stat reads as "cannot be read", which
        would refuse every local install under enforcing."""
        with open(os.path.join(TREE, "appliance", "layer", "base", "adapters.go"), encoding="utf-8") as f:
            block = re.search(r"var cloudInitUnitLinks = \[\]string\{(.*?)\n\}", f.read(), re.S)
        self.assertIsNotNone(block, "adapters.go names no cloudInitUnitLinks")
        links = re.findall(r'"([^"]+)"', block.group(1))
        self.assertTrue(links, "cloudInitUnitLinks is empty")
        manifest, _, _ = repository()
        held = {(m["path"], m["class"], m["perms"]) for m in manifest
                if m["domain"] == "olivares_firstboot_t" and m["kind"] == "grant"}
        for link in links:
            with self.subTest(link=link):
                self.assertIn((link, "lnk_file", "getattr"), held)
                self.assertIn((os.path.dirname(link), "dir", "search"), held)

    def test_first_boot_may_run_every_program_the_guestinfo_carrier_asks(self):
        """The guestinfo carrier reads a runner error as "no VMware tools here" (sources.go), so a program it asks
        that first boot's domain cannot execute makes the carrier silently absent on VMware under enforcing."""
        with open(os.path.join(TREE, "appliance", "answers", "carriers", "sources.go"), encoding="utf-8") as f:
            asked = re.findall(r'c\.Run\(ctx, "([^"]+)"', f.read())
        self.assertTrue(asked, "sources.go names no program the guestinfo carrier runs")
        manifest, _, _ = repository()
        runs = {m["path"] for m in manifest if (m["domain"], m["class"], m["kind"]) == ("olivares_firstboot_t", "file", "grant")
                and {"execute", "execute_no_trans"} <= set(m["perms"].split())}
        for name in asked:
            with self.subTest(program=name):
                self.assertIn("/usr/bin/" + name, runs)

    def test_systemd_userdbd_reads_the_administrator_record(self):
        # The record exists for systemd-userdbd to serve; at the boot after the console wrote it, its getattr was refused.
        manifest, _, _ = repository()
        grants = {(m["path"], m["class"], m["perms"]) for m in manifest
                  if m["domain"] == "systemd_userdbd_t" and m["kind"] == "grant"}
        self.assertIn(("/etc/userdb/olivares.user", "file", "getattr open read"), grants)

    def test_the_repair_console_holds_the_power_verbs_serialization_locks(self):
        # The power verb holds the lifecycle lock shared and the operation store's lock exclusive (repair.HostHold),
        # then reads every record (repair.RecordsGate); the lifecycle directory's search was refused, nothing granted
        # the rest, and the console never writes the store.
        manifest, _, _ = repository()
        console = {(m["path"], m["class"], m["perms"]) for m in manifest
                   if m["domain"] == "olivares_repair_console_t" and m["kind"] == "grant"}
        for entry in (("/run/olivares-lifecycle", "dir", "search"),
                      ("/run/olivares-lifecycle/lifecycle.lock", "file", "getattr lock open read"),
                      ("/var/lib/olivares-portal", "dir", "search"),
                      ("/var/lib/olivares-portal/operations", "dir", "getattr open read search"),
                      ("/var/lib/olivares-portal/operations/store.lock", "file", "getattr lock open read"),
                      ("/var/lib/olivares-portal/operations/<id>.json", "file", "getattr open read")):
            with self.subTest(entry=entry):
                self.assertIn(entry, console)
        portal = {(m["path"], m["class"], m["perms"]) for m in manifest
                  if m["domain"] == "olivares_portal_t" and m["kind"] == "grant"}
        # The engine sets the lock's mode and group when it opens, so the console's group can reach it.
        self.assertIn(("/var/lib/olivares-portal/operations/store.lock", "file", "setattr"), portal)

    def test_the_repair_console_reaches_every_gate_after_the_window_and_the_power_helper(self):
        # An ordinary reboot after the window gate: PackageGate queries rpm's lock with F_OFD_GETLK
        # (repair.lockHeld), StorageGate asks the bus daemon only (Hello, NameHasOwner), then the power helper.
        # The rpm search was refused on an enforcing desktop's first boot; nothing granted the bus.
        manifest, rows, _ = repository()
        console = {(m["path"], m["class"], m["perms"]) for m in manifest
                   if m["domain"] == "olivares_repair_console_t" and m["kind"] == "grant"}
        for entry in (("/usr/lib/sysimage/rpm", "dir", "search"),
                      ("/usr/lib/sysimage/rpm/.rpm.lock", "file", "getattr lock open read"),
                      ("/run/dbus", "dir", "search"),
                      ("/run/dbus/system_bus_socket", "sock_file", "write"),
                      ("/run/dbus/system_bus_socket", "unix_stream_socket", "connectto"),
                      ("/run/olivares-helpers", "dir", "search"),
                      ("/run/olivares-helpers/power.sock", "sock_file", "getattr write"),
                      ("/run/olivares-helpers/power.sock", "unix_stream_socket", "connectto")):
            with self.subTest(entry=entry):
                self.assertIn(entry, console)
        allowed = {(r["source"], r["target"], r["class"]): set(r["perms"].split())
                   for r in rows if r["kind"] == "allow" and "olivares_repair_console_t" in (r["source"], r["target"])}
        self.assertEqual(allowed.get(("olivares_repair_console_t", "system_dbusd_t", "dbus")), {"send_msg"})
        self.assertEqual(allowed.get(("system_dbusd_t", "olivares_repair_console_t", "dbus")), {"send_msg"})
        # The bus daemon only: no service on the bus, udisks included, is a target of the console.
        self.assertEqual(sorted(t for (s, t, c) in allowed if s == "olivares_repair_console_t" and c == "dbus"),
                         ["system_dbusd_t"])
        # Read-only on rpm's database: no write, append, create or map.
        self.assertEqual(sorted(p for (s, t, c), perms in allowed.items() if t == "rpm_var_lib_t"
                                for p in perms if p in ("write", "append", "create", "map", "unlink", "add_name")), [])

    def test_every_local_api_row_and_denial_is_in_the_manifest(self):
        manifest, rows, _ = repository()
        granted = {rid for m in manifest if m["kind"] == "grant" for rid in m["rows"].split(";")}
        self.assertEqual(sorted(set(test_local_api.local_api_rows(rows)) - granted), [])
        refused = {m["rows"] for m in manifest if m["kind"] == "deny"}
        self.assertEqual(sorted(set(test_local_api.DENIED) - refused), [])

    def test_without_the_denial_of_the_clis_key_open_its_entry_fails(self):
        manifest, rows, denied = repository()
        entry = next(m for m in manifest if m["rows"] == "N-CLI-KEY-OPEN")
        self.assertEqual(manifest_failures([entry], rows, [d for d in denied if d["id"] != "N-CLI-KEY-OPEN"]),
                         [f"{entry['id']}: denied.tsv has no row N-CLI-KEY-OPEN for olivares_cli_t open on "
                          "olivares_portal_key_t:file"])

    def test_the_operators_entry_is_in_the_manifest_for_f6(self):
        manifest, rows, _ = repository()
        self.assertEqual(entry_failures(manifest, rows), [])

    def test_the_manifest_without_an_entry_of_the_operator_fails(self):
        manifest, rows, _ = repository()
        self.assertEqual(entry_failures(manifest, rows), [])
        for kind in ("entry", "no-entry", "transition"):
            with self.subTest(kind=kind):
                self.assertTrue(entry_failures([m for m in manifest if m["kind"] != kind], rows))

    def test_an_entry_the_rows_do_not_make_fails(self):
        manifest, rows, denied = repository()
        entry = next(m for m in manifest if m["kind"] == "entry")
        other = dict(entry, expected_label="unconfined_u:unconfined_r:olivares_portal_t:s0-s0:c0.c1023")
        self.assertIn(f"{entry['id']}: row CLI-16 does not enter olivares_portal_t from {entry['domain']} on "
                      "/usr/bin/olivares-appliance", manifest_failures([other], rows, denied))

    def test_a_portal_read_of_the_login_domain_fails_the_refused_copy(self):
        manifest, rows, denied = repository()
        copy = next(m for m in manifest if m["kind"] == "no-entry")
        peer = dict(next(r for r in rows if r["id"] == "PORTAL-32"), id="X-01", target=copy["domain"])
        self.assertIn(f"{copy['id']}: row X-01 lets the portal read /proc of {copy['domain']}, so it would admit the copy",
                      manifest_failures([copy], rows + [peer], denied))

    def test_a_second_transition_to_the_cli_fails_the_sesearch_entry(self):
        manifest, rows, denied = repository()
        once = next(m for m in manifest if m["kind"] == "transition")
        extra = dict(next(r for r in rows if r["id"] == "CLI-16"), id="X-01")
        self.assertIn(f"{once['id']}: {once['domain']} has 2 transitions on olivares_cli_exec_t:process, not one to "
                      "olivares_cli_t", manifest_failures([once], rows + [extra], denied))


    def test_every_network_row_and_denial_is_in_the_manifest(self):
        manifest, rows, _ = repository()
        net = test_network.network_rows(rows)
        granted = {rid for m in manifest if m["kind"] == "grant" for rid in m["rows"].split(";")}
        self.assertEqual(sorted(r["id"] for r in net if r["kind"] == "allow" and r["id"] not in granted), [])
        labels = {m["expected_label"] for m in manifest if m["kind"] == "grant"}
        self.assertEqual(sorted(r["id"] for r in net if r["kind"] == "type_transition"
                                and r["perms"].split(" ", 1)[0] not in labels), [])
        refused = {m["rows"] for m in manifest if m["kind"] == "deny"}
        self.assertEqual(sorted(set(test_network.DENIED) - refused), [])

    def test_the_program_search_matches_names_at_any_depth_and_fails_on_a_bad_root(self):
        """A file or directory whose name starts with the program is found at any depth; the same name under .git or
        node_modules, at any depth, is not; a root it cannot read raises instead of answering empty."""
        with tempfile.TemporaryDirectory() as root:
            found_paths = ("cmd/olivares-snapshotcore/main.go", "appliance/layer/olivares-snapshotcore",
                           "internal/a/b/olivares-snapshotcore-v2/main.go", "bin/olivares-snapshotcore.service")
            ignored = ("node_modules/olivares-snapshotcore/index.js", "web/node_modules/olivares-snapshotcore/index.js",
                       ".git/olivares-snapshotcore", "a/.git/olivares-snapshotcore", "cmd/other/main.go",
                       "cmd/x-olivares-snapshotcore")
            for path in found_paths + ignored:
                os.makedirs(os.path.dirname(os.path.join(root, path)), exist_ok=True)
                open(os.path.join(root, path), "w").close()
            found = [os.path.relpath(p, root) for p in named_like(root, "olivares-snapshotcore")]
            self.assertEqual(found, ["appliance/layer/olivares-snapshotcore", "bin/olivares-snapshotcore.service",
                                     "cmd/olivares-snapshotcore", "internal/a/b/olivares-snapshotcore-v2"])
            with self.assertRaises(OSError):
                named_like(os.path.join(root, "missing"), "olivares-snapshotcore")

    def test_every_go_domain_holds_what_the_runtime_reads_at_start(self):
        """The Go runtime reads its cgroup limits and the huge page size before main, in whatever domain the program
        runs. Each domain with an entry point holds exactly those two reads, with a manifest entry each, or is named
        here. The storage helper's huge page read is HSTO-31, which it holds for its own reason with more permissions."""
        manifest, rows, _ = repository()
        not_go = {"olivares_snapshotcore_t": "olivares-snapshotcore"}
        self.assertTrue(os.path.samefile(os.path.join(TREE, "appliance", "selinux"), HERE),
                        f"{TREE} is not the tree root, so an empty answer below would prove nothing")
        for domain, program in not_go.items():
            found = named_like(TREE, program)
            self.assertEqual(found, [], f"{program} is in the tree now: measure its start and drop {domain} from not_go")
        wanted = (("/sys/fs/cgroup", "cgroup_t", "dir", {"search"}),
                  ("/sys/kernel/mm/transparent_hugepage/hpage_pmd_size", "sysfs_t", "file", {"open", "read"}))
        # The generic-entry domains run generic programs (bash, git), none of them a Go program of this tree.
        domains = sorted({r["source"] for r in rows if "entrypoint" in r["perms"].split()} - set(not_go) -
                         set(generate.GENERIC_DOMAINS))
        self.assertGreaterEqual(len(domains), 16)
        for domain in domains:
            for path, label, cls, perms in wanted:
                with self.subTest(domain=domain, path=path):
                    held = {p for r in rows if (r["kind"], r["source"], r["target"], r["class"], r["condition"]) ==
                            ("allow", domain, label, cls, "") for p in r["perms"].split()}
                    if (domain, label, cls) == ("olivares_helper_storage_t", "sysfs_t", "file"):
                        self.assertLessEqual(perms, held)
                    else:
                        self.assertEqual(perms, held)
                    self.assertTrue(any((m["domain"], m["path"], m["expected_label"], m["class"], m["kind"]) ==
                                        (domain, path, label, cls, "grant") and perms <= set(m["perms"].split())
                                        for m in manifest))

    def test_the_go_domains_outside_a_helper_slice_read_their_cpu_limit(self):
        """On the image the system slice enables the cpu controller, so a unit directly in it, or a login session,
        has a cpu.max the Go runtime reads once it may search the cgroup tree; a helper instance sits in its template's
        slice, which has none. Measured on the image's guest, unit by unit: only these domains showed the denial, so
        only these hold the read and no other domain may."""
        manifest, rows, _ = repository()
        # The firewall helper's program also runs as olivares-firewall.service and olivares-firewall-guard.service,
        # and the storage helper runs as olivares-portal-storage.service, directly in the system slice.
        # An installed tool runs in olivares.service's own cgroup, and its runtime also stats cgroup.controllers
        # (measured on the image with the domain permissive, 2026-10-23). The PEP hook client runs there too, as the
        # tool's child (cpu.max read by comm=olivares on candidate rc16, 2026-10-25).
        system_slice = {"olivares_portal_t", "olivares_repair_console_t", "olivares_net_guard_t", "olivares_firstboot_t",
                        "olivares_t", "olivares_cli_t", "olivares_helper_firewall_t", "olivares_helper_storage_t", "olivares_tool_t",
                        "olivares_hook_t", "olivares_container_hook_t", "olivares_container_relay_t"}
        measured = {"olivares_tool_t": {"getattr", "open", "read"}}
        entry = {r["source"] for r in rows if "entrypoint" in r["perms"].split()}
        self.assertLessEqual(system_slice, entry)
        holders = {r["source"] for r in rows if r["kind"] == "allow" and r["target"] == "cgroup_t" and r["class"] == "file"}
        self.assertEqual(holders, system_slice)
        for domain in sorted(system_slice):
            with self.subTest(domain=domain):
                held = {p for r in rows if (r["kind"], r["source"], r["target"], r["class"], r["condition"]) ==
                        ("allow", domain, "cgroup_t", "file", "") for p in r["perms"].split()}
                self.assertEqual(measured.get(domain, {"open", "read"}), held)
                self.assertTrue(any((m["domain"], m["expected_label"], m["class"], m["kind"]) ==
                                    (domain, "cgroup_t", "file", "grant") and m["path"].endswith("/cpu.max") and
                                    {"open", "read"} <= set(m["perms"].split()) for m in manifest))


    def test_each_folder_the_engine_creates_gets_its_label_at_creation(self):
        """restorecon and the creation transition must agree: a folder the engine creates under its data directory
        gets, by name, the label its file context gives it, and a directory it creates in /tmp gets the engine's
        scratch type, which no rule lets an installed tool reach."""
        _, rows, _ = repository()
        contexts = generate.read_table(os.path.join(HERE, "contexts.tsv"), generate.CONTEXTS_COLUMNS)
        named = {("olivares_var_lib_t", "tools"): "olivares_tool_exec_t",
                 ("olivares_var_lib_t", "accounts"): "olivares_tool_home_t",
                 ("olivares_var_lib_t", "session-workspaces"): "olivares_workspace_t",
                 ("olivares_var_lib_t", "session-worktrees"): "olivares_workspace_t",
                 ("olivares_var_lib_t", "workspaces"): "olivares_workspace_t",
                 ("olivares_var_lib_t", "tool-tmp"): "olivares_tmp_t",
                 ("olivares_var_lib_t", "public"): "olivares_engine_public_t",
                 ("olivares_tool_exec_t", ".probe"): "olivares_tool_home_t",
                 ("olivares_tool_exec_t", ".ripgrep"): "olivares_tool_rg_exec_t",
                 ("olivares_var_lib_t", "run"): "olivares_run_t",
                 ("olivares_var_lib_t", "gitpublish"): "olivares_gitpublish_t",
                 ("olivares_var_lib_t", "imports"): "olivares_skills_import_t"}
        # The skills import's staging is the one named folder below another one of the data directory.
        nested = {"imports": "/var/lib/olivares/skills/imports"}
        found, unnamed = {}, {}
        for r in rows:
            if (r["kind"], r["source"], r["class"]) != ("type_transition", "olivares_t", "dir"):
                continue
            result, _, name = r["perms"].partition(" ")
            if name:
                found[(r["target"], name.strip('"'))] = result
            else:
                unnamed[r["target"]] = result
        self.assertEqual(found, named)
        self.assertEqual(unnamed, {"tmp_t": "olivares_engine_tmp_t"})
        labels = {c["path"]: c["type"] for c in contexts}
        for (parent, name), result in sorted(named.items()):
            if parent == "olivares_var_lib_t":
                with self.subTest(folder=name):
                    self.assertEqual(labels.get(nested.get(name, f"/var/lib/olivares/{name}") + "(/.*)?"), result)
        self.assertEqual(labels.get(r"/var/lib/olivares/tools/\.ripgrep(/.*)?"), "olivares_tool_rg_exec_t")
        # The ripgrep type comes only from its folder: no file transition labels a file by its name anywhere else.
        self.assertEqual([r["id"] for r in rows if r["kind"] == "type_transition" and r["class"] == "file" and
                          r["perms"].split(" ", 1)[0] == "olivares_tool_rg_exec_t"], [])
        self.assertEqual(labels.get("/tmp/(eg|olivares-gpg|dr-restore|dr-inspect)-[^/]+(/.*)?"),
                         "olivares_engine_tmp_t")
        self.assertEqual([r["id"] for r in rows if r["kind"] == "allow" and r["source"] == "olivares_tool_t" and
                          r["target"] == "olivares_engine_tmp_t"], [])

    def test_claude_part_and_final_file_share_one_executable_type(self):
        """The installer creates claude.part and renames it; creation and restorecon must select the same Claude-only type."""
        _, rows, _ = repository()
        self.assertEqual([r["id"] for r in rows if (r["kind"], r["source"], r["target"], r["class"], r["perms"]) ==
                          ("type_transition", "olivares_t", "olivares_tool_exec_t", "file",
                           'olivares_tool_claude_exec_t "claude.part"')], ["TOOL-114"])
        contexts = generate.read_table(os.path.join(HERE, "contexts.tsv"), generate.CONTEXTS_COLUMNS)
        labels = {c["path"]: c["type"] for c in contexts}
        self.assertEqual(labels.get(r"/var/lib/olivares/tools/claude/[^/]+/bin/claude"), "olivares_tool_claude_exec_t")

    def test_each_expected_denial_is_a_refused_access(self):
        _, rows, denied = repository()
        expected = expected_denials()
        self.assertEqual(expected_denial_failures(expected, rows, denied), [])
        # The qualification keeps Claude Code's shell snapshot refused and visible.
        self.assertIn(("N-CMD-HOME-WRITE", "olivares_cmd_t", "olivares_tool_home_t", "dir", "write", "shell-snapshots"),
                      [(e["deny"], e["source"], e["target"], e["class"], e["perm"], e["name"]) for e in expected])

    def test_an_expected_denial_without_its_refusal_fails(self):
        _, rows, denied = repository()
        e = dict(expected_denials()[0], perm="read")
        self.assertTrue(expected_denial_failures([e], rows, denied))
        e = dict(expected_denials()[0])
        grant = dict(rows[0], id="X-01", kind="allow", source=e["source"], target=e["target"], perms=e["perm"])
        grant["class"] = e["class"]
        self.assertIn(f"{e['deny']}: row X-01 grants the expected denial {e['perm']}",
                      expected_denial_failures([e], rows + [grant], denied))

if __name__ == "__main__":
    unittest.main()
