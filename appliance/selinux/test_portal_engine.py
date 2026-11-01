# SPDX-FileCopyrightText: 2026 Olivares.AI
# SPDX-License-Identifier: AGPL-3.0-only
"""The authenticated portal's engine client reaches only the appliance console port."""
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import generate  # noqa: E402
import test_manifest  # noqa: E402

PORTAL = "olivares_portal_t"
CONSOLE = "olivares_console_port_t"
CLIENT_SOCKET = {"accept", "connect", "create", "getattr", "getopt", "read", "setopt", "shutdown", "write"}
PUBLIC = "olivares_engine_public_t"
PRIVATE = "olivares_var_lib_t"
PUBLIC_PATH = "/var/lib/olivares/public(/.*)?"
PUBLISH_DIRECTORY = {"add_name", "create", "getattr", "remove_name", "search", "setattr", "write"}
# os.CreateTemp opens the staging file O_RDWR even though publication only writes it; os.Rename lstats the copy it
# replaces (the regression).
PUBLISH_FILE = {"create", "getattr", "open", "read", "rename", "setattr", "unlink", "write"}
READ_FILE = {"getattr", "open", "read"}


def granted(rows, source, target, objclass):
    return {perm for row in rows
            if (row["kind"], row["source"], row["target"], row["class"]) == ("allow", source, target, objclass)
            for perm in row["perms"].split()}


def generated_grants(policy, source, target, objclass):
    pattern = r"allow %s %s:%s (?:\{([^}]+)\}|([a-z_]+));" % (source, target, objclass)
    return {perm for group, single in re.findall(pattern, policy) for perm in (group or single).split()}


class PortalEngineClient(unittest.TestCase):
    def test_fresh_network_audit_directory_and_append_have_the_required_permissions(self):
        rows = generate.read_table(os.path.join(HERE, "access.tsv"), generate.ACCESS_COLUMNS)
        with open(os.path.join(HERE, "olivares.te"), encoding="utf-8") as stream:
            policy = stream.read()
        # productionNetworkAccess mkdirs operations/audit; audit.appendLine opens O_RDWR|O_APPEND|O_CREATE.
        required = {
            "dir": {"add_name", "create", "getattr", "search", "write"},
            "file": {"append", "create", "getattr", "open", "read"},
        }
        for objclass, permissions in required.items():
            with self.subTest(representation="table", operation=objclass):
                self.assertEqual(permissions - granted(rows, PORTAL, "olivares_portal_ops_t", objclass), set())
            with self.subTest(representation="generated", operation=objclass):
                self.assertEqual(permissions - generated_grants(policy, PORTAL, "olivares_portal_ops_t", objclass), set())

    def test_table_grants_client_creation_and_only_the_console_destination(self):
        rows = generate.read_table(os.path.join(HERE, "access.tsv"), generate.ACCESS_COLUMNS)
        held = {}
        for row in rows:
            if (row["kind"], row["source"], row["class"]) == ("allow", PORTAL, "tcp_socket"):
                held.setdefault(row["target"], set()).update(row["perms"].split())
        self.assertEqual(held.get(PORTAL), CLIENT_SOCKET)
        self.assertEqual({target for target, perms in held.items() if "name_connect" in perms}, {CONSOLE})
        self.assertEqual(held.get(CONSOLE), {"name_connect"})

    def test_generated_policy_keeps_the_same_client_boundary(self):
        with open(os.path.join(HERE, "olivares.te"), encoding="utf-8") as stream:
            policy = stream.read()
        held = {}
        for target, group, single in re.findall(
                r"allow olivares_portal_t ([A-Za-z0-9_]+):tcp_socket (?:\{([^}]+)\}|([a-z_]+));", policy):
            held.setdefault(PORTAL if target == "self" else target, set()).update((group or single).split())
        self.assertEqual(held.get(PORTAL), CLIENT_SOCKET)
        self.assertEqual({target for target, perms in held.items() if "name_connect" in perms}, {CONSOLE})
        self.assertEqual(held.get(CONSOLE), {"name_connect"})


class PublicEngineCredential(unittest.TestCase):
    def test_only_the_public_directory_and_its_staging_files_get_the_public_label(self):
        contexts = generate.read_table(os.path.join(HERE, "contexts.tsv"), generate.CONTEXTS_COLUMNS)
        public = [c for c in contexts if c["type"] == PUBLIC]
        self.assertEqual([(c["path"], c["file_type"], c["entry"], c["declare"]) for c in public],
                         [(PUBLIC_PATH, "all", "module", "files_type")])
        for path in ("/var/lib/olivares/public", "/var/lib/olivares/public/tls.crt",
                     "/var/lib/olivares/public/.olivares-cert-stage"):
            self.assertRegex(path, "^" + PUBLIC_PATH + "$")
        for path in ("/var/lib/olivares/tls.crt", "/var/lib/olivares/tls.key",
                     "/var/lib/olivares/olivares.db", "/var/lib/olivares/public-other/tls.crt"):
            self.assertNotRegex(path, "^" + PUBLIC_PATH + "$")
        with open(os.path.join(HERE, "olivares.fc"), encoding="utf-8") as stream:
            self.assertIn(PUBLIC_PATH + "\tgen_context(system_u:object_r:" + PUBLIC + ",s0)\n", stream.read())

    def test_table_allows_atomic_publication_and_pid1_read_without_private_reads(self):
        rows = generate.read_table(os.path.join(HERE, "access.tsv"), generate.ACCESS_COLUMNS)
        transitions = [r for r in rows if r["kind"] == "type_transition" and r["perms"].split()[0] == PUBLIC]
        self.assertEqual([(r["source"], r["target"], r["class"], r["perms"]) for r in transitions],
                         [("olivares_t", PRIVATE, "dir", PUBLIC + ' "public"')])
        self.assertEqual(granted(rows, "olivares_t", PUBLIC, "dir"), PUBLISH_DIRECTORY)
        self.assertEqual(granted(rows, "olivares_t", PUBLIC, "file"), PUBLISH_FILE)
        self.assertEqual(granted(rows, "init_t", PUBLIC, "dir"), {"getattr", "search"})
        self.assertEqual(granted(rows, "init_t", PUBLIC, "file"), READ_FILE)
        self.assertIn("search", granted(rows, "init_t", PRIVATE, "dir"))
        for source in ("init_t", PORTAL):
            self.assertEqual(granted(rows, source, PRIVATE, "file"), set())
        self.assertEqual(granted(rows, PORTAL, PUBLIC, "file"), set())
        self.assertEqual(granted(rows, PORTAL, "olivares_portal_cred_t", "file"), READ_FILE)

    def test_generated_policy_keeps_publication_and_credential_reads_separate(self):
        with open(os.path.join(HERE, "olivares.te"), encoding="utf-8") as stream:
            policy = stream.read()
        self.assertIn('type_transition olivares_t olivares_var_lib_t:dir ' + PUBLIC + ' "public";', policy)
        self.assertEqual(generated_grants(policy, "olivares_t", PUBLIC, "dir"), PUBLISH_DIRECTORY)
        self.assertEqual(generated_grants(policy, "olivares_t", PUBLIC, "file"), PUBLISH_FILE)
        self.assertEqual(generated_grants(policy, "init_t", PUBLIC, "dir"), {"getattr", "search"})
        self.assertEqual(generated_grants(policy, "init_t", PUBLIC, "file"), READ_FILE)
        self.assertIn("search", generated_grants(policy, "init_t", PRIVATE, "dir"))
        for source in ("init_t", PORTAL):
            self.assertEqual(generated_grants(policy, source, PRIVATE, "file"), set())
        self.assertEqual(generated_grants(policy, PORTAL, PUBLIC, "file"), set())

    def test_manifest_covers_each_client_and_publication_grant_and_denial(self):
        manifest, rows, denied = test_manifest.repository()
        expected = {"PORTAL-47", "PORTAL-48", "PORTAL-49", "PORTAL-50", "PORTAL-51", "PROD-38", "PROD-39"}
        held = {rid for m in manifest if m["kind"] == "grant" for rid in m["rows"].split(";")}
        self.assertEqual(expected - held, set())
        refused = {m["rows"] for m in manifest if m["kind"] == "deny"}
        required_denials = {"N-PORTAL-ENGINE-OPEN", "N-PORTAL-ENGINE-READ", "N-PID1-ENGINE-OPEN",
                           "N-PID1-ENGINE-READ", "N-PORTAL-ENGINE-PUBLIC-WRITE", "N-PID1-ENGINE-PUBLIC-WRITE",
                           "N-PORTAL-ENGINE-HTTP", "N-PORTAL-ENGINE-DNS", "N-PORTAL-ENGINE-UNRESERVED",
                           "N-PORTAL-ENGINE-MODEL"}
        self.assertEqual(required_denials - refused, set())
        self.assertEqual(test_manifest.manifest_failures(manifest, rows, denied), [])


if __name__ == "__main__":
    unittest.main()
