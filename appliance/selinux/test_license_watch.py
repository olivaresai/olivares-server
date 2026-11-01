# SPDX-FileCopyrightText: 2026 Olivares.AI
# SPDX-License-Identifier: AGPL-3.0-only
"""PID 1 watches only a public notification, never the private licence or store."""
import pathlib
import re
import unittest
import generate
import test_manifest
from test_portal_engine import granted

HERE = pathlib.Path(__file__).parent


class LicenseWatch(unittest.TestCase):
    def test_watch_is_readable_without_private_engine_access(self):
        unit = (HERE.parent / "layer/entitled/units/olivares-entitled-repo.path").read_text()
        watched = re.search(r"^PathChanged=(.+)$", unit, re.M).group(1)
        contexts = generate.read_table(str(HERE / "contexts.tsv"), generate.CONTEXTS_COLUMNS)
        public = next(row for row in contexts if row["id"] == "C62")
        self.assertRegex(watched, "^" + public["path"] + "$")
        self.assertEqual(watched, "/var/lib/olivares/public/license.changed")
        rows = generate.read_table(str(HERE / "access.tsv"), generate.ACCESS_COLUMNS)
        self.assertIn("read", granted(rows, "init_t", public["type"], "file"))
        manifest = generate.read_table(str(HERE / "manifest.tsv"), test_manifest.MANIFEST_COLUMNS)
        self.assertTrue(any(row["path"] == watched and row["domain"] == "init_t"
                            and row["perms"] == "read" and row["rows"] == "PORTAL-51"
                            for row in manifest))
        self.assertFalse({"open", "read"} & granted(rows, "init_t", "olivares_var_lib_t", "file"))

    def test_public_directory_is_created_by_tmpfiles_before_cli_writes(self):
        config = (HERE.parent / "layer/portal/units/tmpfiles.d/olivares-hostops.conf").read_text()
        self.assertIn("d /var/lib/olivares/public 0755 olivares olivares - -", config.splitlines())
