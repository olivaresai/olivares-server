# SPDX-FileCopyrightText: 2026 Olivares.AI
# SPDX-License-Identifier: AGPL-3.0-only
"""manifest.tsv is append-only: each SELinux change adds its rows at the end, so two changes in flight touch the same
tail. The repository merges the file with git's union driver (.gitattributes), so the second merge keeps both sets of
rows instead of stopping on a conflict. Union cannot see a repeated id; manifest_failures refuses one.

Run: python3 -m unittest discover -s appliance/selinux -p 'test_*.py'
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TREE = os.path.normpath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, HERE)

import generate  # noqa: E402
import test_manifest  # noqa: E402

ISOLATED = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")


def row(mid, reason):
    return "\t".join((mid, "core/example.go:1", "olivares_t", "/example", "file", "read", "olivares_t", "measured",
                      "PROD-01", "grant", reason))


def git(repo, *args):
    return subprocess.run(["git", "-C", repo, "-c", "user.name=test", "-c", "user.email=test@example.test",
                           "-c", "commit.gpgsign=false", "-c", "core.hooksPath=" + os.devnull, *args],
                          capture_output=True, text=True, env=ISOLATED)


@unittest.skipUnless(shutil.which("git"), "needs git")
class ManifestMergeTest(unittest.TestCase):
    def merged(self, ours, theirs):
        """Two branches each append one row to this manifest, under this tree's .gitattributes; the first is merged
        into by the second. Returns the merge's exit code and the merged manifest's rows (none after a conflict)."""
        with tempfile.TemporaryDirectory() as repo:
            self.assertEqual(git(repo, "init", "-q", "-b", "base").returncode, 0)
            os.makedirs(os.path.join(repo, "appliance", "selinux"))
            shutil.copy(os.path.join(TREE, ".gitattributes"), repo)
            path = os.path.join(repo, "appliance", "selinux", "manifest.tsv")
            shutil.copy(os.path.join(HERE, "manifest.tsv"), path)
            git(repo, "add", "-A")
            self.assertEqual(git(repo, "commit", "-q", "-m", "base").returncode, 0)
            for branch, line in (("ours", ours), ("theirs", theirs)):
                git(repo, "switch", "-q", "-c", branch, "base")
                with open(path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
                self.assertEqual(git(repo, "commit", "-q", "-am", branch).returncode, 0)
            git(repo, "switch", "-q", "ours")
            rc = git(repo, "merge", "-q", "--no-edit", "theirs").returncode
            return rc, generate.read_table(path, test_manifest.MANIFEST_COLUMNS) if rc == 0 else []

    def test_two_changes_appending_rows_merge_and_keep_both(self):
        base = generate.read_table(os.path.join(HERE, "manifest.tsv"), test_manifest.MANIFEST_COLUMNS)
        rc, merged = self.merged(row("M-9001", "ours"), row("M-9002", "theirs"))
        self.assertEqual(rc, 0, "appending rows on two branches conflicts")
        self.assertEqual([m["id"] for m in merged], [m["id"] for m in base] + ["M-9001", "M-9002"])

    def test_two_changes_taking_the_same_id_fail_the_manifest(self):
        _, rows, denied = test_manifest.repository()
        rc, merged = self.merged(row("M-9001", "ours"), row("M-9001", "theirs"))
        self.assertEqual(rc, 0, "appending rows on two branches conflicts")
        self.assertIn("M-9001: repeated manifest id", test_manifest.manifest_failures(merged, rows, denied))


if __name__ == "__main__":
    unittest.main()
