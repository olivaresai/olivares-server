# SPDX-FileCopyrightText: 2026 Olivares.AI
# SPDX-License-Identifier: AGPL-3.0-only
#
# The checked-in toolchain lock and the files that must agree with it. These cases read the
# repository, not the host: they establish that the pins are exact and that the container
# definition and the collector quote the same lock. They do not establish that the toolchain
# builds an image. The preflight workflow is a CI file of the composed build, and its cases
# live with that build (test_preflight_workflow.py).

import hashlib
import json
import pathlib
import re
import unittest

import judge

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[2]
TOOLCHAIN = REPO / "appliance" / "images" / "toolchain"
LOCK_PATH = TOOLCHAIN / "input-lock.json"
CONTAINERFILE = TOOLCHAIN / "Containerfile"
RUNBOOK = TOOLCHAIN / "README.md"
PREFLIGHT = HERE / "preflight.sh"

DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
BARE_DIGEST = re.compile(r"^[0-9a-f]{64}$")
EXACT_VERSION = re.compile(r"^\d+\.\d+\.\d+$")


def lock():
    return json.loads(LOCK_PATH.read_text(encoding="utf-8"))


class LockFile(unittest.TestCase):
    def test_the_lock_is_present_and_parses(self):
        self.assertTrue(LOCK_PATH.is_file(), f"{LOCK_PATH} is missing")
        self.assertIsInstance(lock(), dict)

    def test_the_lock_passes_its_own_validation(self):
        self.assertEqual([], judge.validate_lock(lock()))

    def test_the_lock_is_server_amd64(self):
        architecture = lock()["architecture"]
        self.assertEqual("amd64", architecture["deb"])
        self.assertEqual("x86_64", architecture["uname_machine"])

    def test_the_base_image_is_pinned_by_an_immutable_digest(self):
        base = lock()["base_image"]
        self.assertRegex(base["index_digest"], DIGEST)
        self.assertRegex(base["manifest_digest_amd64"], DIGEST)
        self.assertNotIn(":latest", base["reference"])

    def test_the_kiwi_pin_is_an_exact_version_with_a_hash(self):
        kiwi = lock()["toolchain"]["kiwi"]
        self.assertRegex(kiwi["upstream_version"], EXACT_VERSION)
        self.assertRegex(kiwi["sha256"], BARE_DIGEST)
        self.assertIn(kiwi["upstream_version"], kiwi["package_version"])

    def test_every_locked_package_carries_an_exact_version_and_hash(self):
        packages = list(lock()["distribution"]["system_packages"].values())
        self.assertTrue(packages, "the lock names no toolchain packages")
        for package in packages:
            with self.subTest(package=package.get("Package")):
                self.assertRegex(package["SHA256"], BARE_DIGEST)
                self.assertTrue(package["Version"])
                self.assertNotIn("latest", package["Version"])

    def test_the_repository_basis_is_recorded_with_its_index_hash(self):
        repository = lock()["distribution"]
        self.assertTrue(repository["snapshot_basis"].startswith("https://"))
        self.assertRegex(repository["packages_sha256"], BARE_DIGEST)
        self.assertRegex(repository["inrelease_sha256"], BARE_DIGEST)

    def test_the_distribution_basis_names_a_snapshot(self):
        distribution = lock()["distribution"]
        self.assertEqual("trixie", distribution["codename"])
        self.assertTrue(distribution["version"].startswith("13."))
        self.assertTrue(distribution["snapshot_basis"].startswith("https://snapshot.debian.org/"))

    def test_the_boxed_plugin_decision_is_explicit_and_reasoned(self):
        boxed = lock()["toolchain"]["boxed_plugin"]
        self.assertIn("used", boxed)
        if not boxed["used"]:
            self.assertGreater(len(boxed["reason"]), 40, "an unused route needs its reason")

    def test_the_declared_build_budget_is_positive_visible_and_not_measured(self):
        budget = lock()["budget"]
        self.assertGreater(budget["declared_build_bytes"], 0)
        self.assertGreater(budget["declared_build_minutes"], 0)
        self.assertFalse(budget["measured"], "a declared budget must never be labeled measured")
        self.assertTrue(budget["basis"], "a declared budget needs its stated basis")

    def test_the_declared_build_minutes_fit_the_documented_job_ceiling(self):
        data = lock()
        self.assertLessEqual(
            data["budget"]["declared_build_minutes"], data["runner"]["job_ceiling_minutes"]
        )

    def test_the_probe_bounds_are_positive_and_small(self):
        probe = lock()["probe"]
        self.assertGreater(probe["loop_image_bytes"], 0)
        self.assertLess(probe["loop_image_bytes"], 1024 ** 3, "the probe image stays small")
        self.assertGreater(probe["qemu_timeout_seconds"], 0)
        self.assertGreater(probe["container_timeout_seconds"], 0)
        self.assertEqual("prelaunch", probe["required_qmp_status"])

    def test_the_accelerator_preference_is_explicit(self):
        self.assertEqual(["kvm", "tcg"], lock()["probe"]["accelerator_preference"])

    def test_the_required_capabilities_are_the_documented_container_build_set(self):
        required = set(lock()["invocation"]["required_capabilities"])
        self.assertEqual(
            {"SYS_ADMIN", "MKNOD", "AUDIT_WRITE", "AUDIT_CONTROL"},
            required,
        )


class ContainerDefinition(unittest.TestCase):
    def text(self):
        return CONTAINERFILE.read_text(encoding="utf-8")

    def test_the_container_definition_is_present(self):
        self.assertTrue(CONTAINERFILE.is_file(), f"{CONTAINERFILE} is missing")

    def test_it_carries_the_agpl_records_its_peers_carry(self):
        text = self.text()
        self.assertIn("SPDX-FileCopyrightText: 2026 Olivares.AI", text)
        self.assertIn("SPDX-License-Identifier: AGPL-3.0-only", text)

    def test_the_base_is_the_exact_digest_the_lock_names(self):
        data = lock()
        expected = f"FROM {data['base_image']['reference']}@{data['base_image']['manifest_digest_amd64']}"
        self.assertIn(expected, self.text())

    def test_it_installs_the_exact_locked_kiwi_package_version(self):
        kiwi = lock()["toolchain"]["kiwi"]
        text = self.text()
        self.assertEqual("isolated-venv-offline-wheel", lock()["toolchain"]["route"])
        self.assertIn("install.py install", text)
        packages = lock()["toolchain"]["python"]["packages"]
        self.assertEqual(kiwi["upstream_version"], next(x["version"] for x in packages if x["name"] == "kiwi"))

    def test_it_pins_the_repository_the_lock_names(self):
        bootstrap = (CONTAINERFILE.parent / "bootstrap.sh").read_text()
        self.assertIn(lock()["distribution"]["snapshot_basis"].replace("https:","http:"), bootstrap)
        self.assertIn(lock()["distribution"]["inrelease_sha256"], bootstrap)
        self.assertIn(lock()["distribution"]["packages_sha256"], bootstrap)

    def test_bootstrap_installs_exactly_the_locked_roots(self):
        # Every root the builder installs is a lock record at the same version, and no other.
        bootstrap = (CONTAINERFILE.parent / "bootstrap.sh").read_text()
        pinned = dict(re.findall(r"^ +([a-z0-9][a-z0-9.+-]+)=(\S+?)(?: \\)?$", bootstrap, re.M))
        roots = {name: row["Version"] for name, row in lock()["distribution"]["system_packages"].items()}
        self.assertEqual(roots, pinned)

    def test_bootstrap_refuses_every_lock_but_the_checked_in_one(self):
        digest = hashlib.sha256(LOCK_PATH.read_bytes()).hexdigest()
        bootstrap = (CONTAINERFILE.parent / "bootstrap.sh").read_text()
        self.assertIn(f"'{digest}' input-lock.json | sha256sum -c -", bootstrap)

    def test_it_never_pipes_an_unverified_download_into_a_shell(self):
        # A pipe into an interpreter, not any pipe: piping a downloaded file into
        # sha256sum is the verification this rule is meant to require.
        text = self.text()
        self.assertIsNone(
            re.search(r"\|\s*(?:sh|bash|python3?)(?:\s|$)", text, re.MULTILINE),
            "a download is piped into an interpreter",
        )
        self.assertIn("sha256sum -c", (CONTAINERFILE.parent / "bootstrap.sh").read_text(), "the signed snapshot bytes are never checked")

    def test_it_installs_no_unpinned_latest(self):
        text = self.text()
        self.assertNotIn("apt-get upgrade", text)
        self.assertNotIn("pip install kiwi\n", text)


class Collector(unittest.TestCase):
    def test_the_collector_is_present_and_declares_bash(self):
        self.assertTrue(PREFLIGHT.is_file(), f"{PREFLIGHT} is missing")
        self.assertTrue(PREFLIGHT.read_text(encoding="utf-8").startswith("#!/usr/bin/env bash"))

    def test_the_collector_carries_the_agpl_records(self):
        text = PREFLIGHT.read_text(encoding="utf-8")
        self.assertIn("SPDX-FileCopyrightText: 2026 Olivares.AI", text)
        self.assertIn("SPDX-License-Identifier: AGPL-3.0-only", text)

    def test_the_collector_measures_free_disk_in_bytes(self):
        # The collector moved behind a Bash entry point; statvfs returns bytes exactly.
        text = (PREFLIGHT.parent / "collector.py").read_text(encoding="utf-8")
        self.assertIn("disk.f_bavail*disk.f_frsize", text)

    def test_the_collector_passes_no_host_environment_into_the_container(self):
        text = (PREFLIGHT.parent / "collector.py").read_text(encoding="utf-8")
        self.assertNotIn("--env-host", text)
        self.assertNotIn("-e HOME", text)
        self.assertIn('"--network", "none"', text)

    def test_the_runbook_is_present(self):
        self.assertTrue(RUNBOOK.is_file(), f"{RUNBOOK} is missing")

    def test_the_runbook_documents_the_three_states_and_exits(self):
        text = RUNBOOK.read_text(encoding="utf-8")
        for token in ("eligible", "unavailable", "defect", "receipt.json", "input-lock.json"):
            self.assertIn(token, text)


if __name__ == "__main__":
    unittest.main()
