# SPDX-FileCopyrightText: 2026 Olivares.AI
# SPDX-License-Identifier: AGPL-3.0-only
"""The fixed nft child can resolve interface indices without modifying links or routes."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import compare_rules  # noqa: E402
import generate  # noqa: E402

OWNER = "olivares_helper_firewall_t"
ROUTE = "netlink_route_socket"
# nft's interface cache uses libmnl: socket, bind, getsockname, sendto(RTM_GETLINK), recvmsg.
LOOKUP = {"bind", "create", "getattr", "nlmsg_read", "read", "write"}


class FirewallInterfaceLookup(unittest.TestCase):
    def test_owner_can_resolve_interface_indices_without_route_mutation(self) -> None:
        rows = generate.read_table(os.path.join(HERE, "access.tsv"), generate.ACCESS_COLUMNS)
        route = [r for r in rows if r["kind"] == "allow" and r["source"] == OWNER and r["class"] == ROUTE]
        held = set()
        for row in route:
            self.assertEqual(row["target"], OWNER, "interface lookup uses only the owner's own socket")
            self.assertEqual(row["condition"], "", "first boot must not depend on an optional boolean")
            held.update(row["perms"].split())
        self.assertEqual(held, LOOKUP, "nft needs the interface query, never route/link modification")

        contexts = generate.read_table(os.path.join(HERE, "contexts.tsv"), generate.CONTEXTS_COLUMNS)
        module = generate.Module(rows, contexts).te()
        self.assertIn(f"allow {OWNER} self:{ROUTE} {{ {' '.join(sorted(LOOKUP))} }};", module)

    def test_installed_policy_check_forbids_route_and_link_mutation(self) -> None:
        denied = compare_rules.read_denied(os.path.join(HERE, "denied.tsv"))
        # nlmsg_write covers RTM_NEW/DEL/SET; nlmsg must also stay denied for policies using netlink xperms.
        for perm in ("nlmsg_write", "nlmsg"):
            with self.subTest(permission=perm):
                self.assertTrue(any((row["source"], row["target"], row["class"], row["perm"], row["allowed_when"])
                                    == (OWNER, OWNER, ROUTE, perm, "") for row in denied),
                                f"installed policy must refuse {perm} in every boolean state")


if __name__ == "__main__":
    unittest.main()
