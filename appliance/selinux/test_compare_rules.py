# SPDX-FileCopyrightText: 2026 Olivares.AI
# SPDX-License-Identifier: AGPL-3.0-only
"""The contract of compare_rules.py, the hosted check that the compiled module holds exactly the rows.

cil mode: the rules in the module's CIL minus the rules in the CIL of its declarations alone must equal the row
rules, atom for atom (one permission of one rule). policy mode: the installed policy grants every row and grants
none of denied.tsv without a condition. These tests use CIL text and a fake policy view; the workflow runs the
real compiler and setools.

Run: python3 -m unittest discover -s appliance/selinux -p 'test_*.py'
"""
import collections
import contextlib
import glob
import importlib.util
import io
import os
import sys
import tempfile
import types
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import compare_rules  # noqa: E402
import generate  # noqa: E402


def row(rid, kind, source, target, cls, perms, condition="", via=""):
    return {"id": rid, "kind": kind, "source": source, "target": target, "class": cls, "perms": perms,
            "condition": condition, "via": via, "rationale": "-"}


ROWS = [
    row("D-01", "allow", "init_t", "olivares_d_t", "process", "transition", via="init_daemon_domain"),
    row("D-05", "allow", "olivares_d_t", "init_t", "fd", "use"),
    row("D-06", "allow", "olivares_d_t", "olivares_d_t", "tcp_socket", "accept read"),
    row("D-08", "type_transition", "olivares_d_t", "var_lib_t", "dir", 'olivares_d_var_lib_t "d"'),
    row("D-10", "boolean", "olivares_d_jit", "-", "-", "false"),
    row("D-11", "allow", "olivares_d_t", "olivares_d_t", "process", "execmem", condition="olivares_d_jit"),
]

# What the devel Makefile's module looks like once converted to CIL (hll/pp): the declarations and the
# macro expansions, which the baseline shares, then the row rules.
BASELINE = """
(type olivares_d_t)
(roletype object_r olivares_d_t)
(typeattributeset cil_gen_require init_t)
(boolean olivares_d_jit false)
(allow olivares_d_t olivares_d_exec_t (file (entrypoint execute getattr map open read)))
(typetransition initrc_domain olivares_d_exec_t process olivares_d_t)
(optional olivares_optional_1
    (typeattributeset cil_gen_require socket_proxyd_t)
    (allow olivares_d_t socket_proxyd_t (unix_stream_socket (connectto)))
)
"""
MODULE = BASELINE + """
; the row rules
(allow olivares_d_t init_t (fd (use)))
(allow olivares_d_t self (tcp_socket (accept read)))
(typetransition olivares_d_t var_lib_t dir "d" olivares_d_var_lib_t)
(booleanif olivares_d_jit
    (true
        (allow olivares_d_t self (process (execmem)))
    )
)
"""


class Cil(unittest.TestCase):
    def test_parses_nested_statements_and_quoted_names(self):
        nodes = compare_rules.parse_cil('(a b (c "d e") ; comment\n (f))')
        self.assertEqual(nodes, [["a", "b", ["c", '"d e"'], ["f"]]])

    def test_atoms_split_permissions_and_resolve_self(self):
        atoms = compare_rules.cil_atoms(compare_rules.parse_cil("(allow x self (file (read open)))"))
        self.assertEqual(atoms, {("allow", "x", "x", "file", "read", ""), ("allow", "x", "x", "file", "open", "")})

    def test_atoms_inside_a_boolean_carry_its_condition(self):
        atoms = compare_rules.cil_atoms(compare_rules.parse_cil(
            "(booleanif b (true (allow x y (file (read)))) (false (allow x y (file (write)))))"))
        self.assertEqual(atoms, {("allow", "x", "y", "file", "read", "b:true"),
                                 ("allow", "x", "y", "file", "write", "b:false")})

    def test_atoms_inside_an_optional_block_are_kept(self):
        atoms = compare_rules.cil_atoms(compare_rules.parse_cil("(optional o (allow x y (dir (search))))"))
        self.assertEqual(atoms, {("allow", "x", "y", "dir", "search", "")})

    def test_named_and_plain_type_transitions(self):
        atoms = compare_rules.cil_atoms(compare_rules.parse_cil(
            '(typetransition a b dir "n" c)(typetransition a b process d)'))
        self.assertEqual(atoms, {("type_transition", "a", "b", "dir", "n", "c", ""),
                                 ("type_transition", "a", "b", "process", "", "d", "")})

    def test_other_rule_kinds_are_atoms_too(self):
        atoms = compare_rules.cil_atoms(compare_rules.parse_cil("(dontaudit x y (file (read)))"))
        self.assertEqual(atoms, {("dontaudit", "x", "y", "file", "read", "")})

    def test_rows_become_the_same_atoms(self):
        atoms = compare_rules.row_atoms(ROWS)
        self.assertIn(("allow", "olivares_d_t", "olivares_d_t", "tcp_socket", "accept", ""), atoms)
        self.assertIn(("allow", "olivares_d_t", "olivares_d_t", "process", "execmem", "olivares_d_jit:true"), atoms)
        self.assertIn(("type_transition", "olivares_d_t", "var_lib_t", "dir", "d", "olivares_d_var_lib_t", ""), atoms)
        self.assertNotIn(("allow", "init_t", "olivares_d_t", "process", "transition", ""), atoms,
                         "a macro row is compared in the policy, not in the module's own rules")
        shadow = row("PAM-15", "allow", "olivares_portal_pam_t", "shadow_t", "file", "getattr open read",
                     via="auth_reader_shadow")
        self.assertEqual(compare_rules.row_atoms([shadow]),
                         {("allow", "olivares_portal_pam_t", "shadow_t", "file", p, "")
                          for p in ("getattr", "open", "read")})

    def test_command_domain_rows_become_allow_atoms(self):
        perms = "entrypoint execute execute_no_trans getattr map open read"
        rows = [row(f"TOOL-{n}", "allow", generate.COMMAND_DOMAIN, target, "file", perms,
                    via=generate.COMMAND_VIA)
                for n, target in zip((73, 74, 75), generate.GENERIC_COMMANDS)]
        self.assertEqual(compare_rules.row_atoms(rows),
                         {("allow", generate.COMMAND_DOMAIN, target, "file", p, "")
                          for target in generate.GENERIC_COMMANDS for p in perms.split()})

    def test_hook_entrypoint_rows_are_compared_permission_by_permission(self):
        perms = "entrypoint execute getattr map open read"
        rows = [row("HOOK-05", "allow", generate.HOOK_DOMAIN, generate.HOOK_ENTRY, "file", perms,
                    via=generate.HOOK_VIA)]
        atoms = {("allow", generate.HOOK_DOMAIN, generate.HOOK_ENTRY, "file", p, "")
                 for p in perms.split()}
        self.assertEqual(compare_rules.row_atoms(rows), atoms)
        cil = f"(allow {generate.HOOK_DOMAIN} {generate.HOOK_ENTRY} (file ({perms})))"
        self.assertEqual(compare_rules.compare_cil(cil, "", rows), (set(), set()))
        for perm in perms.split():
            with self.subTest(missing=perm):
                self.assertEqual(compare_rules.compare_cil(cil.replace(perm, ""), "", rows),
                                 (set(), {("allow", generate.HOOK_DOMAIN, generate.HOOK_ENTRY, "file", perm, "")}))
        extra = ("allow", generate.HOOK_DOMAIN, generate.HOOK_ENTRY, "file", "write", "")
        self.assertEqual(compare_rules.compare_cil(cil.replace("read", "read write"), "", rows),
                         ({extra}, set()))

    def test_container_hook_entrypoint_rows_are_compared_permission_by_permission(self):
        perms = "entrypoint execute getattr map open read"
        rows = [row("CHOOK-09", "allow", generate.CONTAINER_HOOK_DOMAIN, generate.CONTAINER_HOOK_ENTRY, "file", perms,
                    via=generate.CONTAINER_HOOK_VIA)]
        atoms = {("allow", generate.CONTAINER_HOOK_DOMAIN, generate.CONTAINER_HOOK_ENTRY, "file", p, "")
                 for p in perms.split()}
        self.assertEqual(compare_rules.row_atoms(rows), atoms)
        cil = f"(allow {generate.CONTAINER_HOOK_DOMAIN} {generate.CONTAINER_HOOK_ENTRY} (file ({perms})))"
        self.assertEqual(compare_rules.compare_cil(cil, "", rows), (set(), set()))

    def test_container_relay_entrypoint_rows_are_compared_permission_by_permission(self):
        rows = generate.read_table(os.path.join(HERE, "access.tsv"), generate.ACCESS_COLUMNS)
        relay = next(r for r in rows if r["id"] == "RELAY-05")
        perms = relay["perms"].split()
        atoms = {("allow", relay["source"], relay["target"], "file", p, "") for p in perms}
        self.assertEqual(compare_rules.row_atoms([relay]), atoms)
        cil = f"(allow {relay['source']} {relay['target']} (file ({' '.join(perms)})))"
        self.assertEqual(compare_rules.compare_cil(cil, "", [relay]), (set(), set()))
        for perm in perms:
            with self.subTest(missing=perm):
                missing = ("allow", relay["source"], relay["target"], "file", perm, "")
                without = f"(allow {relay['source']} {relay['target']} (file ({' '.join(p for p in perms if p != perm)})))"
                self.assertEqual(compare_rules.compare_cil(without, "", [relay]),
                                 (set(), {missing}))
        extra = ("allow", relay["source"], relay["target"], "file", "write", "")
        self.assertEqual(compare_rules.compare_cil(cil.replace("read", "read write"), "", [relay]),
                         ({extra}, set()))

    def test_container_file_entrypoint_is_pinned(self):
        expected = ("allow", generate.COMMAND_DOMAIN, "container_file_t", "file", "entrypoint", "")
        rows = generate.read_table(os.path.join(HERE, "access.tsv"), generate.ACCESS_COLUMNS)
        ctr10 = next(r for r in rows if r["id"] == "CTR-10")
        atoms = compare_rules.row_atoms([ctr10])
        self.assertIn(expected, atoms, "CTR-10 must make the container image's programs executable in the command domain")

    def test_the_module_minus_its_declarations_equals_the_rows(self):
        extra, missing = compare_rules.compare_cil(MODULE, BASELINE, ROWS)
        self.assertEqual((extra, missing), (set(), set()))

    def test_one_extra_allow_is_reported(self):
        extra, missing = compare_rules.compare_cil(
            MODULE + "(allow olivares_d_t olivares_d_key_t (file (read)))", BASELINE, ROWS)
        self.assertEqual(extra, {("allow", "olivares_d_t", "olivares_d_key_t", "file", "read", "")})
        self.assertEqual(missing, set())

    def test_one_extra_permission_is_reported(self):
        extra, _ = compare_rules.compare_cil(MODULE.replace("(fd (use))", "(fd (use getattr))"), BASELINE, ROWS)
        self.assertEqual(extra, {("allow", "olivares_d_t", "init_t", "fd", "getattr", "")})

    def test_a_missing_row_is_reported(self):
        extra, missing = compare_rules.compare_cil(MODULE.replace("(allow olivares_d_t init_t (fd (use)))", ""),
                                                   BASELINE, ROWS)
        self.assertEqual(extra, set())
        self.assertEqual(missing, {("allow", "olivares_d_t", "init_t", "fd", "use", "")})

    def test_a_rule_moved_out_of_its_condition_is_both_extra_and_missing(self):
        text = MODULE.replace("(booleanif olivares_d_jit\n    (true\n        (allow olivares_d_t self "
                              "(process (execmem)))\n    )\n)", "(allow olivares_d_t self (process (execmem)))")
        extra, missing = compare_rules.compare_cil(text, BASELINE, ROWS)
        self.assertEqual(extra, {("allow", "olivares_d_t", "olivares_d_t", "process", "execmem", "")})
        self.assertEqual(missing, {("allow", "olivares_d_t", "olivares_d_t", "process", "execmem",
                                    "olivares_d_jit:true")})


def fact(perms, booleans=None, block=True, evaluate=None):
    """A rule as setools returns it: its permissions and, for a conditional rule, the conditional expression's
    booleans, an optional evaluate(**states) and whether the rule sits in the true or the false block."""
    if booleans is None:
        return types.SimpleNamespace(conditional=None, conditional_block=None, perms=set(perms))
    cond = types.SimpleNamespace(booleans=list(booleans))
    if evaluate:
        cond.evaluate = evaluate
    return types.SimpleNamespace(conditional=cond, conditional_block=block, perms=set(perms))


class FakeView:
    """A policy of setools-shaped rule facts: `rules` maps (source, target, class) to facts, `transitions` holds
    (source, target, class, name, new type, condition) and `booleans` maps a boolean to its default."""

    def __init__(self, rules, transitions=(), booleans=None, roles=None):
        self.rules_, self.transitions, self.booleans = rules, set(transitions), booleans or {}
        self.roles = roles or {}

    def role_has_type(self, role, type_):
        return type_ in self.roles.get(role, set())

    def rules(self, source, target, cls):
        return list(self.rules_.get((source, target, cls), ()))

    def has_transition(self, source, target, cls, name, new_type, condition):
        return (source, target, cls, name, new_type, condition) in self.transitions

    def boolean_default(self, name):
        return self.booleans.get(name)


RULES = {
    ("init_t", "olivares_d_t", "process"): [fact({"transition"})],
    ("olivares_d_t", "init_t", "fd"): [fact({"use"})],
    ("olivares_d_t", "olivares_d_t", "tcp_socket"): [fact({"accept", "read", "write"})],
    ("olivares_d_t", "olivares_d_t", "process"): [fact({"execmem"}, ["olivares_d_jit"], block=True)],
}
TRANSITIONS = {("olivares_d_t", "var_lib_t", "dir", "d", "olivares_d_var_lib_t", "")}
DENIED = [{"id": "N-01", "source": "olivares_d_t", "target": "olivares_d_t", "class": "process", "perm": "execmem",
           "allowed_when": "olivares_d_jit=true", "reason": "no executable memory while the boolean is off"},
          {"id": "N-02", "source": "olivares_d_t", "target": "olivares_d_key_t", "class": "file", "perm": "read",
           "allowed_when": "", "reason": "never the key"}]
BOOLEANS = {"olivares_d_jit": False, "base_bool_on": True, "base_bool_off": False}


def with_rules(extra):
    rules = {k: list(v) for k, v in RULES.items()}
    for key, facts in extra.items():
        rules.setdefault(key, []).extend(facts)
    return rules


class Policy(unittest.TestCase):
    def check(self, rules, transitions=TRANSITIONS, booleans=None, denied=DENIED):
        return compare_rules.compare_policy(FakeView(rules, transitions, booleans or BOOLEANS), ROWS, denied)

    def test_a_policy_with_the_jit_grant_on_its_true_branch_only_passes(self):
        self.assertEqual(self.check(RULES), [])

    def test_a_row_the_policy_does_not_grant_fails(self):
        rules = dict(RULES)
        rules[("olivares_d_t", "olivares_d_t", "tcp_socket")] = [fact({"accept"})]
        self.assertEqual(self.check(rules), ["D-06: the policy does not grant read on olivares_d_t:tcp_socket"])

    def test_a_conditional_row_the_boolean_does_not_enable_fails(self):
        rules = dict(RULES)
        rules[("olivares_d_t", "olivares_d_t", "process")] = [fact({"execmem"}, ["olivares_d_jit"], block=False)]
        failures = self.check(rules)
        self.assertIn("D-11: the policy does not grant execmem on olivares_d_t:process under olivares_d_jit", failures)

    def test_a_false_branch_grant_of_a_denied_access_fails_in_the_states_it_reaches(self):
        failures = self.check(with_rules({("olivares_d_t", "olivares_d_t", "process"):
                                          [fact({"execmem"}, ["olivares_d_jit"], block=False)]}))
        self.assertEqual(failures, ["N-01: the policy grants execmem on olivares_d_t:process to olivares_d_t in "
                                    "the defaults, olivares_d_jit=false (no executable memory while the boolean is "
                                    "off)"])

    def test_an_unconditional_grant_of_a_denied_access_fails(self):
        failures = self.check(with_rules({("olivares_d_t", "olivares_d_key_t", "file"): [fact({"read"})]}))
        self.assertEqual(failures, ["N-02: the policy grants read on olivares_d_key_t:file to olivares_d_t in the "
                                    "defaults, olivares_d_jit=true, olivares_d_jit=false (never the key)"])

    def test_an_inherited_conditional_grant_of_a_denied_access_fails(self):
        failures = self.check(with_rules({("olivares_d_t", "olivares_d_key_t", "file"):
                                          [fact({"read"}, ["base_bool_on"], block=True)]}))
        self.assertEqual(failures, ["N-02: the policy grants read on olivares_d_key_t:file to olivares_d_t in the "
                                    "defaults, olivares_d_jit=true, olivares_d_jit=false (never the key)"])

    def test_a_denied_access_granted_only_when_the_modules_boolean_is_on_fails_in_that_state(self):
        failures = self.check(with_rules({("olivares_d_t", "olivares_d_key_t", "file"):
                                          [fact({"read"}, ["olivares_d_jit"], block=True)]}))
        self.assertEqual(failures, ["N-02: the policy grants read on olivares_d_key_t:file to olivares_d_t in "
                                    "olivares_d_jit=true (never the key)"])

    def test_a_grant_behind_another_booleans_non_default_value_is_outside_the_reachable_states(self):
        self.assertEqual(self.check(with_rules({("olivares_d_t", "olivares_d_key_t", "file"):
                                                [fact({"read"}, ["base_bool_off"], block=True)]})), [])

    def test_an_expression_is_evaluated_with_every_boolean_it_names(self):
        def both(**states):
            return states["base_bool_on"] and not states["olivares_d_jit"]
        failures = self.check(with_rules({("olivares_d_t", "olivares_d_key_t", "file"):
                                          [fact({"read"}, ["base_bool_on", "olivares_d_jit"], True, both)]}))
        self.assertEqual(failures, ["N-02: the policy grants read on olivares_d_key_t:file to olivares_d_t in the "
                                    "defaults, olivares_d_jit=false (never the key)"])

    def test_a_condition_that_cannot_be_evaluated_is_refused(self):
        failures = self.check(with_rules({("olivares_d_t", "olivares_d_key_t", "file"):
                                          [fact({"read"}, ["base_bool_on", "olivares_d_jit"], True)]}))
        self.assertEqual(failures, ["N-02: a rule granting read on olivares_d_key_t:file to olivares_d_t has a "
                                    "condition this check cannot evaluate (base_bool_on olivares_d_jit); refused"])
        failures = self.check(with_rules({("olivares_d_t", "olivares_d_key_t", "file"):
                                          [fact({"read"}, ["unknown_bool"], True)]}))
        self.assertEqual(failures, ["N-02: a rule granting read on olivares_d_key_t:file to olivares_d_t has a "
                                    "condition this check cannot evaluate (unknown_bool); refused"])

    def test_an_allowed_state_that_is_not_a_boolean_assignment_is_refused(self):
        denied = [dict(DENIED[0], allowed_when="olivares_d_jit")]
        self.assertEqual(self.check(RULES, denied=denied),
                         ["N-01: allowed_when 'olivares_d_jit' is not <boolean>=true or <boolean>=false"])

    def test_a_missing_transition_and_a_wrong_boolean_default_fail(self):
        failures = self.check(RULES, transitions=(), booleans=dict(BOOLEANS, olivares_d_jit=True))
        self.assertEqual(failures[:2], [
            'D-08: the policy has no type_transition olivares_d_t var_lib_t:dir olivares_d_var_lib_t "d"',
            "D-10: boolean olivares_d_jit defaults to true, the row says false"])


# The one interface call and the rules unconfined_run_to writes for it (unconfineduser.if:
# domtrans_pattern, the role, userdom_use_user_terminals).
CALL_ROW = row("K-02", "interface", "olivares_cli_t", "olivares_cli_exec_t", "-", "unconfined_run_to")
LOGIN = "unconfined" + "_t"
EXPANSION_CIL = f"""
(optional olivares_optional_2
    (allow {LOGIN} olivares_cli_exec_t (file (getattr open map read execute ioctl)))
    (allow {LOGIN} olivares_cli_t (process (transition)))
    (typetransition {LOGIN} olivares_cli_exec_t process olivares_cli_t)
    (allow olivares_cli_t {LOGIN} (fd (use)))
    (allow olivares_cli_t {LOGIN} (fifo_file (getattr read write append ioctl lock)))
    (allow olivares_cli_t {LOGIN} (process (sigchld)))
    (roletype unconfined_r olivares_cli_t)
    (allow olivares_cli_t user_tty_device_t (chr_file (getattr lock read write append ioctl open)))
    (allow olivares_cli_t user_devpts_t (chr_file (getattr lock read write append ioctl open)))
)
"""


class InterfaceCall(unittest.TestCase):
    def test_the_call_becomes_the_atoms_its_macro_writes(self):
        atoms = compare_rules.row_atoms([CALL_ROW])
        self.assertEqual(len(atoms), 31)  # 30 rules and the call's role (unconfined_r holds olivares_cli_t)
        self.assertIn(("type_transition", LOGIN, "olivares_cli_exec_t", "process", "", "olivares_cli_t", ""), atoms)
        self.assertIn(("allow", "olivares_cli_t", LOGIN, "process", "sigchld", ""), atoms)
        self.assertEqual(atoms, compare_rules.cil_atoms(compare_rules.parse_cil(EXPANSION_CIL)))

    def test_a_module_holding_the_expansion_equals_its_rows(self):
        self.assertEqual(compare_rules.compare_cil(MODULE + EXPANSION_CIL, BASELINE, ROWS + [CALL_ROW]), (set(), set()))

    def test_a_module_without_the_call_misses_its_atoms(self):
        extra, missing = compare_rules.compare_cil(MODULE, BASELINE, ROWS + [CALL_ROW])
        self.assertEqual((extra, len(missing)), (set(), 31))

    def policy(self, drop=()):
        rules = {}
        for a in compare_rules.row_atoms([CALL_ROW]):
            if a[0] == "allow" and a not in drop:
                rules.setdefault((a[1], a[2], a[3]), []).append(fact({a[4]}))
        transitions = {(LOGIN, "olivares_cli_exec_t", "process", "", "olivares_cli_t", "")} - set(drop)
        roles = {} if "role" in drop else {"unconfined_r": {"olivares_cli_t"}}
        return FakeView(rules, transitions, roles=roles)

    def test_the_policy_must_hold_the_calls_rules_transition_and_role(self):
        self.assertEqual(compare_rules.compare_policy(self.policy(), [CALL_ROW], []), [])
        failures = compare_rules.compare_policy(
            self.policy(drop=("role", (LOGIN, "olivares_cli_exec_t", "process", "", "olivares_cli_t", ""),
                              ("allow", LOGIN, "olivares_cli_t", "process", "transition", ""))), [CALL_ROW], [])
        self.assertEqual(failures, [
            f"K-02: the policy does not grant transition on olivares_cli_t:process to {LOGIN} (unconfined_run_to)",
            f"K-02: the policy has no type_transition {LOGIN} olivares_cli_exec_t:process olivares_cli_t (unconfined_run_to)",
            "K-02: role unconfined_r does not hold olivares_cli_t (unconfined_run_to)"])

    def test_a_role_row_is_a_roletype_in_cil_and_a_role_in_the_policy(self):
        role = row("T-09", "role", "system_r", "olivares_tool_t", "-", "-")
        self.assertEqual(compare_rules.row_atoms([role]), {("role", "system_r", "olivares_tool_t", "", "", "")})
        # The module writes it with the rules, so the declarations-only baseline does not cancel it: a module that
        # lost the statement misses its atom, and a stray one is extra.
        held = MODULE + "(roletype system_r olivares_tool_t)\n"
        self.assertEqual(compare_rules.compare_cil(held, BASELINE, ROWS + [role]), (set(), set()))
        self.assertEqual(compare_rules.compare_cil(MODULE, BASELINE, ROWS + [role]),
                         (set(), {("role", "system_r", "olivares_tool_t", "", "", "")}))
        self.assertEqual(compare_rules.compare_cil(held, BASELINE, ROWS),
                         ({("role", "system_r", "olivares_tool_t", "", "", "")}, set()))
        self.assertEqual(compare_rules.compare_policy(FakeView({}, roles={"system_r": {"olivares_tool_t"}}), [role], []), [])
        self.assertEqual(compare_rules.compare_policy(FakeView({}, roles={"system_r": {"olivares_t"}}), [role], []),
                         ["T-09: role system_r does not hold olivares_tool_t"])

    def test_a_row_kind_the_check_does_not_read_is_refused(self):
        failures = compare_rules.compare_policy(FakeView({}), [row("X-01", "mystery", "a_t", "b_t", "file", "read")], [])
        self.assertEqual(failures, ["X-01: rule kind 'mystery' is not one this check reads; refused"])


class RealAdapter(unittest.TestCase):
    """compare_policy through the real SetoolsView, whose setools query is replaced by the same rule facts setools
    returns: the adapter, not a fake, is what the denial verdict depends on."""

    def view(self, facts):
        view = compare_rules.SetoolsView.__new__(compare_rules.SetoolsView)
        view._rules = lambda *args, **kw: iter(facts)
        view.boolean_default = lambda name: False
        return view

    def repository_rows(self):
        rows = generate.read_table(os.path.join(HERE, "access.tsv"), generate.ACCESS_COLUMNS)
        denied = [d for d in compare_rules.read_denied(os.path.join(HERE, "denied.tsv")) if d["id"] == "N-PROD-JIT"]
        return [r for r in rows if r["id"] in ("PROD-20", "PROD-21")], denied

    def test_the_jit_grant_on_its_true_branch_passes(self):
        rows, denied = self.repository_rows()
        facts = [fact({"execmem"}, ["olivares_operate_runtime"], block=True)]
        self.assertEqual(compare_rules.compare_policy(self.view(facts), rows, denied), [])

    def test_a_false_branch_jit_grant_fails(self):
        rows, denied = self.repository_rows()
        facts = [fact({"execmem"}, ["olivares_operate_runtime"], block=True),
                 fact({"execmem"}, ["olivares_operate_runtime"], block=False)]
        failures = compare_rules.compare_policy(self.view(facts), rows, denied)
        self.assertEqual(len(failures), 1, failures)
        self.assertTrue(failures[0].startswith("N-PROD-JIT: the policy grants execmem on olivares_t:process to "
                                               "olivares_t in the defaults, olivares_operate_runtime=false"), failures)


class QueryBatching(unittest.TestCase):
    def test_permissions_targets_and_boolean_states_share_one_source_scan(self):
        class Type(str):
            def expand(self):
                return iter([self])

        rules = [fact({"read", "open"}), fact({"execmem"}, ["jit"])]
        for rule, target, cls in zip(rules, ("file_t", "domain_t"), ("file", "process")):
            rule.source, rule.target, rule.tclass = Type("domain_t"), Type(target), cls
        policy = types.SimpleNamespace(lookup_type_or_attr=Type, lookup_class=str)
        scans = []

        def query(policy, **criteria):
            scans.append(criteria)
            selected = [r for r in rules
                        if (not criteria.get("target") or r.target == criteria["target"])
                        and (not criteria.get("tclass") or r.tclass in criteria["tclass"])]
            return types.SimpleNamespace(results=lambda: iter(selected))

        setools = types.SimpleNamespace(SELinuxPolicy=lambda path: policy, TERuleQuery=query)
        with mock.patch.dict(sys.modules, setools=setools):
            view = compare_rules.SetoolsView("policy")
        view.boolean_default = lambda name: False
        rows = [row("A", "allow", "domain_t", "file_t", "file", "read open"),
                row("B", "boolean", "jit", "-", "-", "false"),
                row("C", "allow", "domain_t", "domain_t", "process", "execmem", condition="jit")]
        denied = [dict(DENIED[0], source="domain_t", target="domain_t", allowed_when="jit=true")]
        self.assertEqual(compare_rules.compare_policy(view, rows, denied), [])
        forbidden = [dict(denied[0], target="file_t", **{"class": "file"}, perm="read", allowed_when="")]
        failures = compare_rules.compare_policy(view, rows, forbidden)
        self.assertEqual(len(failures), 1, failures)
        self.assertIn("the policy grants read on file_t:file to domain_t in the defaults, jit=true, jit=false",
                      failures[0])
        self.assertEqual(len(scans), 1, "each policy scan must serve all targets, permissions and states")

    def test_every_source_shares_one_scan_per_rule_type(self):
        """A TERuleQuery walks the whole policy on every results(): the hosted check needed 33 walks (158 s) for the
        sources its rows and denied accesses name. The sources must share one walk per rule type, and the attribute a
        rule is written for must still reach each type it holds."""
        members = {"domains": {"a_t", "b_t"}}

        class Symbol(str):
            def expand(self):
                return iter(members.get(self, {self}))

        def rule(ruletype, source, target, cls, perms=(), default="new_t", filename=""):
            # As setools shapes them: an allow rule has permissions, a type_transition has a default type and a name.
            made = (fact(perms) if ruletype == "allow"
                    else types.SimpleNamespace(conditional=None, conditional_block=None))
            made.ruletype, made.source, made.target, made.tclass = ruletype, Symbol(source), Symbol(target), cls
            if ruletype != "allow":
                made.default, made.filename = Symbol(default), filename
            return made

        rules = [rule("allow", "a_t", "file_t", "file", {"read"}),
                 rule("allow", "domains", "file_t", "file", {"write"}),
                 rule("allow", "c_t", "file_t", "file", {"open"}),
                 rule("type_transition", "a_t", "file_t", "dir", filename="leaf"),
                 rule("type_transition", "c_t", "file_t", "dir", filename="leaf")]
        scans = []

        def query(policy, **criteria):
            scans.append(criteria)

            def results():
                for r in rules:
                    if r.ruletype not in criteria["ruletype"]:
                        continue
                    if "source" in criteria and not set(Symbol(criteria["source"]).expand()) & set(r.source.expand()):
                        continue
                    yield r
            return types.SimpleNamespace(results=results)

        policy = types.SimpleNamespace(lookup_type_or_attr=Symbol, lookup_class=str)
        setools = types.SimpleNamespace(SELinuxPolicy=lambda path: policy, TERuleQuery=query)
        with mock.patch.dict(sys.modules, setools=setools):
            view = compare_rules.SetoolsView("policy")
        granted = lambda source: {p for r in view.rules(source, "file_t", "file") for p in r.perms}  # noqa: E731
        self.assertEqual(granted("a_t"), {"read", "write"})
        self.assertEqual(granted("b_t"), {"write"})
        self.assertEqual(granted("c_t"), {"open"})
        self.assertEqual(granted("domains"), {"read", "write"})
        self.assertTrue(view.has_transition("a_t", "file_t", "dir", "leaf", "new_t", ""))
        self.assertTrue(view.has_transition("c_t", "file_t", "dir", "leaf", "new_t", ""))
        self.assertFalse(view.has_transition("b_t", "file_t", "dir", "leaf", "new_t", ""))
        self.assertEqual(scans, [{"ruletype": ("allow",)}, {"ruletype": ("type_transition",)}],
                         "one walk per rule type, and none of them narrowed to a source")
        # A source the policy does not know is refused, as TERuleQuery(source=...) refused it; a known one with no
        # rules has none, and never falls back to every rule.
        def lookup(name):
            if name == "typo_t":
                raise ValueError("unknown type")
            return Symbol(name)

        policy.lookup_type_or_attr = lookup
        with self.assertRaisesRegex(ValueError, "unknown type"):
            view.rules("typo_t", "file_t", "file")
        self.assertEqual(view.rules("lonely_t", "file_t", "file"), [])

    def test_attribute_targets_classes_and_transition_defaults_are_filtered(self):
        class Symbol(str):
            def expand(self):
                return iter({"files": {"file_t", "other_t"}, "new_types": {"new_t"}}.get(self, {self}))

        policy = types.SimpleNamespace(lookup_type_or_attr=Symbol, lookup_class=str)
        view = compare_rules.SetoolsView.__new__(compare_rules.SetoolsView)
        view.policy = policy
        grant = fact({"read"})
        grant.target, grant.tclass = Symbol("files"), "file"
        transition = types.SimpleNamespace(target=Symbol("files"), tclass="dir", default=Symbol("new_t"),
                                           filename="leaf", conditional=None)
        view._source_rules = lambda kind, source: (grant,) if kind == "allow" else (transition,)
        self.assertEqual(view.rules("domain_t", "file_t", "file"), [grant])
        self.assertEqual(view.rules("domain_t", "files", "file"), [grant])
        self.assertEqual(view.rules("domain_t", "unrelated_t", "file"), [])
        self.assertEqual(view.rules("domain_t", "file_t", "dir"), [])
        self.assertTrue(view.has_transition("domain_t", "file_t", "dir", "leaf", "new_types", ""))
        self.assertFalse(view.has_transition("domain_t", "file_t", "dir", "other", "new_t", ""))
        self.assertFalse(view.has_transition("domain_t", "file_t", "dir", "leaf", "other_t", ""))
        policy.lookup_class = mock.Mock(side_effect=ValueError("unknown class"))
        with self.assertRaisesRegex(ValueError, "unknown class"):
            view.rules("domain_t", "file_t", "invalid")


POLICIES = glob.glob("/etc/selinux/targeted/policy/policy.*")


@unittest.skipUnless(POLICIES and importlib.util.find_spec("setools"), "needs setools and an installed targeted policy")
class AgainstSetools(unittest.TestCase):
    """The tool's own answer, not a fake of it: the hosted job installs the pinned policy before it runs these tests."""

    @staticmethod
    def identity(rule):
        try:
            perms = tuple(sorted(str(p) for p in rule.perms))
        except Exception:  # pylint: disable=broad-except
            perms = (str(rule.default), str(getattr(rule, "filename", "") or ""))
        cond, block = compare_rules.condition_of(rule)
        return (str(rule.ruletype), str(rule.source), str(rule.target), str(rule.tclass), perms,
                str(cond) if cond is not None else None, block)

    def test_the_single_walk_gives_each_source_the_rules_a_query_for_it_gives(self):
        view = compare_rules.SetoolsView(max(POLICIES, key=lambda p: int(p.rsplit(".", 1)[1])))
        # init_t is held by several attributes whose rules reach it; the attribute is a source in its own right.
        for ruletype, source in (("allow", "init_t"), ("allow", "unconfined_t"), ("allow", "unconfined_domain_type"),
                                 ("type_transition", "init_t")):
            with self.subTest(ruletype=ruletype, source=source):
                query = view.setools.TERuleQuery(view.policy, ruletype=(ruletype,), source=source)
                want = collections.Counter(self.identity(r) for r in query.results())
                got = collections.Counter(self.identity(r) for r in view._source_rules(ruletype, source))
                self.assertTrue(want, "the query finds rules, so the comparison compares something")
                self.assertEqual(got, want)


class CommandLine(unittest.TestCase):
    def test_cil_mode_exits_1_on_an_extra_allow_and_names_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = {}
            for name, text in (("full.cil", MODULE + "(allow olivares_d_t olivares_d_key_t (file (read)))"),
                               ("base.cil", BASELINE)):
                paths[name] = os.path.join(tmp, name)
                with open(paths[name], "w", encoding="utf-8") as f:
                    f.write(text)
            access = os.path.join(tmp, "access.tsv")
            with open(access, "w", encoding="utf-8") as f:
                f.write("id\tkind\tsource\ttarget\tclass\tperms\tcondition\tvia\trationale\n")
                for r in ROWS:
                    f.write("\t".join(r[c] for c in ("id", "kind", "source", "target", "class", "perms", "condition",
                                                     "via", "rationale")) + "\n")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = compare_rules.main(["cil", "--module", paths["full.cil"], "--baseline", paths["base.cil"],
                                           "--access", access])
            self.assertEqual(code, 1, buf.getvalue())
            self.assertIn("in the module but in no row: allow olivares_d_t olivares_d_key_t:file read",
                          buf.getvalue())

    def test_the_repository_denied_table_allows_the_jit_only_under_its_boolean(self):
        denied = {d["id"]: d for d in compare_rules.read_denied(os.path.join(HERE, "denied.tsv"))}
        self.assertEqual(denied["N-PROD-JIT"]["allowed_when"], "olivares_operate_runtime=true")
        self.assertEqual({i for i, d in denied.items() if d["allowed_when"]}, {"N-PROD-JIT"})

    def test_the_repository_denied_table_names_one_access_per_domain(self):
        denied = compare_rules.read_denied(os.path.join(HERE, "denied.tsv"))
        sources = {d["source"] for d in denied}
        rows = generate.read_table(os.path.join(HERE, "access.tsv"), generate.ACCESS_COLUMNS)
        domains = {r["source"] for r in rows if r["class"] == "file" and "entrypoint" in r["perms"].split()}
        # PID 1 delivers the public certificate; private engine reads remain denied. A plain container (container_t)
        # is pinned off the accounts' files and the workspaces: a session's container runs as olivares_tool_t (the regression).
        self.assertEqual(sources, domains | {"init_t", "container_t"})
        self.assertEqual(domains, {"olivares_portal_t", "olivares_repair_console_t", "olivares_helper_power_t",
                                   "olivares_helper_bundle_t", "olivares_snapshotcore_t", "olivares_firstboot_t",
                                   "olivares_t", "olivares_cli_t", "olivares_net_guard_t", "olivares_helper_netrestore_t",
                                   "olivares_helper_netprobe_t", "olivares_portal_pam_t", "olivares_helper_units_t",
                                   "olivares_helper_storage_t", "olivares_helper_firewall_t", "olivares_helper_apt_t",
                                   "olivares_helper_apps_t", "olivares_tool_t", "olivares_cmd_t",
                                   "olivares_gitpub_t", "olivares_git_import_t", "olivares_hook_t", "olivares_container_hook_t",
                                   "olivares_container_relay_t"})


if __name__ == "__main__":
    unittest.main()
