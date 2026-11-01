# SPDX-FileCopyrightText: 2026 Olivares.AI
# SPDX-License-Identifier: AGPL-3.0-only
"""The contract of generate.py: the rule tables produce the policy module, and a table the module must not
carry stops the generator.

Run: python3 -m unittest discover -s appliance/selinux -p 'test_*.py'
"""
import contextlib
import io
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import generate  # noqa: E402  (the module under test sits beside this file)

ACCESS_HEADER = "id\tkind\tsource\ttarget\tclass\tperms\tcondition\tvia\trationale\n"
CONTEXTS_HEADER = "id\tpath\tfile_type\ttype\tentry\tdeclare\tbase_type\tused_by\tnote\n"

# A small, complete pair of tables: one domain with its entry point and NNP transition, a file type, a port
# type, a raw rule, a self rule, a named type transition, the boolean and its conditional rule.
ACCESS = ACCESS_HEADER + "".join("\t".join(r) + "\n" for r in [
    ["D-01", "allow", "init_t", "olivares_d_t", "process", "transition", "", "init_daemon_domain", "PID 1 starts it"],
    ["D-02", "allow", "olivares_d_t", "olivares_d_exec_t", "file", "entrypoint execute getattr map open read", "",
     "init_daemon_domain", "its only entry point"],
    ["D-03", "type_transition", "init_t", "olivares_d_exec_t", "process", "olivares_d_t", "", "init_daemon_domain",
     "the exec transition"],
    ["D-04", "allow", "init_t", "olivares_d_t", "process2", "nnp_transition nosuid_transition", "",
     "init_nnp_daemon_domain", "the unit sets NoNewPrivileges="],
    ["D-05", "allow", "olivares_d_t", "init_t", "fd", "use", "", "", "journal streams PID 1 opened"],
    ["D-06", "allow", "olivares_d_t", "olivares_d_t", "tcp_socket", "accept read", "", "", "serves its listener"],
    ["D-07", "allow", "olivares_d_t", "olivares_d_var_lib_t", "dir", "add_name search write", "", "", "its data"],
    ["D-08", "type_transition", "olivares_d_t", "var_lib_t", "dir", 'olivares_d_var_lib_t "d"', "", "",
     "a directory it creates in /var/lib gets its type"],
    ["D-09", "allow", "olivares_d_t", "olivares_d_port_t", "tcp_socket", "name_bind", "", "", "its private port"],
    ["D-10", "boolean", "olivares_d_jit", "-", "-", "false", "", "", "the JIT switch, off"],
    ["D-11", "allow", "olivares_d_t", "olivares_d_t", "process", "execmem", "olivares_d_jit", "", "the JIT"],
    ["D-12", "allow", "olivares_d_t", "var_lib_t", "dir", "search", "", "", "reaches /var/lib"],
])
CONTEXTS = CONTEXTS_HEADER + "".join("\t".join(r) + "\n" for r in [
    ["C01", "/usr/libexec/d", "--", "olivares_d_exec_t", "module", "init_daemon_domain", "bin_t", "olivares_d_t",
     "entry point"],
    ["C02", "/var/lib/d(/.*)?", "all", "olivares_d_var_lib_t", "module", "files_type", "var_lib_t", "olivares_d_t",
     "its data"],
    ["C03", "tcp 4242", "port", "olivares_d_port_t", "module", "corenet_port", "unreserved_port_t", "olivares_d_t",
     "its port"],
    ["C04", "/usr/libexec", "-d", "bin_t", "base", "-", "bin_t", "all", "the base policy's own label"],
])


def run_generator(access, contexts, *extra):
    """Writes the two tables to a scratch directory, runs generate.main and returns (exit, output, files)."""
    with tempfile.TemporaryDirectory() as tmp:
        a, c, out = os.path.join(tmp, "access.tsv"), os.path.join(tmp, "contexts.tsv"), os.path.join(tmp, "out")
        with open(a, "w", encoding="utf-8") as f:
            f.write(access)
        with open(c, "w", encoding="utf-8") as f:
            f.write(contexts)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            code = generate.main(["--access", a, "--contexts", c, "--out", out, *extra])
        files = {}
        if os.path.isdir(out):
            for name in sorted(os.listdir(out)):
                with open(os.path.join(out, name), encoding="utf-8") as f:
                    files[name] = f.read()
        return code, buf.getvalue(), files


def with_row(table, row):
    return table + "\t".join(row) + "\n"


class GenerateModule(unittest.TestCase):
    def setUp(self):
        self.code, self.out, self.files = run_generator(ACCESS, CONTEXTS)
        self.assertEqual(self.code, 0, self.out)
        self.te, self.fc, self.iface = self.files["olivares.te"], self.files["olivares.fc"], self.files["olivares.if"]

    def test_writes_the_three_module_files(self):
        self.assertEqual(sorted(self.files), ["olivares.fc", "olivares.if", "olivares.te"])

    def test_module_statement_names_the_module_and_its_version(self):
        self.assertIn("\npolicy_module(olivares, %s)\n" % generate.MODULE_VERSION, self.te)

    def test_domains_use_the_base_policy_daemon_macros_with_their_row_ids(self):
        self.assertIn("# D-01 D-02 D-03 D-04\ntype olivares_d_t;\ntype olivares_d_exec_t;\n"
                      "init_daemon_domain(olivares_d_t, olivares_d_exec_t)\n"
                      "init_nnp_daemon_domain(olivares_d_t)\n", self.te)

    def test_macro_rows_are_not_written_twice(self):
        self.assertNotIn("allow init_t olivares_d_t:process transition;", self.te)
        self.assertNotIn("olivares_d_exec_t:file", self.te)

    def test_file_and_port_types_are_declared_from_the_contexts(self):
        self.assertIn("# C02\ntype olivares_d_var_lib_t;\nfiles_type(olivares_d_var_lib_t)\n", self.te)
        self.assertIn("# C03\ntype olivares_d_port_t;\ncorenet_port(olivares_d_port_t)\n", self.te)

    def test_each_rule_follows_its_row_id_and_reason(self):
        self.assertIn("# D-05: journal streams PID 1 opened\nallow olivares_d_t init_t:fd use;\n", self.te)
        self.assertIn("# D-07: its data\nallow olivares_d_t olivares_d_var_lib_t:dir { add_name search write };\n",
                      self.te)

    def test_a_rule_on_its_own_domain_uses_self(self):
        self.assertIn("allow olivares_d_t self:tcp_socket { accept read };\n", self.te)

    def test_a_named_type_transition_keeps_its_object_name(self):
        self.assertIn('type_transition olivares_d_t var_lib_t:dir olivares_d_var_lib_t "d";\n', self.te)

    def test_the_boolean_is_declared_off_and_guards_its_rule(self):
        self.assertIn("gen_tunable(olivares_d_jit, false)\n", self.te)
        self.assertIn("# D-11: the JIT\ntunable_policy(`olivares_d_jit',`\n"
                      "\tallow olivares_d_t self:process execmem;\n')\n", self.te)

    def test_base_types_and_classes_are_required_once(self):
        start = self.te.index("gen_require(`")
        block = self.te[start:self.te.index("')", start)]
        self.assertIn("\ttype init_t;\n", block)
        self.assertIn("\ttype var_lib_t;\n", block)
        self.assertIn("\tclass dir { add_name search write };\n", block)
        self.assertIn("\tclass fd { use };\n", block)
        self.assertNotIn("olivares_", block)

    def test_the_file_contexts_carry_the_module_rows_only(self):
        self.assertIn("/usr/libexec/d\t--\tgen_context(system_u:object_r:olivares_d_exec_t,s0)\n", self.fc)
        self.assertIn("/var/lib/d(/.*)?\tgen_context(system_u:object_r:olivares_d_var_lib_t,s0)\n", self.fc)
        self.assertNotIn("4242", self.fc)
        self.assertNotIn("/usr/libexec\t", self.fc)

    def test_the_interface_file_exports_nothing(self):
        self.assertIn("## <summary>", self.iface)
        self.assertNotIn("interface(", self.iface)

    def test_every_file_carries_the_license_header_and_the_generated_notice(self):
        for name, text in self.files.items():
            self.assertTrue(text.startswith("# SPDX-FileCopyrightText: 2026 Olivares.AI\n"
                                            "# SPDX-License-Identifier: AGPL-3.0-only\n"), name)
            self.assertIn("GENERATED by generate.py", text, name)

    def test_generation_is_deterministic(self):
        _, _, again = run_generator(ACCESS, CONTEXTS)
        self.assertEqual(again, self.files)

    def test_declarations_only_drops_every_row_rule(self):
        code, out, files = run_generator(ACCESS, CONTEXTS, "--declarations-only")
        self.assertEqual(code, 0, out)
        te = files["olivares.te"]
        self.assertIn("init_daemon_domain(olivares_d_t, olivares_d_exec_t)", te)
        self.assertIn("gen_tunable(olivares_d_jit, false)", te)
        self.assertNotIn("allow ", te)
        self.assertNotIn("type_transition ", te)
        self.assertNotIn("tunable_policy(", te)
        self.assertEqual(files["olivares.fc"], self.fc)


class RefuseTables(unittest.TestCase):
    def assertRefused(self, access, contexts, reason):
        code, out, files = run_generator(access, contexts)
        self.assertEqual(code, 1, out)
        self.assertIn(reason, out)
        self.assertEqual(files, {}, "a refused table writes nothing")

    def test_a_permissive_row_stops_the_generator(self):
        self.assertRefused(with_row(ACCESS, ["X-01", "permissive", "olivares_d_t", "-", "-", "-", "", "", "no"]),
                           CONTEXTS, "X-01: rule kind 'permissive' is not allow, type_transition, boolean, interface or role")

    def test_an_unconfined_type_stops_the_generator(self):
        self.assertRefused(with_row(ACCESS, ["X-01", "allow", "init_t", "unconfined_service_t", "process",
                                             "transition", "", "", "no"]),
                           CONTEXTS, "X-01: target names permissive or unconfined")

    def test_a_wildcard_permission_stops_the_generator(self):
        for perms in ("*", "~{ read }", "{ read }", ""):
            with self.subTest(perms=perms):
                self.assertRefused(with_row(ACCESS, ["X-01", "allow", "olivares_d_t", "var_lib_t", "dir", perms,
                                                     "", "", "no"]),
                                   CONTEXTS, "X-01: permission set is not plain permission names")

    def test_executing_a_generic_command_type_stops_the_generator(self):
        for target in ("bin_t", "shell_exec_t"):
            with self.subTest(target=target):
                self.assertRefused(with_row(ACCESS, ["X-01", "allow", "olivares_d_t", target, "file",
                                                     "execute execute_no_trans getattr map open read", "", "",
                                                     "python3 and id"]),
                                   CONTEXTS, f"X-01: olivares_d_t may not execute {target}")

    def test_an_undeclared_module_type_stops_the_generator(self):
        self.assertRefused(with_row(ACCESS, ["X-01", "allow", "olivares_d_t", "olivares_nowhere_t", "file", "read",
                                             "", "", "no"]),
                           CONTEXTS, "X-01: olivares_nowhere_t is a module type that nothing declares")

    def test_a_condition_without_its_boolean_stops_the_generator(self):
        self.assertRefused(with_row(ACCESS, ["X-01", "allow", "olivares_d_t", "var_lib_t", "dir", "read",
                                             "olivares_no_bool", "", "no"]),
                           CONTEXTS, "X-01: condition olivares_no_bool is not a boolean row")

    def test_a_backquote_in_copied_text_stops_the_generator(self):
        self.assertRefused(with_row(ACCESS, ["X-01", "allow", "olivares_d_t", "var_lib_t", "dir", "read", "", "",
                                             "reads `x`"]),
                           CONTEXTS, "X-01: a backquote would break the module's m4 quoting")

    def test_a_repeated_row_id_stops_the_generator(self):
        self.assertRefused(with_row(ACCESS, ["D-05", "allow", "olivares_d_t", "var_lib_t", "dir", "read", "", "",
                                             "again"]),
                           CONTEXTS, "D-05: repeated row id")

    def test_an_unknown_macro_stops_the_generator(self):
        self.assertRefused(with_row(ACCESS, ["X-01", "allow", "init_t", "olivares_d_t", "process", "transition", "",
                                             "unconfined_domain", "no"]),
                           CONTEXTS, "X-01: via names permissive or unconfined")
        self.assertRefused(with_row(ACCESS, ["X-01", "allow", "init_t", "olivares_d_t", "process", "transition", "",
                                             "init_other_domain", "no"]),
                           CONTEXTS, "X-01: via init_other_domain is not a macro the generator writes")

    def test_shadow_read_is_only_for_the_fixed_native_worker(self):
        access = ACCESS.replace("olivares_d_", "olivares_portal_pam_")
        contexts = CONTEXTS.replace("olivares_d_", "olivares_portal_pam_")
        reader = ["PAM-15", "allow", "olivares_portal_pam_t", "shadow_t", "file", "getattr open read", "",
                  "auth_reader_shadow", "native PAM reads shadow and account expiry"]
        code, out, files = run_generator(with_row(access, reader), contexts)
        self.assertEqual(code, 0, out)
        te = files["olivares.te"]
        self.assertIn("auth_reader_shadow(olivares_portal_pam_t)\n", te)
        self.assertIn("allow olivares_portal_pam_t shadow_t:file { getattr open read };", te)
        for field, value in ((2, "olivares_portal_t"), (2, "olivares_t"), (3, "passwd_file_t"),
                             (4, "dir"), (5, "getattr open read write")):
            with self.subTest(field=field, value=value):
                changed = reader.copy()
                changed[field] = value
                self.assertRefused(with_row(access, changed), contexts,
                                   "PAM-15: auth_reader_shadow is only the fixed worker's read on shadow_t:file")

    def test_a_condition_on_a_macro_row_stops_the_generator(self):
        for rid in ("D-01", "D-02", "D-03", "D-04"):
            with self.subTest(row=rid):
                lines = []
                for line in ACCESS.splitlines(keepends=True):
                    f = line.rstrip("\n").split("\t")
                    if f[0] == rid:
                        f[6] = "olivares_d_jit"
                        line = "\t".join(f) + "\n"
                    lines.append(line)
                macro = "init_nnp_daemon_domain" if rid == "D-04" else "init_daemon_domain"
                self.assertRefused("".join(lines), CONTEXTS, f"{rid}: condition olivares_d_jit on a row the {macro} "
                                   "macro writes; the macro cannot carry a condition")

    def test_an_unknown_declaration_stops_the_generator(self):
        self.assertRefused(ACCESS, with_row(CONTEXTS, ["C09", "/x", "--", "olivares_x_t", "module", "files_mystery",
                                                       "etc_t", "-", "no"]),
                           "C09: declare files_mystery is not an interface the generator writes")


# A program a user runs, declared with application_domain: its entry-point row is the only row the macro writes.
APP_ACCESS = with_row(ACCESS, ["E-01", "allow", "olivares_e_t", "olivares_e_exec_t", "file",
                               "entrypoint execute getattr map open read", "", "application_domain", "a program users run"])
APP_CONTEXTS = with_row(CONTEXTS, ["C05", "/usr/bin/e", "--", "olivares_e_exec_t", "module", "application_domain", "bin_t",
                                   "olivares_e_t", "its entry point"])


class ApplicationDomain(unittest.TestCase):
    def assertRefused(self, access, contexts, reason):
        code, out, files = run_generator(access, contexts)
        self.assertEqual(code, 1, out)
        self.assertIn(reason, out)
        self.assertEqual(files, {}, "a refused table writes nothing")

    def test_a_program_users_run_is_declared_with_application_domain(self):
        code, out, files = run_generator(APP_ACCESS, APP_CONTEXTS)
        self.assertEqual(code, 0, out)
        te = files["olivares.te"]
        self.assertIn("# E-01\ntype olivares_e_t;\ntype olivares_e_exec_t;\napplication_domain(olivares_e_t, olivares_e_exec_t)\n", te)
        self.assertNotIn("init_daemon_domain(olivares_e_t", te)
        self.assertNotIn("allow olivares_e_t olivares_e_exec_t", te)
        self.assertIn("/usr/bin/e\t--\tgen_context(system_u:object_r:olivares_e_exec_t,s0)", files["olivares.fc"])

    def test_a_row_application_domain_does_not_write_is_refused(self):
        self.assertRefused(with_row(APP_ACCESS, ["E-02", "allow", "init_t", "olivares_e_t", "process", "transition", "",
                                                 "application_domain", "no"]),
                           APP_CONTEXTS, "E-02: not a row application_domain writes")

    def test_one_domain_under_both_macros_is_refused(self):
        self.assertRefused(with_row(APP_ACCESS, ["E-02", "allow", "init_t", "olivares_e_t", "process", "transition", "",
                                                 "init_daemon_domain", "no"]),
                           APP_CONTEXTS, "E-02: olivares_e_t is declared by both application_domain and init_daemon_domain")

    def test_an_application_domain_context_needs_its_entry_point_row(self):
        self.assertRefused(ACCESS, APP_CONTEXTS,
                           "C05: olivares_e_exec_t is declared by application_domain but no row makes it an entry point")


    def test_a_role_row_authorizes_an_application_domain_among_the_rules(self):
        access = with_row(APP_ACCESS, ["E-02", "role", "system_r", "olivares_e_t", "-", "-", "", "",
                                       "a service domain's exec enters it"])
        code, out, files = run_generator(access, APP_CONTEXTS)
        self.assertEqual(code, 0, out)
        te = files["olivares.te"]
        # With the rules, so compare_rules' cil mode holds it against the declarations-only baseline.
        self.assertIn("# E-02: a service domain's exec enters it\nrole system_r types olivares_e_t;\n",
                      te.split("Rules, one per row")[1])
        self.assertIn("\trole system_r;\n", te.split("Declarations")[0])
        self.assertEqual(te.count("role system_r types"), 1)
        code, out, files = run_generator(access, APP_CONTEXTS, "--declarations-only")
        self.assertEqual(code, 0, out)
        self.assertNotIn("role system_r types", files["olivares.te"])

    def test_a_role_row_for_another_domain_or_in_another_form_is_refused(self):
        for row, reason in [
                (["E-02", "role", "system_r", "olivares_d_t", "-", "-", "", "", "no"],
                 "E-02: role row names olivares_d_t, not a module domain application_domain or the command domain declares"),
                (["E-02", "role", "sysadm_r", "olivares_e_t", "-", "-", "", "", "no"],
                 "E-02: a role row is the role system_r and a domain, with no class, permissions, condition or via"),
                (["E-02", "role", "system", "olivares_e_t", "-", "-", "", "", "no"],
                 "E-02: a role row is the role system_r and a domain, with no class, permissions, condition or via"),
                (["E-02", "role", "system_r", "olivares_e_t", "process", "-", "", "", "no"],
                 "E-02: a role row is the role system_r and a domain, with no class, permissions, condition or via"),
                (["E-02", "role", "system_r", "olivares_e_t", "-", "-", "olivares_d_jit", "", "no"],
                 "E-02: a role row is the role system_r and a domain, with no class, permissions, condition or via")]:
            with self.subTest(row=row):
                self.assertRefused(with_row(APP_ACCESS, row), APP_CONTEXTS, reason)

# The one base-policy interface call the module makes: the operator's login domain runs the CLI in the CLI's domain.
CALL = "unconfined_run_to(olivares_cli_t, olivares_cli_exec_t)"
IF_ACCESS = with_row(with_row(ACCESS, ["K-01", "allow", "olivares_cli_t", "olivares_cli_exec_t", "file",
                                       "entrypoint execute getattr map open read", "", "application_domain", "the CLI"]),
                     ["K-02", "interface", "olivares_cli_t", "olivares_cli_exec_t", "-", "unconfined_run_to", "", "",
                      "the operator's login runs the CLI in its domain"])
IF_CONTEXTS = with_row(CONTEXTS, ["C06", "/usr/bin/cli", "--", "olivares_cli_exec_t", "module", "application_domain",
                                  "bin_t", "olivares_cli_t", "the CLI"])


def replace_field(table, rid, column, value):
    names = ACCESS_HEADER.rstrip("\n").split("\t")
    out = []
    for line in table.splitlines(keepends=True):
        f = line.rstrip("\n").split("\t")
        if f[0] == rid:
            f[names.index(column)] = value
            line = "\t".join(f) + "\n"
        out.append(line)
    return "".join(out)


class InterfaceCall(unittest.TestCase):
    def assertRefused(self, access, contexts, reason):
        code, out, files = run_generator(access, contexts)
        self.assertEqual(code, 1, out)
        self.assertIn(reason, out)
        self.assertEqual(files, {}, "a refused table writes nothing")

    def test_the_one_call_is_written_inside_optional_policy_and_nothing_else(self):
        code, out, files = run_generator(IF_ACCESS, IF_CONTEXTS)
        self.assertEqual(code, 0, out)
        te = files["olivares.te"]
        self.assertIn("# K-02: the operator's login runs the CLI in its domain\noptional_policy(`\n\t" + CALL + "\n')\n", te)
        self.assertEqual(te.count("unconfined"), 1)

    def test_declarations_only_leaves_the_call_out(self):
        code, out, files = run_generator(IF_ACCESS, IF_CONTEXTS, "--declarations-only")
        self.assertEqual(code, 0, out)
        self.assertNotIn("unconfined", files["olivares.te"])

    def test_the_call_naming_another_domain_or_entry_type_is_refused(self):
        for column, value in (("source", "olivares_portal_t"), ("target", "olivares_portal_exec_t")):
            with self.subTest(column=column):
                self.assertRefused(replace_field(IF_ACCESS, "K-02", column, value), IF_CONTEXTS,
                                   "K-02: interface unconfined_run_to(" + (value if column == "source" else "olivares_cli_t")
                                   + ", " + (value if column == "target" else "olivares_cli_exec_t")
                                   + ") is not the one call the module makes, " + CALL)

    def test_another_unconfined_interface_is_refused(self):
        self.assertRefused(replace_field(IF_ACCESS, "K-02", "perms", "unconfined_domain"), IF_CONTEXTS,
                           "K-02: perms names permissive or unconfined outside the one interface call")

    def test_a_second_call_is_refused(self):
        self.assertRefused(with_row(IF_ACCESS, ["K-03", "interface", "olivares_cli_t", "olivares_cli_exec_t", "-",
                                                "unconfined_run_to", "", "", "again"]),
                           IF_CONTEXTS, "K-03: a second interface row; the module makes one call")

    def test_a_condition_or_a_via_on_the_call_is_refused(self):
        for column, value in (("condition", "olivares_d_jit"), ("via", "application_domain")):
            with self.subTest(column=column):
                self.assertRefused(replace_field(IF_ACCESS, "K-02", column, value), IF_CONTEXTS,
                                   "K-02: an interface row carries no condition and no via")

    def test_a_raw_row_of_the_calls_expansion_is_refused(self):
        self.assertRefused(with_row(IF_ACCESS, ["TEST-02", "allow", "unconfined_t", "olivares_cli_t", "process",
                                                "transition", "", "", "the login enters the CLI"]),
                           IF_CONTEXTS, "TEST-02: source names permissive or unconfined outside the one interface call")
        self.assertRefused(with_row(IF_ACCESS, ["TEST-05", "allow", "olivares_cli_t", "unconfined_t", "fd", "use", "", "",
                                                "the shell's descriptors"]),
                           IF_CONTEXTS, "TEST-05: target names permissive or unconfined outside the one interface call")

    def test_unconfined_domain_of_an_olivares_domain_is_refused(self):
        self.assertRefused(with_row(IF_ACCESS, ["X-01", "allow", "olivares_cli_t", "olivares_cli_exec_t", "file",
                                                "entrypoint", "", "unconfined_domain", "no"]),
                           IF_CONTEXTS, "X-01: via names permissive or unconfined outside the one interface call")
        self.assertRefused(IF_ACCESS, with_row(IF_CONTEXTS, ["C09", "/x", "--", "olivares_x_t", "module",
                                                             "unconfined_domain", "etc_t", "-", "no"]),
                           "C09: declare names permissive or unconfined outside the one interface call")


# The command domain: a shell or a generic program an installed tool executes runs in olivares_cmd_t, entered only
# by that exec from olivares_tool_t; nothing else may execute a generic command type.
CMD_ROWS = [
    ["T-01", "allow", "olivares_tool_t", "olivares_tool_exec_t", "file", "entrypoint execute getattr map open read", "",
     "application_domain", "the tool's program"],
    ["T-02", "allow", "olivares_tool_t", "shell_exec_t", "file", "execute getattr map open read", "", "",
     "the tool runs a shell for its Bash tool"],
    ["T-03", "type_transition", "olivares_tool_t", "shell_exec_t", "process", "olivares_cmd_t", "", "",
     "and the shell runs in the command domain"],
    ["T-04", "allow", "olivares_tool_t", "olivares_cmd_t", "process", "transition", "", "", "the transition"],
    ["T-05", "allow", "olivares_cmd_t", "shell_exec_t", "file", "entrypoint execute execute_no_trans getattr map open read",
     "", "command_domain", "a shell is an entry point of the command domain"],
    ["T-06", "allow", "olivares_cmd_t", "bin_t", "file", "entrypoint execute execute_no_trans getattr map open read",
     "", "command_domain", "so is a generic program, and it runs the next one in place"],
    ["T-07", "role", "system_r", "olivares_cmd_t", "-", "-", "", "", "the tool's exec computes system_r"],
]
CMD_ACCESS = ACCESS + "".join("\t".join(r) + "\n" for r in CMD_ROWS)
CMD_CONTEXTS = with_row(CONTEXTS, ["C05", "/var/lib/tools(/.*)?", "all", "olivares_tool_exec_t", "module",
                                   "application_domain", "var_lib_t", "olivares_tool_t", "the tools"])


# The engine, an init daemon, also runs a generic command (git) into the command domain (the regression).
ENGINE_ACCESS = CMD_ACCESS + "".join("\t".join(r) + "\n" for r in [
    ["E-01", "allow", "init_t", "olivares_t", "process", "transition", "", "init_daemon_domain", "PID 1 starts it"],
    ["E-02", "allow", "olivares_t", "olivares_exec_t", "file", "entrypoint execute getattr map open read", "",
     "init_daemon_domain", "its only entry point"],
    ["E-03", "type_transition", "init_t", "olivares_exec_t", "process", "olivares_t", "", "init_daemon_domain",
     "the exec transition"],
    ["E-04", "allow", "olivares_t", "bin_t", "file", "execute getattr open read", "", "", "the engine runs git"],
    ["E-05", "type_transition", "olivares_t", "bin_t", "process", "olivares_cmd_t", "", "",
     "and git runs in the command domain"],
    ["E-06", "allow", "olivares_t", "olivares_cmd_t", "process", "transition", "", "", "the transition"],
])
# The engine's network git runs in two generic-entry domains, gitpublish's and the skills import's, each entered only by
# the engine naming it for its next exec, never by a type transition (the regression).
NET_ACCESS = "".join("\t".join(r) + "\n" for r in [
    ["N-01", "allow", "olivares_t", "olivares_t", "process", "setexec", "", "", "names the domain of its next exec"],
    ["N-02", "allow", "olivares_t", "olivares_gitpub_t", "process", "transition", "", "", "enters the network git domain"],
    ["N-03", "allow", "olivares_gitpub_t", "bin_t", "file", "entrypoint execute execute_no_trans getattr map open read",
     "", "command_domain", "git is its entry point and runs its helpers in place"],
    ["N-04", "role", "system_r", "olivares_gitpub_t", "-", "-", "", "", "the engine's exec computes system_r"],
    ["N-05", "allow", "olivares_t", "olivares_git_import_t", "process", "transition", "", "", "enters the import's domain"],
    ["N-06", "allow", "olivares_git_import_t", "bin_t", "file", "entrypoint execute execute_no_trans getattr map open read",
     "", "command_domain", "prlimit is its entry point and runs git in place"],
    ["N-07", "role", "system_r", "olivares_git_import_t", "-", "-", "", "", "the engine's exec computes system_r"],
])
ENGINE_CONTEXTS = with_row(CMD_CONTEXTS, ["C06", "/usr/bin/olivares", "--", "olivares_exec_t", "module",
                                          "init_daemon_domain", "bin_t", "olivares_t", "the engine"])
# The PEP hook client (the regression): the hook line Claude Code runs through sh executes the engine's program, and that exec
# from the command domain enters the hook domain, whose one entry point is that program.
HOOK_ACCESS = "".join("\t".join(r) + "\n" for r in [
    ["H-01", "allow", "olivares_cmd_t", "olivares_exec_t", "file", "execute getattr open read", "", "",
     "sh executes the hook command"],
    ["H-02", "type_transition", "olivares_cmd_t", "olivares_exec_t", "process", "olivares_hook_t", "", "",
     "and it runs in the hook domain"],
    ["H-03", "allow", "olivares_cmd_t", "olivares_hook_t", "process", "transition", "", "", "the transition"],
    ["H-04", "allow", "olivares_cmd_t", "olivares_hook_t", "process2", "nnp_transition", "", "", "under no_new_privs"],
    ["H-05", "allow", "olivares_hook_t", "olivares_exec_t", "file", "entrypoint execute getattr map open read", "",
     "hook_domain", "its one entry point"],
    ["H-06", "role", "system_r", "olivares_hook_t", "-", "-", "", "", "the exec computes system_r"],
    ["H-07", "allow", "olivares_hook_t", "ephemeral_port_t", "tcp_socket", "name_connect", "", "", "reaches the PEP"],
])
ENGINE_CONTEXTS = with_row(CMD_CONTEXTS, ["C06", "/usr/bin/olivares", "--", "olivares_exec_t", "module",
                                        "init_daemon_domain", "bin_t", "olivares_t", "the engine"])
HOOK_CONTEXTS = with_row(CMD_CONTEXTS, ["C06", "/usr/bin/olivares", "--", "olivares_exec_t", "module",
                                        "files_type", "bin_t", "-", "the engine program"])


def without(access, rid):
    return "".join(line for line in access.splitlines(keepends=True) if not line.startswith(rid + "\t"))


class CommandDomain(unittest.TestCase):
    def assertRefused(self, access, contexts, reason):
        code, out, files = run_generator(access, contexts)
        self.assertEqual(code, 1, out)
        self.assertIn(reason, out)
        self.assertEqual(files, {}, "a refused table writes nothing")

    def test_the_command_domain_is_declared_and_its_entry_rows_are_rules(self):
        code, out, files = run_generator(CMD_ACCESS, CMD_CONTEXTS)
        self.assertEqual(code, 0, out)
        te = files["olivares.te"]
        declarations, rules = te.split("Rules, one per row")
        declared = re.findall(r"(?m)^type ([a-z_]+);$", declarations)
        self.assertEqual(len(declared), len(set(declared)), f"duplicate type declarations: {declared}")
        self.assertIn("# T-05 T-06\ntype olivares_cmd_t;\ndomain_type(olivares_cmd_t)\n", declarations)
        self.assertIn("allow olivares_cmd_t shell_exec_t:file { entrypoint execute execute_no_trans getattr map open read };",
                      rules)
        self.assertIn("allow olivares_tool_t shell_exec_t:file { execute getattr map open read };", rules)
        self.assertIn("type_transition olivares_tool_t shell_exec_t:process olivares_cmd_t;", rules)
        self.assertIn("role system_r types olivares_cmd_t;", rules)
        code, out, files = run_generator(CMD_ACCESS, CMD_CONTEXTS, "--declarations-only")
        self.assertEqual(code, 0, out)
        self.assertIn("domain_type(olivares_cmd_t)", files["olivares.te"])
        self.assertNotIn("allow olivares_cmd_t", files["olivares.te"])

    def test_the_tool_executes_a_generic_command_only_into_the_command_domain(self):
        self.assertRefused(without(CMD_ACCESS, "T-03"), CMD_CONTEXTS,
                           "T-02: olivares_tool_t may execute shell_exec_t only into olivares_cmd_t")
        self.assertRefused(with_row(CMD_ACCESS, ["T-08", "allow", "olivares_tool_t", "bin_t", "file",
                                                 "execute execute_no_trans", "", "", "no"]),
                           CMD_CONTEXTS, "T-08: olivares_tool_t may not execute bin_t, a generic command type")

    def test_no_other_domain_executes_a_generic_command(self):
        self.assertRefused(with_row(CMD_ACCESS, ["T-08", "allow", "olivares_d_t", "bin_t", "file", "execute", "", "",
                                                 "no"]),
                           CMD_CONTEXTS, "T-08: olivares_d_t may not execute bin_t, a generic command type")

    def test_the_command_domain_enters_no_other_domain(self):
        for row in (["T-08", "type_transition", "olivares_cmd_t", "olivares_tool_exec_t", "process", "olivares_tool_t",
                     "", "", "no"],
                    ["T-08", "allow", "olivares_cmd_t", "olivares_tool_t", "process", "transition", "", "", "no"],
                    ["T-08", "allow", "olivares_cmd_t", "olivares_tool_t", "process2", "nnp_transition", "", "", "no"]):
            with self.subTest(row=row):
                self.assertRefused(with_row(CMD_ACCESS, row), CMD_CONTEXTS,
                                   "T-08: olivares_cmd_t enters no other domain")

    def test_a_command_domain_row_is_only_its_entry_on_a_generic_command(self):
        for row in (["T-08", "allow", "olivares_d_t", "bin_t", "file", "entrypoint", "", "command_domain", "no"],
                    ["T-08", "allow", "olivares_cmd_t", "olivares_tool_exec_t", "file", "entrypoint", "",
                     "command_domain", "no"],
                    ["T-08", "allow", "olivares_cmd_t", "bin_t", "file", "read", "", "command_domain", "no"]):
            with self.subTest(row=row):
                self.assertRefused(with_row(CMD_ACCESS, row), CMD_CONTEXTS,
                                   "T-08: a command_domain row is the entrypoint of olivares_cmd_t, olivares_gitpub_t or olivares_git_import_t on bin_t "
                                   "or shell_exec_t")

    def test_only_the_tools_exec_of_a_generic_command_enters_the_command_domain(self):
        for row in (["T-08", "type_transition", "olivares_d_t", "bin_t", "process", "olivares_cmd_t", "", "", "no"],
                    ["T-08", "type_transition", "olivares_tool_t", "olivares_tool_exec_t", "process", "olivares_cmd_t",
                     "", "", "no"]):
            with self.subTest(row=row):
                self.assertRefused(with_row(CMD_ACCESS, row), CMD_CONTEXTS,
                                   "T-08: only the exec of bin_t or shell_exec_t by olivares_tool_t or olivares_t enters olivares_cmd_t")
        self.assertRefused(with_row(CMD_ACCESS, ["T-08", "allow", "olivares_cmd_t", "olivares_tool_exec_t", "file",
                                                 "entrypoint", "", "", "no"]),
                           CMD_CONTEXTS, "T-08: olivares_cmd_t's entry points are its command_domain rows")

    def test_the_engine_executes_a_generic_command_only_into_the_command_domain(self):
        # the regression: the engine runs git for session Git and worktree sessions; the exec enters olivares_cmd_t.
        code, out, files = run_generator(ENGINE_ACCESS, ENGINE_CONTEXTS)
        self.assertEqual(code, 0, out)
        self.assertIn("type_transition olivares_t bin_t:process olivares_cmd_t;", files["olivares.te"])
        self.assertIn("allow olivares_t bin_t:file { execute getattr open read };", files["olivares.te"])
        self.assertRefused(without(ENGINE_ACCESS, "E-05"), ENGINE_CONTEXTS,
                           "E-04: olivares_t may execute bin_t only into olivares_cmd_t")
        self.assertRefused(with_row(ENGINE_ACCESS, ["E-07", "allow", "olivares_t", "bin_t", "file",
                                                    "execute execute_no_trans", "", "", "no"]),
                           ENGINE_CONTEXTS, "E-07: olivares_t may not execute bin_t, a generic command type")

    def test_the_network_git_domain_is_entered_only_by_the_engines_setexec(self):
        access = ENGINE_ACCESS + NET_ACCESS
        code, out, files = run_generator(access, ENGINE_CONTEXTS)
        self.assertEqual(code, 0, out)
        self.assertIn("type olivares_gitpub_t;\ndomain_type(olivares_gitpub_t)\n", files["olivares.te"])
        self.assertIn("type olivares_git_import_t;\ndomain_type(olivares_git_import_t)\n", files["olivares.te"])
        self.assertIn("allow olivares_gitpub_t bin_t:file { entrypoint execute execute_no_trans getattr map open read };",
                      files["olivares.te"])
        for row, reason in (
                (["N-09", "type_transition", "olivares_t", "bin_t", "process", "olivares_gitpub_t", "", "", "no"],
                 "N-09: olivares_gitpub_t is entered only by olivares_t naming it for its next exec"),
                (["N-09", "allow", "olivares_tool_t", "olivares_gitpub_t", "process", "transition", "", "", "no"],
                 "N-09: olivares_gitpub_t is entered only by olivares_t naming it for its next exec"),
                (["N-09", "allow", "olivares_gitpub_t", "olivares_cmd_t", "process", "transition", "", "", "no"],
                 "N-09: olivares_gitpub_t enters no other domain"),
                (["N-09", "allow", "olivares_gitpub_t", "shell_exec_t", "file", "entrypoint", "", "", "no"],
                 "N-09: olivares_gitpub_t's entry points are its command_domain rows")):
            with self.subTest(row=row):
                self.assertRefused(with_row(access, row), ENGINE_CONTEXTS, reason)
        # setexec makes every domain the engine may transition to selectable by name: that set is pinned.
        self.assertRefused(with_row(access, ["N-09", "allow", "olivares_t", "olivares_d_t", "process", "transition", "", "",
                                             "no"]), ENGINE_CONTEXTS,
                           "N-09: olivares_t enters only olivares_tool_t, olivares_cmd_t, olivares_gitpub_t or "
                           "olivares_git_import_t")
    def test_the_hook_domain_is_entered_only_by_the_command_domains_exec_of_the_engine(self):
        access = ENGINE_ACCESS + HOOK_ACCESS
        code, out, files = run_generator(access, ENGINE_CONTEXTS)
        self.assertEqual(code, 0, out)
        te = files["olivares.te"]
        self.assertIn("# H-05\ntype olivares_hook_t;\ndomain_type(olivares_hook_t)\n", te)
        self.assertIn("type_transition olivares_cmd_t olivares_exec_t:process olivares_hook_t;", te)
        self.assertIn("allow olivares_hook_t olivares_exec_t:file { entrypoint execute getattr map open read };", te)
        self.assertIn("role system_r types olivares_hook_t;", te)
        entered = "olivares_hook_t is entered only by olivares_cmd_t's exec of olivares_exec_t"
        for row, reason in (
                (["H-09", "type_transition", "olivares_tool_t", "olivares_exec_t", "process", "olivares_hook_t", "", "",
                  "no"], entered),
                (["H-09", "type_transition", "olivares_cmd_t", "bin_t", "process", "olivares_hook_t", "", "", "no"], entered),
                (["H-09", "allow", "olivares_tool_t", "olivares_hook_t", "process", "transition", "", "", "no"], entered),
                (["H-09", "allow", "olivares_cmd_t", "olivares_hook_t", "process", "dyntransition", "", "", "no"], entered),
                (["H-09", "type_transition", "olivares_cmd_t", "olivares_exec_t", "process", "olivares_tool_t", "", "",
                  "no"], "olivares_cmd_t enters no other domain"),
                (["H-09", "allow", "olivares_hook_t", "olivares_cmd_t", "process", "transition", "", "", "no"],
                 "olivares_hook_t enters no other domain"),
                (["H-09", "allow", "olivares_hook_t", "olivares_hook_t", "process", "setexec", "", "", "no"],
                 "olivares_hook_t enters no other domain"),
                (["H-09", "allow", "olivares_hook_t", "bin_t", "file", "entrypoint", "", "", "no"],
                 "olivares_hook_t's one entry point is olivares_exec_t, by its hook_domain row"),
                (["H-09", "allow", "olivares_cmd_t", "olivares_exec_t", "file", "execute_no_trans", "", "", "no"],
                 "olivares_cmd_t may execute olivares_exec_t only into olivares_hook_t"),
                (["H-09", "allow", "olivares_d_t", "olivares_exec_t", "file", "entrypoint", "", "hook_domain", "no"],
                 "a hook_domain row is olivares_hook_t's entrypoint on olivares_exec_t")):
            with self.subTest(row=row):
                self.assertRefused(with_row(access, row), ENGINE_CONTEXTS, "H-09: " + reason)
        self.assertRefused(without(access, "H-02"), ENGINE_CONTEXTS,
                           "H-01: olivares_cmd_t may execute olivares_exec_t only into olivares_hook_t")

    def test_container_image_programs_enter_the_command_domain(self):
        access = CMD_ACCESS + "".join("\t".join(r) + "\n" for r in [
            ["CTR-07", "type_transition", "olivares_tool_t", "container_file_t", "process", "olivares_cmd_t", "", "",
             "the image program enters the command domain"],
            ["CTR-10", "allow", "olivares_cmd_t", "container_file_t", "file",
             "entrypoint execute execute_no_trans getattr map open read", "", "command_domain", "the command runs it"],
        ])
        code, out, files = run_generator(access, CMD_CONTEXTS)
        self.assertEqual(code, 0, out)
        self.assertIn("type_transition olivares_tool_t container_file_t:process olivares_cmd_t;", files["olivares.te"])
        self.assertRefused(without(access, "CTR-07"), CMD_CONTEXTS,
                           "CTR-10: olivares_cmd_t may execute container_file_t only into olivares_cmd_t")
        wrong_domain = with_row(without(access, "CTR-07"),
                                ["CTR-07", "type_transition", "olivares_tool_t", "container_file_t", "process",
                                 "olivares_d_t", "", "", "the wrong command domain"])
        self.assertRefused(wrong_domain, CMD_CONTEXTS,
                           "CTR-10: olivares_cmd_t may execute container_file_t only into olivares_cmd_t")

    def test_the_command_domain_cannot_set_its_next_exec_context(self):
        self.assertRefused(with_row(CMD_ACCESS, ["T-08", "allow", "olivares_cmd_t", "olivares_cmd_t", "process", "setexec",
                                                 "", "", "no"]),
                           CMD_CONTEXTS, "T-08: olivares_cmd_t enters no other domain")


class RepositoryModule(unittest.TestCase):
    def test_the_hook_has_no_grant_on_container_content(self):
        rows = generate.read_table(os.path.join(HERE, "access.tsv"), generate.ACCESS_COLUMNS)
        self.assertEqual([r["id"] for r in rows if r["kind"] == "allow" and r["source"] == "olivares_hook_t" and
                          r["target"] == "container_file_t"], [])

    def test_container_t_needs_its_own_hook_transition(self):
        with open(os.path.join(HERE, "access.tsv"), encoding="utf-8") as f:
            access = f.read()
        access += "\t".join(["X-CHOOK", "type_transition", "container_t", "olivares_container_hook_exec_t", "process",
                             "olivares_container_hook_t", "", "", "plain container entry"]) + "\n"
        with open(os.path.join(HERE, "contexts.tsv"), encoding="utf-8") as f:
            contexts = f.read()
        code, out, _ = run_generator(access, contexts)
        self.assertEqual(code, 1, out)
        self.assertIn("olivares_container_hook_t is entered only by a container command's exec", out)

    def test_the_container_hook_has_one_entrypoint(self):
        rows = generate.read_table(os.path.join(HERE, "access.tsv"), generate.ACCESS_COLUMNS)
        rows.append({"id": "X-CHOOK", "kind": "allow", "source": "olivares_container_hook_t", "target": "olivares_exec_t",
                     "class": "file", "perms": "entrypoint", "condition": "", "via": "", "rationale": "wrong entry"})
        table = ACCESS_HEADER + "".join("\t".join([r["id"], r["kind"], r["source"], r["target"], r["class"],
                                                  r["perms"], r["condition"], r["via"], r["rationale"]]) + "\n"
                                       for r in rows)
        with open(os.path.join(HERE, "contexts.tsv"), encoding="utf-8") as f:
            contexts = f.read()
        code, out, _ = run_generator(table, contexts)
        self.assertEqual(code, 1, out)
        self.assertIn("X-CHOOK: olivares_container_hook_t's one entry point is olivares_container_hook_exec_t, by its mcs_constrained row", out)

    def test_container_hook_execute_refusal_names_its_entrypoint(self):
        with open(os.path.join(HERE, "access.tsv"), encoding="utf-8") as f:
            access = f.read()
        access += "\t".join(["X-CHOOK", "allow", "olivares_cmd_t", "olivares_container_hook_exec_t", "file",
                             "execute_no_trans", "", "", "no transition"]) + "\n"
        with open(os.path.join(HERE, "contexts.tsv"), encoding="utf-8") as f:
            contexts = f.read()
        code, out, _ = run_generator(access, contexts)
        self.assertEqual(code, 1, out)
        self.assertIn("olivares_cmd_t may execute olivares_container_hook_exec_t only into olivares_container_hook_t", out)

    def test_container_hook_entrypoint_has_executable_attributes_in_te_syntax(self):
        # checkmodule reads .te, not CIL: typeattributeset is a syntax error there (olivares.te:510 on EL10)
        with open(os.path.join(HERE, "access.tsv"), encoding="utf-8") as f:
            access = f.read()
        with open(os.path.join(HERE, "contexts.tsv"), encoding="utf-8") as f:
            contexts = f.read()
        code, out, files = run_generator(access, contexts)
        self.assertEqual(code, 0, out)
        module = files["olivares.te"]
        self.assertNotIn("typeattributeset", module)
        self.assertIn("\tattribute entry_type;\n", module)
        self.assertIn("corecmd_executable_file(olivares_container_hook_exec_t)\n", module)
        self.assertIn("typeattribute olivares_container_hook_exec_t entry_type;\n", module)

    def test_committed_module_compiles(self):
        if shutil.which("checkmodule") is None:
            self.skipTest("selinux-policy-devel is not installed")
        with tempfile.TemporaryDirectory() as tmp:
            for name in ("olivares.te", "olivares.fc", "olivares.if"):
                shutil.copy(os.path.join(HERE, name), os.path.join(tmp, name))
            result = subprocess.run(["make", "-f", "/usr/share/selinux/devel/Makefile", "olivares.pp"], cwd=tmp,
                                    capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_container_domains_do_not_inherit_sandbox_rules(self):
        with open(os.path.join(HERE, "olivares.te"), encoding="utf-8") as f:
            module = f.read()
        self.assertIn("type olivares_tool_t;", module)
        self.assertIn("type olivares_container_hook_t;", module)
        self.assertIn("type olivares_cmd_t;", module)
        self.assertNotIn("attribute container_domain;", module)
        self.assertNotIn("attribute svirt_sandbox_domain;", module)

    def test_container_session_domains_are_mcs_constrained(self):
        with open(os.path.join(HERE, "olivares.te"), encoding="utf-8") as f:
            module = f.read()
        domains = ("olivares_tool_t", "olivares_cmd_t", "olivares_container_hook_t")
        self.assertEqual([d for d in domains if f"mcs_constrained({d})" not in module], [])

    def test_container_relay_is_mcs_constrained_and_enters_tool(self):
        with open(os.path.join(HERE, "olivares.te"), encoding="utf-8") as f:
            module = f.read()
        self.assertIn("type olivares_container_relay_t;", module)
        self.assertIn("mcs_constrained(olivares_container_relay_t)", module)
        self.assertIn("allow container_runtime_t olivares_container_relay_t:process transition;", module)
        self.assertIn("type_transition olivares_container_relay_t olivares_tool_exec_t:process olivares_tool_t;", module)
        self.assertIn("type_transition olivares_t olivares_tool_claude_exec_t:process olivares_tool_t;", module)
        self.assertIn("type_transition olivares_container_relay_t olivares_tool_claude_exec_t:process olivares_tool_t;", module)
        self.assertIn("corecmd_executable_file(olivares_tool_claude_exec_t)", module)
        self.assertIn("typeattribute olivares_tool_claude_exec_t entry_type;", module)

    def test_generator_refuses_an_entrypoint_to_a_plain_file_type(self):
        with open(os.path.join(HERE, "access.tsv"), encoding="utf-8") as f:
            access = f.read()
        access += "\t".join(["X-ENTRY", "allow", "olivares_tool_t", "olivares_tool_home_t", "file",
                             "entrypoint", "", "", "a plain file type is not an executable entry point"]) + "\n"
        with open(os.path.join(HERE, "contexts.tsv"), encoding="utf-8") as f:
            contexts = f.read()
        code, out, files = run_generator(access, contexts)
        self.assertEqual(code, 1, out)
        self.assertIn("entrypoint target olivares_tool_home_t is declared without entry_type", out)
        self.assertEqual(files, {})

    def test_container_egress_rights_never_move_to_tool(self):
        rows = generate.read_table(os.path.join(HERE, "access.tsv"), generate.ACCESS_COLUMNS)
        forbidden = (("olivares_tool_exec_t", "file", "execute_no_trans"),
                     ("olivares_engine_tmp_t", "sock_file", "write"),
                     ("olivares_t", "unix_stream_socket", "connectto"),
                     ("olivares_exec_t", "file", "entrypoint"),
                     ("container_file_t", "file", "entrypoint"))
        for target, cls, perm in forbidden:
            with self.subTest(target=target, cls=cls, perm=perm):
                granted = [r["id"] for r in rows if r["kind"] == "allow" and r["source"] == "olivares_tool_t" and
                           r["target"] == target and r["class"] == cls and perm in r["perms"].split()]
                self.assertEqual(granted, [])

    def test_generator_refuses_engine_and_tool_entrypoint_escapes(self):
        with open(os.path.join(HERE, "access.tsv"), encoding="utf-8") as f:
            access = f.read()
        with open(os.path.join(HERE, "contexts.tsv"), encoding="utf-8") as f:
            contexts = f.read()
        cases = (["X-ESCAPE", "allow", "olivares_t", "container_file_t", "file", "entrypoint execute_no_trans", "", "", "engine image execution"],
                 ["X-ESCAPE", "allow", "olivares_tool_t", "olivares_container_hook_exec_t", "file", "entrypoint", "", "", "tool hook entry"])
        for row in cases:
            with self.subTest(source=row[2], target=row[3]):
                code, out, files = run_generator(access + "\t".join(row) + "\n", contexts)
                self.assertEqual(code, 1, out)
                self.assertEqual(files, {})

    def test_relay_and_engine_refusals_name_the_boundary(self):
        with open(os.path.join(HERE, "access.tsv"), encoding="utf-8") as f:
            access = f.read()
        with open(os.path.join(HERE, "contexts.tsv"), encoding="utf-8") as f:
            contexts = f.read()
        engine = "olivares_tool_t has no right on the engine binary"
        relay = "olivares_container_relay_t is entered only by runc, never by a tool"
        exit_reason = "olivares_container_relay_t exits only to olivares_tool_t through olivares_tool_exec_t or olivares_tool_claude_exec_t"
        cases = ((["X-ENGINE", "allow", "olivares_tool_t", "olivares_exec_t", "file", "execute getattr open read", "", "", "no"], engine),
                 (["X-ENGINE", "type_transition", "olivares_tool_t", "olivares_exec_t", "process", "olivares_t", "", "", "no"], engine),
                 (["X-RELAY", "allow", "olivares_tool_t", "olivares_container_relay_t", "process", "transition", "", "", "no"], relay),
                 (["X-RELAY", "allow", "olivares_t", "olivares_container_relay_t", "process", "transition", "", "", "no"], relay),
                 (["X-RELAY", "allow", "olivares_container_relay_t", "olivares_t", "process", "transition", "", "", "no"], exit_reason),
                 (["X-RELAY", "allow", "olivares_container_relay_t", "olivares_t", "process", "setexec", "", "", "no"], exit_reason))
        for row, reason in cases:
            with self.subTest(row=row):
                code, out, files = run_generator(access + "\t".join(row) + "\n", contexts)
                self.assertEqual(code, 1, out)
                self.assertIn(reason, out)
                self.assertEqual(files, {})

    def test_relay_never_enters_a_domain_from_an_image_program(self):
        with open(os.path.join(HERE, "access.tsv"), encoding="utf-8") as f:
            access = f.read()
        with open(os.path.join(HERE, "contexts.tsv"), encoding="utf-8") as f:
            contexts = f.read()
        cases = ((["X-IMAGE", "allow", "olivares_container_relay_t", "container_file_t", "file", "entrypoint", "", "", "no"], "may not execute container_file_t, a generic command type"),
                 (["X-IMAGE", "allow", "olivares_container_relay_t", "container_file_t", "file", "execute_no_trans", "", "", "no"], "may not execute container_file_t, a generic command type"),
                 (["X-IMAGE", "allow", "olivares_container_relay_t", "container_file_t", "file", "map", "", "", "no"], "olivares_container_relay_t may not map an image program"),
                 (["X-IMAGE", "allow", "olivares_container_relay_t", "shell_exec_t", "file", "execute", "", "", "no"], "may not execute shell_exec_t, a generic command type"),
                 (["X-IMAGE", "allow", "olivares_container_relay_t", "bin_t", "file", "execute", "", "", "no"], "may not execute bin_t, a generic command type"),
                 (["X-IMAGE", "type_transition", "olivares_container_relay_t", "container_file_t", "process", "olivares_tool_t", "", "", "no"],
                  "olivares_container_relay_t exits only to olivares_tool_t through olivares_tool_exec_t or olivares_tool_claude_exec_t"))
        for row, reason in cases:
            with self.subTest(row=row):
                code, out, files = run_generator(access + "\t".join(row) + "\n", contexts)
                self.assertEqual(code, 1, out)
                self.assertIn(reason, out)
                self.assertEqual(files, {})

    def test_relay_binds_a_labeled_local_model_port_not_generic_http(self):
        rows = generate.read_table(os.path.join(HERE, "access.tsv"), generate.ACCESS_COLUMNS)
        self.assertEqual([r["target"] for r in rows if r["id"] == "RELAY-30"], ["olivares_model_runtime_port_t"])
        self.assertEqual([r["id"] for r in rows if r["kind"] == "allow" and r["source"] == "olivares_container_relay_t" and
                          r["target"] == "http_port_t" and r["class"] == "tcp_socket" and "name_bind" in r["perms"].split()], [])

    def test_plain_container_t_never_enters_the_container_hook(self):
        rows = generate.read_table(os.path.join(HERE, "access.tsv"), generate.ACCESS_COLUMNS)
        self.assertEqual([r["id"] for r in rows if r["kind"] == "type_transition" and r["source"] == "container_t" and
                          r["target"] == "olivares_container_hook_exec_t"], [])
        self.assertEqual([r["id"] for r in rows if r["kind"] == "allow" and r["source"] == "container_t" and
                          r["target"] == "olivares_container_hook_t" and r["class"] in ("process", "process2")], [])

    def test_other_domains_are_refused_as_hook_entry_sources(self):
        for source in ("container_runtime_t", "init_t", "spc_t"):
            with self.subTest(source=source):
                with open(os.path.join(HERE, "access.tsv"), encoding="utf-8") as f:
                    access = f.read()
                access += "\t".join(["X-CHOOK", "type_transition", source, "olivares_container_hook_exec_t", "process",
                                     "olivares_container_hook_t", "", "", "forbidden source"]) + "\n"
                with open(os.path.join(HERE, "contexts.tsv"), encoding="utf-8") as f:
                    contexts = f.read()
                code, out, _ = run_generator(access, contexts)
                self.assertEqual(code, 1, out)
                self.assertIn("olivares_container_hook_t is entered only by a container command's exec", out)

    """The repository's own tables generate a module with every row in it."""

    def test_the_repository_tables_generate(self):
        with open(os.path.join(HERE, "access.tsv"), encoding="utf-8") as f:
            access = f.read()
        with open(os.path.join(HERE, "contexts.tsv"), encoding="utf-8") as f:
            contexts = f.read()
        code, out, files = run_generator(access, contexts)
        self.assertEqual(code, 0, out)
        te = files["olivares.te"]
        for line in access.splitlines():
            if line.startswith("#") or line.startswith("id\t") or not line.strip():
                continue
            with self.subTest(row=line.split("\t")[0]):
                self.assertRegex(te, r"(?m)^# (.* )?%s(:| |$)" % line.split("\t")[0])

    def test_the_command_line_runs_from_the_repository_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = subprocess.run([sys.executable, os.path.join(HERE, "generate.py"), "--out", tmp],
                               capture_output=True, text=True, check=False)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertEqual(sorted(os.listdir(tmp)), ["olivares.fc", "olivares.if", "olivares.te"])



class RepositoryMutants(unittest.TestCase):
    """Mutants of the repository's own tables that must be refused."""

    def test_portal_01_with_the_operate_runtime_condition_is_refused(self):
        with open(os.path.join(HERE, "access.tsv"), encoding="utf-8") as f:
            access = f.read()
        with open(os.path.join(HERE, "contexts.tsv"), encoding="utf-8") as f:
            contexts = f.read()
        header = next(line for line in access.splitlines() if line.startswith("id\t")).split("\t")
        lines = []
        for line in access.splitlines(keepends=True):
            f = line.rstrip("\n").split("\t")
            if f[0] == "PORTAL-01":
                f[header.index("condition")] = "olivares_operate_runtime"
                line = "\t".join(f) + "\n"
            lines.append(line)
        code, out, files = run_generator("".join(lines), contexts)
        self.assertEqual(code, 1, out)
        self.assertIn("PORTAL-01: condition olivares_operate_runtime on a row the init_daemon_domain macro writes; "
                      "the macro cannot carry a condition", out)
        self.assertEqual(files, {})


class CommittedModule(unittest.TestCase):
    """olivares.te, olivares.fc and olivares.if are committed, and are exactly what the tables generate."""

    def test_the_committed_module_is_the_generators_output(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            code = generate.main(["--check"])
        self.assertEqual(code, 0, buf.getvalue())

    def test_every_selinux_type_the_engine_names_in_go_is_declared(self):
        repo = os.path.normpath(os.path.join(HERE, "..", ".."))
        # Assembly archives the sources without a Git index. Inspect the tree being tested.
        types = set()
        for source in Path(repo).rglob("*.go"):
            if source.is_file() and not source.name.endswith("_test.go"):
                types.update(re.findall(r'"(olivares_[a-z_]+_t)"', source.read_text(encoding="utf-8")))
        self.assertLessEqual({"olivares_gitpub_t", "olivares_git_import_t", "olivares_portal_key_t"}, types,
                             "production Go sources must name the engine's SELinux types")
        with open(os.path.join(HERE, "olivares.te"), encoding="utf-8") as f:
            declared = set(re.findall(r"(?m)^type (olivares_[a-z_]+_t)(?:, [^;]+)?;$", f.read()))
        self.assertEqual(sorted(types - declared), [], "every SELinux type named in production Go is declared")


class AssembledGoTypes(unittest.TestCase):
    def test_untracked_go_sources_are_checked_without_an_index(self):
        with tempfile.TemporaryDirectory() as tmp:
            here = os.path.join(tmp, "appliance", "selinux")
            os.makedirs(here)
            types = ("olivares_gitpub_t", "olivares_git_import_t", "olivares_portal_key_t")
            with open(os.path.join(tmp, "engine.go"), "w", encoding="utf-8") as f:
                f.write("\n".join('var _ = "' + name + '"' for name in types))
            with open(os.path.join(tmp, "engine_test.go"), "w", encoding="utf-8") as f:
                f.write('var _ = "olivares_test_only_t"')
            os.makedirs(os.path.join(tmp, "not_a_file.go"))
            policy = os.path.join(here, "olivares.te")
            with open(policy, "w", encoding="utf-8") as f:
                f.write("\n".join("type " + name + ";" for name in types))
            check = CommittedModule("test_every_selinux_type_the_engine_names_in_go_is_declared")
            with patch.dict(globals(), HERE=here):
                check.test_every_selinux_type_the_engine_names_in_go_is_declared()
                with open(os.path.join(tmp, "extra.go"), "w", encoding="utf-8") as f:
                    f.write('var _ = "olivares_undeclared_t"')
                with self.assertRaisesRegex(AssertionError, "olivares_undeclared_t"):
                    check.test_every_selinux_type_the_engine_names_in_go_is_declared()

    def test_no_go_types_is_an_assertion_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            here = os.path.join(tmp, "appliance", "selinux")
            os.makedirs(here)
            check = CommittedModule("test_every_selinux_type_the_engine_names_in_go_is_declared")
            with patch.dict(globals(), HERE=here):
                with self.assertRaisesRegex(AssertionError, "production Go sources"):
                    check.test_every_selinux_type_the_engine_names_in_go_is_declared()


if __name__ == "__main__":
    unittest.main()
