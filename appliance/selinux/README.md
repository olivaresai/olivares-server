# The appliance's SELinux policy module

The AlmaLinux appliance runs with SELinux enforcing and the targeted policy. This directory holds the policy module
`olivares` that confines the appliance's own services, and the package `olivares-selinux` that installs it.

## What it confines

| Domain | Runs | Started by |
|---|---|---|
| `olivares_portal_t` | the Appliance Console (`olivares-portal.service`) | its socket, `olivares-portal.socket` |
| `olivares_repair_console_t` | the repair console on tty1 | PID 1 |
| `olivares_helper_power_t` | the power helper, one instance per connection | `olivares-helper-power.socket` |
| `olivares_helper_bundle_t` | the support-bundle helper, one instance per connection | `olivares-helper-support-bundle.socket` |
| `olivares_snapshotcore_t` | the return-point observe, good, verify and excluded-state guard units | PID 1 |
| `olivares_firstboot_t` | first boot and its readiness unit | PID 1 |
| `olivares_portal_pam_t` | one native PAM Authenticate/Account transaction on a systemd-accepted Unix connection | `olivares-portal-pam.socket`, fixed per-connection template |
| `olivares_t` | the product engine (`olivares.service`) | PID 1, enabled by first boot |
| `olivares_tool_t` | an AI tool the engine installed (`/var/lib/olivares/tools`), in a session, a sign-in or an install probe | the engine's confine helper, by its exec of the tool |
| `olivares_cmd_t` | a shell or generic program (`bin_t`, `shell_exec_t`) such a tool runs: its Bash tool and the programs it calls; and the `git` the engine runs for session Git and worktree sessions | the tool's exec of the program; the engine's exec of `git` |
| `olivares_hook_t` | Claude Code's PEP hook, `olivares claude-hook`: it reads the tool call, resolves the paths it names and asks the engine's PEP | the command domain's exec of `/usr/bin/olivares` (the hook line runs through `sh`) |
| `olivares_cli_t` | `olivares-appliance`, the local API's command-line and terminal client | an operator's SSH login, through one base-policy interface call |
| `olivares_net_guard_t` | the network guard (`olivares-net-guard.service`), NetworkManager's sole writer, and its root runtime initializer | its socket, `olivares-net-guard.socket`; `olivares-network-runtime.service` |
| `olivares_helper_netrestore_t` | netrestore, root's restoration of the baseline keyfile, one instance per connection | `olivares-helper-netrestore.socket` |
| `olivares_helper_netprobe_t` | netprobe, the unprivileged network probe, one instance per connection | `olivares-helper-netprobe.socket` |
| `olivares_helper_apps_t` | the optional apps helper, one instance per connection; it runs the fixed `/usr/bin/docker` Compose project of Nginx Proxy Manager against the local daemon's socket | `olivares-helper-apps.socket` |

Every unit's program has its own entry type, so no appliance service runs in a catch-all domain. The booted-root
capture runs in the initrd, before the policy is loaded. The module adds no permissive domain and one boolean,
`olivares_operate_runtime`, off by default: it lets the product run a conducted runtime that needs executable
memory, and is set with the Operate drop-in.

The network guard talks to NetworkManager over its own system-bus connection and is the only domain that
changes profiles, through NetworkManager's methods; it writes no keyfile. netrestore, admitted for the guard and the
repair console, alone removes NetworkManager's runtime shadow keyfile and asks for a reload; it reads the guard's
journal and writes only root's ledger in `/run/olivares-netrestore`. First boot's cloud-init host-owner drop-in has its
own type, so first boot writes no other file in `/etc`.

The optional apps helper reaches the container runtime through its socket (`/run/docker.sock`, `container_var_run_t`,
the daemon `container_runtime_t`) and runs the Docker client and its Compose plugin (`container_runtime_exec_t`) in its own
domain, with no transition into the daemon's domain. Access to the daemon's socket is root-equivalent on the host,
so this domain does not contain a helper that runs something other than its fixed argv: the helper's fixed
commands, its admission of the Appliance Console alone and the closed manifest are what limit it. It owns `/var/lib/olivares-apps` (`olivares_helper_apps_var_lib_t`),
where the Compose project and the Docker account directory live. The host's Docker daemon must run with `"selinux-enabled": true` in
`/etc/docker/daemon.json`, so the app's container runs confined as `container_t`, and the app's manifest asks for
`bind: {selinux: z}` on its two folders: the runtime relabels `data` and `letsencrypt` to `container_file_t` the
first time it creates the container, which is the only way the confined container can write them. The long form of
the mount with `create_host_path: false` sends the mount through an API that cannot relabel, so the manifest does not
carry it. The label is the shared `z`, not the private `Z`: `Z` adds categories that belong to one container, and the
certificate helper reads the certificate from outside the container (the helper has no domain of its own yet, and the
read of a categorized file has not been measured), so the shared label is kept until that read is measured. A relabel of the tree that puts `data` and `letsencrypt` back to the helper's type stops a running container
from writing until it starts again: the runtime relabels the folders each time the container starts.

Every Go program reads its cgroup limits and the huge page size before `main`, whatever domain it runs in: each
domain holds `search` on `cgroup_t` directories and `open read` on the `sysfs_t` huge page file (`GORT-*`; the apps
helper's are HAPP-35 and HAPP-36 and the storage helper's huge page read is HSTO-31). `getattr` was never asked for. A
program that runs directly in the system slice or in a login session, where the cpu controller is on, also reads
`cpu.max` of its cgroup: the portal, the repair console, the network guard, first boot, the engine, the CLI and the
firewall helper (whose program also runs as `olivares-firewall.service` and `olivares-firewall-guard.service`) hold that
read too. A helper instance sits in its template's slice, which has no `cpu.max`, so the other helpers do not hold it.
`test_manifest.py` requires exactly the first two reads of every domain with an entry point except the snapshot core,
whose program is not in this tree (the test fails when it appears), and names the seven domains of the third. The grants
are as narrow as the base policy's types let them be, which is wider than the files: `cgroup_t` labels every cgroup
control file, so the seven can also read, for example, `cgroup.procs` and `memory.stat`, and `sysfs_t` every sysfs file
that has no type of its own. A module cannot type one file, and `dontaudit` is refused by the generator.

The portal's local API listens on `/run/olivares-portal-api/local.sock`. Its one admitted caller domain is
`olivares_cli_t`: only that domain may connect. Separately, the portal reads `/proc/<pid>/cgroup` of the held
native PAM worker and engine for outbound peer attestation; neither gains local API admission.
The module declares the CLI domain and its entry type with `application_domain`.
An operator's SSH login (root, through sudo) runs in the base policy's default login domain, and the module
enters the CLI's domain from it through exactly one call of the base policy's interface for that domain, row CLI-16, written
inside `optional_policy`. That call is the only place the module names the login domain: the generator refuses any
other such term, a raw row of the call's rules, and the call with other arguments. A copy of the program with another
label stays in the login domain, and the portal refuses it. The portal's writable state is the operations leaf
`/var/lib/olivares-portal/operations` of the static `olivares-portal` account (never `/var/lib/private`); its parent
is searchable only, and the portal holds `/run/olivares-lifecycle/lifecycle.lock` read-only and shared.

An installed AI tool runs in `olivares_tool_t`. It executes its own program (`olivares_tool_exec_t`), keeps its state
in its account's home (`/var/lib/olivares/accounts`, `olivares_tool_home_t`), works in its session's folder
(`olivares_workspace_t`) and uses a TMPDIR the engine makes for it under `/var/lib/olivares/tool-tmp` (`olivares_tmp_t`).
Claude Code's installed program alone has `olivares_tool_claude_exec_t`: it is the only installed program the tool domain
may re-execute without a transition, and both native and container-relay entry still select `olivares_tool_t`.
It reaches the engine's egress proxy over loopback TCP, never one of the engine's own sockets, and it reads nothing in
`/etc/olivares` or the engine's data. The engine's own scratch in `/tmp` (the egress proxy's socket, signature checks,
DR restores) has a type of its own, `olivares_engine_tmp_t`, which no tool rule names. A shell or generic program the
tool starts runs in `olivares_cmd_t`: it works in the session's folder and the TMPDIR, may run what it builds there,
and reads none of the account's login files; it never enters the tool's domain again. A command may enter only the native
or in-container hook domain, and only by running that hook's engine entrypoint: Claude Code's PEP hook reads names and links
in the session's folder and TMPDIR, never a file's contents, and makes one TCP connection to the PEP. Limits of this release:

- Native sessions and provider accounts are not separated from each other by SELinux: every native tool runs in the one
  domain, so their separation is the confine helper's (Landlock and the session's own folder). Container sessions are
  MCS-constrained on `container_file_t`: one container's tool, command and hook cannot read or change another
  container's labelled files.
- The image ships no `git`, so a session's commands cannot use it until it is installed.
- The tool and its commands share the session's folder and the TMPDIR, so a command (a repository's build script) can
  write files the tool later loads in its own domain, such as its configuration or plugins. The command domain keeps a
  command itself off the account's login files; it does not keep the tool from loading what a command wrote.
- The hook domain may connect to an ephemeral-range port on any host, not only the PEP's: the PEP listens on a port the
  kernel chooses, and SELinux checks a port's label, not its address. Only `/usr/bin/olivares` runs in that domain; in
  it the program refuses every command but `olivares claude-hook` before it runs, and claude-hook refuses an endpoint
  off loopback before it dials (both exit 2). An unreadable SELinux context denies every other command too, and the
  hook client follows neither redirects nor environment proxies, so only a compromised `olivares` binary could reach
  a remote port. A file-labeled endpoint (a unix socket) would close it in the policy.
- The engine may run the Docker client the image ships for `isolation=container` (DOCK-01..04), and its user is in the
  docker group so the client reaches the daemon's socket (config.sh). Both are root-equivalent on the host: rootful
  Docker runs what the engine asks as root. A rootless runtime for container sessions would close it.
- A session's container runs in the tool's own domain (`--security-opt label=type:olivares_tool_t`, CTR-01..05), with
  the native session's Olivares rules plus only measured image-file access, not upstream `container_domain` or
  `svirt_sandbox_domain` rules. Its tool, command and in-container hook are MCS-constrained. Olivares-labelled tool and
  workspace mounts keep their types (`NoRelabel`), so a container session cannot take them from native sessions; other
  paths get the container's labels. Plain `container_t` gets no access to accounts' files or workspaces and cannot enter
  the hook domain (N-CONTAINER-HOME, N-CONTAINER-WORKSPACE, N-CHOOK-CONTAINER-ENTRY). The daemon that starts it is
  rootful Docker, outside this policy: the ceiling stays DOCK-04's.
- A local MCP server's test probe runs from the engine with its folder in the engine's `/tmp` scratch, not in the tool
  or command domain, so it is not covered by these rules.
- An upgrade does not relabel the folders the engine made before the policy knew them. After upgrading from a release
  without these types, run `restorecon -RF /var/lib/olivares`.
- A workspace registered outside `/var/lib/olivares/workspaces` keeps its own label, which the tool domain cannot use.
  Label it once: `semanage fcontext -a -t olivares_workspace_t '<folder>(/.*)?'` and `restorecon -RF <folder>`.

## Files

- `access.tsv`: one row per rule, with its id, the rule and its reason; one `interface` row is the module's single
  the base policy interface call (its source and target are the two arguments, its perms column the interface's name). `contexts.tsv`: one row per file or port
  context, with how the module declares the type and the type the base policy gives the path or port without the module.
- `generate.py`: writes `olivares.te`, `olivares.fc` and `olivares.if` from the two tables. The three are committed and
  never edited by hand; `generate.py --check` compares them.
- `olivares-selinux.spec`: the noarch package, built with the devel Makefile of selinux-policy-devel and installed at priority 200
  by the `selinux-policy` RPM macros. On the first install it records the seven ports in one `semanage import`:
  `port -m` for 8443, which the base policy holds as an exact record in `http_port_t`, and for the local model runtimes'
  1234, 8000 and 8080 (exact records in `monopd_port_t`, `soundd_port_t` and `http_cache_port_t`); `port -a` for 8444, 9443
  and 11434, which the base policy covers only by a range (its unreserved range, `pki_ca_port_t`'s 9443-9447). An upgrade
  adds any of the seven that is missing. On erase it deletes them before the module leaves. A failed import is named on stderr and the
  scriptlet still exits 0. It requires `container-selinux`, which defines the container runtime types the apps helper's
  rows name (`selinux-policy-targeted` has none of them); without it `semodule` refuses the module at the first
  unresolved type and `semanage` then calls `olivares_grpc_port_t` "not a port type".
- Local model runtimes: a session bound to a provider on a loopback address relays to it from the session's own network,
  which needs the provider's port to be one the engine may bind. The policy labels the local model runtimes' default
  ports `olivares_model_runtime_port_t`: 11434 (Ollama), 1234 (LM Studio), 8000 (vLLM) and 8080 (llama.cpp's
  `llama-server`). A runtime on any other port is refused until the administrator labels it, and the session's error
  names the command: `semanage port -a -t olivares_model_runtime_port_t -p tcp <port>` (`port -m` if the base policy
  already labels that port, as `semanage port -l | grep -w <port>` shows). No unreserved port is bindable by default.
- `denied.tsv`: accesses the compiled policy must not grant, at least one per domain. A row may name the one boolean
  state it is allowed in (`allowed_when`): the engine's executable memory only with `olivares_operate_runtime=true`.
- `expected-denials.tsv`: the refusals of `denied.tsv` a supported journey reaches, which stay audited: Claude Code's
  shell snapshot (N-CMD-HOME-WRITE). The enforcing qualification excuses an AVC only when its source type, target
  type, class, permission and name equal a row there, and fails on any other; `test_manifest.py` ties each row to its
  deny row.
- `compare_rules.py`: the hosted check that the compiled module holds exactly the rows, and that the installed policy
  grants every row and none of `denied.tsv` in the policy's defaults or with a boolean the module declares at true or
  at false; conditional rules count where their condition puts them in force. SETools walks the policy once per rule
  kind and each source takes its rules from that walk, with indirect attribute matching preserved. The workflow bounds the installed-policy step to four
  minutes, reports its duration and fails with a diagnostic on timeout; the job limit remains 30 minutes.
- `manifest.tsv`: the accesses the enforcing image must show, each with its source line, domain, path, class,
  permissions, the label the base policy gives the path and the rows that hold it, and the accesses it must refuse.
  `test_manifest.py` holds it against the tables.
- `recipe-pins.json`: the image recipe's container digest and selinux-policy build (the lock's URL and sha256), which the image workflow must use
  (this repository holds no image workflow).

## Changing a rule

1. Edit the row in `access.tsv` (or `contexts.tsv`); its reason names what in the product needs it.
2. Run `python3 appliance/selinux/generate.py` and `python3 -m unittest discover -s appliance/selinux -p 'test_*.py'`.
3. Commit the tables and the three generated files together.

The generator refuses a permissive or unconfined term, a wildcard permission, an execution of `bin_t` or
`shell_exec_t`, and a module type nothing declares. The SELinux workflow, which this repository does not hold, compiles the module in an AlmaLinux 10
container, runs SELint, compares the compiled rules with the rows, builds and installs the package, and erases it.

The firewall owner's fixed nft child reads interface indices over `NETLINK_ROUTE` for the index-based loopback
rule, both on load and table readback. Its own route socket permits the `RTM_GETLINK` query through `nlmsg_read`;
socket `write` sends that query, while `nlmsg_write` and `nlmsg` remain denied. It cannot change links, addresses
or routes. The fixed nft arguments, rules, `NoNewPrivileges` and sole `CAP_NET_ADMIN` bound remain unchanged.

The native PAM worker alone reads the host shadow data; portal, engine and CLI gain no shadow access.
Its fixed AF_UNIX socket uses the existing helper parent and group for DAC only. Native kernel UID/pidfd/cgroup
and the current system-unit MainPID select and attest each side; read-only systemctl runs in the caller domain,
with only status on the fixed peer units. Only the root worker has CAP_DAC_READ_SEARCH for the distribution's mode0000
shadow; NoNewPrivileges remains on. The base policy's native reader assertion accompanies its explicit read-only rule.
pam_unix also executes its existing unix_chkpwd in that same worker domain. The fixed chkpwd executable
alone receives execute_no_trans; no helper domain transition, NNP exception or capability gain is permitted.
No unit start/stop, DAC write capability, ptrace or private engine-file access is added.
The installed enforcing AlmaLinux PAM/Account and browser/CLI journey remain required; table checks are source proof.

The engine reads native passwd/group data for the fixed worker socket custody check; this supplies DAC metadata,
never product authority. Its shadow access remains denied.

The engine receives one original accepted portal socket for kernel peer provenance. Linux requires read/write
permission on an O_RDWR descriptor at SCM_RIGHTS receipt; the native consumer only observes peer metadata and
closes the descriptor, never reads, writes or shuts down its stream. No engine connect/bind/create permission is added.

The existing engine receives its sole named authority listener from the fixed root-owned systemd socket.
Only the portal broker connects; both peers use held UID/pidfd/current MainPID/cgroup, and the engine checks
the original accepted socket independently. Readonly process cgroup and fixed unit status are transport
attestation, never identity from a group. CLI and PAM cannot connect to the authority endpoint; the engine
retains its private database boundary. The installed enforcing browser/CLI/current-authority journey remains required.

## The base policy

The module is built and checked against AlmaLinux 10's `selinux-policy` 42.1.18 (the build the image recipe's lock pins),
which is RHEL 10's policy source rebuilt. Measured on 42.1.18-4.el10_2.4 (2026-10-17): the module compiles with the
`selinux-policy-devel` Makefile, links into the targeted store at priority 200, `compare_rules.py policy` passes (664 rows and
80 denied accesses, 0 failures), the four port records need the same `semanage` operations (8443 is an exact `http_port_t`
record, 9443 lies in `pki_ca_port_t`'s 9443-9447, 8444 and 11434 only in the unreserved range), and every label the
manifest expects of a path that the base policy labels is the label `matchpathcon` gives on the shipped `file_contexts`. One
access is new: the image does not install systemd-resolved, NetworkManager writes `resolv.conf` (a link into `/run/NetworkManager`
when it makes the file, the target `net_conf_t` like the link), and row PROD-41 lets the engine search that directory.
