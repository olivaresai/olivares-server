<!-- SPDX-FileCopyrightText: 2026 Olivares.AI -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Appliance answers

The offline answers tool validates one document and describes the work needed for
a Community installation. It does not install or configure the machine. A valid
plan has `state: planned`, `executable: false`, and pending prerequisites; it does
not establish that cloud-init completed or that Olivares is ready.

In this repository run a task as `task -d . -t appliance/Taskfile.yml appliance:build:answers`; a composed build includes
that file from its own Taskfile, where `task appliance:build:answers` works as written.

Build with `task appliance:build:answers`, then run:

```sh
bin/appliance-answers validate --input appliance/answers/testdata/cloud-init.json
bin/appliance-answers plan --input appliance/answers/testdata/cloud-init.json
cat appliance/answers/testdata/cloud-init.json | bin/appliance-answers plan --input -
```

Select exactly one file or stdin. Multiple inputs and repeated `--input` options
are refused. The tool does not discover, merge or ingest NoCloud, guestinfo,
systemd credentials or assistant state. The document's `source` labels asserted
provenance only; it does not verify a carrier or assign host authority.

Exit 0 means valid answers or successfully emitted plan; 1 means refused answers;
2 means usage, input or output failure. Successful output goes to stdout and
diagnostics to stderr. Diagnostics identify a schema path and reason, without
echoing submitted values or unknown field names. No apply command exists.

## Document contract

Every field below is required. There are no implicit deployment defaults. Unknown
fields, duplicate object keys, nulls, wrong types and extra JSON documents fail.
Input must be UTF-8 and at most 64 KiB; nesting is bounded to eight levels and
arrays to sixteen entries, with narrower limits below. Objects use exact field
names. Values are strings except objects and the two arrays shown in the example.

| Path | Accepted values and meaning |
| --- | --- |
| `schema_version` | `appliance-answers/v1` only. |
| `source` | One of `file`, `nocloud`, `guestinfo`, `systemd-credential`, `local-assistant`; asserted provenance, not discovery. |
| `host.owner` | `cloud-init`, or `local` for an install with no cloud-init seed (the Anaconda images), only with `source` `file` and DHCP: first boot then verifies the hostname, UTC and NetworkManager itself, refuses a cloud-init that can run at boot (its program or an enabled unit, unless disabled) then and at every later verification, and writes nothing under `/etc/cloud`. |
| `host.hostname` | Complete static kernel hostname, 1–64 ASCII bytes with DNS-shaped labels of 1–63 letters/digits/hyphens. No leading/trailing hyphen, trailing dot, localhost or wholly numeric final label; IP addresses and all-digit names are refused. Lowercased in the plan. |
| `host.network.mode` | `dhcp` only; fixed addresses, gateways and DNS settings are not supported in this version. |
| `host.time.timezone` | `UTC` only. |
| `host.time.servers` | Array of 1–8 unique DNS names or unicast IP addresses; no loopback, link-local, multicast, zone identifiers or localhost. Names are lowercased and IPs normalized. |
| `host.administrator` | Optional, and only in a document labelled `source: file`. `deferred`: the installer found no administrator and wrote no SSH key, and first boot creates one on the tty1 console; on the desktop, GDM waits for it and opens at the next boot. `installed`: the installer created the administrator, a wheel member or root with authorized keys, and holds its credentials. |
| `host.ssh_authorized_keys` | Array of 1–16 unique `ssh-ed25519` public keys, or empty when `host.administrator` is present: `deferred`, and no one can sign in over SSH until first boot creates the administrator; `installed`, and the administrator signs in with what the installer gave it. Always empty when `host.owner` is `local`: Olivares applies no SSH key there. Each has exactly the algorithm, one space and its standard base64 SSH wire value; the wire algorithm and 32-byte key length must agree. Options, comments, other algorithms and private keys are refused. |
| `product.storage_profile` | `single-node-prod`, the existing SQLite configuration profile. `eval`, `postgres-prod` and `k8s` are unsupported here. |
| `product.public_console_url` | HTTPS origin: DNS name or unicast IP, optional port 1–65535 and optional trailing slash. No credentials, query, fragment, other path, percent escapes, whitespace, localhost or loopback/link-local/multicast IPs. It is not contacted or resolved. |
| `product.update_channel` | `stable`, `security` or `lts`, the product's existing channels. |
| `product.node_role` | `control` only. Distributed `inference` is not implemented. |

The checked-in [example](answers/testdata/cloud-init.json) uses a synthetic public
SSH key for validation; supply your own public key for installation planning.
The hostname is the complete static kernel value expected after cloud-init,
including any dotted labels. It is not cloud-init's separate FQDN metadata: the
tool neither takes the first label nor truncates a longer name. A future adapter
must compare the complete observed hostname to this normalized value. The console
origin may be a separate DNS name or proxy. Neither is resolved or compared to live
machine settings by this tool.

Only public settings are accepted. Passwords, tokens, private keys and literal
DSNs have no field in this schema. PostgreSQL and protected secret references need
a later extension; the tool does not resolve or hash any secret material.
An error always returns no usable plan.

## Plan contract

`appliance-plan/v1` contains the normalized answers, these ordered operations and
the pending prerequisites. Each operation has state `pending`:

| Owner | Action | Meaning |
| --- | --- | --- |
| `cloud-init` | `wait-for-completion` | A future adapter must observe successful completion of the external host owner. |
| `cloud-init` | `verify-host-settings` | A future adapter must verify declared hostname, network, time and public SSH prerequisites. It must not reapply them. |
| `olivares` | `verify-host-settings` | With `host.owner` `local`, in place of the two cloud-init rows: first boot verifies the hostname, UTC and NetworkManager itself and never changes them. |
| `olivares` | `generate-product-config` | A future adapter must use the product's configuration generator. |
| `olivares` | `initialize-storage` | A future adapter must use the product's initialization mechanism. |

Host/product adapters, instance identities, firewall policy, protected setup-token
delivery and expiry, service start and health are pending. These declarations are
not an executable installation sequence, and no prerequisite has been measured.
Packages, first boot, restart recovery, clone isolation and VM support require
their own implementation and verification.

Canonical JSON has a fixed object order and terminal newline. Object key order in
the input does not affect output. Time-server and SSH-key arrays are sets and are
sorted to detect and reject duplicates. DNS names are lowercased; HTTPS port 443
and the optional trailing slash are omitted. Output preserves the asserted source label.

Go callers use `answers.Build(io.Reader)` followed by `Plan.JSON()`. The module is
in `go.work`, so workspace build/test/vet sweeps include it. Run its bounded tests
with `task appliance:test:answers`. The implementation uses the standard library
and imports no product runtime or host adapter.

## Base package and first boot

`olivares-appliance-base` is the layer every appliance recipe installs beside the
product package (`packaging/nfpm/olivares-appliance-base.yaml`). It installs
`/usr/bin/appliance-firstboot`, `/usr/bin/appliance-answers`, the units
`olivares-appliance-firstboot.service`, `olivares-appliance-readiness.service` and
`olivares-console-certificate.service` (with the drop-in `olivares.service.d/50-console-certificate.conf`
that has the product start it), the console banner `/etc/issue.d/olivares-appliance.issue`, the state directory
`/var/lib/olivares-appliance` and the directory
`/etc/systemd/system/olivares.service.d` for the drop-in first boot writes; its postinstall
creates `/etc/olivares-portal` (root, 0755) when it is missing, for the Appliance Console's
selection. It owns no
path of the product package and recommends `olivares`, `cloud-init` and
`openssh-server` (first boot records the instance's SSH host keys). Installing it
enables the first-boot unit and starts nothing, so it installs into an image root the
same way it installs onto a host. Removing it disables the unit and keeps the
first-boot record, the configuration first boot generated and the product; a
reinstallation enables the unit again if the removal found it enabled.
Build and test with `task appliance:build:firstboot`, `task appliance:package:base`
and `task appliance:test:base`; the image workflow installs the package in
a Debian 13 container with systemd and cloud-init and runs
`appliance/layer/base/fixture/firstboot-battery.sh`. A container is component
evidence: it qualifies no image, hypervisor import, firmware or Secure Boot.

### Ordering and hardening

Debian 13's `cloud-final.service` and `cloud-init.target` are ordered after
`multi-user.target`. The first-boot unit is wanted by `multi-user.target` and runs
after `cloud-final.service`, so it sets `DefaultDependencies=no` and restates a
service's default dependencies: `multi-user.target` does not wait for it, and no
ordering cycle exists. It is not ordered before the product, which only first boot
enables. Both units carry the product unit's hardening directives with the same
values, except `ProtectHome=read-only` (the authorized SSH keys are verified),
`CapabilityBoundingSet=CAP_DAC_READ_SEARCH` (first boot reads other accounts' keys and
the product's data directory as root) and `UMask=0077`; each unit states why. They
may write only `/etc/olivares`, the drop-in directory and `/etc/olivares-portal`.

### The product console on 443

`https://host/` opens the product console as well as `https://host:8443/`. The firewall policy renders one nat row,
`fib daddr type local tcp dport 443 redirect to :8443` in a `prerouting` chain of its table, so the product's one listener
answers on both ports: there is no second listener, no second certificate and nothing new for the input chain to admit.
It matches the host's own addresses only: a container's or a routed client's HTTPS to the internet is forwarded traffic
and passes untouched. The row exists only
while no other row claims 443/tcp, an optional application's (Nginx Proxy Manager publishes 443) or SSH on that port; then
the chain is not rendered, 443 is that row's, the product console stays on 8443, and the Firewall page of the Appliance Console
says so in one line. The owner measures the redirect with the rest of the table: a kernel that did not take it is not the loaded
policy. The deb/rpm package and the container are not the appliance and stay on 8443.

Passkeys work only at the address declared as `product.public_console_url` (the product takes the one WebAuthn origin
from it, port included): with `https://host:8443` a passkey sign-in on `https://host/` fails the origin check, and with
`https://host` it fails on `:8443`. Password sign-in works on both ports.

### The Appliance Console's certificate

The product makes one local CA at its first start and signs :8443 with it. `olivares-console-certificate.service`
signs the Appliance Console's pair (`/etc/olivares-portal/tls.crt` and `tls.key`, the files the console's unit loads
as credentials) with that same CA, so the operator trusts one CA for both consoles: the leaf names the host name,
loopback and every LAN address, as the engine's does. `olivares.service` wants the unit, so it runs at every start of the
product, first boot's start included, and a changed host name or address is re-issued from the same CA and key.
`appliance-firstboot console-certificate` waits for the product's CA (four minutes), makes none, makes the console's
key under a staged name the SELinux policy labels, and exits 0 when the pair was issued or is current. A pair another
CA signed (the operator's, or one made with `olivares-portal-cert generate`) is left as it is, and a
certificate without its key is refused rather than replaced. The unit runs in the first-boot domain and its
SELinux rows are `FBOOT-102` to `FBOOT-104`; no other domain gains the CA key. A refusal fails only this unit, never the product.
The console loads its pair when it starts: a start before the pair exists fails, a re-issued pair reaches a running
console at its next start, and a host without `/etc/olivares-portal` skips the unit.

One CA for both consoles means the CA key, which the product account holds, anchors the Appliance Console's identity
too: whoever reads that key can forge a certificate for either console to a client that trusts the CA. An engine started
with an operator's own `--tls-cert` makes no CA, so this unit finds none, fails after its four minutes at each start
(a console start that is queued behind it waits that long), and the console keeps whatever pair it has.

### Carriers

First boot reads one `appliance-answers/v1` document from these carriers and
refuses, naming them, when present carriers disagree:

| Carrier | Where the document is |
| --- | --- |
| `nocloud` | `/etc/olivares-appliance/carriers/nocloud.json`, written by cloud-init from the NoCloud seed's `write_files` (see `answers/carriers/testdata/nocloud/user-data`, which also sets `fqdn` and `prefer_fqdn_over_hostname` so the kernel hostname is the complete `host.hostname`). |
| `guestinfo` | Property `olivares-appliance-answers`, base64, of the OVF environment in `guestinfo.ovfEnv`, read with `vmtoolsd --cmd`, which first boot runs in its own SELinux domain (`appliance/selinux/README.md`). |
| `systemd-credential` | Credential `olivares.appliance.answers`, imported by the unit from the system credentials (SMBIOS type 11, `systemd.set_credential=` or a container manager). |
| `file` | `/etc/olivares-appliance/answers.json`, written by an operator or the local assistant. |

Carriers are compared by the answers module's canonical plan without the `source`
label, so formatting does not matter and any difference in an answer refuses.
`source` is advisory: it states where the author meant the document to travel, it is
neither compared nor part of the restart digest, and the first-boot record's `source`
names the carrier that actually delivered the answers. Writing one carrier name to
`/etc/olivares-appliance/carrier` selects it explicitly. Every carrier input must be a
regular file owned by root and not writable by group or others; links are refused. A
carrier that is gone at a later boot (a removed SMBIOS credential, for example) leaves
the recorded outcome in place; first boot continues when a carrier is present again.

### Stages and status

`appliance-firstboot apply` runs, under a lock in the state directory, the stages
`validate`, `prepare-identity`, `verify-host-settings`, `generate-product-config`,
`initialize-storage`, `prepare-setup-delivery`, `verify-firewall`, `start-services`
and `measure-readiness`. A stage is recorded as in progress before its effect can
begin, and each completed stage atomically in `/var/lib/olivares-appliance/state.json`;
a later run compares the recorded effect with the host instead of repeating it. The
record's `product_may_have_started`, written with start-services' in-progress record
before the product's start can be queued and never cleared, means the product's store
and keys are this instance's: a later refusal, a carrier read error or a drifted effect
does not turn them into an imported installation. The field is additive within schema
v1; a record written without it derives it when read from start-services in progress or
completed, never from a refusal recorded at start-services. A seam, the
answers loader or the identity inspection that is not installed refuses before any
stage runs. The answers' `host.owner` owns the host settings. With `cloud-init`, first boot waits
for it and verifies the hostname, UTC, the authorized SSH keys and its error-free
completion; with `local` (an install with no cloud-init seed), it verifies the hostname, UTC and
NetworkManager's persistent profiles and refuses an enabled cloud-init. It never applies them. A
`local` host whose installer deferred no administrator is reached only through the accounts the
installer created. The product's own `config generate` writes the
product configuration; the public console address goes to a drop-in the appliance
owns. When the answers declare `portal.enabled`, `portal.listen` or
`host.management_interfaces`, generate-product-config also publishes them, as validated, to
`/etc/olivares-portal/selection.json` (root, 0644), the one file the Appliance Console reads
its selection from, and records its digest; when they declare none, no selection is published
and one left from earlier answers is removed. initialize-storage records the data directory's owner and mode; the product's
first start creates the store, and readiness measures it. First boot never starts the product
until the setup-token delivery and the host firewall are measured, and both seams
refuse by default: the product has no protected setup-token delivery sink yet, and no
firewall owner is selected. Ready requires the product's `/readyz` over this
instance's certificate, polled until it answers ok because the product unit is
`Type=simple` and active before the product has created its files, and then its store
and its identity files: not a `systemctl` exit.

If the firewall cannot measure the SSH port, inspect
`journalctl -u olivares-firewall.service`. The SSH port probe uses OpenSSH 9.3+
configuration-only mode, which validates the native configuration without loading
private host keys. A failed fixed `sshd -G` probe records
its native exit or signal and recognized error categories there. Raw stderr and
configuration paths are withheld; the helper's refusal text and code remain unchanged.
Failed `nft -f -` boot loads use the same journal path for native exit or signal,
recognized error categories, and command-start failures. The journal withholds raw
stderr and ruleset contents; an unrecognized error is reported without its text.

The answers' digest is recorded with the first stage that depends on them,
verify-host-settings. Answers corrected before then simply apply; answers changed
after then are refused. `sudo appliance-firstboot reconcile` is the recovery before
the product starts: it forgets the recorded stages that depend on the answers
(prepare-identity and the instance identity stay), and
`sudo systemctl start olivares-appliance-firstboot.service` runs them again with the
current answers and host, inside the unit, with its credentials and hardening; an
`appliance-firstboot apply` from a shell has neither. The same recovers a stage whose
recorded effect the host no longer matches. Once the product may have started, reconcile refuses and
changes nothing: first boot does not reconfigure a started product.

`appliance-firstboot status` (root: `sudo appliance-firstboot status`) prints the
record and exits 0 when ready, 1 when refused and 2 when pending, applying or
unrecorded. `apply` exits 0 when ready or pending, 1 when refused and 2 when it could
not run; `reconcile` exits 0 when it reconciled, 1 when refused and 2 when it could not
run. A record written by another version (schema other than
`olivares-appliance-firstboot/v1`) is refused by name with exit 1 and never rewritten:
a newer version migrates older records forward, and an older version refuses a newer
record until the newer package is installed again. `appliance-firstboot plan` prints
the plan of the document the carriers deliver, and `appliance-firstboot
check-template ROOT` exits 1 naming every instance identity under an image root (SSH
host keys, machine ID, the product's TLS key, setup token, audit, catalog and policy
signing keys and store, and a first-boot record): an initialized instance is never a
template.

## Backup disks and data growth

On the local Appliance Console's **Storage** page, sign in with a current product
superadministrator session and complete any required step-up. **Use for backups**
shows the selected disk's name and asks for confirmation before erasing it. The
system disk and disks with active consumers cannot be selected. The disk becomes
an ext4 filesystem, mounted by UUID below `/mnt/olivares-backups/` with `nofail`;
the existing backup schedule then uses it. Existing bundles on the original
backup directory remain available. If the disk is absent, backups report a
failure instead of writing into the system volume beneath the mountpoint.

If saving the target fails after formatting, **Finish backup setup** retries the
settings write without formatting again. The nightly schedule, retention and
restore protection settings are preserved.

On images with the recipe-owned appliance profile declaration, increasing the
virtual disk grows its last root partition and btrfs filesystem on the next boot.
**Grow now** performs the same grow-only operation online, including on older
images without that declaration. It preserves the partition start, existing
filesystems and boot partitions; it refuses other layouts and multi-device root
filesystems. The page reports disk, free trailing space and measured data volume
sizes.

## Console sign-in modes

The Appliance Console decides who may ask it for an act from the state of the
appliance, states the mode it is in on every page, and offers nothing that mode
does not offer. It holds no password, hash or credential store of its own.

| Mode | Who authenticates | What is offered |
| --- | --- | --- |
| `product-up` | The product's own identity, with a step-up through the product's existing authorizer. The console asks once and returns the answer unchanged, keeping no decision of its own. | Everything the console has. |
| `product-down-repair` | The host, through the PAM service the layer ships, for a human in the `olivares-admins` local group: who this human is on this host. | The repair verbs only: `apply-update`, `roll-back`, `network`, `certificate`, `support-bundle`, `power`. |
| `unavailable` | Nobody, over the network: the product does not answer and the console's sign-in service cannot be used, or the product's state could not be checked. | Nothing. A product that could not be checked is not assumed down, and the page sends the person to the repair console on tty1. |

That sign-in is never a session identity and never a provider-account identity, and a
step-up in it is a re-authentication, because no policy engine is running to ask. A human
the host does not place in `olivares-admins` is offered nothing, and their credential is
never presented to the host's stack: the group check runs first. Every refusal is one
phrase, because a refusal that names the check it failed is an oracle.

The remaining door is the **Appliance Repair Console on tty1**, and it is designed as
one. It is not a network service, so the failure that closes the console on 9443 cannot
close it. It authenticates its operator by its own sign-in, through the host's local-console
sign-in service, never by access to this machine: access to the console alone authorizes no
act, and the console keeps no credential store of its own. It carries the same repair verbs
and one more, `repair-portal-pam`, which no other surface can carry, because over the network
that stack is what is broken. In this version neither console performs a verb: the console on
9443 offers the verbs and performs none of them, and the repair console's qualified sign-in
is not implemented yet, so `power` refuses like `certificate` and `repair-portal-pam`, states
why, and asks nothing of the power helper (below).

The repair console exits 0 when the operator leaves with `q` or its input ends. It exits 2
on an input or output failure: a read that fails, a line longer than it reads, or output it
cannot write. It then stops and states one fixed sentence on stderr, which its unit sends
to the journal. No selection is refused, so it never exits 1.

Both doors are wired on the network console. The product probe is a request to the product's
`/livez` over loopback, and a refused connection is the only evidence that the product is down:
a timeout or a failed trust check is unmeasured, never "down", so the host's stack is not offered
beside a product that may be answering. While the product answers, the person signs in to the
product (its own sign-in on port 8443; the session cookie is host-scoped, so it reaches 9443 on the
same name), and every request asks the product's `whoami` over loopback once and obeys it. Host
administration needs a product superadministrator whose session meets the deployment's step-up policy
(`step_up_satisfied`, the answer of the product's own `StepUpSatisfied`: nothing by default, an
authenticator code or a passkey when the administrator asks for it). An answer that does not say is
not a step-up met. A caller who is not a superadministrator reads one phrase that names no check; a
superadministrator who has not stepped up is told to complete the step-up in the product console and
reload. While the product is down, `/sign-in` takes an OS account and password for a member of
`olivares-admins` through the native PAM worker (`olivares-portal-pam.socket`) and offers the repair
verbs; the group check runs before any credential reaches the stack. `/sign-in` measures
the mode on every request, and the pages a signed-in superadministrator reads state `product-up`.
The server image enables the tty1 unit: its
`config.sh` links the unit at `multi-user.target` and masks `getty@tty1.service`, which
the unit conflicts with and which logind would otherwise start again on a switch back to
the first virtual console. The unit prints the banner `/run/olivares-banner/issue` each time the
console starts, on a screen it has just cleared, because the login prompt that printed it is gone from tty1.
(agetty reads `/run/issue.d` only when `/etc/issue` does not exist, and both images ship it, so the unit names
the file.) `olivares-tty1-banner.service` writes that file: the packaged text of `/etc/issue.d` plus one
`https://<address>:8443/setup` line for each global IPv4 address of the host, container bridges left out, and the
way to the setup token (`s` to sign in, then `t`). The service runs before each console start and writes only that
file: the console is the only process that writes to tty1, so nothing draws over its prompts. A lease that arrives
later reaches the screen when the operator chooses `q`, which restarts the console with the refreshed file.
It keeps `TTYVTDisallocate=` off, which would wipe the banner after it is printed, and clears the screen again
when the console stops. The address in the banner
is the one the machine has at that moment, so on a first boot that waits for DHCP the
banner printed again after the console restarts is the one to trust. The other consoles
(tty2 to tty6, the serial console) keep their login prompt and the banner. A machine that
has only its tty1 screen has the repair console's verb menu as its only local sign-in. The
desktop image enables the unit only while the administrator is deferred: the installer's marker holds gdm, and the
banner service quits the boot splash that gdm would otherwise quit; from the boot after the console creates the
administrator, tty1 is gdm's. The PAM service
file was measured against a real stack in a container, with real accounts: on Debian 12 and on AlmaLinux 10.2 a
member of `olivares-admins` is authenticated with the right password, an expired member is authenticated and
refused at the account step, and a non-member, a locked password, a wrong password and an unknown login are
refused. Opening a session and the enforcing SELinux host are not covered by it.

## Privileged helpers

Every privileged act leaves the consoles through a closed helper (`layer/helpers`). Each
helper has a socket unit with `Accept=yes` at `/run/olivares-helpers/<name>.sock`, root's and
mode 0600, which starts one helper instance per connection with the connection as its
standard input and output. A helper:

- reads one JSON document of at most 4096 bytes, and refuses a field its schema does not
  name, a null, a repeated key and a second document; it takes no argument but `--help`, and
  no path. Every mutating document carries the `operation_id` its client minted when the
  operator confirmed (128 random bits, 32 lowercase hexadecimal digits), which the helper logs;
  it is not the `request_id` a consumer of an act authorization keeps for itself;
- admits its invoker from the connection alone: the account of the peer's credentials
  (`SO_PEERCRED`), the process the peer's pidfd names (`SO_PEERPIDFD`, Linux 6.5 and later),
  that process's unit, read from its cgroup, and its controlling terminal, both read while the
  pidfd shows it alive. Without a pidfd it refuses every mutating subcommand. A document, an
  argument or the environment never names the invoker. Invokers come from one closed table:
  the repair console on tty1 (root, `olivares-repair-console.service`, `/dev/tty1`), the
  Appliance Console (`olivares-portal`, `olivares-portal.service`) and the network guard
  (`olivares-net-guard`, `olivares-net-guard.service`), which runs as its own static account
  and may invoke the network restore helper alone;
- performs a mutating subcommand only for an invoker it admitted from the pidfd: the appliance's
  own kernel was proven, in a guest, to give each instance its peer's pidfd and to refuse a recycled
  pid (the record is [The guest proof](#the-guest-proof)). Were the proof not recorded, an admitted
  mutation would be refused with `pidfd_unproven`; subcommands that change nothing never wait for it;
- names every file of its spool from a nonce it issued under its own key;
- exits 0 when it performed or answered, 1 when it refused, with no effect, and 2 on a usage,
  setup or input/output failure, with no effect.

| Helper | Runs as | Subcommands | Admitted invokers |
| --- | --- | --- | --- |
| `power` (`olivares-portal-power`) | root (`User=root`), with no capability | `reboot` and `shutdown`: `systemctl reboot` or `systemctl poweroff`, a fixed argument vector, no shell | the repair console on tty1 |
| `support-bundle` (`olivares-portal-support-bundle`) | its static, non-login account (`User=olivares-support-bundle`), whose state directory `/var/lib/olivares-support-bundle` (`StateDirectory=olivares-support-bundle`, 0700) holds its key and its `acts/` and `out/` directories, each 0700; each bundle goes to `out/` | `produce` and `fetch` | none yet: the verb stays unavailable on every surface |
| `apps` (`olivares-portal-apps`, a module helper in `layer/optionalapps`) | root (`User=root`), in the host's network namespace with `CAP_NET_BIND_SERVICE` alone | `status`, `install`, `start`, `stop` and `uninstall` of Nginx Proxy Manager: the fixed Compose project of `layer/optionalapps/nginx-proxy-manager.json`, run with `/usr/bin/docker` against the local daemon's socket and the helper's own empty Docker config | the Appliance Console, as every module helper |

Each helper's service template names its account with `User=`, and none allocates a dynamic
account. Every helper program is installed directly in `/usr/libexec/olivares/`, beside the
consoles. The support-bundle account is static and non-login, with no supplementary group; the
portal package declares it before the helper's unit can start.

Only with a qualified sign-in does the repair console's `power` verb ask the power helper for
`reboot` or `shutdown`, with an operation id it mints for that request, and state what the
helper answered: `performed` means the service manager accepted the request, not that the host
has gone down.
Neither the pidfd proof nor access to the machine replaces the sign-in. The console's
`certificate` and `repair-portal-pam` verbs stay not implemented; each arrives with its own
helper. The consoles reach a helper through `layer/portal/helperclient`,
only on a socket that is root's and not a link: an absent helper is `503
consumer_unavailable` and asks nothing, and a request whose answer was lost is
`outcome_unknown`, never performed. `layer/helpers/polkit/50-olivares-helpers.rules` refuses
the console's account and the support-bundle helper's account every action of the service,
login, disk and package managers, so no act leaves through polkit. `layer/portal/audit` is the
console's append-only audit spool: records wait there while the product's ledger cannot take
them and are ingested once.

### The guest proof

`guestProven` (`layer/helpers/invocation/serve.go`) records that the appliance's own kernel gives each per-connection
helper instance its peer's pidfd and that a recycled pid is refused. `test/guestproof/run.sh` measures it; it is not
shipped, and it runs as root in a disposable AlmaLinux guest only. It installs the units helper's real socket and service
units (`Accept=yes`, one instance per connection), the console's real local socket unit and its sysusers and tmpfiles
files, and two builds of the helper that differ in that constant alone. The console in the guest is the real local
session server (`localsession.OpenWithPackages`, the helper client, the audit spool) with one stand-in, the product's
identity owner, which authorizes the services verb on a unit target and nothing else.

Measured on 2026-10-23, under KVM, on the AlmaLinux 10.2 GenericCloud image pinned in `test/network/image.json` (sha256
`cbee4726fc0f5a60694bb4f289003cc221e715dfbacebcce76b54daf386d8eca`), kernel `6.12.0-211.64.1.el10_2.x86_64`, systemd
`257-23.el10_2.2.alma.1`, SELinux enforcing: 69 lines `PASS` and none `FAIL` on each of three fresh boots.

- Each instance receives its peer's pidfd. With the helper built before the proof, the console's own unit
  (`olivares-portal.service`, account `olivares-portal`) is refused `pidfd_unproven` only after the instance's journal says
  it admitted the connection from the pidfd (`unit "olivares-portal.service" ... attested`). Root in another system unit
  and the console's account in another unit are `not_admitted`; root in a login session, which no system unit names, has no
  connection identity (`no_connection_identity`).
- A recycled pid is refused. A client opens a connection and exits; a process of the same admitted unit then holds the
  client's pid number (with `kernel.pid_max` lowered so that the number comes round), and `/proc/<pid>/cgroup` names
  `olivares-portal.service`; the instance, which looks only then, answers `attested false: start refused:
  no_connection_identity` and runs nothing. The control without the recycling is refused the same way.
- With the helper built after the proof the admitted invoker's `start` is `performed`, and the services acts run end to
  end through the real `olivares-appliance` command line and the console's local session: `start` of both update units (with
  `succeeded` receipts), `stop`, `start`, `disable` and `enable` of `dnf-automatic-install.timer` (each measured before and
  afterwards with `systemctl`), `logs` with its default 100 entries, which the console takes whole although they are larger
  than a frame, a confirmation of another act's plan refused, a replayed operation id run once, a protected unit refused by
  the class table before any dial, the durable operation records and the audit spool written, and none of the journal's text
  in either.

What it does not measure: the helpers' own SELinux domains (the guest has no appliance policy), the product's sign-in, the
update units' real bodies (the proof replaces their `ExecStart` with a line in the journal, and `dnf-automatic` is the
guest's own package) and the built appliance image's boot (`test/boot-battery.sh`). Rerun it on a new guest with the files
listed in the script's header; its last line counts the lines and its exit code is 1 on a `FAIL`.

### Host-package plan

The Appliance Console offers `host-package update` and `host-package recover` only when a plan is retained in
`/var/lib/olivares-package-plan`, root's and private. `olivares-package-retain.service` is the one writer of it. A trusted
source (the entitled channel) leaves three files in `/var/lib/olivares-package-delivery`, root's and private, then starts the
unit as root: `previous.rpm` (the installed version), `next.rpm`, and `delivery.json`
(`{"schema": "olivares-package-delivery/v1", "previous": {...}, "next": {...}}`, each side the package's `Name`, `NEVRA`,
`Repository` and `SHA256`). The program fetches nothing and takes no argument. It copies the files into the plan directory
and prepares the plan (`updates.RPM.Retain`): both files must match their SHA-256, carry a signature the preinstalled key
verifies and name the stated NEVRA; the installed package must be the previous one; and `rpm -U --test` must show that
installing the next one replaces it and needs nothing else (no dependency, no conflict, no kernel or other installonly
package, no obsoleted package). Any refusal removes what it copied, and so does a plan.json that is empty or cut short, so
the next try starts empty. A retained plan is never replaced by another pair (`plan_exists`): its previous RPM is the
recovery of an update that may have run. The same pair again loads the plan and succeeds, so a start whose console restart
failed is run again. A lock on the directory refuses a second retention at once (`retention_running`); start the unit, which
systemd also runs once at a time.

The unit then restarts the console, which composes its package tasks once, when its local listener opens. An update runs
`rpm -U` of the retained file in the helper (`olivares-helper-apt@.service`), and its confinement is the measured set in
that unit's header. The guest proof (above) is recorded, so an admitted act reaches the helper's own checks.

Which packages may be delivered is the delivery source's decision: Retain checks that the package is signed by a key the host
trusts, is the installed one's successor and replaces nothing else, and the administrator confirms the exact change in the
console; it keeps no list of names. The source must therefore be root's alone.

Not there yet: nothing delivers the three files (the entitled channel's package delivery is not built yet, and
the unit is started by hand until then), and a plan is retired by no code, so a second update waits for that owner.

### Updates and activation

`/updates` is the Appliance Console's one page for what changes the appliance over time. It is served to a signed-in
human superadministrator on any host, and it names state words and the update units alone: no interface, address,
disk or mount point.

| Part | What it shows | Where it reads |
| --- | --- | --- |
| Edition and licence | The build (Community or Business), the licence status, licensee, plan and expiry, and the one next step. | The product's own `GET /v1/console/license`, under the caller's session. An answer the page does not know is shown as unread. |
| Product updates | `olivares-entitled-repo.service` (the channel's refresh) and `olivares-appliance-update.service` (the update). | The console's last read of the units helper. A unit that is not loaded is idle: the service manager unloads a unit that finished without failing and keeps a failed one. |
| AlmaLinux updates | `dnf-automatic-install.timer` and its run, and the policy: security advisories of the AlmaLinux repositories only, applied by default, the Olivares packages left out, reboot only when needed, in the timer's nightly window. | The same read, and the image's policy (`images/kiwi`). |

Activation is the one act the page carries, because the product, not the console, decides it. The form posts the
licence to `/updates/licence`, which relays it to the product's `POST /v1/console/license` under the caller's browser
session and nothing else: fixed route, method and body; the CSRF token the product derives for that session
(`/v1/auth/browser-session`), which the product checks again; no bearer credential; the product's own superadministrator
gate and step-up. The console records the intent before it asks and the outcome after (`host-updates.activate`), never
the licence, and shows the product's answer by its status, never by its text. A caller without a browser session gets no
form and is told the command line: `olivares license install`.

Applying an update is not carried by the web page: each unit act is one operation with its own act authorization, plan and
confirmation, which the console's command line carries, so the page names `olivares-appliance service <verb> <unit>` for
each act. Run alone, the command shows the act's plan, its digest and the command that confirms it; with `--confirm <digest>`
it performs the act through the console and prints the receipt. `logs` also prints the entries it read, which the console
holds in memory under the act's operation id for the session that asked, for at most two minutes and until they have been
collected whole, and never writes to the receipt, the operation record or the audit spool. The sequence on an appliance is: activate the licence (the entitled channel is refreshed at once and every six
hours), then `olivares-appliance service start olivares-appliance-update.service` for the product, and
`olivares-appliance service start dnf-automatic-install.service` for the operating system's security updates when you do not
want to wait for the window; that run reboots the host a minute after it when an update needs it, as the nightly one does.
Both units are oneshot services, so their start is reached when its job finished done and the unit exited cleanly; a run
longer than the helper's 100 s wait for its job stays `unknown`, and `olivares-appliance service logs <unit>` and
`dnf history` tell what it did. When the channel offers a newer Olivares package, the update first stops the product and
takes a read-only btrfs snapshot of `/var/lib/olivares` (the last three are kept; see docs/UPGRADE-AND-ROLLBACK.md), and
with the data volume 95% full or more it refuses before the package manager starts. It keeps the Olivares packages it
replaces beside that snapshot, and `olivares-appliance service start olivares-appliance-rollback.service` (or
`olivares upgrade rollback`) returns the product to both: see docs/UPGRADE-AND-ROLLBACK.md.
The timer has four acts because its verbs differ: `stop` and `start` act now, and `disable` and `enable` only decide
whether it starts at boot, so `disable` alone leaves tonight's run in place.
Stopping `olivares-appliance-update.service` while it runs asks the package manager to finish or unwind (it gets ten
minutes) and starts a product the update stopped, so read `dnf history` and `rpm -Va` afterwards.

### Optional apps

Nginx Proxy Manager is the one optional app. Its manifest, `layer/optionalapps/nginx-proxy-manager.json`, is
the single source of the image (pinned by digest), the container, its volumes, its network and its ports; no
document names an image, a folder or a port. The Appliance Console serves four acts for it (`install`, `start`,
`stop`, `uninstall`, all `product-up`, each with a confirmation) and asks the apps helper for its state first.
Install pulls the pinned image and starts the project; uninstall removes the container and keeps the data and
certificates in `/var/lib/olivares-apps/nginx-proxy-manager`. The app's admin listener is published on loopback
only, and installing the app opens no port: its public ports (80 and 443) are rows of the firewall policy. Its 443 row
is what ends the redirect of 443 to the product console (see "The product console on 443").

The rows are the firewall's `app-row` act, which the Appliance Console adopts:
`olivares-appliance firewall app-row nginx-proxy-manager add --plan` prints the plan and its digest, and
`... add --confirm <digest>` submits it once (`remove` takes the rows away). The rows come from the manifest
alone: each port it publishes beyond loopback, on every interface, and the bridge its network is made with
(`olv-npm`). The owner loads them, reads the table back and confirms them in the same act; a load that is not
confirmed reverts at its deadline and is recorded as partial. Docker publishes a port by rewriting the destination
before the filter, so the port's traffic is forwarded traffic, and the app's own traffic (an ACME authority, DNS,
the hosts it proxies to) leaves as forwarded traffic too. A row therefore also admits, in the forward chain, the
connections the rewrite marked whose original port is the row's, and lets the app's bridge send traffic out; the
chain still admits replies and nothing else. The bridge's traffic may go to any destination, because the forward
chain filters nothing by destination. A packet from the bridge to the host is input traffic, and the input chain
admits SSH and the product's ports (8443 and 8444) on every interface, the app's container included, besides the
app's own 80 and 443; no other port of the host is open to it. The firewall helper accepts an apply only as one
application's own act with exactly the rows its manifest gives, or none, so a console process cannot ask it for
another policy, a port or a bridge of its choosing.

The helper needs Docker with the Compose plugin on the host, and the Docker daemon must run with SELinux support
(`"selinux-enabled": true` in `/etc/docker/daemon.json`) so that the container is confined as `container_t`; the
manifest asks the runtime to relabel the app's two folders (`selinux/README.md` says how, and why not the long
form). Without the daemon the app is unavailable and nothing is asked.

What is not there yet, so that nothing here reads as more than it is:

- The AlmaLinux images (both editions) carry the container runtime. The set that runs the app, measured on
  AlmaLinux 10.2 (kernel 6.12.0-211.64.1, selinux-policy 42.1.18-4.el10_2.4), is `docker-ce`, `docker-ce-cli`,
  `containerd.io` and `docker-compose-plugin` from Docker's `rhel/10` repository, with `container-selinux`,
  `iptables-nft` and `nftables` from AlmaLinux and `kernel-modules-extra` for the kernel in the image: Docker's
  iptables backend needs `xt_addrtype`, which the kernel's own modules package does not carry. The image reads no
  Docker repository: `images/toolchain/almalinux10/input-lock.json` (`container_runtime`) pins each of Docker's four
  RPMs by sha256 and size and Docker's release key by fingerprint, the stage step downloads exactly those files into
  the per-build repository and checks their signatures, and the SBOM and the source bundle name them. `config.sh`
  writes `/etc/docker/daemon.json` with `"selinux-enabled": true` and links `docker.service`; `images.sh` fails the
  build when the daemon, the Compose plugin or `xt_addrtype` is missing. Docker's updates reach a host with the next
  image, not through a Docker repository on the host. The relock of the AlmaLinux pins does not move Docker's: a newer
  Docker is a reviewed edit of `container_runtime` (version, sha256, size, upstream commit), made in the change that
  ships it. Docker's RPMs also carry components of their own (runc, `docker-init`, rootlesskit) under permissive
  licenses: the lock pins the RPMs, not those components' sources. The daemon starts on every boot with Docker's own
  defaults for the `docker0` bridge (172.17.0.0/16) and for log size; the image sets only `selinux-enabled`.
- Every mutating helper act waited for the guest proof above. The measurements in this section were made on an
  AlmaLinux 10.2 guest with that proof's flag set in a lab build of the helpers; the kernel gave each instance its
  peer's pidfd and the console was admitted from it. The proof is now recorded, and the flag is the repository's.
- A relabel of `/var/lib/olivares-apps` (`restorecon -R`) puts the data and certificates folders back to the
  helper's SELinux type, and a running container cannot write them until it starts again: the runtime relabels
  them each time the container starts (measured: after `restorecon` and `docker restart` the admin listener answers
  and the folders are `container_file_t` again).

#### The console's certificate from an ACME authority

Nginx Proxy Manager obtains certificates from Let's Encrypt and keeps them in its `letsencrypt` directory. The
repair console on tty1 offers `adopt` beside `generate` for the `certificate` verb: the certificate helper reads
that directory, takes the certificate that names the host's origin, is valid now, chains to a root the host
trusts and pairs with its key (of several, the one that stays valid longest), and installs it through the same
writer as `generate`. The directory is the app container's to write, so the helper takes nothing on its word: a
self-issued certificate, one from an authority the host does not trust, a key others can read and a link that
leaves the directory are all refused. A renewal is another `adopt`.

No package installs the helpers, their units or the polkit rule yet, and nothing enables the
sockets: that is the image's decision, with the repair console's. A real reboot and shutdown
are verified on an appliance image, not in a container.

### Optional network fields

Existing `host.network: {"mode":"dhcp"}` documents retain the same plan. Optional
`dns.servers` contains literal unicast addresses, and `dns.search` contains DNS
search suffixes. An empty array requests an empty set; omitted fields remain absent.

Static settings use `"mode":"static"` and `interfaces`, for example:

```json
{"mode":"static","interfaces":[{"name":"ens4","ipv4":{"addresses":["192.0.2.10/24"],"gateway":"192.0.2.1"},"ipv6":{"addresses":["2001:db8::10/64"]}}],"dns":{"servers":["192.0.2.53"],"search":["example.test"]}}
```

Each interface has one or both address families, with explicit CIDR addresses and
an optional gateway within an address prefix. Duplicate names or addresses, wrong
families, loopback, unspecified and mapped addresses are refused. First boot verifies
these settings against cloud-init's NetworkManager output. A local answers file or
systemd credential alone cannot configure static networking: also supply matching
cloud-init network configuration, such as a NoCloud seed's `network-config`.

## The image recipe

`appliance/images` is the recipe of an appliance image: ONE KIWI NG description with a
profile per edition and architecture (`kiwi/config.xml`, profile `almalinux10-server-amd64`,
the shipping base, built from the signed product RPMs, and profile `almalinux10-desktop-amd64`,
the server profile plus GNOME; the Debian 13 profile `debian13-server-amd64` stays in the description, not shipping),
the assembly of the formats built from the disk it produces (`formats/`), and the
tests that hold both to their shape. `appliance/test` is the boot side of the same recipe.

### The base

The shipping base is AlmaLinux 10 (RHEL 10 compatible), at the minor the pinned trees name: 10.2, recorded in
`images/formats/formats.json` (`base.minor`), in `images/kiwi/almalinux-repositories.json` and in the builder lock, and
kept equal by `images/recipe_test.go`. It replaced Fedora 44 before any image was built: a Fedora
release lives about thirteen months, which would mean a major upgrade on customer hosts every year, and Debian 12's 6.1
kernel has Landlock ABI 2 where Olivares needs ABI 3 or newer for read-only session paths.

- Lifecycle: AlmaLinux 10 has active support to 2030-05-31 and security support to 2035-05-31 (wiki.almalinux.org release
  notes).
- Kernel 6.12 LTS, systemd 257, SELinux targeted policy 42.1, GRUB 2.12, shim 16.1, DNF 4.20 (`dnf`; AlmaLinux 10 has no
  dnf5; the host-package update path installs its retained RPM with `rpm -U`), btrfs from `kernel-modules` and AppStream's `btrfs-progs` (the root layout is unchanged).
- AlmaLinux 10 is built for x86-64-v3 (AVX2): the image does not boot on a CPU model without it. AlmaLinux's separate
  `x86_64_v2` builds are not used.
- The image reads BaseOS and AppStream only; `crb` and `extras`, which `almalinux-repos` enables, are turned off by
  `config.sh`. Only the builder reads EPEL 10 (`gdisk`, `python3-typer` with its closure, `python3-poetry-core`,
  `python3-simplejson`, `screen`) and CRB (`python3-pygments`, which EPEL's `python3-rich` needs).
- A new minor is a reviewed edit of the trees' base URLs and the builder lock (`images/toolchain/almalinux10/README.md`).
- FIPS and STIG profiles are part of the Business build, not of this recipe.
- AlmaLinux security updates apply by default: dnf-automatic's install timer is enabled, `/etc/dnf/automatic.conf` takes
  security advisories only (`upgrade_type = security`, applied, reboot when needed) and the timer's drop-in
  `10-olivares-window.conf` is the one reboot window (03:00 and up to 30 minutes after it; `Persistent=false`, which overrides the stock timer's `true`, so a night
  missed while the host was off is not made up at boot, where its reboot would land outside the window). The other three
  timers stay disabled, and `excludepkgs = olivares*` in the `[base]` of `automatic.conf` leaves the product, the appliance
  layer and the SELinux policy out of the run, even a security fix the entitled channel may carry for them: a product
  release is never applied by it, that is the administrator's act
  (`olivares-appliance-update.service`). `config.sh` reads each of these back and fails the build without one.
- Fedora is for development only. A CentOS Stream 10 canary for the next RHEL minor does not exist yet.

The Fedora 44 pieces and what replaced them:

| Fedora 44 | AlmaLinux 10 |
| --- | --- |
| Profiles `fedora44-*`, base id `fedora44` | `almalinux10-server-amd64`, `almalinux10-desktop-amd64`, `almalinux10-firmware`; `--base almalinux10` |
| Builder `toolchain/fedora44`, `relock-fedora.py`, Koji URLs | `toolchain/almalinux10`, `relock-almalinux.py`, repository trees and vault source trees pinned by `repomd.xml` sha256 |
| `fedora-release`, `fedora-repos`, `fedora-gpg-keys`, the openh264 repository | `almalinux-release`, `almalinux-repos`, `almalinux-gpg-keys`; `crb` and `extras` turned off |
| DNF 5, `pkg_gpgcheck`, `/etc/dnf/libdnf5.conf.d` | DNF 4.20, `gpgcheck` and `repo_gpgcheck`, `installonly_limit` read from `dnf.conf` and checked in `config.sh` |
| `dnf5 --store` host-package update | `rpm -U` of the retained, signature-verified file (`layer/updates`) |
| rpm 6 keyring handling | rpm 4.19: the per-build key and Docker's release key are removed by their key IDs and the AlmaLinux key is checked to remain |
| SELinux module built on Fedora's policy | built and checked against the policy RPMs of the 10.2 trees (`selinux/recipe-pins.json`); columns `fedora_*` renamed `base_*` |
| Fedora cloud image for the network oracle, Fedora fixture container | AlmaLinux GenericCloud 10.2 image, `almalinux:10` fixture container |

Not replaced here: the entitled-package builder (not in this repository) still uses a Fedora 44 container
and DNF 5; that is a separate change. The EPEL 10 URLs
live on `dl.fedoraproject.org`, which is where Fedora hosts EPEL.

### Editions: Community in the image, Business with the licence

The image is the Community edition and nothing else. `images/kiwi/config.sh` fails the build when the root holds
`olivares-business`, when `/usr/bin/olivares` does not report `"edition": "community"` in `version -o json`, or when a
licence is installed (`/var/lib/olivares/license.key`). The channel's credential file cannot be in the root either:
the enabled-repositories check there admits no repository but AlmaLinux's two.

Business arrives on the running appliance, when a licence is activated. `olivares-edition.service` makes the installed
edition the one the licence earns. It requires `olivares-entitled-repo.service` first, so the entitled repository is
current before it decides. `olivares-entitled-repo.timer` starts it two minutes after boot and every six hours; that is
the dependable trigger and the retry for a channel that was not ready. `olivares-entitled-repo.path` starts it when the
product replaces its empty `public/license.changed` notification after a console or CLI licence install, replacement,
connect renewal or removal. The marker holds no licence data and has the existing public-file SELinux label, so PID 1
can re-arm the watch after every change without reading the licence, database or private keys. Direct file edits do
not publish a notification; the timer reconciles those changes.

| The licence | The repository file | The step |
| --- | --- | --- |
| installed, earns the feature suite (`current`) | has `[olivares-entitled-stable]` | on Community: `dnf swap olivares olivares-business`, one transaction |
| installed, expired (`security-only`) | has the security suite alone | nothing: the installed edition stays, security updates continue |
| installed, channel not refreshed yet | none | nothing |
| removed (and no licence in the product's environment file) | removed by the step once nothing is left to swap (the credential has no use) | on Business: `dnf swap olivares-business olivares`, with the public repository `olivares` (shipped disabled in `olivares.repo`) enabled for that one command |

Nothing else changes. The two packages conflict, and the swap is one transaction, so a swap that fails before the
transaction runs (no match in the channel, a conflict, a refused signature, no network) leaves the host as it was and the
unit failed in the journal; the timer tries again. The data
directory `/var/lib/olivares`, the configuration `/etc/olivares` and the keys belong to the product's state and are kept
by both packages. The product stops with the package it belongs to and the new package starts nothing, so the step
starts it again when it was running; a product that was stopped stays stopped (first boot owns the first start). Before
each swap whose package the channel offers it takes the same read-only data snapshot as the update. It is
forward only, like the update: it keeps no way back to a previous build. A licence file, repository file or environment
file it cannot read is an error and changes nothing: only a missing file means none. A licence that
`/etc/olivares/olivares.env` hands the product (`OLIVARES_LICENSE` or `OLIVARES_LICENSE_PATH` with a value) counts as
installed, so a host licensed that way never returns to Community. Each run re-reads the facts after a swap
(up to four passes), so a licence removed while a swap ran is acted on in the same run. A licence installed while a
swap back ran is left to the next refresh, which starts the step again: the repository file then still describes the
old licence. A product that does not start after a swap fails the unit with the reason; the step does not retry it.
The environment-file licence keeps the installed edition and nothing more: the entitled channel follows the data
directory's binding, so such a host is never moved to Business by this step.

Every decision is one line in the journal of `olivares-edition.service`: the licence, the feature suite, the installed
package and what the step did, so a licensed host that stays on Community says why.

On the running appliance `/var/lib/olivares` is its own volume, so the product package's post-install step places its
install manifest through the product (`olivares __place-install-manifest`) instead of renaming it across volumes; a
failure refuses as `manifest-placement-failed`. Install and upgrade complete that step there. The swap runs the same
step; it has not been run yet.

What it needs from outside this repository: the entitled channel must offer `olivares-business` (published by the release
process), and the public repository at `packages.olivares.ai` must serve `olivares` for the way back. The address
answered 404 on 2026-10-22; until it serves the package the swap back fails before any change, the host stays Business
and the unit fails in the journal.

### The two variants

Both variants are the same recipe on the same base, differ only in their package set and
overlay, and ship the same three formats (ISO installer, qcow2 disk, OVA). Each is built and
booted by the image workflow maintained with the licensed distribution, which
takes an `edition` input. It runs on dedicated runners; its host preflight first measures the tools
and, for `accelerator: kvm`, `/dev/kvm`, and skips the image jobs with a named reason when the
runner lacks them.

| Variant | What it is for | Minimum resources |
| --- | --- | --- |
| Server (`almalinux10-server-amd64`, the default) | A machine room or cloud appliance administered over SSH and the Appliance Console: the product and its first boot, no graphical desktop and no second management interface. | 2 vCPU of an x86-64-v3 CPU, 2 GiB RAM, 12 GiB disk, a serial console or SSH reachability |
| Desktop (`almalinux10-desktop-amd64`) | The same appliance for a desk: GNOME Shell with GDM on the graphical target, Firefox to browse, Ptyxis as the terminal, Nautilus as the file browser, and SSH/SFTP enabled so files travel to it the usual way. | 2 vCPU of an x86-64-v3 CPU, 4 GiB RAM, 12 GiB disk, a graphical console (keyboard and monitor or a SPICE/VNC window) |

AlmaLinux 10 is built for x86-64-v3: Intel Haswell or AMD Zen, or newer. On an older CPU, or on a virtual CPU model
without those features, the kernel starts and init stops at once with `Fatal glibc error: CPU does not support
x86-64-v2` (or `v3`). In a virtual machine, give the guest the host's CPU: CPU type `host` on Proxmox VE and libvirt
(`host-passthrough`), `-cpu host` with QEMU and KVM. The default models of several hypervisors (`kvm64`, `qemu64`,
`x86-64-v2-AES`) do not boot it.

The desktop profile adds GNOME on top of the server profile's packages — nothing of the
server's set or behavior changes — and the recipe's config.sh sets the machine's default
target to `graphical.target` and enables `gdm` (as `display-manager.service`, the only way
gdm's unit installs) and `sshd` inside the image root, with the links `systemctl enable`
would create; the stock `sshd_config` already serves the SFTP subsystem. The desktop
artifact sizes are predictions near the 2 GiB release-asset ceiling until the first hosted
build weighs them; a heavier artifact is refused by the assembly, and shrinking the set or
declaring the format split is the owner's decision then.

```sh
# Hosted current job only, after staging the Community and layer packages:
task appliance:build ACCELERATOR=kvm EVIDENCE="$RUNNER_TEMP/appliance-attempt" FORMAT=all
# The desktop edition is the same transaction with EDITION named:
task appliance:build ACCELERATOR=kvm EVIDENCE="$RUNNER_TEMP/appliance-attempt" EDITION=desktop FORMAT=all
# Standalone guest observation over existing artifacts (no builder admission):
task appliance:boot ACCELERATOR=kvm
# TCG is an explicit choice and must match the prerequisite trial:
task appliance:build ACCELERATOR=tcg EVIDENCE="$RUNNER_TEMP/appliance-tcg" FIRMWARE=free
```

Neither target is a push gate and neither is on the hook's fast path: an image build needs a
container runtime and privileges a push must never take. The image workflow maintained with the licensed
distribution is dispatched by hand; it builds the three artifacts,
boots them and publishes nothing. All phases share that job; no downloaded receipt from another
VM can admit a builder. The recipe has no separate Containerfile or KIWI installation.
`FORMAT=all` is the single qualification transaction: iso, qcow2 and ova are built together
because the guest cases need the disk and the installer. Any other `FORMAT` is refused:
`task -x appliance:build FORMAT=qcow2` exits 2, while plain `task` reports its own status 201
for any failing command.
The attempt runs `formats/assemble.sh --format` once per format as one of its steps; calling it
alone is not a supported or qualified export.
On the AlmaLinux base the `admin-shell` phase runs between `build` and the formats:
`test/admin-shell-battery.sh` chroots the root KIWI built at `<target-dir>/build/image-root` and
checks the administrator's shell (the aliases, `vi` as vim and the tools the issue names).
Like the privileged `build` phase it needs root or passwordless `sudo` on the builder; without
either it exits 2 ("cannot measure") and the recipe stops there.
The owner always attempts release after failure; hard runner loss or an unknown daemon
outcome remains unconfirmed cleanup. Evidence and recipe work are retained, never erased
as proof of cleanup. See [builder admission](images/toolchain/README.md).

The build, format, boot and NoCloud phases stream their output into `<phase>.log` as it
arrives, so an interrupted phase keeps what it printed. Such a log keeps its first 16 MiB and
its last 256 KiB, and `<phase>.log.json` records the raw exit, start, finish, duration and any
interruption. The preflight is the exception: it runs through the prerequisite's unchanged
`workflow.py` and collector, which keep the last 256 KiB of output and write
`prerequisite/preflight.log` only when the collector ends. There is no `preflight.log.json`.
An interrupted preflight's log holds only the line "collector interrupted; resource release
unconfirmed", and a receipt the collector never wrote is replaced by the explicit incomplete
receipt. `prerequisite/workflow-result.json` records the preflight's exit, and
`recipe-result.json` lists every phase's times, the preflight's included. `disk-samples.jsonl`
samples free bytes of `/`, the evidence and the target directory at each phase start and
every 30 s. Use between samples is not observed, so the
largest sampled drop is a lower bound of peak use, not the peak. The Actions log receives one
progress line per 30 s: phase, elapsed time, output bytes, free bytes and the last output
line, at most 160 printable characters. The job reads no secret. The evidence artifact keeps
text records, guest `seconds`, `qemu.cmd` and `qemu.stderr`, but no guest disk. Only the
streamed phase logs are byte-capped. The guests' `serial.log`, NoCloud's `console.log` and
`probe.log`, and each `qemu.stderr` are written by QEMU or a shell redirection with no byte cap.
They are bounded only by each guest's timeout (900 s boot, 1800 s install, 1200 s NoCloud) and
are retained whole. No total byte budget is declared for the evidence artifact.

Release records are never rewritten. The first release writes `cleanup.json`, `release.log`
and the prerequisite's `prerequisite/builder-release.json`. Each later release, such as the
always step or a retry after a failed release, claims a new `recovery/NNN/`. It holds its own
receipt copy, `builder-release.json`, release log, `cleanup.json` and `SHA256SUMS`. A record's
`SHA256SUMS` also hashes the manifest before it, so the latest sealed record commits to every
earlier one. A record without `SHA256SUMS` was interrupted and stays as it was left. The
attempt's own `SHA256SUMS` is written once, by the attempt or, if the attempt was stopped
first, by the first always step. `cd EVIDENCE && sha256sum -c SHA256SUMS recovery/*/SHA256SUMS`
verifies them all. A cidfile that names another owner's container, and a labeled container
with no cidfile, are refused and nothing is deleted.

The attempt exits 0 when every phase and the release completed, and 2 only when the
prerequisite or a phase classified a missing prerequisite. Any other failure is 1, including
a timeout (124), a missing command (127) and an interruption; `recipe-result.json` keeps the
raw `phase_exit`. A builder command that fails after admission makes `build.sh` exit 1 whatever
its container returned (GNU tar's fatal status is 2); `build.log` keeps that raw status.
Release follows the prerequisite receipt's typed custody. A builder the collector already
removed, even without a recorded ID, or never retained, is not released
again; the collector's own `cleaned` result decides whether that custody is confirmed.

| Piece | What it is |
| --- | --- |
| `kiwi/config.xml` | the one description: profiles, disk layout, package lists, repositories |
| `kiwi/config.sh` | what runs inside the image root: the serial console, the datasources, and a template with no instance identity, checked by the layer's own `appliance-firstboot check-template` |
| `toolchain/input-lock.json` and `toolchain/Containerfile` | the single reviewed builder owner; exact Debian snapshot, source and artifact closure |
| `kiwi/attempt.py` | one same-job preflight/admission/build/boot owner; exact child and image retirement in finally, with an always-step recovery path |
| `kiwi/build.sh` | rechecks current admission before effects, uses the immutable image ID, stages the dracut modules from the builder's lock-declared path, and records attempt/image/accelerator/input digests |
| `kiwi/product-dev.nfpm.yaml` | a DEVELOPMENT product package so an image can be built before the release process learns the image artifact type. The published package is the release process's |
| `formats/` | `iso.sh`, `qcow2.sh`, `ova.sh` and the declaration `formats.json` they share, each writing the artifact's manifest beside it |

The image installs the product and the appliance layer as **packages** and starts nothing.
Every identity — host keys, machine ID, TLS, setup token, signing keys — is made on the first
boot of each instance, and `config.sh` fails the build if the finished root already carries
one. The description takes packages from the pinned AlmaLinux 10 BaseOS and AppStream trees and from the appliance's own
local repository, and from nowhere else; KIWI's dracut modules, which AlmaLinux does not package,
come from the same pinned KIWI release the build uses.

`FIRMWARE=nonfree` (the default) adds redistributable non-free firmware, which is what the
official Debian installer has carried since bookworm and what makes the image boot on most
server network and storage controllers. Whether the published image carries it is still the
owner's decision; `FIRMWARE=free` answers it the other way and the image is then 100% free.

### Sizes, and the ceiling

No file of a GitHub release may pass **2 GiB**, and the licence gate serves the images from R2 whatever
their size (the publisher sends the images, the signed table, its signature and its certificate there).
Each artifact declares its own ceiling in `formats.json` and the assembly refuses to hand over one that
passes it, so an image that grew is a build failure and not a discovery at upload time. The
server edition is predicted at roughly 1.2–1.5 GiB per artifact and has never been measured:
the first hosted build replaces the prediction with the weight. An edition that cannot fit —
the workstation edition with a full desktop is the candidate — declares itself split in the
same file, with the size of its parts.

The corresponding source bundle follows the same rule, declared per edition under `source_bundle` in `formats.json`.
The server edition's stays one file below the R2 single-PUT bound of 5363466239 bytes, and a bundle over it is refused as
before. The desktop edition declares itself split: `release_outputs.py bundle --edition desktop` writes the same
zstd stream as numbered parts of at most `split_part_max_bytes` (2147483647, below a GitHub release asset's 2 GiB):
`olivares-appliance-VERSION-source.tar.zst.001`, `.002`, and so on, and `source-bundle.json` adds `parts` (each part's
name, size and sha256) beside the whole stream's size and sha256. `cat` of the parts in order is the archive;
`release_outputs.py verify-bundle` checks each part, the joined stream and that no other part sits beside them. A desktop
bundle that fits one part stays one file with no `parts`. Parts are numbered with three digits, so a stream over 999 parts is
refused by name; an existing archive is never replaced by the write. The Business publication carries the parts under the
published stem (`olivares-appliance-desktop-VERSION-source.tar.zst.001` and on) as rows of the signed table.

### Building on a host that has only docker and Go

The qualification delivery, `attempt.py`, the formats, the boot battery and the NoCloud seed can take their host tools
from the host toolbox, `images/host/Containerfile`: the Debian 13 base of `images/toolchain`, one pinned Debian
snapshot, and the package set the boot battery passes with. `bash appliance/images/host/run.sh -- COMMAND` runs
COMMAND in it from the current directory, privileged (KIWI and the preflight loop-mount images), with `/dev/kvm` and the
host's docker socket: the AlmaLinux builder still runs on the host's docker, so the work directories are mounted at
their own paths. The root user's files are handed back to the caller when COMMAND ends. The host needs docker that the caller
may use (the socket gives root on the host), the Go toolchain of `go.work`, which the toolbox mounts read-only for the
qualification delivery, and, for `--accelerator kvm`, `/dev/kvm`. From a checkout of this repository:

```sh
mkdir -p dist
bash appliance/images/host/run.sh -- bash appliance/images/kiwi/qualification-delivery.sh "$PWD/.delivery"
bash appliance/images/host/run.sh -- python3 appliance/images/kiwi/attempt.py --evidence "$PWD/.evidence" \
  --accelerator kvm --base almalinux10 --edition server --package-dir "$PWD/.delivery/packages" \
  --qualification-key "$(cat .delivery/qualification-key.fingerprint)" --target-dir "$PWD/dist/appliance"
```

### What the recipe does not claim

No artifact of this phase is signed and none is published: checksums, signatures, SBOM, VEX,
provenance and the GPL source offer belong to the publication helpers maintained with the licensed distribution,
and the recipe says so in
every manifest it writes (`"signed": false`). The OVA is well formed and its manifest matches
its contents; whether vSphere, VirtualBox and Proxmox import it is not tested here. The disk does not grow to its target: KIWI's resize capability is a dracut
module Debian does not package, so the disk is the size the description declares.

## The boot battery

`appliance/test/boot-battery.sh ARTIFACTS EVIDENCE` is the acceptance oracle: an appliance
that does not reach `multi-user.target` and show the console label on its serial console has
not booted. The label is read on the console. The target is read in the guest's journal, which
each boot streams to a second serial port (`journal.log` beside `serial.log`): systemd stops
printing status lines on a console a getty runs on. It answers that on amd64 four times:

| Case | What it boots | What it proves |
| --- | --- | --- |
| `bios` | the disk under SeaBIOS | the legacy path KIWI keeps on the same disk |
| `uefi` | the disk under OVMF | shim and the signed GRUB under EFI |
| `uefi-secureboot` | the disk under OVMF with the Microsoft keys enrolled | the firmware verified the chain; the kernel says it was booted with Secure Boot on. Removing `shim-signed` from the recipe makes this case red and no other |
| `iso-install` | the installer medium, unattended, then the disk it wrote | the medium an owner burns installs and boots |

It **refuses rather than passing**: an explicit KVM choice without `/dev/kvm` exits 2 before
QEMU. An admitted TCG choice is passed unchanged to every guest consumer; unknown choices
refuse. The existing 900s boot, 1800s install and 1200s NoCloud ceilings are declared bounds,
not measured TCG performance. A prerequisite prelaunch proof does not establish guest support
or a usable boot budget. Full guest observations remain required on the composed head.

`appliance/test/nocloud-probe.sh` is the unattended first boot on a real machine: it boots the
disk from the seed the layer's own carrier fixture delivers and asserts the first-boot record
with that battery's own assertions, loaded rather than copied. The appliance ships no
credential, so there is no shell in the guest to read a file from: the probe hands systemd an
observer unit through an SMBIOS credential, and the unit prints the record to a second serial
port and powers the machine off. The image is not modified. The probe also hands systemd the
seed's own document as the `olivares.appliance.answers` credential, so PID 1 sets up a unit
credential on the image, and it refuses a boot whose journal holds an SELinux denial of PID 1
(`appliance/test/lib/pid1-denial.sh`). It asserts too that cloud-init wrote the NoCloud
carrier file, because first boot reads the credential first and would otherwise never use it.

`appliance/test/battery-selftest.sh` is what both promise before they boot anything — the
three firmware cases are named, the refusals refuse, the label is the layer's — and it runs on
any machine, with no hypervisor and no artifact.

## Session container image

Both AlmaLinux editions build `localhost/olivares-session:latest` during KIWI configuration
(`session-image.sh`, run by `config.sh`) and save it as `/usr/lib/olivares/session-image.tar`.
KIWI runs the script in a chroot, where the kernel refuses user namespaces, so root builds with
Podman into a throwaway store (host network, `--storage-driver overlay`) and the build directory
goes away with the script. The product package supplies
`/usr/share/olivares/session-image/Containerfile`; an absent recipe, failed build, failed
`podman image exists` or failed save stops the image build. The base is pinned by digest and the
build mounts dated signed Debian snapshots over apt's sources. Building needs network access;
first boot needs no image pull. The product RPM gives `olivares` its subordinate UID and GID
ranges, which rootless Podman needs.

The engine user's own Podman serves the engine. The helper links the user units
`podman.socket` and `podman.service` (from the Podman package) into the user's manager
and enables linger, so `user@<uid>.service` starts them at boot. The service first loads the
current archive into the user's store (no network), then answers the API. The
engine's drop-in sets `OLIVARES_SESSION_CONTAINER_RUNTIME=podman` and `CONTAINER_HOST` to that
socket, which makes `podman` a client of it, and wants the user manager without a hard startup
dependency. `newuidmap` runs in the user service, never in the engine, so the engine keeps its
empty capability set and `NoNewPrivileges`. The drop-in also gives the engine its own
`XDG_RUNTIME_DIR` (`/var/lib/olivares/podman-client`): the engine learns that it has no user
manager of its own from a refused lookup of the manager's sockets, and must keep failing it, while
podman needs an existing runtime directory without an unreadable bus. A call the unit's seccomp
filter does not list answers `ENOSYS` instead of killing the process, which podman's SELinux
library copes with; nothing outside the filter's list becomes allowed. The engine user is not in the `docker` group and has
no access to Docker's socket: Docker stays for the optional apps.

On an installed Docker-session appliance, the base package upgrade requires Podman and the matching product version (which
allocates subordinate IDs before the migration) and runs `session-image --migrate`. It exports the existing session image with `docker save`,
loads it into the engine user's Podman store without pulling, installs the same runtime
configuration as a new image, then removes `60-session-docker.conf` and the engine user's
Docker group membership and restarts an active engine. Export or load failure stops the
migration before the runtime configuration changes; the Docker image is retained.
The vendor user units retain `KillMode=process` and `Delegate=true`; per-user drop-ins only
load the archive, allow time for that load, and restrict the socket mode to 0600.
The product RPM's subordinate-ID allocation applies on every RPM host, not only appliances.

Check the image with
`sudo -u olivares env XDG_RUNTIME_DIR=/run/user/$(id -u olivares) podman image exists localhost/olivares-session:latest`,
then `olivares doctor` (container-runtime: podman) and a container session
on the booted appliance with SELinux enforcing.
