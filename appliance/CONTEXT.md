<!-- SPDX-FileCopyrightText: 2026 Olivares.AI -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Appliance vocabulary

The words this directory uses, and what each one excludes.

| Term | Meaning |
| --- | --- |
| Edition | The product edition a component belongs to. Everything under `appliance/` is Community and AGPL-3.0-only; private capabilities are separate modules that add and never remove. The server and workstation images are profiles of one layer, not editions. |
| Layer | What turns an AlmaLinux 10 installation (or the non-shipping Debian 13 profile) into an Olivares appliance: the answers module, the Appliance Console and, later, host adapters. The composition root also imports its portal authority packages to serve appliance operations. |
| Appliance Console | The appliance's management console on port 9443, in `layer/portal`. A descriptive label, not a brand, and distinct from the product console on 8443. It shows read-only status and performs one act, the relay of a licence to the product's own licence API (`/updates/licence`); every other act is named with its command and performed by none. |
| Answers | One `appliance-answers/v1` document, the only input to installation planning, validated by `answers/`. Unknown fields, duplicate keys, nulls, wrong types, a second document and input over 64 KiB are refused. |
| Carrier | How an answers document reaches a host: a file, a NoCloud seed, OVF guestinfo, a systemd credential or the local assistant. Every carrier emits the same document and none merges sources; `source` records which one was asserted. The Appliance Console reads no carrier: it reads the selection first boot publishes. |
| Selection | The Appliance Console's view of the validated answers: `portal.enabled`, `portal.listen` and `host.management_interfaces`, published by first boot to `/etc/olivares-portal/selection.json`. It is derived, never edited, and it is not a second configuration store. |
| Management interface | A network interface the operator names in `host.management_interfaces` for remote access to the Appliance Console. Naming it configures nothing. |
| Packaged, enabled | Packaged: the binary and units are installed. Enabled: something starts them at boot or exposes them to the network. Installing the Appliance Console package enables its socket, which listens on loopback only, and nothing that is exposed to the network. The server image also enables the repair console on tty1. |

## Appliance Console exposure

The console binds no socket; it serves only sockets the service manager passes in, and
decides which of them it may serve:

| Decision | When | Serves |
| --- | --- | --- |
| `disabled` | `portal.enabled` is `false`, or TLS custody is unverified | nothing, not even loopback |
| `local-only` | any remote prerequisite is missing | loopback addresses |
| `remote` | `portal.enabled` is `true`, `portal.listen` is `management`, at least one management interface is selected, TLS custody is verified and the firewall prerequisite holds | loopback, and each socket the kernel binds to a selected interface, read back from the socket. Each such socket comes from a separate socket unit per management interface, whose `[Socket]` section sets `BindToDevice=` and `Service=olivares-portal.service`; never from a drop-in on `olivares-portal.socket`, where `BindToDevice=` would also bind `127.0.0.1:9443` to the uplink |

A wildcard address is never served, and neither is a non-loopback socket bound to no
selected interface: an address alone proves no interface. TLS custody is measured where
the operator keeps the files, in the directory the service unit names: the directory,
the certificate and the key are owned by root (or the service's own user) and writable
by their owner only, the key is mode 0600 or 0400, none is a symbolic link, the
delivered certificate is byte for byte the operator's, and the delivered key pairs
with it. A caller that is not on loopback reads state words only: no interface names,
addresses, firewall rules, tenant, account or support data.

The selection and the firewall prerequisite are each read from one file, and only when it
is a regular file, not a symbolic link, owned by root and writable by neither its group nor
others:

| File | Writer | Read as |
| --- | --- | --- |
| `/etc/olivares-portal/selection.json` (mode 0644, schema `olivares-portal-selection/v1`) | first boot's `generate-product-config`, from the validated answers, only when they declare one of its fields; a selection they no longer declare is removed | the operator's selection. No file is the empty selection (loopback status only); a refused file is served as none and the refusal is logged |
| `/run/olivares-firewall/measured.json` (mode 0644, schema `olivares-firewall-measurement/v1`: `boot_id`, `measured_at`, `policy_digest`, `input_policy`, `rows[]{port, interfaces}`) | the host firewall's owner, after every load of its policy | held when it is this boot's measurement (`boot_id` equals the kernel's), the input policy is `drop`, and the rows admit `9443/tcp` on exactly the selected management interfaces: not on another interface, not on every interface (`*`), not on only some of them. Absent, foreign-owned, malformed or another boot's: unmeasured |

The host firewall's owner (`layer/firewall`, `olivares-firewall.service`) publishes the measurement
after every load of its policy. Until it has, or when its rows are not the selection's, the
prerequisite is unmeasured or not held and the decision is `local-only` at most.

`olivares-portal-sockets.service` (root, one shot) makes the socket units of the `remote` row. It runs
once `network-online.target` is reached, so a DHCP lease is already known, and again each time
`olivares-portal-sockets.path` sees the selection or the firewall owner's measurement published, and
every two minutes. It
decides as the console does (`portal.DecideHost`: the selection and the measurement) and, only for
`remote`, writes `/run/systemd/system/olivares-portal-mgmt-<interface>.socket` with one
`ListenStream=` per global unicast address the kernel reports on that interface now (never
link-local, loopback, multicast or a wildcard), `BindToDevice=` the interface,
`Service=olivares-portal.service` and the limits of `olivares-portal.socket`. In every other decision
it stops and removes the units it wrote, and in the default one it does nothing at all. The units
live in `/run`, so a reboot starts with none. TLS custody stays the console's judgment: with it
unverified the console serves nothing on any socket.

The console holds the sockets it was passed until it exits, and the service manager refuses to
start a socket while its service runs. So the generator stops the console after it removes or
replaces a socket, and stops it when the manager refuses to start a new one; the next connection to
a socket that is listening starts a console with the current set. A unit file stays until its
socket has stopped, so a failed stop is found and stopped again by the next run, and a marker
beside the units (`.olivares-portal-mgmt.unfinished`, in `/run`) says that a change was begun and
not finished, so a run that was killed, or whose reload or console stop failed, is redone in full
by the next one whatever the files say.

What the generator could not finish it reports with a non-zero exit: a selected interface that holds
no global address yet (a lease still pending), a socket that would not stop or start. Its timer
(`olivares-portal-sockets.timer`) runs it again every two minutes, which also picks up what no file
change announces: a lease that moved the address of a running socket, a socket that failed by itself
(its device went away, a limit tripped), a publication that landed while a run was in progress. A run
that has nothing to change reads two files, calls nothing and writes nothing to the journal. The
console accepts `portal.MaxListenFDs` (8) passed sockets and the package's own two use two of them,
so the management interfaces are listened on at six addresses together, shared round-robin between
the interfaces and IPv4 first within each; the journal says how many further addresses are not
served. The generator's program is not confined by the SELinux module yet, as the entitled channel's
refresh is not.

## Optional answers fields

These fields are optional, unlike the fields `README.md` lists. A document without them
validates and plans exactly as before; the plan echoes them only when present, and they
change no planned operation.

| Path | Accepted values and meaning |
| --- | --- |
| `portal.enabled` | Boolean. Through the published selection, `false` turns the console off, even on loopback, and `true` consents to remote access, which still needs every prerequisite above. Absent: loopback status only. |
| `portal.listen` | `local` or `management`. `management` requires `host.management_interfaces`. Absent means `local`. No value selects every address. |
| `host.management_interfaces` | Array of 1–16 unique names, each 1–15 ASCII letters, digits, dots, hyphens or underscores beginning with a letter or digit. Case-sensitive; sorted in the plan. |

# appliance/ — what the words mean here

This directory turns the product into a machine somebody can install. Six words carry the
design, and each one names exactly one thing in the tree. Using them precisely is what keeps
the recipe from growing a second installer, and the layer from growing a second updater.

| Word | What it is | Where it lives |
| --- | --- | --- |
| **edition** | the set of software an image ships installed. `server` today; `workstation` is `server` plus a desktop. An edition is a profile of one recipe, never a second recipe | `images/kiwi/config.xml` profiles |
| **layer** | the appliance's own behaviour, shipped as a PACKAGE beside the product: first boot, the console label, the state directory. It is a package so it can be tested without building an image and updated on appliances that are already installed | `layer/base` |
| **recipe** | the description an image builder reads, plus the assembly of the formats built from it. It installs packages and starts nothing | `images/` |
| **answers** | one `appliance-answers/v1` document: the public settings an instance needs. Never a secret, never a password | `answers/` |
| **carrier** | where a copy of that document travelled from — a NoCloud seed, an OVF property, a systemd credential, a file. First boot compares the carriers it finds and refuses when they disagree | `answers/carriers` |
| **enablement** | turning on hardware whose vendor licence the owner must accept first, after the appliance is installed. Not in any image, and not part of this version | none yet |

## The dependency rule

Recipes depend on the layer. The layer uses product interfaces, and the product composition
root imports appliance portal authority packages in
`cmd/olivares/appliance_authority.go` in the Olivares AI repository.
This is a build dependency even when no appliance image is being built.

Read it in the direction that bites: anything an image needs at first boot belongs to the
layer, not to a script inside the recipe. A recipe script can only be tested by building an
image, and it never reaches an appliance that is already installed — the same work in the
layer is tested in a container in seconds and updates through the normal package channel. The
recipe's own share is the image's own state: the partitioning, the boot chain, the package
set, and a template that carries no instance identity.

## Two rules that are easy to break quietly

**An image is a template, not a machine.** No host key, machine ID, certificate, token or
signing key is made while an image is built; every one of them is made on the first boot of
each instance. The recipe's last act is to ask the layer's own gate whether the root is still
a template, and a root that carries an identity fails the build instead of cloning that
identity into every appliance.

**An inability is not a pass.** Every battery here exits 2 when it could not measure — no
`/dev/kvm` when KVM was selected, no container runtime, no artifact — and 1 only when something it did measure was
wrong. A green that means "I did not look" is the one result this directory must never
produce.

## Where the phases are

The layer, the answers and the first-boot contract are delivered. This recipe, its three
formats and the boot battery are the image. The publication helpers maintained with the licensed distribution
write the release evidence of an image artifact as rows of the one signed table
`SHA256SUMS-<edition>`: the SBOM of the image root, an OpenVEX document (no statements: no scanner of the
image's RPMs runs in the build), a SLSA v1 provenance statement whose subjects are every other file, the
source bundle with the list of its source RPMs by NEVRA, and the written offer for the corresponding source.
The publication verifier checks that set before any upload. The
provenance is made by the build job and covered by the table's keyless signature; it is a bare in-toto statement,
not a DSSE envelope and not a SLSA Build L3 claim, so `slsa-verifier` does not apply to it. Nothing is published until that path has run on a 1.x release. Rollback, AppArmor and SCAP, the workstation edition, arm64 and
accelerator enablement, and the cluster role come after.

The recipe consumes the single `images/toolchain` builder through a same-job retained-image
admission. A historical prerequisite receipt is a reading, not authority to reuse an image.
`images/kiwi/attempt.py` owns build/guest work and exact-ID release; the workflow retains
that custody through its always step. An explicit TCG choice does not waive any guest oracle.
