// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

// Package entitled is the appliance side of the entitled DNF channel: it reads the handoff the
// product's `license connect dnf-refresh` publishes and writes the repository file DNF reads.
//
// The product proves possession of its bound key to the licensing service and receives a download
// credential (`oad1.`, 24 hours) with the class its licence earns: `current` for both suites,
// `security-only` for an expired licence. That is the whole policy. This package copies the answer
// into the one file below and decides nothing else, so the feature suite leaves the file at the next
// successful refresh after the service stops granting it. A refresh that obtains nothing leaves the old
// file as it was; the service itself refuses a credential whose licence is no longer live. The credential is written only to that file (mode 0600, root) and
// is never returned in an error.
package entitled

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/olivaresai/olivares/core/license/dnfrefresh"
)

// RepoFile is the one file this package owns under /etc/yum.repos.d.
const RepoFile = "olivares-entitled.repo"

// Login is the user name the licensing service's DNF adapter requires with the credential.
const Login = "olivares-dnf"

// GPGKey is the preinstalled key that signs the entitled publication: a path in the image, never a URL.
const GPGKey = "file:///etc/pki/rpm-gpg/RPM-GPG-KEY-olivares-package-repository"

var id128 = regexp.MustCompile(`^[0-9a-f]{32}$`)

// hostPort is the authority a repository file may carry: a DNS name or IPv4 address and an optional port. DNF splits
// baseurl on commas and expands $variables, and Go decodes %xx escapes and accepts other bytes in a URL host, so
// anything outside this grammar is refused rather than passed through.
var hostPort = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:[0-9]{1,5})?$`)

// Origin returns the scheme and authority of the licensing service the product reports, or an error.
// Only https is accepted: the credential travels as a Basic password, so a plain http origin is refused.
//
// The origin is the product's report, and the product runs as an unprivileged user, so it is the one input here that
// root takes from that user without a custody check. It cannot install anything: both signature checks and the
// preinstalled key decide what DNF accepts. What it can do is name the host that receives the credential, which the
// product user already holds.
func Origin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("entitled: the licensing service origin is not a URL")
	}
	switch {
	case u.Scheme != "https":
		return "", errors.New("entitled: the licensing service origin must be https")
	case !hostPort.MatchString(u.Host):
		return "", errors.New("entitled: the licensing service origin is not a host name and a port")
	case u.User != nil, u.Opaque != "", u.RawQuery != "", u.ForceQuery, u.Fragment != "":
		return "", errors.New("entitled: the licensing service origin carries more than a scheme and a host")
	case u.Path != "" && u.Path != "/":
		return "", errors.New("entitled: the licensing service origin carries a path")
	}
	return "https://" + u.Host, nil
}

// ReadHandoff returns the handoff of cycle that the product published into dir, which must be a
// directory of uid with mode 0700 that is not a symbolic link. The file must be a regular,
// private file of uid, within the product's size bound, and byte for byte the canonical form of a
// document that passes the product's own schema; and it must name this cycle and invocation. The
// invocation is the service manager's id of the unit that started the product, so a handoff made by
// hand, or left by another run, is refused. Any outcome that is valid is returned, issued or not, so
// the caller can name it.
func ReadHandoff(dir, cycle, invocation string, uid int) (dnfrefresh.Document, error) {
	if !id128.MatchString(cycle) || !id128.MatchString(invocation) {
		return dnfrefresh.Document{}, errors.New("entitled: the cycle and the invocation must be 32 lowercase hexadecimal characters")
	}
	if info, err := os.Lstat(dir); err != nil {
		return dnfrefresh.Document{}, fmt.Errorf("entitled: inspect the handoff directory: %w", err)
	} else if info.Mode()&fs.ModeSymlink != 0 {
		return dnfrefresh.Document{}, fmt.Errorf("entitled: the handoff directory %s is a symbolic link", dir)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return dnfrefresh.Document{}, fmt.Errorf("entitled: open the handoff directory: %w", err)
	}
	defer func() { _ = root.Close() }()
	dirInfo, err := root.Stat(".")
	if err != nil {
		return dnfrefresh.Document{}, fmt.Errorf("entitled: inspect the handoff directory: %w", err)
	}
	if !ownedBy(dirInfo, uid) || !dirInfo.IsDir() || dirInfo.Mode().Perm() != 0o700 {
		return dnfrefresh.Document{}, fmt.Errorf("entitled: %s must be a directory of uid %d with mode 0700", dir, uid)
	}
	name := cycle + ".json"
	linkInfo, err := root.Lstat(name)
	if err != nil {
		return dnfrefresh.Document{}, fmt.Errorf("entitled: the handoff of cycle %s is not there: %w", cycle, err)
	}
	// Before the open: the product user owns the directory and can leave a named pipe here, which a read-only open
	// would wait on until the unit's timeout.
	if !linkInfo.Mode().IsRegular() {
		return dnfrefresh.Document{}, errors.New("entitled: the handoff is not the regular file the directory names")
	}
	f, err := root.Open(name)
	if err != nil {
		return dnfrefresh.Document{}, fmt.Errorf("entitled: open the handoff: %w", err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return dnfrefresh.Document{}, fmt.Errorf("entitled: inspect the handoff: %w", err)
	}
	switch {
	// The name was a regular file when it was inspected; what was opened is checked again, so a swap in between
	// cannot hand over anything but a regular, private file of uid.
	case !info.Mode().IsRegular():
		return dnfrefresh.Document{}, errors.New("entitled: the handoff is not the regular file the directory names")
	case !ownedBy(info, uid) || info.Mode().Perm()&0o077 != 0:
		return dnfrefresh.Document{}, fmt.Errorf("entitled: the handoff must be private to uid %d", uid)
	}
	data, err := io.ReadAll(io.LimitReader(f, dnfrefresh.MaxHandoffBytes+1))
	if err != nil {
		return dnfrefresh.Document{}, fmt.Errorf("entitled: read the handoff: %w", err)
	}
	if len(data) > dnfrefresh.MaxHandoffBytes {
		return dnfrefresh.Document{}, errors.New("entitled: the handoff is larger than the product writes")
	}
	var doc dnfrefresh.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		return dnfrefresh.Document{}, errors.New("entitled: the handoff is not a document of the product's schema")
	}
	// The product's own writer produced exactly Marshal's bytes: equality is the whole validation, and
	// it refuses trailing bytes, reordered or extra fields and anything the schema's checks refuse.
	canonical, err := doc.Marshal()
	if err != nil || !bytes.Equal(canonical, data) {
		return dnfrefresh.Document{}, errors.New("entitled: the handoff is not the canonical form of a valid document")
	}
	if doc.Cycle != cycle || doc.Invocation == nil || *doc.Invocation != invocation {
		return dnfrefresh.Document{}, errors.New("entitled: the handoff belongs to another cycle or invocation")
	}
	return doc, nil
}

// ownedBy reports whether the kernel names uid as the owner of info.
func ownedBy(info fs.FileInfo, uid int) bool {
	owner, ok := ownerUID(info)
	return ok && owner == uid
}

// Render returns the repository file for an issued handoff: one section per suite the service
// granted, each with both signature checks on. A handoff that is not issued, or has expired, renders
// nothing. The values come from grammars the product already enforced, so none can add a line.
func Render(origin string, d dnfrefresh.Document, now time.Time) ([]byte, error) {
	base, err := Origin(origin)
	if err != nil {
		return nil, err
	}
	if _, err := d.Marshal(); err != nil {
		return nil, errors.New("entitled: the handoff is not a valid document")
	}
	if d.Outcome != dnfrefresh.OutcomeIssued {
		return nil, fmt.Errorf("entitled: the handoff outcome is %s, not issued", d.Outcome)
	}
	if *d.Exp <= now.Unix() {
		return nil, errors.New("entitled: the credential in the handoff has expired")
	}
	var b strings.Builder
	b.WriteString("# Written by olivares-entitled-repo from the licensing service's answer; replaced on every refresh.\n")
	b.WriteString("# The suites listed are the ones the licence earns now: an expired licence keeps only the security suite.\n")
	for _, suite := range d.Suites {
		id := "olivares-" + suite
		fmt.Fprintf(&b, "\n[%s]\n", id)
		fmt.Fprintf(&b, "name=Olivares %s\n", strings.ReplaceAll(suite, "-", " "))
		fmt.Fprintf(&b, "baseurl=%s/dnf/v1/ctx/%s/%s\n", base, *d.Context, suite)
		fmt.Fprintf(&b, "username=%s\n", Login)
		fmt.Fprintf(&b, "password=%s\n", *d.Credential)
		b.WriteString("enabled=1\n")
		// Each check on its own: in DNF 4 gpgcheck checks the packages and repo_gpgcheck the metadata. DNF 4 has no
		// pkg_gpgcheck (it ignores an option it does not know), so naming it would leave the packages unchecked.
		b.WriteString("gpgcheck=1\nrepo_gpgcheck=1\n")
		fmt.Fprintf(&b, "gpgkey=%s\n", GPGKey)
		b.WriteString("metadata_expire=0\ntype=rpm-md\n")
	}
	return []byte(b.String()), nil
}

// Install replaces dir/RepoFile with content: a private temporary file in the same directory, written,
// synced and renamed over the old one, so DNF reads the old file or the new one and never half of one.
// The target is replaced, not written through, so a symbolic link left there redirects nothing.
func Install(dir string, content []byte) (err error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("entitled: open %s: %w", dir, err)
	}
	defer func() { _ = root.Close() }()
	tmp := "." + RepoFile + ".tmp"
	if err := root.Remove(tmp); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("entitled: remove a stale %s: %w", tmp, err)
	}
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("entitled: create %s: %w", tmp, err)
	}
	defer func() {
		if err != nil {
			_ = root.Remove(tmp)
		}
	}()
	if err = f.Chmod(0o600); err == nil {
		_, err = f.Write(content)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("entitled: write %s: %w", tmp, err)
	}
	if err = root.Rename(tmp, RepoFile); err != nil {
		return fmt.Errorf("entitled: replace %s: %w", RepoFile, err)
	}
	d, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("entitled: sync %s: %w", dir, err)
	}
	defer func() { _ = d.Close() }()
	if err = d.Sync(); err != nil {
		return fmt.Errorf("entitled: sync %s: %w", dir, err)
	}
	return nil
}
