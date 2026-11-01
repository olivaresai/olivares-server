// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package base

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/olivaresai/olivares/core/secure"
)

// ConsoleTLSDir is the Appliance Console's TLS directory: tls.crt and tls.key, which the console's unit
// delivers to it as credentials.
const ConsoleTLSDir = "/etc/olivares-portal"

// stagedConsoleKey is the name the console's key is written under before it is renamed to tls.key. The
// SELinux policy gives a file first boot creates under this exact name the type olivares_portal_key_t
// (access.tsv, FBOOT-102): a rename keeps the label, and the console refuses a key without it.
const stagedConsoleKey = "tls.key.new"

// consoleWait is how often the step looks for the product's CA while it is still being made.
const consoleWait = 2 * time.Second

// ConsoleCertificate gives the Appliance Console a TLS pair signed by the product's local CA, the CA the
// engine made at its first start and signs :8443 with: the operator trusts one CA for both consoles.
// It makes no CA, so it waits for the engine's, and it runs at every start of the product, so a
// changed host name or address is re-issued from the same CA and key. A pair the operator installed,
// or made on request, is left as it is.
type ConsoleCertificate struct {
	Host Host
	// Poll is how often the step looks for the product's CA; zero means consoleWait.
	Poll time.Duration
}

// Issue makes or renews the console's pair and reports whether it wrote a certificate, with the
// certificate's SHA-256 fingerprint. It returns a Pending outcome while the product has not made its CA
// by ctx's deadline, and a Refused one for a state it will not repair by overwriting.
func (c ConsoleCertificate) Issue(ctx context.Context) (created bool, fingerprint string, err error) {
	data := c.Host.path(ProductDataDir)
	// The engine makes its CA, then its leaf: the leaf's presence says the CA pair is whole.
	caCert, caKey := filepath.Join(data, "tls.crt.ca"), filepath.Join(data, "tls.key.ca")
	if err := c.waitForProductCA(ctx, filepath.Join(data, "tls.crt"), caCert, caKey); err != nil {
		return false, "", err
	}
	dir := c.Host.path(ConsoleTLSDir)
	info, err := os.Stat(dir)
	switch {
	case errors.Is(err, os.ErrNotExist) || (err == nil && !info.IsDir()):
		return false, "", Refuse(ConsoleTLSDir + " does not exist; the appliance package creates it")
	case err != nil:
		return false, "", Refuse(ConsoleTLSDir + " cannot be read: " + err.Error())
	case info.Mode().Perm()&0o022 != 0 || !ownedByThisAccount(info):
		// The key is written into this directory: no other account may be able to put a file there first.
		return false, "", Refuse(ConsoleTLSDir + " is writable by group or others, or not owned by this account; first boot does not write a key into it")
	}
	cert, key := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if err := placeConsoleKey(dir, cert, key); err != nil {
		return false, "", err
	}
	created, fingerprint, err = secure.EnsureTLSCertSignedBy(cert, key, caCert, caKey)
	if err != nil {
		return false, "", Refuse("the console's certificate cannot be issued from the product's CA: " + err.Error())
	}
	return created, fingerprint, nil
}

func (c ConsoleCertificate) waitForProductCA(ctx context.Context, files ...string) error {
	poll := c.Poll
	if poll <= 0 {
		poll = consoleWait
	}
	for {
		missing := ""
		for _, f := range files {
			info, err := os.Stat(f)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				// A file that is there but cannot be read is not one the product is still making.
				return Refuse("the product's local CA cannot be read: " + err.Error())
			}
			if err != nil || !info.Mode().IsRegular() {
				missing = f
				break
			}
		}
		if missing == "" {
			return nil
		}
		select {
		case <-ctx.Done():
			return Wait("the product has not made its local CA yet (" + filepath.Base(missing) + " is absent)")
		case <-time.After(poll):
		}
	}
}

// placeConsoleKey makes the console's key when there is none, under stagedConsoleKey, 0600 from its
// creation. A key already in place is kept: it is the console's, and a re-issue certifies it again. A
// certificate with no key is refused, because making a key would replace a certificate that may be the
// operator's.
func placeConsoleKey(dir, cert, key string) error {
	if info, err := os.Lstat(key); err == nil {
		if !info.Mode().IsRegular() {
			return Refuse(ConsoleTLSDir + "/tls.key is not a regular file; first boot does not replace it")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return Refuse("the console's key cannot be measured: " + err.Error())
	}
	if _, err := os.Lstat(cert); err == nil {
		return Refuse(ConsoleTLSDir + "/tls.crt exists without tls.key; first boot does not replace a certificate it did not issue with a new key")
	}
	pemKey, err := secure.NewTLSKeyPEM()
	if err != nil {
		return Refuse("no key could be generated for the console: " + err.Error())
	}
	staged := filepath.Join(dir, stagedConsoleKey)
	// O_TRUNC reuses a leftover of a run that stopped here, which first boot may not remove; the mode
	// is checked on the descriptor before anything is written, so a leftover wider than 0600 never
	// receives the key.
	f, err := os.OpenFile(staged, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return Refuse("the console's key cannot be staged: " + err.Error())
	}
	if info, err := f.Stat(); err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		_ = f.Close()
		return Refuse(ConsoleTLSDir + "/" + stagedConsoleKey + " is not a private regular file; remove it")
	}
	if _, err := f.Write(pemKey); err != nil {
		_ = f.Close()
		return Refuse("the console's key cannot be written: " + err.Error())
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return Refuse("the console's key cannot be flushed: " + err.Error())
	}
	if err := f.Close(); err != nil {
		return Refuse("the console's key cannot be closed: " + err.Error())
	}
	if err := os.Rename(staged, key); err != nil {
		return Refuse(fmt.Sprintf("the console's key cannot be placed: %v", err))
	}
	return nil
}
