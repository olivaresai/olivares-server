// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/olivaresai/olivares/appliance/layer/helpers/helperschema"
)

// maxAdoptable bounds the certificates of the optional app the helper looks through, and maxLooked
// the directory entries it looks at to find them.
const (
	maxAdoptable = 64
	maxLooked    = 4096
)

// appCertificate is the name of a certificate directory under the app's live directory: the
// numbered directory Nginx Proxy Manager gives each certificate it obtains.
var appCertificate = regexp.MustCompile(`^npm-[0-9]{1,6}$`)

// adopt installs, as the portal's pair, the certificate Nginx Proxy Manager obtained from an ACME
// certificate authority (Let's Encrypt) for this host's origin. The helper looks in the app's own
// certificate directory, which no document names, and takes the certificate that names the origin
// the host states now, is valid now, chains to a root the host trusts and pairs with its key; of
// several it takes the one that stays valid longest. Nothing is replaced unless one
// qualifies. A renewal is another adopt: the app renews in its directory and this copies the result.
func (e env) adopt() helperschema.Response {
	if e.Facts == nil || e.AppCertRoot == "" || e.Now == nil {
		return failed("the host's facts or the app's certificate directory are not wired; nothing was adopted")
	}
	origin, err := e.Facts.Origin()
	if err != nil || !dnsName(origin) {
		return refused(helperschema.CodeInputRefused, "the host states no portal origin that is a host name; nothing was adopted")
	}
	origin = strings.ToLower(origin)
	root, err := os.OpenRoot(e.AppCertRoot)
	if errors.Is(err, fs.ErrNotExist) {
		return refused(helperschema.CodeInputRefused, "the app has obtained no certificate; nothing was adopted")
	}
	if err != nil {
		return failed("the app's certificate directory cannot be opened; nothing was adopted")
	}
	defer root.Close()
	names, err := certificateDirectories(root)
	if errors.Is(err, fs.ErrNotExist) {
		return refused(helperschema.CodeInputRefused, "the app has obtained no certificate; nothing was adopted")
	}
	if err != nil {
		return failed("the app's certificate directory cannot be read within its bound; nothing was adopted")
	}
	now := e.Now()
	var certPEM, keyPEM []byte
	var latest time.Time
	for _, name := range names {
		candidateCert, errCert := readInRoot(root, "live/"+name+"/fullchain.pem", false)
		candidateKey, errKey := readInRoot(root, "live/"+name+"/privkey.pem", true)
		if errCert != nil || errKey != nil {
			continue
		}
		expires, ok := qualifies(candidateCert, candidateKey, origin, now, e.Roots)
		if ok && expires.After(latest) {
			certPEM, keyPEM, latest = candidateCert, candidateKey, expires
		}
	}
	if certPEM == nil {
		return refused(helperschema.CodeInputRefused, "no certificate of the app names this host's origin, is valid now, chains to a root the host trusts and pairs with its key; nothing was adopted")
	}
	if err := writePair(e.TLSDir, certPEM, keyPEM); err != nil {
		return failed("the pair could not be installed; the portal's previous pair is unchanged or refused by its custody check")
	}
	return helperschema.Response{Result: helperschema.ResultPerformed,
		Detail: "the certificate the app obtained for this host's origin was installed with its key"}
}

// qualifies reports whether certPEM and keyPEM are certificates and the key that pairs with the
// first of them, whose leaf names origin as a server certificate and chains, through the rest, to a
// root in roots (the host's own roots when nil) at now, and when it does, the leaf's expiry. The
// app's directory is its container's to write, so nothing in it is taken on its own word: a
// self-issued leaf or one from an authority the host does not trust does not qualify.
func qualifies(certPEM, keyPEM []byte, origin string, now time.Time, roots *x509.CertPool) (time.Time, bool) {
	if !onlyCertificates(certPEM) {
		return time.Time{}, false
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return time.Time{}, false
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return time.Time{}, false
	}
	intermediates := x509.NewCertPool()
	for _, der := range pair.Certificate[1:] {
		if c, err := x509.ParseCertificate(der); err == nil {
			intermediates.AddCert(c)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: origin, Roots: roots, Intermediates: intermediates, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return time.Time{}, false
	}
	return leaf.NotAfter, true
}

// certificateDirectories returns the names of the numbered certificate directories under live, at
// most maxAdoptable of them. Other entries are skipped, but only a bounded number are looked at, so
// a directory the app's container fills with anything else cannot make the helper read forever.
func certificateDirectories(root *os.Root) ([]string, error) {
	live, err := root.Open("live")
	if err != nil {
		return nil, err
	}
	defer live.Close()
	var names []string
	for looked := 0; looked < maxLooked; {
		entries, err := live.ReadDir(64)
		for _, entry := range entries {
			looked++
			if entry.IsDir() && appCertificate.MatchString(entry.Name()) {
				if len(names) == maxAdoptable {
					return nil, errors.New("too many certificates")
				}
				names = append(names, entry.Name())
			}
		}
		if errors.Is(err, io.EOF) {
			return names, nil
		}
		if err != nil {
			return nil, err
		}
	}
	return nil, errors.New("too many entries")
}

// readInRoot reads name under root: a regular file of at most 64 KiB, the same file when opened as
// when measured. A link is followed only inside root, which is how the app's live directory points
// at its archive; one that leaves root is refused. When private is set the file must also be
// readable by its owner alone.
func readInRoot(root *os.Root, name string, private bool) ([]byte, error) {
	// O_NONBLOCK: a FIFO the app's container planted in its place must fail the regular-file check
	// below, not hold this open until the unit's time runs out.
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxPEMBytes || private && info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("not a protected regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxPEMBytes+1))
	if err != nil || len(data) > maxPEMBytes {
		return nil, errors.New("unreadable")
	}
	return data, nil
}
