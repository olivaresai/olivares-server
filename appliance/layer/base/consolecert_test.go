// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package base

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/olivaresai/olivares/core/secure"
)

// engineStarted makes the pair the product creates at its first start in root's data directory, with
// its local CA beside it, and returns the host that holds it.
func engineStarted(t *testing.T) Host {
	t.Helper()
	host := Host{Root: t.TempDir()}
	dir := host.path(ProductDataDir)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, _, err := secure.EnsureTLSCert(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")); err != nil {
		t.Fatal(err)
	}
	return host
}

func consoleDir(t *testing.T, host Host) string {
	t.Helper()
	dir := host.path(ConsoleTLSDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// selfSignedPair is the pair `olivares-portal-cert generate` makes, or an operator installs: a
// certificate no local CA signed.
func selfSignedPair(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "operator.example"},
		DNSNames: []string{"operator.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func read(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// The Appliance Console's certificate is signed by the product's own local CA, for the names the
// product's certificate carries, so the operator trusts one CA for both consoles.
func TestConsoleCertificateIsSignedByTheProductsLocalCA(t *testing.T) {
	host := engineStarted(t)
	dir := consoleDir(t, host)
	created, fingerprint, err := ConsoleCertificate{Host: host}.Issue(context.Background())
	if err != nil || !created || fingerprint == "" {
		t.Fatalf("created=%v fingerprint=%q: %v", created, fingerprint, err)
	}
	pair, err := tls.LoadX509KeyPair(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(read(t, host.path(ProductDataDir+"/tls.crt.ca"))) {
		t.Fatal("no product CA")
	}
	names := []string{"localhost", "127.0.0.1", "::1"}
	if name, err := os.Hostname(); err == nil && name != "" {
		names = append(names, name)
	}
	for _, name := range names {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: name}); err != nil {
			t.Errorf("the product's CA does not verify %q: %v", name, err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "tls.crt" && e.Name() != "tls.key" {
			t.Errorf("first boot left %s beside the pair", e.Name())
		}
	}
	if info, err := os.Stat(filepath.Join(dir, "tls.key")); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the console's key: %v, %v", info, err)
	}
}

// Running again with the same host names changes nothing: the pair is kept, not re-issued at each start.
func TestConsoleCertificateIsKeptWhenNothingChanged(t *testing.T) {
	host := engineStarted(t)
	dir := consoleDir(t, host)
	if _, _, err := (ConsoleCertificate{Host: host}).Issue(context.Background()); err != nil {
		t.Fatal(err)
	}
	cert, key := read(t, filepath.Join(dir, "tls.crt")), read(t, filepath.Join(dir, "tls.key"))
	created, _, err := ConsoleCertificate{Host: host}.Issue(context.Background())
	if err != nil || created {
		t.Fatalf("created=%v: %v", created, err)
	}
	if !bytes.Equal(cert, read(t, filepath.Join(dir, "tls.crt"))) || !bytes.Equal(key, read(t, filepath.Join(dir, "tls.key"))) {
		t.Error("an unchanged host was re-issued")
	}
}

// The key is written under the fixed name tls.key.new and renamed into place: that name is the one the
// SELinux policy labels olivares_portal_key_t when first boot creates it. A leftover of a run that
// stopped there is overwritten, never certified.
func TestConsoleKeyIsStagedUnderItsLabeledName(t *testing.T) {
	host := engineStarted(t)
	dir := consoleDir(t, host)
	if err := os.WriteFile(filepath.Join(dir, "tls.key.new"), []byte("half a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := (ConsoleCertificate{Host: host}).Issue(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "tls.key.new")); !os.IsNotExist(err) {
		t.Errorf("the staged key was not renamed into place: %v", err)
	}
	if _, err := tls.LoadX509KeyPair(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")); err != nil {
		t.Errorf("the pair does not load: %v", err)
	}
}

// A leftover that is not private to its owner is refused: the key must never exist wider than 0600.
func TestConsoleKeyRefusesAWideStagingFile(t *testing.T) {
	host := engineStarted(t)
	dir := consoleDir(t, host)
	staged := filepath.Join(dir, "tls.key.new")
	if err := os.WriteFile(staged, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(staged, 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err := ConsoleCertificate{Host: host}.Issue(context.Background())
	var outcome *Outcome
	if !errors.As(err, &outcome) || outcome.State != Refused {
		t.Fatalf("want a refusal, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "tls.key")); !os.IsNotExist(err) {
		t.Errorf("a key was installed from a wide staging file: %v", err)
	}
	if len(read(t, staged)) != 0 {
		t.Error("the wide staging file received the key")
	}
}

// The staging name is opened without following a link: a link there is refused and its target is left alone.
func TestConsoleKeyDoesNotFollowALinkAtItsStagingName(t *testing.T) {
	host := engineStarted(t)
	dir := consoleDir(t, host)
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(target, []byte("not the key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "tls.key.new")); err != nil {
		t.Fatal(err)
	}
	_, _, err := ConsoleCertificate{Host: host}.Issue(context.Background())
	var outcome *Outcome
	if !errors.As(err, &outcome) || outcome.State != Refused {
		t.Fatalf("want a refusal, got %v", err)
	}
	if string(read(t, target)) != "not the key" {
		t.Error("the link's target was written through")
	}
}

// A key that is not a regular file is not a key first boot replaces: the operator's certificate stays.
func TestConsoleCertificateRefusesAKeyThatIsNotARegularFile(t *testing.T) {
	host := engineStarted(t)
	dir := consoleDir(t, host)
	certPEM, _ := selfSignedPair(t)
	if err := os.WriteFile(filepath.Join(dir, "tls.crt"), certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "nowhere"), filepath.Join(dir, "tls.key")); err != nil {
		t.Fatal(err)
	}
	_, _, err := ConsoleCertificate{Host: host}.Issue(context.Background())
	var outcome *Outcome
	if !errors.As(err, &outcome) || outcome.State != Refused {
		t.Fatalf("want a refusal, got %v", err)
	}
	if !bytes.Equal(certPEM, read(t, filepath.Join(dir, "tls.crt"))) {
		t.Error("the operator's certificate was overwritten")
	}
}

// A key already in place with no certificate (a run that stopped between the two) is the key certified.
func TestConsoleCertificateCertifiesAKeyAlreadyInPlace(t *testing.T) {
	host := engineStarted(t)
	dir := consoleDir(t, host)
	keyPEM, err := secure.NewTLSKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tls.key"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	created, _, err := ConsoleCertificate{Host: host}.Issue(context.Background())
	if err != nil || !created {
		t.Fatalf("created=%v: %v", created, err)
	}
	if !bytes.Equal(keyPEM, read(t, filepath.Join(dir, "tls.key"))) {
		t.Error("the key in place was replaced")
	}
	if _, err := tls.LoadX509KeyPair(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")); err != nil {
		t.Errorf("the pair does not load: %v", err)
	}
}

// A certificate with a key that is not its own, or a key others can read, is refused and nothing is replaced.
func TestConsoleCertificateRefusesAKeyThatDoesNotFitOrIsTooOpen(t *testing.T) {
	for _, tc := range []struct {
		name    string
		withCrt bool
		mode    os.FileMode
	}{
		{"another key than the certificate's", true, 0o600},
		{"a key others can read", false, 0o644},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := engineStarted(t)
			dir := consoleDir(t, host)
			certPEM, _ := selfSignedPair(t)
			_, otherKey := selfSignedPair(t)
			if tc.withCrt {
				if err := os.WriteFile(filepath.Join(dir, "tls.crt"), certPEM, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(dir, "tls.key"), otherKey, tc.mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(filepath.Join(dir, "tls.key"), tc.mode); err != nil {
				t.Fatal(err)
			}
			_, _, err := ConsoleCertificate{Host: host}.Issue(context.Background())
			var outcome *Outcome
			if !errors.As(err, &outcome) || outcome.State != Refused {
				t.Fatalf("want a refusal, got %v", err)
			}
			if tc.withCrt && !bytes.Equal(certPEM, read(t, filepath.Join(dir, "tls.crt"))) {
				t.Error("the certificate was overwritten")
			}
			if !tc.withCrt {
				if _, err := os.Stat(filepath.Join(dir, "tls.crt")); !os.IsNotExist(err) {
					t.Errorf("a certificate was written for a key others can read: %v", err)
				}
			}
		})
	}
}

// The CA is whole only when its certificate, its key and the leaf the engine makes last are all there.
func TestConsoleCertificateWaitsForEachFileOfTheProductsCA(t *testing.T) {
	for _, missing := range []string{"tls.crt", "tls.crt.ca", "tls.key.ca"} {
		t.Run(missing, func(t *testing.T) {
			host := engineStarted(t)
			dir := consoleDir(t, host)
			if err := os.Remove(host.path(ProductDataDir + "/" + missing)); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			_, _, err := ConsoleCertificate{Host: host, Poll: 10 * time.Millisecond}.Issue(ctx)
			var outcome *Outcome
			if !errors.As(err, &outcome) || outcome.State != Pending {
				t.Fatalf("want pending, got %v", err)
			}
			if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
				t.Fatalf("files written before the CA was whole: %v, %v", entries, err)
			}
		})
	}
}

// A CA file that is there but cannot be read is a refusal naming the cause, not four minutes of waiting.
func TestConsoleCertificateRefusesACAItCannotRead(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a directory its mode closes")
	}
	host := engineStarted(t)
	consoleDir(t, host)
	data := host.path(ProductDataDir)
	if err := os.Chmod(data, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(data, 0o750) })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	_, _, err := ConsoleCertificate{Host: host, Poll: 10 * time.Millisecond}.Issue(ctx)
	var outcome *Outcome
	if !errors.As(err, &outcome) || outcome.State != Refused {
		t.Fatalf("want a refusal, got %v", err)
	}
	if time.Since(start) > time.Second {
		t.Errorf("the refusal came after %v: it waited", time.Since(start))
	}
}

// The key is written into the console's directory: one another account can write is not used.
func TestConsoleCertificateRefusesADirectoryOthersCanWrite(t *testing.T) {
	host := engineStarted(t)
	dir := consoleDir(t, host)
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	_, _, err := ConsoleCertificate{Host: host}.Issue(context.Background())
	var outcome *Outcome
	if !errors.As(err, &outcome) || outcome.State != Refused {
		t.Fatalf("want a refusal, got %v", err)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Fatalf("files written into the open directory: %v, %v", entries, err)
	}
}

// A pair the operator installed, or made on request, is not replaced.
func TestConsoleCertificateLeavesAnOperatorsPairIntact(t *testing.T) {
	host := engineStarted(t)
	dir := consoleDir(t, host)
	certPEM, keyPEM := selfSignedPair(t)
	if err := os.WriteFile(filepath.Join(dir, "tls.crt"), certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tls.key"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	cert, key := read(t, filepath.Join(dir, "tls.crt")), read(t, filepath.Join(dir, "tls.key"))
	created, _, err := ConsoleCertificate{Host: host}.Issue(context.Background())
	if err != nil || created {
		t.Fatalf("created=%v: %v", created, err)
	}
	if !bytes.Equal(cert, read(t, filepath.Join(dir, "tls.crt"))) || !bytes.Equal(key, read(t, filepath.Join(dir, "tls.key"))) {
		t.Error("the operator's pair was replaced")
	}
}

// A certificate without its key is a state first boot does not repair by overwriting the certificate.
func TestConsoleCertificateRefusesACertificateWithoutItsKey(t *testing.T) {
	host := engineStarted(t)
	dir := consoleDir(t, host)
	cert := []byte("an installed certificate")
	if err := os.WriteFile(filepath.Join(dir, "tls.crt"), cert, 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err := ConsoleCertificate{Host: host}.Issue(context.Background())
	var outcome *Outcome
	if !errors.As(err, &outcome) || outcome.State != Refused {
		t.Fatalf("want a refusal, got %v", err)
	}
	if !bytes.Equal(cert, read(t, filepath.Join(dir, "tls.crt"))) {
		t.Error("the certificate was overwritten")
	}
}

// First boot waits for the product's first start, which makes the CA, and writes nothing before it.
func TestConsoleCertificateWaitsForTheProductsCA(t *testing.T) {
	host := Host{Root: t.TempDir()}
	dir := consoleDir(t, host)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	_, _, err := ConsoleCertificate{Host: host, Poll: 10 * time.Millisecond}.Issue(ctx)
	var outcome *Outcome
	if !errors.As(err, &outcome) || outcome.State != Pending {
		t.Fatalf("want pending, got %v", err)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Fatalf("files written before the CA existed: %v, %v", entries, err)
	}
}

func TestConsoleCertificateIssuesOnceTheProductHasStarted(t *testing.T) {
	started := engineStarted(t)
	host := Host{Root: t.TempDir()}
	dir := consoleDir(t, host)
	go func() {
		time.Sleep(60 * time.Millisecond)
		// The product's first start lands in the data directory the step watches.
		src := started.path(ProductDataDir)
		dst := host.path(ProductDataDir)
		_ = os.MkdirAll(dst, 0o750)
		// Each file lands whole, as the product's own writes do, the leaf last.
		for _, name := range []string{"tls.key.ca", "tls.crt.ca", "tls.key", "tls.crt"} {
			if data, err := os.ReadFile(filepath.Join(src, name)); err == nil {
				_ = os.WriteFile(filepath.Join(dst, name+".part"), data, 0o600)
				_ = os.Rename(filepath.Join(dst, name+".part"), filepath.Join(dst, name))
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	created, _, err := ConsoleCertificate{Host: host, Poll: 10 * time.Millisecond}.Issue(ctx)
	if err != nil || !created {
		t.Fatalf("created=%v: %v", created, err)
	}
	if _, err := tls.LoadX509KeyPair(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")); err != nil {
		t.Errorf("the pair does not load: %v", err)
	}
}

// First boot does not create the console's directory: the package does, and the unit may not.
func TestConsoleCertificateRefusesWithoutTheConsolesDirectory(t *testing.T) {
	host := engineStarted(t)
	_, _, err := ConsoleCertificate{Host: host}.Issue(context.Background())
	var outcome *Outcome
	if !errors.As(err, &outcome) || outcome.State != Refused {
		t.Fatalf("want a refusal, got %v", err)
	}
	if _, err := os.Stat(host.path(ConsoleTLSDir)); !os.IsNotExist(err) {
		t.Errorf("the directory was created: %v", err)
	}
}
