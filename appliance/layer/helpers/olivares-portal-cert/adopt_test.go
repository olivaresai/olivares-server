// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/olivaresai/olivares/appliance/layer/helpers/helperschema"
)

// authority is a certificate authority that issues the leaves a case needs.
type authority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newAuthority(t *testing.T) authority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: testNow.Add(-48 * time.Hour), NotAfter: testNow.Add(48 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return authority{cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (a authority) pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(a.cert)
	return pool
}

// issue returns the chain (leaf then authority) and the leaf's key for names, valid from notBefore to notAfter.
func (a authority) issue(t *testing.T, serial int64, notBefore, notAfter time.Time, names ...string) (chainPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, a.cert, &key.PublicKey, a.key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	leaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return append(leaf, a.pem...), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
}

// obtain places a certificate in the app's directory the way the app does: the live files are links
// to numbered files in its archive.
func obtain(t *testing.T, e env, id string, chainPEM, keyPEM []byte, keyMode os.FileMode) {
	t.Helper()
	archive := filepath.Join(e.AppCertRoot, "archive", id)
	live := filepath.Join(e.AppCertRoot, "live", id)
	for _, dir := range []string{archive, live} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, file := range map[string]struct {
		data []byte
		mode os.FileMode
	}{"fullchain": {chainPEM, 0o644}, "privkey": {keyPEM, keyMode}} {
		if err := os.WriteFile(filepath.Join(archive, name+"1.pem"), file.data, file.mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(archive, name+"1.pem"), file.mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join("..", "..", "archive", id, name+"1.pem"), filepath.Join(live, name+".pem")); err != nil {
			t.Fatal(err)
		}
	}
}

// adoptEnv is the helper's environment for a host named origin that trusts the authority ca.
func adoptEnv(t *testing.T, origin string, ca authority) env {
	t.Helper()
	e := newEnv(t, &facts{origin: origin})
	e.AppCertRoot = filepath.Join(t.TempDir(), "letsencrypt")
	e.Roots = ca.pool()
	if err := os.MkdirAll(filepath.Join(e.AppCertRoot, "live"), 0o755); err != nil {
		t.Fatal(err)
	}
	return e
}

func adopt(e env) helperschema.Response {
	return helper(e).Perform(context.Background(), helperschema.Peer{}, &helperschema.CertRequest{Op: helperschema.CertAdopt, OperationID: testOperationID})
}

func TestCertHelper_AdoptInstallsTheCertificateTheAppObtainedForTheOrigin(t *testing.T) {
	ca := newAuthority(t)
	day := 24 * time.Hour

	t.Run("the pair the app obtained is installed through its archive links", func(t *testing.T) {
		e := adoptEnv(t, "Console.Example.Test", ca)
		chain, key := ca.issue(t, 10, testNow.Add(-day), testNow.Add(60*day), "console.example.test")
		obtain(t, e, "npm-1", chain, key, 0o600)
		if response := adopt(e); response.Result != helperschema.ResultPerformed {
			t.Fatalf("adopt answered %+v", response)
		}
		gotCert, gotKey := installed(t, e)
		if !bytes.Equal(gotCert, chain) || !bytes.Equal(gotKey, key) {
			t.Fatal("the installed pair is not the app's chain and key")
		}
		for name, mode := range map[string]os.FileMode{"tls.crt": 0o644, "tls.key": 0o600} {
			if info, err := os.Stat(filepath.Join(e.TLSDir, name)); err != nil || info.Mode().Perm() != mode {
				t.Errorf("%s is %v (%v), want mode %v", name, info, err, mode)
			}
		}
	})

	t.Run("a wildcard certificate names a host one label below it, and no other", func(t *testing.T) {
		chain, key := ca.issue(t, 11, testNow.Add(-day), testNow.Add(60*day), "*.example.test")
		for origin, want := range map[string]string{"console.example.test": helperschema.ResultPerformed,
			"example.test": helperschema.ResultRefused, "a.b.example.test": helperschema.ResultRefused} {
			e := adoptEnv(t, origin, ca)
			obtain(t, e, "npm-2", chain, key, 0o600)
			if response := adopt(e); response.Result != want {
				t.Errorf("%s: adopt answered %+v, want %s", origin, response, want)
			}
		}
	})

	// The directory is listed in whatever order the file system gives, so the one that stays valid
	// longest sits first, in the middle and last in turn.
	t.Run("of several, the one that stays valid longest, wherever it is listed", func(t *testing.T) {
		for _, longest := range []string{"npm-1", "npm-2", "npm-3"} {
			e := adoptEnv(t, "console.example.test", ca)
			var want []byte
			for i, id := range []string{"npm-1", "npm-2", "npm-3"} {
				life := time.Duration(10+i) * day
				if id == longest {
					life = 80 * day
				}
				chain, key := ca.issue(t, int64(30+i), testNow.Add(-day), testNow.Add(life), "console.example.test")
				obtain(t, e, id, chain, key, 0o600)
				if id == longest {
					want = chain
				}
			}
			otherChain, otherKey := ca.issue(t, 40, testNow.Add(-day), testNow.Add(90*day), "other.example.test")
			obtain(t, e, "npm-4", otherChain, otherKey, 0o600)
			if response := adopt(e); response.Result != helperschema.ResultPerformed {
				t.Fatalf("adopt answered %+v", response)
			}
			if gotCert, _ := installed(t, e); !bytes.Equal(gotCert, want) {
				t.Errorf("with %s longest, the installed certificate is not the one that stays valid longest for the origin", longest)
			}
		}
	})

	t.Run("a certificate the host can adopt is skipped for the next when its key is readable by others", func(t *testing.T) {
		e := adoptEnv(t, "console.example.test", ca)
		longChain, longKey := ca.issue(t, 50, testNow.Add(-day), testNow.Add(80*day), "console.example.test")
		shortChain, shortKey := ca.issue(t, 51, testNow.Add(-day), testNow.Add(10*day), "console.example.test")
		obtain(t, e, "npm-1", longChain, longKey, 0o644)
		obtain(t, e, "npm-2", shortChain, shortKey, 0o600)
		if response := adopt(e); response.Result != helperschema.ResultPerformed {
			t.Fatalf("adopt answered %+v", response)
		}
		if gotCert, _ := installed(t, e); !bytes.Equal(gotCert, shortChain) {
			t.Fatal("the installed certificate is not the one whose key is private")
		}
	})
}

// A certificate the helper refuses leaves the portal's pair as it was, and the refusal says why.
func TestCertHelper_AdoptRefusesWhatIsNotATrustedCertificateForTheOriginAndChangesNothing(t *testing.T) {
	ca := newAuthority(t)
	stranger := newAuthority(t)
	day := 24 * time.Hour
	selfChain, selfKey := selfSigned(t, "console.example.test")
	goodChain, goodKey := ca.issue(t, 20, testNow.Add(-day), testNow.Add(60*day), "console.example.test")
	_, otherKey := ca.issue(t, 21, testNow.Add(-day), testNow.Add(60*day), "console.example.test")
	expiredChain, expiredKey := ca.issue(t, 22, testNow.Add(-3*day), testNow.Add(-day), "console.example.test")
	futureChain, futureKey := ca.issue(t, 23, testNow.Add(day), testNow.Add(60*day), "console.example.test")
	untrustedChain, untrustedKey := stranger.issue(t, 24, testNow.Add(-day), testNow.Add(60*day), "console.example.test")
	const none = "no certificate of the app names this host's origin"

	for name, c := range map[string]struct {
		chain, key []byte
		keyMode    os.FileMode
		origin     string
	}{
		"a self-signed certificate":                        {selfChain, selfKey, 0o600, "console.example.test"},
		"a certificate from an authority the host rejects": {untrustedChain, untrustedKey, 0o600, "console.example.test"},
		"an expired certificate":                           {expiredChain, expiredKey, 0o600, "console.example.test"},
		"a certificate not yet valid":                      {futureChain, futureKey, 0o600, "console.example.test"},
		"another host's certificate":                       {goodChain, goodKey, 0o600, "elsewhere.example.test"},
		"a key that does not pair":                         {goodChain, otherKey, 0o600, "console.example.test"},
		"a key others can read":                            {goodChain, goodKey, 0o644, "console.example.test"},
		"a chain that holds a key":                         {append(append([]byte{}, goodChain...), goodKey...), goodKey, 0o600, "console.example.test"},
	} {
		t.Run(name, func(t *testing.T) {
			e := adoptEnv(t, c.origin, ca)
			previousCert, previousKey := selfSigned(t, "previous.example.test")
			if err := os.WriteFile(filepath.Join(e.TLSDir, "tls.crt"), previousCert, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(e.TLSDir, "tls.key"), previousKey, 0o600); err != nil {
				t.Fatal(err)
			}
			obtain(t, e, "npm-1", c.chain, c.key, c.keyMode)
			if response := adopt(e); response.Result != helperschema.ResultRefused || !strings.Contains(response.Detail, none) {
				t.Fatalf("adopt answered %+v, want a refusal that says %q", response, none)
			}
			if gotCert, gotKey := installed(t, e); !bytes.Equal(gotCert, previousCert) || !bytes.Equal(gotKey, previousKey) {
				t.Fatal("a refused adopt replaced the portal's pair")
			}
		})
	}

	t.Run("a link that leaves the app's directory", func(t *testing.T) {
		e := adoptEnv(t, "console.example.test", ca)
		outside := t.TempDir()
		if err := os.WriteFile(filepath.Join(outside, "privkey.pem"), goodKey, 0o600); err != nil {
			t.Fatal(err)
		}
		obtain(t, e, "npm-1", goodChain, goodKey, 0o600)
		live := filepath.Join(e.AppCertRoot, "live", "npm-1", "privkey.pem")
		if err := os.Remove(live); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(outside, "privkey.pem"), live); err != nil {
			t.Fatal(err)
		}
		if response := adopt(e); response.Result != helperschema.ResultRefused || !strings.Contains(response.Detail, none) {
			t.Fatalf("a key outside the app's directory answered %+v, want a refusal", response)
		}
		if _, err := os.Stat(filepath.Join(e.TLSDir, "tls.crt")); err == nil {
			t.Fatal("a refused adopt installed a certificate")
		}
	})

	t.Run("an app that has obtained nothing", func(t *testing.T) {
		e := adoptEnv(t, "console.example.test", ca)
		if response := adopt(e); response.Result != helperschema.ResultRefused || !strings.Contains(response.Detail, none) {
			t.Fatalf("an empty directory answered %+v, want a refusal", response)
		}
		e.AppCertRoot = filepath.Join(t.TempDir(), "absent")
		if response := adopt(e); response.Result != helperschema.ResultRefused || !strings.Contains(response.Detail, "obtained no certificate") {
			t.Fatalf("an absent directory answered %+v, want a refusal", response)
		}
	})

	t.Run("a host that states no origin", func(t *testing.T) {
		e := adoptEnv(t, "", ca)
		obtain(t, e, "npm-1", goodChain, goodKey, 0o600)
		if response := adopt(e); response.Result != helperschema.ResultRefused || !strings.Contains(response.Detail, "no portal origin") {
			t.Fatalf("no origin answered %+v, want a refusal that says so", response)
		}
	})

	t.Run("the portal's directory is not protected", func(t *testing.T) {
		e := adoptEnv(t, "console.example.test", ca)
		obtain(t, e, "npm-1", goodChain, goodKey, 0o600)
		if err := os.Chmod(e.TLSDir, 0o777); err != nil {
			t.Fatal(err)
		}
		if response := adopt(e); response.Result != helperschema.ResultFailed {
			t.Fatalf("an unprotected directory answered %+v, want a failure", response)
		}
		if _, err := os.Stat(filepath.Join(e.TLSDir, "tls.crt")); err == nil {
			t.Fatal("a failed adopt installed a certificate")
		}
	})
}

// What the app's container can plant in its directory cannot hold the helper or hide a real certificate.
func TestCertHelper_AdoptIsNotHeldByWhatTheAppPlants(t *testing.T) {
	ca := newAuthority(t)
	day := 24 * time.Hour
	chain, key := ca.issue(t, 60, testNow.Add(-day), testNow.Add(60*day), "console.example.test")

	t.Run("a FIFO in place of a certificate is skipped, not waited on", func(t *testing.T) {
		e := adoptEnv(t, "console.example.test", ca)
		obtain(t, e, "npm-2", chain, key, 0o600)
		if err := os.MkdirAll(filepath.Join(e.AppCertRoot, "live", "npm-1"), 0o755); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"fullchain.pem", "privkey.pem"} {
			if err := syscall.Mkfifo(filepath.Join(e.AppCertRoot, "live", "npm-1", name), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		done := make(chan helperschema.Response, 1)
		go func() { done <- adopt(e) }()
		select {
		case response := <-done:
			if response.Result != helperschema.ResultPerformed {
				t.Fatalf("adopt answered %+v, want the real certificate installed", response)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("adopt waits on a FIFO")
		}
	})

	t.Run("entries that are not certificate directories neither count nor hide one", func(t *testing.T) {
		e := adoptEnv(t, "console.example.test", ca)
		obtain(t, e, "npm-1", chain, key, 0o600)
		live := filepath.Join(e.AppCertRoot, "live")
		for i := 0; i < maxAdoptable+10; i++ {
			if err := os.WriteFile(filepath.Join(live, fmt.Sprintf("junk-%d", i)), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		obtain(t, e, "other-1", chain, key, 0o600)
		if response := adopt(e); response.Result != helperschema.ResultPerformed {
			t.Fatalf("adopt answered %+v, want the numbered certificate installed", response)
		}
	})

	t.Run("a certificate under a name the app does not give its certificates is not read", func(t *testing.T) {
		e := adoptEnv(t, "console.example.test", ca)
		obtain(t, e, "other-1", chain, key, 0o600)
		obtain(t, e, "npm-1234567", chain, key, 0o600)
		if response := adopt(e); response.Result != helperschema.ResultRefused {
			t.Fatalf("adopt answered %+v, want a refusal", response)
		}
	})

	t.Run("more certificate directories than the helper looks through", func(t *testing.T) {
		e := adoptEnv(t, "console.example.test", ca)
		for i := 0; i <= maxAdoptable; i++ {
			if err := os.MkdirAll(filepath.Join(e.AppCertRoot, "live", fmt.Sprintf("npm-%d", i+1)), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if response := adopt(e); response.Result != helperschema.ResultFailed {
			t.Fatalf("adopt answered %+v, want a failure", response)
		}
	})
}

// The helper reads the directory the app writes: the paths of the three parties agree.
func TestCertHelper_AdoptReadsWhereTheAppsHelperKeepsTheCertificates(t *testing.T) {
	unit, err := os.ReadFile(filepath.Join("..", "..", "optionalapps", "units", "olivares-helper-apps@.service"))
	if err != nil {
		t.Fatal(err)
	}
	state := regexp.MustCompile(`(?m)^StateDirectory=(.+)$`).FindSubmatch(unit)
	manifest, err := os.ReadFile(filepath.Join("..", "..", "optionalapps", "nginx-proxy-manager.json"))
	if err != nil {
		t.Fatal(err)
	}
	if state == nil || !bytes.Contains(manifest, []byte(`"source": "./letsencrypt", "target": "/etc/letsencrypt"`)) {
		t.Fatalf("the apps unit names no state directory (%q) or the manifest keeps the certificates elsewhere", state)
	}
	// The unit lists one state directory per app; Nginx Proxy Manager's is the one ending in its name.
	var npm string
	for _, dir := range strings.Fields(string(state[1])) {
		if filepath.Base(dir) == "nginx-proxy-manager" {
			npm = dir
		}
	}
	if want := "/var/lib/" + npm + "/letsencrypt"; npm == "" || appliance().AppCertRoot != want {
		t.Fatalf("adopt reads %s, the app keeps its certificates in %s (state directories %q)", appliance().AppCertRoot, want, state[1])
	}
}

func TestCertHelper_AdoptTakesNoFieldAndIsTheRepairConsolesAlone(t *testing.T) {
	for _, field := range []string{`"path": "/etc/shadow"`, `"nonce": "` + strings.Repeat("a", 64) + `"`, `"key_ref": "store:portal"`, `"origin": "evil.test"`} {
		document := `{"op": "adopt", "operation_id": "` + testOperationID + `", ` + field + `}`
		if err := helperschema.Decode(strings.NewReader(document), &helperschema.CertRequest{}); err == nil {
			t.Errorf("adopt accepted %s", field)
		}
	}
	if err := helperschema.Decode(strings.NewReader(`{"op": "adopt"}`), &helperschema.CertRequest{}); err == nil {
		t.Error("adopt without an operation id was accepted")
	}
	if err := helperschema.Decode(strings.NewReader(`{"op": "adopt", "operation_id": "`+testOperationID+`"}`), &helperschema.CertRequest{}); err != nil {
		t.Errorf("adopt as the client marshals it: %v", err)
	}
}
