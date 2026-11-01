// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package portal

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/olivaresai/olivares/appliance/layer/portal/auth"
)

// holdUntilAbandoned is a native fixture that never answers. A client that times out sends
// close_notify before it closes the socket, so the handler can see the client leave while the
// client is still inside Get. Returning then makes net/http write an empty 200, and the transport
// hands a response that raced the cancel to the caller: the probe measured an answer. Aborting
// the response writes nothing.
func holdUntilAbandoned(_ http.ResponseWriter, r *http.Request) {
	<-r.Context().Done()
	panic(http.ErrAbortHandler)
}

func TestNativeProductProbe_VerifiedAnswersAndAmbiguity(t *testing.T) {
	probe := func(t *testing.T, client *productClient) auth.ProductProbe {
		t.Helper()
		value, ok := any(client).(auth.ProductProbe)
		if !ok {
			t.Fatal("native product client has no ProductProbe; the installed selector remains unmeasured")
		}
		return value
	}
	clientFor := func(t *testing.T, handler http.HandlerFunc) *productClient {
		t.Helper()
		native := httptest.NewTLSServer(handler)
		t.Cleanup(native.Close)
		public := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: native.Certificate().Raw})
		client, err := newProductClient(public)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(client.http.CloseIdleConnections)
		client.endpoint = native.URL
		t.Logf("native TLS fixture on own free port: %s", native.URL)
		return client
	}
	for _, status := range []int{http.StatusOK, http.StatusUnauthorized, http.StatusServiceUnavailable, http.StatusFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			client := clientFor(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/livez" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
					t.Errorf("probe must use anonymous native liveness: %s %s", r.Method, r.URL.Path)
				}
				if status == http.StatusFound {
					w.Header().Set("Location", "https://127.0.0.1:0/not-native")
				}
				w.WriteHeader(status)
			})
			if got := probe(t, client).MeasureProduct(); got != (auth.ProductMeasurement{Measured: true, Answers: true}) {
				t.Fatalf("verified HTTP %d answer measured as %+v", status, got)
			}
		})
	}
	t.Run("typed nil", func(t *testing.T) {
		var client *productClient
		if got := probe(t, client).MeasureProduct(); got != (auth.ProductMeasurement{}) {
			t.Fatalf("nil native client measured as %+v", got)
		}
		if got := auth.NewSelector(probe(t, client), nil).Select(); got.Mode != auth.Unavailable {
			t.Fatalf("missing native client opened %s", got.Mode)
		}
	})
	t.Run("missing HTTP client", func(t *testing.T) {
		if got := probe(t, &productClient{}).MeasureProduct(); got != (auth.ProductMeasurement{}) {
			t.Fatalf("absent transport measured as %+v", got)
		}
	})
	t.Run("connection refused", func(t *testing.T) {
		client := clientFor(t, func(http.ResponseWriter, *http.Request) {})
		client.endpoint = "https://127.0.0.1:0"
		if got := probe(t, client).MeasureProduct(); got != (auth.ProductMeasurement{Measured: true}) {
			t.Fatalf("definitely absent listener measured as %+v", got)
		}
	})
	t.Run("untrusted TLS", func(t *testing.T) {
		client := clientFor(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
		client.http.Transport.(*http.Transport).TLSClientConfig.RootCAs = x509.NewCertPool()
		if got := probe(t, client).MeasureProduct(); got != (auth.ProductMeasurement{}) {
			t.Fatalf("failed trust opened down mode: %+v", got)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		client := clientFor(t, holdUntilAbandoned)
		client.http.Timeout = 25 * time.Millisecond
		if got := probe(t, client).MeasureProduct(); got != (auth.ProductMeasurement{}) {
			t.Fatalf("timeout measured as %+v", got)
		}
	})
}

func TestHoldUntilAbandoned_NeverAnswers(t *testing.T) {
	entered := make(chan struct{}, 1)
	native := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		holdUntilAbandoned(w, r)
	}))
	t.Cleanup(native.Close)
	conn, err := net.DialTimeout("tcp", native.Listener.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if _, err := io.WriteString(conn, "GET /livez HTTP/1.1\r\nHost: native\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the fixture never received the request")
	}
	// While its client waits, the fixture holds the request open: no bytes, no close.
	if err := conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if n, err := conn.Read(make([]byte, 1)); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("fixture did not hold the request open: %d bytes, %v", n, err)
	}
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	// A clean close or a reset both mean "no answer"; only bytes or a hang fail.
	reply, err := io.ReadAll(conn)
	if len(reply) != 0 {
		t.Fatalf("fixture answered after its client gave up: %q", reply)
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("fixture neither answered nor closed after its client gave up")
	}
}
