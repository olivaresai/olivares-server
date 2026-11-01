// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package portal

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/olivaresai/olivares/appliance/layer/portal/audit"
)

const productSessionCookie = "__Host-olivares-session"
const maxProductBody = 64 << 10
const productCredential = "product.crt"
const networkAuditDirectory = "/var/lib/olivares-portal/operations/audit"

type productClient struct {
	endpoint string
	http     *http.Client
}

type productReply struct {
	status  int
	headers http.Header
	body    []byte
}

func newProductClient(certPEM []byte) (*productClient, error) {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		return nil, errors.New("product trust certificate unavailable")
	}
	transport := &http.Transport{
		Proxy:                  nil,
		TLSClientConfig:        &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    5 * time.Second,
		ResponseHeaderTimeout:  5 * time.Second,
		MaxResponseHeaderBytes: 16 << 10,
		MaxConnsPerHost:        8,
		MaxIdleConns:           8,
		MaxIdleConnsPerHost:    4,
		IdleConnTimeout:        time.Minute,
	}
	return &productClient{endpoint: "https://127.0.0.1:8443", http: &http.Client{
		Transport: transport, Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

func productionNetworkAccess(credentials string) (networkAccess, error) {
	if credentials == "" {
		return networkAccess{}, errors.New("product trust credential unavailable")
	}
	certPEM, err := readRegularFile(filepath.Join(credentials, productCredential))
	if err != nil {
		return networkAccess{}, errors.New("product trust credential unavailable")
	}
	product, err := newProductClient(certPEM)
	if err != nil {
		return networkAccess{}, err
	}
	if err := os.MkdirAll(networkAuditDirectory, 0o700); err != nil {
		return networkAccess{}, errors.New("network audit unavailable")
	}
	records, err := audit.Open(networkAuditDirectory)
	if err != nil {
		return networkAccess{}, errors.New("network audit unavailable")
	}
	return networkAccess{product: product, records: records}, nil
}

func (p *productClient) request(source *http.Request, method, path string, body []byte) (productReply, error) {
	request, err := http.NewRequestWithContext(source.Context(), method, p.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return productReply{}, errors.New("product authentication unavailable")
	}
	// Preserve the browser origin for the native engine's same-origin check,
	// while URL (and TLS verification) stays fixed to the engine's loopback.
	request.Host = source.Host
	for _, key := range []string{"Authorization", "Origin", "Sec-Fetch-Site", "X-CSRF-Token", "X-Olivares-Session", "Content-Type"} {
		if value := source.Header.Get(key); value != "" {
			request.Header.Set(key, value)
		}
	}
	if cookie, err := source.Cookie(productSessionCookie); err == nil {
		request.AddCookie(&http.Cookie{Name: productSessionCookie, Value: cookie.Value})
	}
	response, err := p.http.Do(request)
	if err != nil {
		return productReply{}, errors.New("product authentication unavailable")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxProductBody+1))
	if err != nil || len(data) > maxProductBody || response.StatusCode < 200 || (response.StatusCode >= 300 && response.StatusCode < 400) {
		return productReply{}, errors.New("product authentication unavailable")
	}
	return productReply{status: response.StatusCode, headers: response.Header, body: data}, nil
}
