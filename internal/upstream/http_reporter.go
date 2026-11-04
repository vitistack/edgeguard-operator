/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package upstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// defaultTimeout bounds a single upstream request.
const defaultTimeout = 10 * time.Second

// HTTPReporter is a scaffold Reporter that POSTs port reports to an external
// HTTP API as JSON.
//
// TODO(user): Adjust this to the real upstream contract:
//   - Confirm the request path and method the upstream API expects.
//   - Add authentication (mTLS, HMAC, ...) if the API requires it.
//   - Map the response body / status codes to retryable vs. terminal errors.
//   - Add tracing / metrics as needed.
type HTTPReporter struct {
	// BaseURL is the root URL of the upstream API, e.g. "https://ipam-api.vitistack.io/v2".
	// It is sourced from the UPSTREAM_API_URL environment variable; an empty value
	// means upstream reporting is not configured.
	BaseURL string
	// InsecureSkipVerify disables upstream TLS certificate verification. It is
	// opt-in via the UPSTREAM_INSECURE_SKIP_VERIFY environment variable and is only
	// intended for trusted dev/test mirrors with self-signed certificates.
	InsecureSkipVerify bool
	// Client is the HTTP client used for requests. If nil, a client with
	// defaultTimeout is used.
	Client *http.Client
}

// NewHTTPReporter builds an HTTPReporter for the given base URL. A zero-value
// baseURL yields a reporter that is not Configured and whose ReportPorts always
// errors, which callers should treat as a misconfiguration. When insecureSkipVerify
// is true the HTTP client skips upstream TLS verification (dev/test mirrors only).
func NewHTTPReporter(baseURL string, insecureSkipVerify bool) *HTTPReporter {
	// An empty CA bundle path never fails to load, so the error is safe to drop.
	r, _ := NewHTTPReporterWithCA(baseURL, insecureSkipVerify, "")
	return r
}

// NewHTTPReporterWithCA builds an HTTPReporter that trusts an additional CA bundle
// when verifying the upstream's TLS certificate, in addition to the system trust
// store. This is for upstreams fronted by a private/internal CA (the chart mounts
// such a bundle via manager.caBundle and points this at it with UPSTREAM_CA_BUNDLE).
//
// caBundlePath may be empty, in which case the system trust store is used unchanged.
// When insecureSkipVerify is true, verification is skipped entirely and the CA bundle
// is ignored. A non-empty caBundlePath that cannot be read or contains no valid
// certificates is a hard error, since silently falling back to the system store would
// mask the misconfiguration the operator is trying to fix.
func NewHTTPReporterWithCA(baseURL string, insecureSkipVerify bool, caBundlePath string) (*HTTPReporter, error) {
	client := &http.Client{Timeout: defaultTimeout}
	switch {
	case insecureSkipVerify:
		client.Transport = &http.Transport{
			// InsecureSkipVerify is gated behind an explicit opt-in env var and is
			// documented as dev/test-only, so disabling verification here is intentional.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // opt-in via UPSTREAM_INSECURE_SKIP_VERIFY
		}
	case caBundlePath != "":
		pool, err := loadCABundle(caBundlePath)
		if err != nil {
			return nil, err
		}
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		}
	}
	return &HTTPReporter{
		BaseURL:            baseURL,
		InsecureSkipVerify: insecureSkipVerify,
		Client:             client,
	}, nil
}

// loadCABundle builds a cert pool containing the system trust store plus the
// certificates found at path. path may be a single PEM file or a directory of PEM
// files (e.g. a whole ConfigMap mounted without subPath); in the directory case every
// regular file is read and Kubernetes atomic-writer artifacts (".."-prefixed entries
// such as "..data") and subdirectories are skipped. A path that cannot be read, or
// that yields no parseable certificates, is returned as an error.
func loadCABundle(path string) (*x509.CertPool, error) {
	files, err := caBundleFiles(path)
	if err != nil {
		return nil, err
	}
	// Start from the system pool so public roots still verify; fall back to an empty
	// pool if the system store is unavailable (e.g. a scratch image).
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	added := false
	for _, f := range files {
		// The path is operator-supplied configuration (the --upstream-ca-bundle flag /
		// UPSTREAM_CA_BUNDLE env var), not attacker-controlled input, so reading it is safe.
		pem, err := os.ReadFile(f) //nolint:gosec // G304: path is trusted operator config (UPSTREAM_CA_BUNDLE)
		if err != nil {
			return nil, fmt.Errorf("reading upstream CA bundle %q: %w", f, err)
		}
		if pool.AppendCertsFromPEM(pem) {
			added = true
		}
	}
	if !added {
		return nil, fmt.Errorf("upstream CA bundle %q contained no valid certificates", path)
	}
	return pool, nil
}

// caBundleFiles resolves path to the list of files to read: the path itself when it is
// a regular file, or every non-hidden regular file inside it when it is a directory.
func caBundleFiles(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("reading upstream CA bundle %q: %w", path, err)
	}
	if !info.IsDir() {
		return []string{path}, nil
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("reading upstream CA bundle directory %q: %w", path, err)
	}
	var files []string
	for _, e := range entries {
		name := e.Name()
		// Skip Kubernetes atomic-writer artifacts ("..data", "..<timestamp>") and any
		// other hidden entries.
		if len(name) > 0 && name[0] == '.' {
			continue
		}
		full := filepath.Join(path, name)
		// Stat follows symlinks (ConfigMap keys are symlinks into ..data); keep only
		// regular files.
		fi, err := os.Stat(full)
		if err != nil || fi.IsDir() {
			continue
		}
		files = append(files, full)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("upstream CA bundle directory %q contained no files", path)
	}
	return files, nil
}

// Configured reports whether the reporter has a BaseURL and can deliver reports.
// The controller uses this to surface an upstream-not-configured status instead
// of attempting a report that is guaranteed to fail.
func (h *HTTPReporter) Configured() bool {
	return h.BaseURL != ""
}

// ReportPorts implements Reporter by POSTing the report as JSON to
// <BaseURL>.
//
// TODO(user): This is scaffolding. Validate the endpoint path, auth, and
// response handling against the real upstream service before relying on it.
func (h *HTTPReporter) ReportPorts(ctx context.Context, report PortReport) error {
	return h.send(ctx, http.MethodPost, report)
}

// DeletePorts implements Reporter by sending an HTTP DELETE with the report body
// to <BaseURL>, withdrawing a previously reported port set when the
// policy or its target Service is removed.
func (h *HTTPReporter) DeletePorts(ctx context.Context, report PortReport) error {
	return h.send(ctx, http.MethodDelete, report)
}

// send marshals the report and issues a single request to the port-reports
// endpoint with the given HTTP method.
func (h *HTTPReporter) send(ctx context.Context, method string, report PortReport) error {
	if h.BaseURL == "" {
		return fmt.Errorf("upstream HTTPReporter has no BaseURL configured")
	}

	body, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("marshaling port report: %w", err)
	}

	// TODO(user): confirm the real endpoint path and method.
	endpoint := h.BaseURL
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building upstream request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// Idempotency-Key lets the upstream dedupe retries and duplicates (e.g. a
	// report re-sent after a reconcile conflict): identical policy/ports/IPs yield
	// the same key. TODO(user): confirm the header name the upstream expects.
	req.Header.Set("Idempotency-Key", report.IdempotencyKey())

	client := h.Client
	if client == nil {
		client = &http.Client{Timeout: defaultTimeout}
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("sending port report upstream: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Any 2xx status counts as the report being accepted. A 4xx is a client error:
	// the upstream refused the request and it will not succeed if retried unchanged,
	// so it is reported as the terminal ErrUpstreamRejected. Anything else (5xx,
	// redirects, ...) is a transient failure the controller surfaces and retries. The
	// upstream's response body is included in the error (and thus the log) to aid
	// debugging a rejection.
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		return fmt.Errorf("%w: status %d: %s", ErrUpstreamRejected, resp.StatusCode, upstreamResponseBody(resp))
	default:
		return fmt.Errorf("upstream returned unexpected status %d: %s", resp.StatusCode, upstreamResponseBody(resp))
	}
}

// maxErrorBodyBytes bounds how much of an error response body is read into an error
// message, so a large (or hostile) upstream response cannot bloat logs or memory.
const maxErrorBodyBytes = 2 << 10 // 2 KiB

// upstreamResponseBody reads a bounded, single-line snippet of the response body for
// inclusion in an error message. Whitespace (including newlines) is collapsed so the
// body stays on the structured log's single error field; it returns "(empty)" when
// there is nothing to read.
func upstreamResponseBody(resp *http.Response) string {
	data, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
	body := strings.Join(strings.Fields(string(data)), " ")
	if body == "" {
		return "(empty)"
	}
	return body
}

// Ensure HTTPReporter satisfies the interface at compile time.
var _ Reporter = (*HTTPReporter)(nil)
