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
	"encoding/json"
	"fmt"
	"net/http"
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
	client := &http.Client{Timeout: defaultTimeout}
	if insecureSkipVerify {
		client.Transport = &http.Transport{
			// InsecureSkipVerify is gated behind an explicit opt-in env var and is
			// documented as dev/test-only, so disabling verification here is intentional.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // opt-in via UPSTREAM_INSECURE_SKIP_VERIFY
		}
	}
	return &HTTPReporter{
		BaseURL:            baseURL,
		InsecureSkipVerify: insecureSkipVerify,
		Client:             client,
	}
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
	// redirects, ...) is a transient failure the controller surfaces and retries.
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		return fmt.Errorf("%w: status %d", ErrUpstreamRejected, resp.StatusCode)
	default:
		return fmt.Errorf("upstream returned unexpected status %d", resp.StatusCode)
	}
}

// Ensure HTTPReporter satisfies the interface at compile time.
var _ Reporter = (*HTTPReporter)(nil)
