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
//   - Replace the bearer-token auth below if the API uses mTLS, HMAC, or another scheme.
//   - Map the response body / status codes to retryable vs. terminal errors.
//   - Add tracing / metrics as needed.
type HTTPReporter struct {
	// BaseURL is the root URL of the upstream API, e.g. "https://ipam-api.vitistack.io/v2".
	BaseURL string
	// Token, when set, is sent as an "Authorization: Bearer <token>" header.
	Token string
	// Client is the HTTP client used for requests. If nil, a client with
	// defaultTimeout is used.
	Client *http.Client
}

// NewHTTPReporter builds an HTTPReporter for the given base URL. A zero-value
// baseURL yields a reporter whose ReportPorts always errors, which callers
// should treat as a misconfiguration.
func NewHTTPReporter(baseURL, token string) *HTTPReporter {
	return &HTTPReporter{
		BaseURL: baseURL,
		Token:   token,
		Client:  &http.Client{Timeout: defaultTimeout},
	}
}

// ReportPorts implements Reporter by POSTing the report as JSON to
// <BaseURL>/v1/port-reports.
//
// TODO(user): This is scaffolding. Validate the endpoint path, auth, and
// response handling against the real upstream service before relying on it.
func (h *HTTPReporter) ReportPorts(ctx context.Context, report PortReport) error {
	if h.BaseURL == "" {
		return fmt.Errorf("upstream HTTPReporter has no BaseURL configured")
	}

	body, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("marshaling port report: %w", err)
	}

	// TODO(user): confirm the real endpoint path and method.
	endpoint := h.BaseURL + "/v1/port-reports"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building upstream request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// Idempotency-Key lets the upstream dedupe retries and duplicates (e.g. a
	// report re-sent after a reconcile conflict): identical policy/ports/IPs yield
	// the same key. TODO(user): confirm the header name the upstream expects.
	req.Header.Set("Idempotency-Key", report.IdempotencyKey())
	if h.Token != "" {
		req.Header.Set("Authorization", "Bearer "+h.Token)
	}

	client := h.Client
	if client == nil {
		client = &http.Client{Timeout: defaultTimeout}
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("sending port report upstream: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// TODO(user): map upstream status codes to retryable vs. terminal errors.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("upstream rejected port report: status %d", resp.StatusCode)
	}
	return nil
}

// Ensure HTTPReporter satisfies the interface at compile time.
var _ Reporter = (*HTTPReporter)(nil)
