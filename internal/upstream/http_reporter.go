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

const (
	// statusQueuePollInterval is the delay between successive polls of a report's
	// status URL within a single report attempt.
	statusQueuePollInterval = 2 * time.Second
	// statusQueuePollTimeout bounds how long one report attempt waits for the queued
	// job to reach a terminal state before giving up. Exceeding it is surfaced as a
	// transient error so the controller requeues; because the report carries a stable
	// Idempotency-Key, the re-submission on the next reconcile resolves to the same
	// job and polling resumes rather than duplicating work. Keep this comfortably
	// below the controller's reconcile expectations so a worker is not held too long.
	statusQueuePollTimeout = 30 * time.Second
	// maxStatusBodyBytes bounds how much of a status-queue response body is read and
	// decoded, so a large (or hostile) upstream response cannot bloat memory.
	maxStatusBodyBytes = 64 << 10 // 64 KiB
)

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
	// ReportingStatusQueue enables the asynchronous status-queue flow. When true, a
	// 2xx submission is not treated as final: the upstream is expected to return a
	// status URL in the response body, which this reporter then polls until the queued
	// job reports completion or failure (see awaitStatusQueue). It is opt-in via the
	// UPSTREAM_REPORTING_STATUS_QUEUE environment variable. When false, any 2xx
	// response counts as immediate success and the body is ignored.
	ReportingStatusQueue bool
	// Client is the HTTP client used for requests. If nil, a client with
	// defaultTimeout is used.
	Client *http.Client
	// StatusPollInterval and StatusPollTimeout override the status-queue polling
	// cadence: the delay between polls of a report's status URL and the total budget
	// one report attempt waits for a terminal state. When zero the statusQueuePoll*
	// package defaults apply. They are sourced from the
	// UPSTREAM_REPORTING_STATUS_QUEUE_POLL_INTERVAL / _TIMEOUT environment variables.
	StatusPollInterval time.Duration
	StatusPollTimeout  time.Duration
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

	// The upstream expects ipv4Addresses and ipv6Addresses to always be present as
	// arrays, so a report with no address of a family serializes it as [] rather than
	// null. report is a value copy, so normalizing here does not mutate the caller's
	// report.
	if report.IPv4Addresses == nil {
		report.IPv4Addresses = []string{}
	}
	if report.IPv6Addresses == nil {
		report.IPv6Addresses = []string{}
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

	// Any 2xx status counts as the report being accepted. A 404 is singled out as
	// ErrUpstreamNotFound (it wraps ErrUpstreamRejected) so a withdrawal can treat it as
	// already-gone; any other 4xx is the terminal ErrUpstreamRejected. Anything else
	// (5xx, redirects, ...) is a transient failure the controller surfaces and retries.
	// The upstream's response body is included in the error (and thus the log) to aid
	// debugging a rejection.
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		// Accepted. Without the status queue the report is done; with it, the 2xx only
		// means the job was queued and its real outcome is polled from the status URL.
		if !h.ReportingStatusQueue {
			return nil
		}
		return h.awaitStatusQueue(ctx, resp)
	case resp.StatusCode == http.StatusNotFound:
		return fmt.Errorf("%w: status 404: %s", ErrUpstreamNotFound, upstreamResponseBody(resp))
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		return fmt.Errorf("%w: status %d: %s", ErrUpstreamRejected, resp.StatusCode, upstreamResponseBody(resp))
	default:
		return fmt.Errorf("upstream returned unexpected status %d: %s", resp.StatusCode, upstreamResponseBody(resp))
	}
}

// reportAck is the upstream's response to an accepted report when the status queue
// is enabled: StatusURL is the location to poll for the queued job's outcome and
// JobID identifies the job for logging. An empty StatusURL means the upstream
// completed the report synchronously and there is nothing to poll.
//
// TODO(user): align these field names (statusUrl/jobId) with the real upstream contract.
type reportAck struct {
	StatusURL string `json:"statusUrl"`
	JobID     string `json:"jobId,omitempty"`
}

// jobStatus is the upstream's response when polling a report's status URL. Status
// carries the queued job's state and Message is an optional human-readable detail
// included in surfaced errors.
//
// TODO(user): align the field names and the recognized Status values below with the
// real upstream contract.
type jobStatus struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

// jobSucceeded and jobFailed classify a terminal job Status (case-insensitively).
// Any value in neither set is treated as still in progress and keeps the reporter
// polling until the status-queue budget is spent.
var (
	jobSucceeded = map[string]bool{"completed": true, "complete": true, "succeeded": true, "success": true, "done": true}
	jobFailed    = map[string]bool{"failed": true, "failure": true, "error": true, "rejected": true, "cancelled": true, "canceled": true}
)

// awaitStatusQueue polls the status URL returned by an accepted submission until the
// queued job reaches a terminal state or the per-attempt budget is exhausted. It maps
// the outcome onto the same error contract as a synchronous report: nil on success,
// ErrUpstreamRejected (terminal) when the job failed, and a plain transient error on a
// poll failure or timeout so the controller requeues and the next attempt resumes the
// same job via the report's Idempotency-Key.
func (h *HTTPReporter) awaitStatusQueue(ctx context.Context, submitResp *http.Response) error {
	var ack reportAck
	if err := decodeStatusBody(submitResp, &ack); err != nil {
		return fmt.Errorf("decoding upstream report acknowledgement: %w", err)
	}
	// No status URL: the upstream completed the report synchronously despite the queue
	// being enabled, so there is nothing to poll.
	if ack.StatusURL == "" {
		return nil
	}

	deadline := time.Now().Add(h.EffectiveStatusPollTimeout())
	for {
		status, err := h.pollJobStatus(ctx, ack.StatusURL)
		if err != nil {
			return err
		}
		state := strings.ToLower(strings.TrimSpace(status.Status))
		switch {
		case jobSucceeded[state]:
			return nil
		case jobFailed[state]:
			// The upstream processed and refused the report; an identical retry will not
			// succeed, so surface it as the terminal rejection (the controller remembers
			// the payload and stops retrying until the policy/Service changes).
			// TODO(user): if your job failures are usually transient, return a plain error
			// here instead so the controller keeps requeuing.
			return fmt.Errorf("%w: job %q %s: %s", ErrUpstreamRejected, ack.JobID, state, statusMessage(status.Message))
		}
		// Still queued/running: wait and poll again until the budget is spent.
		if time.Now().After(deadline) {
			return fmt.Errorf("upstream report job %q still %q after %s", ack.JobID, state, h.EffectiveStatusPollTimeout())
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(h.EffectiveStatusPollInterval()):
		}
	}
}

// EffectiveStatusPollInterval and EffectiveStatusPollTimeout return the status-queue
// polling cadence actually in use, falling back to the package defaults when the
// corresponding field is unset. They let callers log the resolved values.
func (h *HTTPReporter) EffectiveStatusPollInterval() time.Duration {
	if h.StatusPollInterval > 0 {
		return h.StatusPollInterval
	}
	return statusQueuePollInterval
}

func (h *HTTPReporter) EffectiveStatusPollTimeout() time.Duration {
	if h.StatusPollTimeout > 0 {
		return h.StatusPollTimeout
	}
	return statusQueuePollTimeout
}

// pollJobStatus issues a single GET to the status URL and decodes the job's state.
// Status-code classification mirrors send: a 4xx means the status URL itself is bad
// (terminal rejection), anything else non-2xx is transient so the caller requeues.
func (h *HTTPReporter) pollJobStatus(ctx context.Context, statusURL string) (jobStatus, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, statusURL, nil)
	if err != nil {
		return jobStatus{}, fmt.Errorf("building upstream status request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	client := h.Client
	if client == nil {
		client = &http.Client{Timeout: defaultTimeout}
	}

	resp, err := client.Do(req)
	if err != nil {
		return jobStatus{}, fmt.Errorf("polling upstream report status: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		var status jobStatus
		if err := decodeStatusBody(resp, &status); err != nil {
			return jobStatus{}, fmt.Errorf("decoding upstream report status: %w", err)
		}
		return status, nil
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		return jobStatus{}, fmt.Errorf("%w: status URL returned %d: %s",
			ErrUpstreamRejected, resp.StatusCode, upstreamResponseBody(resp))
	default:
		return jobStatus{}, fmt.Errorf("upstream status URL returned unexpected status %d: %s",
			resp.StatusCode, upstreamResponseBody(resp))
	}
}

// decodeStatusBody JSON-decodes a bounded prefix of a status-queue response body into
// v. The read is capped at maxStatusBodyBytes so an oversized response cannot bloat
// memory.
func decodeStatusBody(resp *http.Response, v any) error {
	return json.NewDecoder(io.LimitReader(resp.Body, maxStatusBodyBytes)).Decode(v)
}

// statusMessage renders an optional job message for inclusion in an error, collapsing
// whitespace and substituting a placeholder when empty.
func statusMessage(msg string) string {
	msg = strings.Join(strings.Fields(msg), " ")
	if msg == "" {
		return "(no message)"
	}
	return msg
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
