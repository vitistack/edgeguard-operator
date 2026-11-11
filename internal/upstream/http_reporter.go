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

// maxStatusBodyBytes bounds how much of a status-queue response body is read and
// decoded, so a large (or hostile) upstream response cannot bloat memory.
const maxStatusBodyBytes = 64 << 10 // 64 KiB

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
	// status URL in the response body. For a report, ReportPorts returns that URL as a
	// Pending ReportStatus and the controller polls it via PollReport across reconciles;
	// for a withdrawal, DeletePorts returns Pending the same way and the controller
	// polls it (holding its finalizer) until the job completes. Both are non-blocking.
	// It is opt-in via the UPSTREAM_REPORTING_STATUS_QUEUE environment variable. When
	// false, any 2xx response counts as immediate success and the body is ignored.
	ReportingStatusQueue bool
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

// ReportPorts implements Reporter by POSTing the report as JSON to <BaseURL> with a
// single round-trip. With the status queue disabled, any 2xx is immediate success
// (ReportStatus{Done}). With it enabled, a 2xx means the job was accepted: the
// upstream returns a status URL which the controller polls via PollReport on a later
// reconcile, so no worker is held waiting here. A 2xx with no status URL is treated as
// synchronous success.
//
// TODO(user): This is scaffolding. Validate the endpoint path, auth, and
// response handling against the real upstream service before relying on it.
func (h *HTTPReporter) ReportPorts(ctx context.Context, report PortReport) (ReportStatus, error) {
	resp, err := h.submit(ctx, http.MethodPost, report)
	if err != nil {
		return ReportStatus{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	// Without the status queue the 2xx is final. With it, the 2xx only means the job
	// was queued; its real outcome is polled from the status URL by the controller.
	if !h.ReportingStatusQueue {
		return ReportStatus{Done: true}, nil
	}
	return ackToStatus(resp)
}

// PollReport implements Reporter by performing a single poll of a queued report's
// status URL. It maps the job's state onto the Reporter error contract: Done on
// success, the terminal ErrUpstreamRejected when the job failed, a plain transient
// error on a poll failure (so the controller requeues and polls again), or a still-in-
// flight ReportStatus (Pending, carrying the same status URL) while the job runs. It is
// shared by report and withdrawal jobs, which poll the same status-URL contract.
func (h *HTTPReporter) PollReport(ctx context.Context, statusURL string) (ReportStatus, error) {
	status, err := h.pollJobStatus(ctx, statusURL)
	if err != nil {
		return ReportStatus{}, err
	}
	state := strings.ToLower(strings.TrimSpace(status.Status))
	switch {
	case jobSucceeded[state]:
		return ReportStatus{Done: true}, nil
	case jobFailed[state]:
		// The upstream processed and refused the report; an identical retry will not
		// succeed, so surface it as the terminal rejection.
		// TODO(user): if your job failures are usually transient, return a plain error
		// here instead so the controller keeps requeuing.
		return ReportStatus{}, fmt.Errorf("%w: job %s: %s", ErrUpstreamRejected, state, statusMessage(status.Message))
	default:
		// Still queued/running: report it as pending so the controller requeues and polls
		// again, without blocking a worker here.
		return ReportStatus{StatusURL: statusURL}, nil
	}
}

// DeletePorts implements Reporter by sending an HTTP DELETE with the report body to
// <BaseURL>, withdrawing a previously reported port set when the policy or its target
// Service is removed. Like ReportPorts it is a single round-trip: with the status queue
// enabled a 2xx carrying a status URL is returned as a Pending ReportStatus that the
// controller polls via PollReport across reconciles — holding its finalizer until the
// withdrawal job completes — rather than blocking a worker here.
func (h *HTTPReporter) DeletePorts(ctx context.Context, report PortReport) (ReportStatus, error) {
	resp, err := h.submit(ctx, http.MethodDelete, report)
	if err != nil {
		return ReportStatus{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if !h.ReportingStatusQueue {
		return ReportStatus{Done: true}, nil
	}
	return ackToStatus(resp)
}

// ackToStatus decodes a queued-submission acknowledgement into a ReportStatus: Done
// when the upstream completed synchronously (no status URL in the body), or a Pending
// status carrying the status URL and job ID the controller polls. It backs the status-
// queue branch of both ReportPorts and DeletePorts.
func ackToStatus(resp *http.Response) (ReportStatus, error) {
	var ack reportAck
	if err := decodeStatusBody(resp, &ack); err != nil {
		return ReportStatus{}, fmt.Errorf("decoding upstream acknowledgement: %w", err)
	}
	if ack.StatusURL == "" {
		return ReportStatus{Done: true}, nil
	}
	return ReportStatus{StatusURL: ack.StatusURL, JobID: ack.JobID}, nil
}

// submit marshals the report and issues a single request to the port-reports endpoint
// with the given HTTP method. On a 2xx it returns the live response (the caller must
// close its body). Any non-2xx is classified and returned as an error: a 404 is
// ErrUpstreamNotFound (which wraps ErrUpstreamRejected so a report still treats it as
// terminal while a withdrawal can single out the already-gone case), any other 4xx is
// the terminal ErrUpstreamRejected, and anything else (5xx, redirects) is a transient
// failure the controller retries. The upstream's response body is included in the
// error to aid debugging a rejection.
func (h *HTTPReporter) submit(ctx context.Context, method string, report PortReport) (*http.Response, error) {
	if h.BaseURL == "" {
		return nil, fmt.Errorf("upstream HTTPReporter has no BaseURL configured")
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
		return nil, fmt.Errorf("marshaling port report: %w", err)
	}

	// TODO(user): confirm the real endpoint path and method.
	endpoint := h.BaseURL
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("building upstream request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// Idempotency-Key lets the upstream dedupe retries and duplicates (e.g. a
	// report re-sent after a reconcile conflict, or a submission resumed across
	// reconciles): identical policy/ports/IPs yield the same key, so the re-submission
	// resolves to the same queued job rather than duplicating work.
	// TODO(user): confirm the header name the upstream expects.
	req.Header.Set("Idempotency-Key", report.IdempotencyKey())

	client := h.Client
	if client == nil {
		client = &http.Client{Timeout: defaultTimeout}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending port report upstream: %w", err)
	}

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return resp, nil
	case resp.StatusCode == http.StatusNotFound:
		err = fmt.Errorf("%w: status 404: %s", ErrUpstreamNotFound, upstreamResponseBody(resp))
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		err = fmt.Errorf("%w: status %d: %s", ErrUpstreamRejected, resp.StatusCode, upstreamResponseBody(resp))
	default:
		err = fmt.Errorf("upstream returned unexpected status %d: %s", resp.StatusCode, upstreamResponseBody(resp))
	}
	_ = resp.Body.Close()
	return nil, err
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

// pollJobStatus issues a single GET to the status URL and decodes the job's state.
// Status-code classification mirrors submit: a 4xx means the status URL itself is bad
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
