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
	"context"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// testServiceName is the placeholder Service name used across reporter tests.
const testServiceName = "svc"

// Queued-job state strings reused across the status-queue tests (goconst).
const (
	statePending   = "pending"
	stateCompleted = "completed"
	stateFailed    = "failed"
)

// TestHTTPReporterAlwaysSendsAddressArrays verifies the serialized report always
// carries ipv4Addresses and ipv6Addresses as arrays (as [] when the Service has no
// address of that family).
func TestHTTPReporterAlwaysSendsAddressArrays(t *testing.T) {
	var got string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	reporter := NewHTTPReporter(server.URL, false)
	if _, err := reporter.ReportPorts(context.Background(), PortReport{ServiceName: testServiceName}); err != nil {
		t.Fatalf("ReportPorts: %v", err)
	}
	if !strings.Contains(got, `"ipv4Addresses":[]`) {
		t.Fatalf("expected ipv4Addresses:[] in request body, got: %s", got)
	}
	if !strings.Contains(got, `"ipv6Addresses":[]`) {
		t.Fatalf("expected ipv6Addresses:[] in request body, got: %s", got)
	}
}

// TestHTTPReporterErrorIncludesBody verifies the upstream's response body and status
// code are surfaced in the returned error (and thus the log), for both a terminal 4xx
// rejection and a transient 5xx, with newlines collapsed to a single line.
func TestHTTPReporterErrorIncludesBody(t *testing.T) {
	cases := map[string]struct {
		status int
		body   string
		want   string
	}{
		"400 with body":  {status: http.StatusBadRequest, body: "invalid datacenter\n\"test-south-az1\"", want: `invalid datacenter "test-south-az1"`},
		"500 with body":  {status: http.StatusInternalServerError, body: "boom", want: "boom"},
		"400 empty body": {status: http.StatusBadRequest, body: "", want: "(empty)"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()

			reporter := NewHTTPReporter(server.URL, false)
			_, err := reporter.ReportPorts(context.Background(), PortReport{ServiceName: testServiceName})
			if err == nil {
				t.Fatalf("expected an error for status %d", tc.status)
			}
			if got := err.Error(); !strings.Contains(got, tc.want) ||
				!strings.Contains(got, strconv.Itoa(tc.status)) {
				t.Fatalf("error %q did not contain status %d and body %q", got, tc.status, tc.want)
			}
		})
	}
}

// TestHTTPReporterStatusHandling verifies how the reporter classifies upstream
// responses: any 2xx is success; a 4xx is the terminal ErrUpstreamRejected; any
// other status (5xx, redirects) is a transient failure the controller retries.
func TestHTTPReporterStatusHandling(t *testing.T) {
	cases := map[string]struct {
		status       int
		wantErr      bool
		wantRejected bool
	}{
		"200 OK":                  {status: http.StatusOK, wantErr: false},
		"201 Created":             {status: http.StatusCreated, wantErr: false},
		"204 No Content":          {status: http.StatusNoContent, wantErr: false},
		"400 Bad Request":         {status: http.StatusBadRequest, wantErr: true, wantRejected: true},
		"404 Not Found":           {status: http.StatusNotFound, wantErr: true, wantRejected: true},
		"409 Conflict":            {status: http.StatusConflict, wantErr: true, wantRejected: true},
		"500 Internal":            {status: http.StatusInternalServerError, wantErr: true, wantRejected: false},
		"502 Bad Gateway":         {status: http.StatusBadGateway, wantErr: true, wantRejected: false},
		"503 Service Unavailable": {status: http.StatusServiceUnavailable, wantErr: true, wantRejected: false},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
			}))
			defer server.Close()

			reporter := NewHTTPReporter(server.URL, false)
			_, err := reporter.ReportPorts(context.Background(), PortReport{ServiceName: testServiceName})

			if tc.wantErr && err == nil {
				t.Fatalf("expected an error for status %d, got nil", tc.status)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected no error for status %d, got %v", tc.status, err)
			}
			if got := errors.Is(err, ErrUpstreamRejected); got != tc.wantRejected {
				t.Fatalf("status %d: errors.Is(err, ErrUpstreamRejected) = %v, want %v (err=%v)",
					tc.status, got, tc.wantRejected, err)
			}
		})
	}
}

// TestHTTPReporterDeleteRejection confirms DeletePorts classifies a 4xx the same way
// as ReportPorts, so a withdrawal the upstream refuses surfaces as terminal.
func TestHTTPReporterDeleteRejection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
	}))
	defer server.Close()

	reporter := NewHTTPReporter(server.URL, false)
	_, err := reporter.DeletePorts(context.Background(), PortReport{ServiceName: testServiceName})
	if !errors.Is(err, ErrUpstreamRejected) {
		t.Fatalf("expected ErrUpstreamRejected for a 422 DELETE, got %v", err)
	}
}

// TestHTTPReporterNotFound confirms a 404 is surfaced as ErrUpstreamNotFound, which
// also satisfies errors.Is(err, ErrUpstreamRejected) so report handling still treats it
// as terminal while withdrawal handling can single out the already-gone case.
func TestHTTPReporterNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	reporter := NewHTTPReporter(server.URL, false)
	_, err := reporter.DeletePorts(context.Background(), PortReport{ServiceName: testServiceName})
	if !errors.Is(err, ErrUpstreamNotFound) {
		t.Fatalf("expected ErrUpstreamNotFound for a 404, got %v", err)
	}
	if !errors.Is(err, ErrUpstreamRejected) {
		t.Fatalf("expected a 404 to also satisfy ErrUpstreamRejected, got %v", err)
	}
}

// writeCertPEM writes a DER certificate to a temp .pem file and returns its path.
func writeCertPEM(t *testing.T, der []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("writing cert PEM: %v", err)
	}
	return path
}

// TestHTTPReporterCABundle verifies that a reporter configured with a CA bundle trusts
// an upstream whose certificate is signed by that CA, while the same upstream fails
// verification without it, and that insecureSkipVerify bypasses verification entirely.
func TestHTTPReporterCABundle(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	caPath := writeCertPEM(t, server.Certificate().Raw)

	t.Run("trusts bundled CA", func(t *testing.T) {
		reporter, err := NewHTTPReporterWithCA(server.URL, false, caPath)
		if err != nil {
			t.Fatalf("NewHTTPReporterWithCA: %v", err)
		}
		if _, err := reporter.ReportPorts(context.Background(), PortReport{ServiceName: testServiceName}); err != nil {
			t.Fatalf("expected report to succeed with trusted CA, got %v", err)
		}
	})

	t.Run("fails without CA", func(t *testing.T) {
		reporter := NewHTTPReporter(server.URL, false)
		if _, err := reporter.ReportPorts(context.Background(), PortReport{ServiceName: testServiceName}); err == nil {
			t.Fatal("expected a TLS verification error without the CA, got nil")
		}
	})

	t.Run("insecureSkipVerify bypasses verification", func(t *testing.T) {
		reporter, err := NewHTTPReporterWithCA(server.URL, true, "")
		if err != nil {
			t.Fatalf("NewHTTPReporterWithCA: %v", err)
		}
		if _, err := reporter.ReportPorts(context.Background(), PortReport{ServiceName: testServiceName}); err != nil {
			t.Fatalf("expected report to succeed with insecureSkipVerify, got %v", err)
		}
	})

	t.Run("trusts CA from a directory mount", func(t *testing.T) {
		// Mimic a ConfigMap mounted as a directory (no subPath): the CA sits in a real
		// data dir, exposed via a "..data" symlink, with the key a symlink into it. The
		// loader must read the cert and ignore the ".."-prefixed atomic-writer artifacts.
		dir := t.TempDir()
		dataDir := filepath.Join(dir, "..2026_data")
		if err := os.Mkdir(dataDir, 0o700); err != nil {
			t.Fatalf("mkdir data dir: %v", err)
		}
		caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
		if err := os.WriteFile(filepath.Join(dataDir, "nhn-certbundle.crt"), caPEM, 0o600); err != nil {
			t.Fatalf("writing cert into data dir: %v", err)
		}
		if err := os.Symlink("..2026_data", filepath.Join(dir, "..data")); err != nil {
			t.Fatalf("symlink ..data: %v", err)
		}
		if err := os.Symlink(filepath.Join("..data", "nhn-certbundle.crt"),
			filepath.Join(dir, "nhn-certbundle.crt")); err != nil {
			t.Fatalf("symlink key: %v", err)
		}

		reporter, err := NewHTTPReporterWithCA(server.URL, false, dir)
		if err != nil {
			t.Fatalf("NewHTTPReporterWithCA: %v", err)
		}
		if _, err := reporter.ReportPorts(context.Background(), PortReport{ServiceName: testServiceName}); err != nil {
			t.Fatalf("expected report to succeed with CA from directory, got %v", err)
		}
	})
}

// TestHTTPReporterCABundleErrors verifies that an unreadable or invalid CA bundle is a
// hard construction error rather than a silent fallback to the system trust store.
func TestHTTPReporterCABundleErrors(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		if _, err := NewHTTPReporterWithCA("https://example.test", false,
			filepath.Join(t.TempDir(), "does-not-exist.pem")); err == nil {
			t.Fatal("expected an error for a missing CA bundle, got nil")
		}
	})

	t.Run("no valid certificates", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "junk.pem")
		if err := os.WriteFile(path, []byte("not a certificate"), 0o600); err != nil {
			t.Fatalf("writing junk file: %v", err)
		}
		if _, err := NewHTTPReporterWithCA("https://example.test", false, path); err == nil {
			t.Fatal("expected an error for a CA bundle with no valid certificates, got nil")
		}
	})
}

// statusQueueReporter builds a reporter pointed at server with the status queue
// enabled. Submissions and polls are single round-trips, so no polling-cadence tuning
// is needed; the controller owns the poll interval.
func statusQueueReporter(serverURL string) *HTTPReporter {
	r := NewHTTPReporter(serverURL, false)
	r.ReportingStatusQueue = true
	return r
}

// TestStatusQueueDisabledIgnoresBody confirms that with the status queue off, a 2xx
// submission is final (Done) and the (status-URL-bearing) response body is ignored.
func TestStatusQueueDisabledIgnoresBody(t *testing.T) {
	var polled bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			polled = true
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"statusUrl":"` + "http://unused" + `"}`))
	}))
	defer server.Close()

	reporter := NewHTTPReporter(server.URL, false) // status queue disabled
	status, err := reporter.ReportPorts(context.Background(), PortReport{ServiceName: testServiceName})
	if err != nil {
		t.Fatalf("ReportPorts: %v", err)
	}
	if !status.Done {
		t.Fatalf("expected Done with the status queue disabled, got %+v", status)
	}
	if polled {
		t.Fatal("status queue disabled, but the reporter polled a status URL")
	}
}

// TestStatusQueueSyncCompletion confirms that when the status queue is enabled but the
// submission returns no status URL, the 2xx is treated as immediate success (Done).
func TestStatusQueueSyncCompletion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	status, err := statusQueueReporter(server.URL).
		ReportPorts(context.Background(), PortReport{ServiceName: testServiceName})
	if err != nil {
		t.Fatalf("ReportPorts: %v", err)
	}
	if !status.Done {
		t.Fatalf("expected Done when the upstream completes synchronously, got %+v", status)
	}
}

// TestReportPortsQueuedDoesNotBlock confirms that with the status queue enabled, a 2xx
// carrying a status URL returns a Pending ReportStatus without polling — the controller
// drives polling via PollReport on later reconciles, so a worker is never held here.
func TestReportPortsQueuedDoesNotBlock(t *testing.T) {
	var polled bool
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, _ *http.Request) {
		polled = true
		_, _ = w.Write([]byte(`{"status":"pending"}`))
	})
	var server *httptest.Server
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"statusUrl":"` + server.URL + `/status","jobId":"j1"}`))
	})
	server = httptest.NewServer(mux)
	defer server.Close()

	status, err := statusQueueReporter(server.URL).
		ReportPorts(context.Background(), PortReport{ServiceName: testServiceName})
	if err != nil {
		t.Fatalf("ReportPorts: %v", err)
	}
	if !status.Pending() {
		t.Fatalf("expected a pending ReportStatus for a queued report, got %+v", status)
	}
	if status.StatusURL != server.URL+"/status" || status.JobID != "j1" {
		t.Fatalf("expected the queued job's status URL and ID, got %+v", status)
	}
	if polled {
		t.Fatal("ReportPorts polled the status URL; polling must be driven by PollReport")
	}
}

// TestPollReportDrivesToTerminalState drives PollReport through each outcome: a pending
// job stays Pending, a succeeded job is Done, a failed job is the terminal
// ErrUpstreamRejected, a 4xx status URL is terminal, and a 5xx is a plain transient error.
func TestPollReportDrivesToTerminalState(t *testing.T) {
	cases := map[string]struct {
		state        string
		httpStatus   int
		wantDone     bool
		wantPending  bool
		wantErr      bool
		wantRejected bool
	}{
		"pending":    {state: statePending, httpStatus: http.StatusOK, wantPending: true},
		"completed":  {state: stateCompleted, httpStatus: http.StatusOK, wantDone: true},
		"succeeded":  {state: "SUCCEEDED", httpStatus: http.StatusOK, wantDone: true},
		"failed":     {state: stateFailed, httpStatus: http.StatusOK, wantErr: true, wantRejected: true},
		"status 400": {httpStatus: http.StatusBadRequest, wantErr: true, wantRejected: true},
		"status 500": {httpStatus: http.StatusInternalServerError, wantErr: true, wantRejected: false},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tc.httpStatus != http.StatusOK {
					w.WriteHeader(tc.httpStatus)
					return
				}
				_, _ = w.Write([]byte(`{"status":"` + tc.state + `","message":"m"}`))
			}))
			defer server.Close()

			status, err := statusQueueReporter(server.URL).PollReport(context.Background(), server.URL)
			if tc.wantErr && err == nil {
				t.Fatalf("expected an error, got nil (status=%+v)", status)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if got := errors.Is(err, ErrUpstreamRejected); got != tc.wantRejected {
				t.Fatalf("errors.Is(err, ErrUpstreamRejected) = %v, want %v (err=%v)", got, tc.wantRejected, err)
			}
			if status.Done != tc.wantDone {
				t.Fatalf("Done = %v, want %v", status.Done, tc.wantDone)
			}
			if status.Pending() != tc.wantPending {
				t.Fatalf("Pending() = %v, want %v", status.Pending(), tc.wantPending)
			}
		})
	}
}

// TestDeletePortsQueuedDoesNotBlock confirms that with the status queue enabled, a 2xx
// withdrawal carrying a status URL returns a Pending ReportStatus without polling — the
// controller drives withdrawal polling via PollReport across reconciles, holding its
// finalizer, so no worker is held here.
func TestDeletePortsQueuedDoesNotBlock(t *testing.T) {
	var polled bool
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, _ *http.Request) {
		polled = true
		_, _ = w.Write([]byte(`{"status":"` + statePending + `"}`))
	})
	var server *httptest.Server
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"statusUrl":"` + server.URL + `/status","jobId":"w1"}`))
	})
	server = httptest.NewServer(mux)
	defer server.Close()

	status, err := statusQueueReporter(server.URL).
		DeletePorts(context.Background(), PortReport{ServiceName: testServiceName})
	if err != nil {
		t.Fatalf("DeletePorts: %v", err)
	}
	if !status.Pending() {
		t.Fatalf("expected a pending ReportStatus for a queued withdrawal, got %+v", status)
	}
	if status.StatusURL != server.URL+"/status" || status.JobID != "w1" {
		t.Fatalf("expected the queued job's status URL and ID, got %+v", status)
	}
	if polled {
		t.Fatal("DeletePorts polled the status URL; polling must be driven by PollReport")
	}
}

// TestDeletePortsSyncCompletion confirms a 2xx withdrawal with no status URL is treated
// as immediate success (Done), both with the status queue off and on.
func TestDeletePortsSyncCompletion(t *testing.T) {
	for name, queue := range map[string]bool{"queue off": false, "queue on": true} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{}`))
			}))
			defer server.Close()

			reporter := NewHTTPReporter(server.URL, false)
			reporter.ReportingStatusQueue = queue
			status, err := reporter.DeletePorts(context.Background(), PortReport{ServiceName: testServiceName})
			if err != nil {
				t.Fatalf("DeletePorts: %v", err)
			}
			if !status.Done {
				t.Fatalf("expected Done for a synchronous withdrawal, got %+v", status)
			}
		})
	}
}
