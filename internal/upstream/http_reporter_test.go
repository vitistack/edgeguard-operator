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
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

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
			err := reporter.ReportPorts(context.Background(), PortReport{ServiceName: "svc"})

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
	err := reporter.DeletePorts(context.Background(), PortReport{ServiceName: "svc"})
	if !errors.Is(err, ErrUpstreamRejected) {
		t.Fatalf("expected ErrUpstreamRejected for a 422 DELETE, got %v", err)
	}
}
