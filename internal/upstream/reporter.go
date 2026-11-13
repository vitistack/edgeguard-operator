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

// Package upstream reports Service port discovery from EdgePolicies to an
// external system. The controller calls a Reporter whenever the discovered
// ports for a policy change; implementations translate that into whatever the
// upstream API expects (HTTP, message queue, gRPC, ...).
package upstream

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Port describes a single discovered Service port in the upstream payload.
type Port struct {
	// Name is the Service port name, if one is set.
	Name string `json:"name,omitempty"`
	// Port is the port number exposed by the Service.
	Port int32 `json:"port"`
	// Protocol is the IP protocol for this port (TCP, UDP, or SCTP).
	Protocol string `json:"protocol,omitempty"`
}

// PortReport is the payload describing an EdgePolicy's currently discovered ports.
type PortReport struct {
	// ClusterID is the UID of the kube-system namespace, used as a stable
	// cluster identifier.
	ClusterID string `json:"clusterId,omitempty"`
	// EdgePolicyNamespaceID is the UID of the namespace the EdgePolicy lives in.
	EdgePolicyNamespaceID string `json:"edgePolicyNamespaceId,omitempty"`
	// EdgePolicyID is the UID of the EdgePolicy object the report describes.
	EdgePolicyID string `json:"edgePolicyId,omitempty"`
	// ServiceName is the target Service the ports were discovered on.
	ServiceName string `json:"serviceName"`
	// Datacenter is the availability zone the EdgePolicy belongs to, from
	// spec.datacenter, when set.
	Datacenter string `json:"datacenter,omitempty"`
	// IpamZone is the value of the ipam.vitistack.io/zone annotation on the target
	// Service, when present.
	IpamZone string `json:"ipamZone,omitempty"`
	// IpamSecret is the credential resolved from the Secret named by the target
	// Service's ipam.vitistack.io/secret annotation, when present.
	IpamSecret string `json:"ipamSecret,omitempty"`
	// IPv4Addresses and IPv6Addresses are the load balancer ingress addresses
	// assigned to the target Service, split by IP family. Both are always serialized
	// (as [] when the Service has no address of that family) so the shape is stable.
	IPv4Addresses []string `json:"ipv4Addresses"`
	IPv6Addresses []string `json:"ipv6Addresses"`
	// Filter carries the port-discovery state derived from spec.filter: whether
	// reporting is enabled plus the discovered and user-declared ports.
	Filter FilterReport `json:"filter"`
	// DDoS carries the DDoS geographic region policy derived from spec.ddos:
	// whether it is enabled, the permitted region, and any additional allowed CIDRs.
	// The controller always populates it — a policy with no spec.ddos block reports it
	// disabled (enabled=false) rather than omitting the section, mirroring filter. It
	// stays a pointer (with omitempty) so other callers may still omit it.
	DDoS *DDoSReport `json:"ddos,omitempty"`
}

// FilterReport mirrors spec.filter in the upstream payload: it reports whether
// port discovery is enabled alongside the discovered and declared ports.
type FilterReport struct {
	// Enabled reflects spec.filter.enabled, i.e. whether the policy opts into
	// port discovery and reporting.
	Enabled bool `json:"enabled"`
	// ObservedPorts is the full, current set of discovered ports (not a delta).
	ObservedPorts []Port `json:"observedPorts"`
	// AdditionalPorts is the set of user-declared ports from
	// spec.filter.additionalPortList, reported alongside the discovered ports.
	// Always serialized (as [] when none are declared) so the shape is stable.
	AdditionalPorts []Port `json:"additionalPorts"`
}

// DDoSReport mirrors spec.ddos in the upstream payload: it reports whether the
// DDoS geographic region policy is enabled, the permitted region, and any extra
// allowed CIDRs.
type DDoSReport struct {
	// Enabled reflects spec.ddos.enabled, i.e. whether the policy opts into the
	// DDoS geographic region policy.
	Enabled bool `json:"enabled"`
	// Region is the permitted geographic region from spec.ddos.region. Omitted from
	// the payload when unset (unlike the always-present port/CIDR lists).
	Region string `json:"region,omitempty"`
	// AdditionalCidrList is the set of extra allowed CIDRs from
	// spec.ddos.additionalCidrList. Always serialized (as [] when none are
	// declared) so the shape is stable.
	AdditionalCidrList []string `json:"additionalCidrList"`
}

// ErrIncompleteReport indicates a report is missing a field the upstream requires
// on every POST and DELETE. The upstream cannot act on a report that lacks the IPAM
// credential or any load balancer address, so such a report is not sent.
var ErrIncompleteReport = errors.New("incomplete port report")

// ErrUpstreamRejected indicates the upstream refused a report with a 4xx client
// error. Unlike a transient failure (connectivity, 5xx), the request will not
// succeed if retried unchanged, so the controller treats it as terminal: it surfaces
// the rejection and stops retrying on the timer, re-attempting only when the policy
// or its target Service changes.
var ErrUpstreamRejected = errors.New("upstream rejected port report")

// ErrUpstreamNotFound indicates the upstream returned 404. It wraps ErrUpstreamRejected
// so report (POST) handling still treats it as a terminal rejection, while withdrawal
// (DELETE) handling can single it out and treat it as success: a 404 on a withdrawal
// means the upstream has no record of the report, i.e. it is already gone.
var ErrUpstreamNotFound = fmt.Errorf("%w (not found)", ErrUpstreamRejected)

// Validate reports whether the payload carries the fields the upstream requires on
// every report and withdrawal: a resolved IPAM credential (IpamSecret) and at least
// one load balancer address (an IPv4 or IPv6 entry). It returns an error wrapping
// ErrIncompleteReport that names the missing fields, or nil when the report is
// complete. The error message never includes the credential value itself.
func (r PortReport) Validate() error {
	var missing []string
	if r.IpamSecret == "" {
		missing = append(missing, "ipamSecret")
	}
	if len(r.IPv4Addresses) == 0 && len(r.IPv6Addresses) == 0 {
		missing = append(missing, "ipAddresses")
	}
	if len(missing) == 0 {
		return nil
	}
	return fmt.Errorf("%w: missing %s", ErrIncompleteReport, strings.Join(missing, ", "))
}

// IdempotencyKey returns a stable identifier for the dedupe-relevant content of
// the report: the target Service plus its discovered ports and load balancer IPs,
// the datacenter, the filter-enabled flag, the declared additional ports, and the
// DDoS region policy. Two reports with the same such content produce the same key,
// so an upstream can treat a retry — or a duplicate caused by a reconcile conflict —
// as the same request and ignore it. Fields that do not change the meaning of the
// report (credential, zone, cluster ID) are deliberately excluded, so rotating a
// credential alone does not defeat deduplication.
func (r PortReport) IdempotencyKey() string {
	var b strings.Builder
	b.WriteString(r.ServiceName)
	// Separate sections with a byte that cannot appear in the values above so
	// distinct inputs cannot collide by concatenation.
	b.WriteByte('\n')
	b.WriteString(r.Datacenter)
	b.WriteByte('\n')
	b.WriteString(strconv.FormatBool(r.Filter.Enabled))
	b.WriteByte('\n')
	writePorts := func(ports []Port) {
		for _, p := range ports {
			b.WriteString(p.Name)
			b.WriteByte('\t')
			b.WriteString(strconv.FormatInt(int64(p.Port), 10))
			b.WriteByte('\t')
			b.WriteString(p.Protocol)
			b.WriteByte('\n')
		}
	}
	writePorts(r.Filter.ObservedPorts)
	b.WriteByte('\n')
	writePorts(r.Filter.AdditionalPorts)
	b.WriteByte('\n')
	if r.DDoS != nil {
		b.WriteString(strconv.FormatBool(r.DDoS.Enabled))
		b.WriteByte('\n')
		b.WriteString(r.DDoS.Region)
		b.WriteByte('\n')
		for _, cidr := range r.DDoS.AdditionalCidrList {
			b.WriteString(cidr)
			b.WriteByte('\n')
		}
	}
	b.WriteByte('\n')
	for _, ip := range r.IPv4Addresses {
		b.WriteString(ip)
		b.WriteByte('\n')
	}
	for _, ip := range r.IPv6Addresses {
		b.WriteString(ip)
		b.WriteByte('\n')
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// ReportStatus is the outcome of submitting or polling an upstream report. A report
// is either Done (durably accepted upstream, nothing more to do) or still in flight,
// in which case StatusURL names the URL to poll for its outcome and JobID identifies
// the queued job for logging. A terminal rejection or a transient delivery failure is
// returned as a non-nil error, not encoded in a ReportStatus.
type ReportStatus struct {
	// Done is true when the report has been durably accepted upstream.
	Done bool
	// StatusURL, when non-empty, is the URL to poll for a queued job that is still in
	// flight. It is meaningful only when Done is false.
	StatusURL string
	// JobID identifies the queued job, for logging and correlation.
	JobID string
}

// Pending reports whether the report is still in flight: queued, not yet accepted,
// and carrying a StatusURL the caller must poll.
func (s ReportStatus) Pending() bool { return !s.Done && s.StatusURL != "" }

// Reporter reports discovered Service ports to an external upstream system.
//
// Implementations must be safe for concurrent use: the controller may invoke these
// methods from multiple reconciles at once. Each method performs a single upstream
// round-trip and does not block waiting on a queued job; the controller drives any
// polling across reconciles so a worker is never held waiting on the upstream.
//
// ReportPorts submits a report and returns its outcome: Done when the upstream
// accepted it synchronously, or a Pending ReportStatus carrying a StatusURL when the
// upstream queued it for asynchronous processing. PollReport performs one poll of such
// a StatusURL and is shared by reports and withdrawals. DeletePorts withdraws a
// previously reported set of ports when the policy or its target Service is removed,
// with the same submit/poll contract as ReportPorts. Each returns a non-nil error
// (ErrUpstreamRejected / ErrIncompleteReport / a plain transient error) when the
// operation was not durably accepted, so the controller can requeue and retry.
type Reporter interface {
	ReportPorts(ctx context.Context, report PortReport) (ReportStatus, error)
	PollReport(ctx context.Context, statusURL string) (ReportStatus, error)
	DeletePorts(ctx context.Context, report PortReport) (ReportStatus, error)
}

// NoopReporter is a Reporter that discards every report and reports success. It
// backs the "reporting disabled" mode: the operator behaves as if every report
// was delivered, without contacting any upstream or surfacing a failure.
type NoopReporter struct{}

// ReportPorts implements Reporter and reports immediate success without polling.
func (NoopReporter) ReportPorts(context.Context, PortReport) (ReportStatus, error) {
	return ReportStatus{Done: true}, nil
}

// PollReport implements Reporter and reports immediate success; a NoopReporter never
// queues a job, so there is nothing to poll.
func (NoopReporter) PollReport(context.Context, string) (ReportStatus, error) {
	return ReportStatus{Done: true}, nil
}

// DeletePorts implements Reporter and reports immediate success without polling.
func (NoopReporter) DeletePorts(context.Context, PortReport) (ReportStatus, error) {
	return ReportStatus{Done: true}, nil
}

// Configured reports true so the controller treats disabled reporting as healthy
// (no UpstreamReady=False condition) rather than as a missing configuration.
func (NoopReporter) Configured() bool { return true }

// Disabled reports true so the controller can log that reports were accepted
// without being delivered, instead of claiming a real upstream delivery.
func (NoopReporter) Disabled() bool { return true }

// Ensure NoopReporter satisfies the interface at compile time.
var _ Reporter = NoopReporter{}
