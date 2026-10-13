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
	ClusterID string `json:"clusterID,omitempty"`
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
	// assigned to the target Service, split by IP family.
	IPv4Addresses []string `json:"ipv4Addresses,omitempty"`
	IPv6Addresses []string `json:"ipv6Addresses,omitempty"`
	// ObservedPorts is the full, current set of discovered ports (not a delta).
	ObservedPorts []Port `json:"observedPorts"`
	// AdditionalPorts is the set of user-declared ports from
	// spec.filter.additionalPortList, reported alongside the discovered ports.
	AdditionalPorts []Port `json:"additionalPorts,omitempty"`
}

// IdempotencyKey returns a stable identifier for the dedupe-relevant content of
// the report: the target Service plus its discovered ports and load balancer IPs,
// the datacenter, and the declared additional ports. Two reports with the same
// such content produce the same key, so an upstream can treat a retry — or a
// duplicate caused by a reconcile conflict — as the same request and ignore it.
// Fields that do not change the meaning of the report (credential, zone, cluster
// ID) are deliberately excluded, so rotating a credential alone does not defeat
// deduplication.
func (r PortReport) IdempotencyKey() string {
	var b strings.Builder
	b.WriteString(r.ServiceName)
	// Separate sections with a byte that cannot appear in the values above so
	// distinct inputs cannot collide by concatenation.
	b.WriteByte('\n')
	b.WriteString(r.Datacenter)
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
	writePorts(r.ObservedPorts)
	b.WriteByte('\n')
	writePorts(r.AdditionalPorts)
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

// Reporter reports discovered Service ports to an external upstream system.
//
// Implementations must be safe for concurrent use: the controller may invoke
// ReportPorts from multiple reconciles at once. ReportPorts should return a
// non-nil error when the report was not durably accepted upstream so the
// controller can requeue and retry. DeletePorts withdraws a previously reported
// set of ports when the policy or its target Service is removed, with the same
// retry semantics.
type Reporter interface {
	ReportPorts(ctx context.Context, report PortReport) error
	DeletePorts(ctx context.Context, report PortReport) error
}

// NoopReporter is a Reporter that discards every report and reports success. It
// backs the "reporting disabled" mode: the operator behaves as if every report
// was delivered, without contacting any upstream or surfacing a failure.
type NoopReporter struct{}

// ReportPorts implements Reporter and does nothing.
func (NoopReporter) ReportPorts(context.Context, PortReport) error { return nil }

// DeletePorts implements Reporter and does nothing.
func (NoopReporter) DeletePorts(context.Context, PortReport) error { return nil }

// Configured reports true so the controller treats disabled reporting as healthy
// (no UpstreamReady=False condition) rather than as a missing configuration.
func (NoopReporter) Configured() bool { return true }

// Disabled reports true so the controller can log that reports were accepted
// without being delivered, instead of claiming a real upstream delivery.
func (NoopReporter) Disabled() bool { return true }

// Ensure NoopReporter satisfies the interface at compile time.
var _ Reporter = NoopReporter{}
