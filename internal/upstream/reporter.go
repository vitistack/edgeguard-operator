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
	// ClusterUID is the UID of the kube-system namespace, used as a stable
	// cluster identifier.
	ClusterUID string `json:"clusterUID,omitempty"`
	// PolicyNamespace and PolicyName identify the EdgePolicy that owns the report.
	PolicyNamespace string `json:"policyNamespace"`
	PolicyName      string `json:"policyName"`
	// PolicyUID uniquely identifies the policy instance across recreations.
	PolicyUID string `json:"policyUID,omitempty"`
	// ServiceName is the target Service the ports were discovered on.
	ServiceName string `json:"serviceName"`
	// IpamZone is the value of the ipam.vitistack.io/zone annotation on the target
	// Service, when present.
	IpamZone string `json:"ipamZone,omitempty"`
	// IpamSecret is the credential resolved from the Secret named by the target
	// Service's ipam.vitistack.io/secret annotation, when present.
	IpamSecret string `json:"ipamSecret,omitempty"`
	// LoadBalancerIPv4 and LoadBalancerIPv6 are the load balancer ingress
	// addresses assigned to the target Service, split by IP family.
	LoadBalancerIPv4 []string `json:"loadBalancerIPv4,omitempty"`
	LoadBalancerIPv6 []string `json:"loadBalancerIPv6,omitempty"`
	// Ports is the full, current set of discovered ports (not a delta).
	Ports []Port `json:"ports"`
}

// IdempotencyKey returns a stable identifier for the dedupe-relevant content of
// the report: the owning policy plus its discovered ports and load balancer IPs.
// Two reports with the same policy, ports, and IPs produce the same key, so an
// upstream can treat a retry — or a duplicate caused by a reconcile conflict — as
// the same request and ignore it. Fields that do not change the meaning of the
// report (credential, zone, cluster UID) are deliberately excluded, so rotating a
// credential alone does not defeat deduplication.
func (r PortReport) IdempotencyKey() string {
	var b strings.Builder
	b.WriteString(r.PolicyUID)
	// Separate sections with a byte that cannot appear in the values above so
	// distinct inputs cannot collide by concatenation.
	b.WriteByte('\n')
	for _, p := range r.Ports {
		b.WriteString(p.Name)
		b.WriteByte('\t')
		b.WriteString(strconv.FormatInt(int64(p.Port), 10))
		b.WriteByte('\t')
		b.WriteString(p.Protocol)
		b.WriteByte('\n')
	}
	b.WriteByte('\n')
	for _, ip := range r.LoadBalancerIPv4 {
		b.WriteString(ip)
		b.WriteByte('\n')
	}
	for _, ip := range r.LoadBalancerIPv6 {
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
// controller can requeue and retry.
type Reporter interface {
	ReportPorts(ctx context.Context, report PortReport) error
}

// NoopReporter is a Reporter that discards every report. It is the default when
// no upstream endpoint is configured, which keeps the controller usable without
// an external dependency.
type NoopReporter struct{}

// ReportPorts implements Reporter and does nothing.
func (NoopReporter) ReportPorts(context.Context, PortReport) error { return nil }

// Ensure NoopReporter satisfies the interface at compile time.
var _ Reporter = NoopReporter{}
