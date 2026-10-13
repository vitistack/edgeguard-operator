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

import "testing"

// protoTCP and portHTTP avoid repeating literals across fixtures (goconst).
const (
	protoTCP = "TCP"
	portHTTP = "http"
)

// baseReport is a representative report used across the idempotency-key tests.
func baseReport() PortReport {
	return PortReport{
		PolicyUID:        "uid-1",
		Ports:            []Port{{Name: portHTTP, Port: 80, Protocol: protoTCP}},
		LoadBalancerIPv4: []string{"203.0.113.10"},
		LoadBalancerIPv6: []string{"2001:db8::10"},
	}
}

func TestIdempotencyKeyIgnoresNonDedupeFields(t *testing.T) {
	base := baseReport()

	// Same policy/ports/IPs but a rotated credential, different zone, cluster UID,
	// and policy name must not change the key.
	other := baseReport()
	other.IpamSecret = "rotated"
	other.IpamZone = "oslo-2"
	other.ClusterUID = "a-different-cluster"
	other.PolicyName = "renamed"
	other.PolicyNamespace = "elsewhere"
	other.ServiceName = "renamed-svc"

	if base.IdempotencyKey() != other.IdempotencyKey() {
		t.Fatalf("expected equal keys when only non-dedupe fields differ:\n base=%s\n other=%s",
			base.IdempotencyKey(), other.IdempotencyKey())
	}
}

func TestIdempotencyKeyChangesWithDedupeFields(t *testing.T) {
	base := baseReport()
	baseKey := base.IdempotencyKey()

	cases := map[string]func(*PortReport){
		"policy UID": func(r *PortReport) { r.PolicyUID = "uid-2" },
		"port added": func(r *PortReport) {
			r.Ports = append(r.Ports, Port{Name: "https", Port: 443, Protocol: protoTCP})
		},
		"port number": func(r *PortReport) { r.Ports = []Port{{Name: portHTTP, Port: 8080, Protocol: protoTCP}} },
		"protocol":    func(r *PortReport) { r.Ports = []Port{{Name: portHTTP, Port: 80, Protocol: "UDP"}} },
		"ipv4":        func(r *PortReport) { r.LoadBalancerIPv4 = []string{"203.0.113.11"} },
		"ipv6":        func(r *PortReport) { r.LoadBalancerIPv6 = nil },
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := baseReport()
			mutate(&r)
			if r.IdempotencyKey() == baseKey {
				t.Fatalf("expected key to change when %s changes", name)
			}
		})
	}
}
