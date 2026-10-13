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

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// EdgePolicySpec defines the desired state of EdgePolicy
//
// +kubebuilder:validation:XValidation:rule="has(self.acl) || has(self.allowedRegion)",message="At least one of acl or allowedRegion must be specified"
type EdgePolicySpec struct {
	// TargetRef references the object in the same namespace that this policy applies to.
	// +required
	TargetRef TargetReference `json:"targetRef"`

	// Enables service port discovery and reporting to the upstream system.
	// +optional
	ACL *bool `json:"acl,omitempty"`

	// Geographic region policy with optional additional allowed IP ranges.
	// +optional
	AllowedRegion *AllowedRegionSpec `json:"allowedRegion,omitempty"`
}

// TargetReference references an object by apiVersion, kind, and name in the same namespace as the EdgePolicy.
type TargetReference struct {
	// APIVersion of the referenced object. Only "v1" is supported.
	// +required
	// +kubebuilder:validation:Enum=v1
	APIVersion string `json:"apiVersion"`

	// Kind of the referenced object. Only "Service" is supported.
	// +required
	// +kubebuilder:validation:Enum=Service
	Kind string `json:"kind"`

	// Name of the referenced object.
	// +required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// AllowedRegionSpec defines the geographic policy and CIDR exceptions.
type AllowedRegionSpec struct {
	// Geographic region permitted by the edge policy.
	// +kubebuilder:validation:Enum=norway;nordics;europe
	Region string `json:"region"`

	// Additional IPv4 or IPv6 CIDR ranges allowed regardless of geographic region.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=256
	// +kubebuilder:validation:items:Type=string
	// +kubebuilder:validation:items:MaxLength=43
	// +kubebuilder:validation:XValidation:rule="self.all(cidr, isCIDR(cidr))",message="Each entry must be a valid IPv4 or IPv6 CIDR"
	AdditionalAllowList []string `json:"additionalAllowList,omitempty"`
}

// ObservedPort describes a port discovered on the target Service.
type ObservedPort struct {
	// Name is the name of the Service port, if one is set.
	// +optional
	// +kubebuilder:validation:MaxLength=63
	Name string `json:"name,omitempty"`

	// Port is the port number exposed by the Service.
	// +required
	Port int32 `json:"port"`

	// Protocol is the IP protocol for this port (TCP, UDP, or SCTP).
	// +optional
	// +kubebuilder:validation:Enum=TCP;UDP;SCTP
	Protocol corev1.Protocol `json:"protocol,omitempty"`
}

// EdgePolicyStatus defines the observed state of EdgePolicy.
type EdgePolicyStatus struct {
	// ObservedGeneration is the most recent generation observed by the controller.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// ObservedPorts lists the ports discovered on the target Service.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=256
	ObservedPorts []ObservedPort `json:"observedPorts,omitempty"`

	// ObservedIPs lists the load balancer ingress IP addresses discovered on the
	// target Service.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=256
	// +kubebuilder:validation:items:MaxLength=45
	ObservedIPs []string `json:"observedIPs,omitempty"`

	// Conditions represent the current status of the edge policy.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=epol
// +kubebuilder:printcolumn:name="Target",type=string,JSONPath=".spec.targetRef.name"
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=".status.conditions[?(@.type=='Ready')].reason",priority=1
// +kubebuilder:printcolumn:name="Secret",type=string,JSONPath=".status.conditions[?(@.type=='IpamSecretReady')].reason",priority=1
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=".metadata.creationTimestamp"

// EdgePolicy is the Schema for the edgepolicies API
type EdgePolicy struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of EdgePolicy
	// +required
	Spec EdgePolicySpec `json:"spec"`

	// status defines the observed state of EdgePolicy
	// +optional
	Status EdgePolicyStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// EdgePolicyList contains a list of EdgePolicy
type EdgePolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []EdgePolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &EdgePolicy{}, &EdgePolicyList{})
		return nil
	})
}
