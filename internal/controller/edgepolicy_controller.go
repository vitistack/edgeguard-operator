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

package controller

import (
	"context"
	"fmt"
	"net"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	securityv1alpha1 "github.com/vitistack/edgeguard-operator/api/v1alpha1"
	"github.com/vitistack/edgeguard-operator/internal/upstream"
)

// targetRefField is the index key used to look up EdgePolicies by their referenced Service.
const targetRefField = ".spec.targetRef.name"

// serviceFinalizer is added to Services targeted by an EdgePolicy so the policy can
// clean up before the Service is removed.
const serviceFinalizer = "security.vitistack.io/edgepolicy-protection"

// edgePolicyFinalizer is added to the EdgePolicy itself so its deletion triggers a
// reconcile where we can release the finalizer held on the target Service.
const edgePolicyFinalizer = "security.vitistack.io/edgepolicy-finalizer"

// Condition types and reasons reported on the EdgePolicy status.
const (
	// conditionTypeReady summarizes whether the policy's target Service is protected.
	conditionTypeReady = "Ready"

	reasonServiceProtected       = "ServiceProtected"
	reasonServiceNotFound        = "ServiceNotFound"
	reasonServiceTerminating     = "ServiceTerminating"
	reasonServiceNotLoadBalancer = "ServiceNotLoadBalancer"

	// conditionTypeIpamSecretReady reports whether the Secret referenced by the
	// target Service's ipam.vitistack.io/secret annotation could be resolved.
	conditionTypeIpamSecretReady = "IpamSecretReady"

	reasonSecretResolved      = "SecretResolved"
	reasonSecretNotFound      = "SecretNotFound"
	reasonSecretInvalid       = "SecretInvalid"
	reasonSecretNotConfigured = "SecretNotConfigured"
)

// zoneAnnotation, when present on the target Service, carries the IPAM zone reported upstream.
const zoneAnnotation = "ipam.vitistack.io/zone"

// secretAnnotation names the Secret holding the upstream password for the target Service.
const secretAnnotation = "ipam.vitistack.io/secret"

const (
	// defaultSecretValue is the sentinel annotation value that resolves to the
	// shared Secret named defaultSecretName in defaultSecretNamespace, instead of
	// a Secret in the Service's own namespace.
	defaultSecretValue     = "default"
	defaultSecretName      = "default"
	defaultSecretNamespace = "ipam-system"

	// secretDataKey is the data key read from the resolved Secret.
	secretDataKey = "secret"
)

// EdgePolicyReconciler reconciles a EdgePolicy object
type EdgePolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// Reporter publishes discovered Service ports to an external system. When nil,
	// upstream reporting is skipped.
	Reporter upstream.Reporter
}

// +kubebuilder:rbac:groups=security.vitistack.io,resources=edgepolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.vitistack.io,resources=edgepolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.vitistack.io,resources=edgepolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups=core,resources=services,verbs=get;list;watch;patch;delete
// +kubebuilder:rbac:groups=core,resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the EdgePolicy object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.25.0/pkg/reconcile
//
// Optimistic-concurrency conflicts are treated as a soft, expected outcome: a
// conflict means the object changed under us (commonly the informer cache lagging
// a recent write), so we requeue quietly on the next event instead of surfacing a
// noisy error with a stack trace.
func (r *EdgePolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	log := logf.FromContext(ctx)

	// Soften optimistic-concurrency conflicts into a quiet requeue.
	defer func() {
		if apierrors.IsConflict(err) {
			log.V(1).Info("Reconcile hit an update conflict; retrying on next event", "conflict", err.Error())
			result, err = ctrl.Result{}, nil
		}
	}()

	// Fetch the EdgePolicy being reconciled.
	var policy securityv1alpha1.EdgePolicy
	if err := r.Get(ctx, req.NamespacedName, &policy); err != nil {
		// The policy may have been deleted after the reconcile request was enqueued.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Handle EdgePolicy deletion: release the Service finalizer, then drop our own.
	if !policy.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(&policy, edgePolicyFinalizer) {
			if err := r.releaseServiceFinalizer(ctx, &policy); err != nil {
				return ctrl.Result{}, err
			}
			if controllerutil.RemoveFinalizer(&policy, edgePolicyFinalizer) {
				if err := r.Update(ctx, &policy); err != nil {
					return ctrl.Result{}, err
				}
				log.Info("Removed finalizer from EdgePolicy", "edgepolicy", policy.Name)
			}
		}
		return ctrl.Result{}, nil
	}

	// Ensure the EdgePolicy carries our finalizer so we are reconciled on its deletion.
	if controllerutil.AddFinalizer(&policy, edgePolicyFinalizer) {
		if err := r.Update(ctx, &policy); err != nil {
			return ctrl.Result{}, err
		}
		log.Info("Added finalizer to EdgePolicy", "edgepolicy", policy.Name)
		// The update re-enqueues the policy; continue on the next reconcile with the latest object.
		return ctrl.Result{}, nil
	}

	// Fetch the Service referenced by the policy in the same namespace.
	service := &corev1.Service{}
	serviceKey := types.NamespacedName{Namespace: policy.Namespace, Name: policy.Spec.TargetRef.Name}
	if err := r.Get(ctx, serviceKey, service); err != nil {
		if apierrors.IsNotFound(err) {
			// The target Service does not exist yet; nothing to do until it appears.
			log.Info("Target Service not found, skipping finalizer", "service", serviceKey.Name)
			changed := setReadyCondition(&policy, metav1.ConditionFalse, reasonServiceNotFound,
				fmt.Sprintf("Target Service %q not found", serviceKey.Name))
			return ctrl.Result{}, r.writeStatus(ctx, &policy, changed)
		}
		return ctrl.Result{}, err
	}

	// If the Service is being deleted, release our finalizer so it can finish terminating.
	if !service.DeletionTimestamp.IsZero() {
		if controllerutil.RemoveFinalizer(service, serviceFinalizer) {
			if err := r.Update(ctx, service); err != nil {
				log.Error(err, "Failed to remove finalizer from terminating Service", "service", service.Name)
				return ctrl.Result{}, err
			}
			log.Info("Removed finalizer from terminating Service", "service", service.Name)
		}
		changed := setReadyCondition(&policy, metav1.ConditionFalse, reasonServiceTerminating,
			fmt.Sprintf("Target Service %q is being deleted", service.Name))
		return ctrl.Result{}, r.writeStatus(ctx, &policy, changed)
	}

	// Only Services of type LoadBalancer are managed by this operator. If the target
	// is any other type, release any finalizer we previously placed and mark the policy
	// inactive without discovering or reporting ports.
	if service.Spec.Type != corev1.ServiceTypeLoadBalancer {
		if controllerutil.RemoveFinalizer(service, serviceFinalizer) {
			if err := r.Update(ctx, service); err != nil {
				log.Error(err, "Failed to remove finalizer from non-LoadBalancer Service", "service", service.Name)
				return ctrl.Result{}, err
			}
			log.Info("Removed finalizer from non-LoadBalancer Service", "service", service.Name)
		}
		changed := setReadyCondition(&policy, metav1.ConditionFalse, reasonServiceNotLoadBalancer,
			fmt.Sprintf("Target Service %q is not of type LoadBalancer", service.Name))
		if len(policy.Status.ObservedPorts) > 0 || len(policy.Status.ObservedIPs) > 0 {
			policy.Status.ObservedPorts = nil
			policy.Status.ObservedIPs = nil
			changed = true
		}
		return ctrl.Result{}, r.writeStatus(ctx, &policy, changed)
	}

	// Add the finalizer to the Service if not already present.
	if controllerutil.AddFinalizer(service, serviceFinalizer) {
		if err := r.Update(ctx, service); err != nil {
			log.Error(err, "Failed to add finalizer to Service", "service", service.Name)
			return ctrl.Result{}, err
		}
		log.Info("Added finalizer to Service", "service", service.Name)
	}

	return ctrl.Result{}, r.reconcileProtectedService(ctx, &policy, service)
}

// reconcileProtectedService records the discovered ports and IPs of a protected
// LoadBalancer Service on the policy status, reports them upstream when ACL is
// enabled, and persists the status only when something actually changed.
func (r *EdgePolicyReconciler) reconcileProtectedService(ctx context.Context,
	policy *securityv1alpha1.EdgePolicy, service *corev1.Service) error {
	log := logf.FromContext(ctx)

	// Reflect that the target Service is now protected by this policy.
	condChanged := setReadyCondition(policy, metav1.ConditionTrue, reasonServiceProtected,
		fmt.Sprintf("Finalizer present on Service %q", service.Name))

	// Resolve the IPAM secret (when ACL reporting is enabled) and surface its
	// state on the status. A missing Secret is tolerated: the policy reports a
	// not-found condition but reconciliation continues with an empty credential.
	var ipamSecret string
	secretChanged := false
	if aclEnabled(policy) {
		value, state, err := r.resolveIpamSecret(ctx, service)
		if err != nil {
			log.Error(err, "Failed to resolve IPAM secret", "service", service.Name)
			return err
		}
		ipamSecret = value
		secretChanged = setIpamSecretCondition(policy, service, state)
	} else {
		// No reporting configured; drop any stale secret condition.
		secretChanged = meta.RemoveStatusCondition(&policy.Status.Conditions, conditionTypeIpamSecretReady)
	}

	// Record the discovered Service ports and load balancer IPs. Report them
	// upstream before persisting the change so a failed report is retried on the
	// next reconcile instead of being masked by an already-updated status.
	desiredPorts := observedPortsFromService(service)
	desiredIPs := loadBalancerIPs(service)
	portsChanged := !observedPortsEqual(policy.Status.ObservedPorts, desiredPorts)
	ipsChanged := !stringSlicesEqual(policy.Status.ObservedIPs, desiredIPs)
	if portsChanged || ipsChanged {
		if aclEnabled(policy) {
			if err := r.reportPortsUpstream(ctx, policy, service, ipamSecret, desiredPorts, desiredIPs); err != nil {
				log.Error(err, "Failed to report discovered ports upstream", "service", service.Name)
				return err
			}
		}
		policy.Status.ObservedPorts = desiredPorts
		policy.Status.ObservedIPs = desiredIPs
	}

	return r.writeStatus(ctx, policy, condChanged || secretChanged || portsChanged || ipsChanged)
}

// setReadyCondition mutates the Ready condition and ObservedGeneration on the policy
// status in memory, returning whether anything actually changed.
func setReadyCondition(policy *securityv1alpha1.EdgePolicy,
	status metav1.ConditionStatus, reason, message string) bool {
	changed := meta.SetStatusCondition(&policy.Status.Conditions, metav1.Condition{
		Type:               conditionTypeReady,
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: policy.Generation,
	})
	if policy.Status.ObservedGeneration != policy.Generation {
		policy.Status.ObservedGeneration = policy.Generation
		changed = true
	}
	return changed
}

// observedPortsFromService maps a Service's ports into the status representation.
func observedPortsFromService(service *corev1.Service) []securityv1alpha1.ObservedPort {
	ports := make([]securityv1alpha1.ObservedPort, 0, len(service.Spec.Ports))
	for _, p := range service.Spec.Ports {
		ports = append(ports, securityv1alpha1.ObservedPort{
			Name:     p.Name,
			Port:     p.Port,
			Protocol: p.Protocol,
		})
	}
	return ports
}

// observedPortsEqual reports whether two observed-port lists are identical in order and content.
func observedPortsEqual(a, b []securityv1alpha1.ObservedPort) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// aclEnabled reports whether the policy opts into upstream port reporting via spec.acl.
func aclEnabled(policy *securityv1alpha1.EdgePolicy) bool {
	return policy.Spec.ACL != nil && *policy.Spec.ACL
}

// reportPortsUpstream sends the discovered ports to the external system via the
// configured Reporter. It is a no-op when no Reporter is configured. The caller
// supplies the already-resolved ipamSecret so secret resolution and its status
// condition are handled in one place.
func (r *EdgePolicyReconciler) reportPortsUpstream(ctx context.Context, policy *securityv1alpha1.EdgePolicy,
	service *corev1.Service, ipamSecret string, ports []securityv1alpha1.ObservedPort, ips []string) error {
	if r.Reporter == nil {
		return nil
	}

	clusterUID, err := r.clusterUID(ctx)
	if err != nil {
		return fmt.Errorf("resolving cluster UID: %w", err)
	}

	ipv4, ipv6 := splitIPFamilies(ips)
	report := upstream.PortReport{
		ClusterUID:       clusterUID,
		PolicyNamespace:  policy.Namespace,
		PolicyName:       policy.Name,
		PolicyUID:        string(policy.UID),
		ServiceName:      service.Name,
		IpamZone:         service.Annotations[zoneAnnotation],
		IpamSecret:       ipamSecret,
		LoadBalancerIPv4: ipv4,
		LoadBalancerIPv6: ipv6,
		Ports:            make([]upstream.Port, 0, len(ports)),
	}
	for _, p := range ports {
		report.Ports = append(report.Ports, upstream.Port{
			Name:     p.Name,
			Port:     p.Port,
			Protocol: string(p.Protocol),
		})
	}
	if err := r.Reporter.ReportPorts(ctx, report); err != nil {
		return err
	}
	logf.FromContext(ctx).Info("Reported discovered ports upstream",
		"edgepolicy", policy.Name, "service", service.Name, "ports", len(ports), "ips", len(ips))
	return nil
}

// clusterUID returns the UID of the kube-system namespace, used as a stable
// cluster identifier. A missing kube-system namespace yields an empty UID
// rather than an error.
func (r *EdgePolicyReconciler) clusterUID(ctx context.Context) (string, error) {
	var ns corev1.Namespace
	if err := r.Get(ctx, types.NamespacedName{Name: "kube-system"}, &ns); err != nil {
		if apierrors.IsNotFound(err) {
			return "", nil
		}
		return "", err
	}
	return string(ns.UID), nil
}

// ipamSecretState captures how the ipam.vitistack.io/secret reference resolved.
type ipamSecretState int

const (
	// ipamSecretResolved means the Secret was found and carried the expected key
	// (or no Secret was referenced at all).
	ipamSecretResolved ipamSecretState = iota
	// ipamSecretNotFound means the referenced Secret does not exist.
	ipamSecretNotFound
	// ipamSecretInvalid means the referenced Secret exists but lacks the expected key.
	ipamSecretInvalid
)

// resolveIpamSecret reads the credential for the target Service, as named by its
// ipam.vitistack.io/secret annotation. A "default" value resolves to the shared
// Secret ipam-system/default; any other value resolves to a Secret of that name in
// the Service's own namespace.
//
// It returns the credential and a state describing how resolution went. A missing
// annotation, a referenced Secret that does not exist, and a Secret that lacks the
// expected key are all non-fatal: they yield an empty credential and a state the
// caller surfaces on the status without blocking reconciliation. Only unexpected
// API errors are returned as err.
func (r *EdgePolicyReconciler) resolveIpamSecret(
	ctx context.Context, service *corev1.Service) (string, ipamSecretState, error) {
	name := service.Annotations[secretAnnotation]
	if name == "" {
		return "", ipamSecretResolved, nil
	}

	key := types.NamespacedName{Namespace: service.Namespace, Name: name}
	if name == defaultSecretValue {
		key = types.NamespacedName{Namespace: defaultSecretNamespace, Name: defaultSecretName}
	}

	var secret corev1.Secret
	if err := r.Get(ctx, key, &secret); err != nil {
		if apierrors.IsNotFound(err) {
			return "", ipamSecretNotFound, nil
		}
		return "", ipamSecretResolved, err
	}
	value, ok := secret.Data[secretDataKey]
	if !ok {
		return "", ipamSecretInvalid, nil
	}
	return string(value), ipamSecretResolved, nil
}

// setIpamSecretCondition reflects the resolution state of the ipam.vitistack.io/secret
// annotation on the policy status, returning whether the status changed. When the
// Service carries no such annotation, the condition is set to SecretNotConfigured so
// the missing credential is visible rather than silent.
func setIpamSecretCondition(policy *securityv1alpha1.EdgePolicy, service *corev1.Service,
	state ipamSecretState) bool {
	name := service.Annotations[secretAnnotation]
	if name == "" {
		return meta.SetStatusCondition(&policy.Status.Conditions, metav1.Condition{
			Type:               conditionTypeIpamSecretReady,
			Status:             metav1.ConditionFalse,
			Reason:             reasonSecretNotConfigured,
			Message:            fmt.Sprintf("Service has no %s annotation", secretAnnotation),
			ObservedGeneration: policy.Generation,
		})
	}

	status, reason, message := metav1.ConditionTrue, reasonSecretResolved,
		fmt.Sprintf("Resolved Secret %q", name)
	switch state {
	case ipamSecretNotFound:
		status, reason, message = metav1.ConditionFalse, reasonSecretNotFound,
			fmt.Sprintf("Secret %q referenced by %s annotation not found", name, secretAnnotation)
	case ipamSecretInvalid:
		status, reason, message = metav1.ConditionFalse, reasonSecretInvalid,
			fmt.Sprintf("Secret %q has no %q key", name, secretDataKey)
	case ipamSecretResolved:
		// Keep the resolved defaults set above.
	}
	return meta.SetStatusCondition(&policy.Status.Conditions, metav1.Condition{
		Type:               conditionTypeIpamSecretReady,
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: policy.Generation,
	})
}

// loadBalancerIPs returns the Service's load balancer ingress IPs in order,
// ignoring blank or unparseable entries.
func loadBalancerIPs(service *corev1.Service) []string {
	ips := make([]string, 0, len(service.Status.LoadBalancer.Ingress))
	for _, ingress := range service.Status.LoadBalancer.Ingress {
		if ingress.IP == "" {
			continue
		}
		if net.ParseIP(ingress.IP) == nil {
			continue
		}
		ips = append(ips, ingress.IP)
	}
	return ips
}

// splitIPFamilies partitions IPs into IPv4 and IPv6, preserving order within each family.
func splitIPFamilies(ips []string) (ipv4, ipv6 []string) {
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			continue
		}
		if parsed.To4() != nil {
			ipv4 = append(ipv4, ip)
		} else {
			ipv6 = append(ipv6, ip)
		}
	}
	return ipv4, ipv6
}

// stringSlicesEqual reports whether two string slices are identical in order and content.
func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// writeStatus persists the policy status subresource only when changed is true.
func (r *EdgePolicyReconciler) writeStatus(ctx context.Context, policy *securityv1alpha1.EdgePolicy, changed bool) error {
	if !changed {
		return nil
	}
	if err := r.Status().Update(ctx, policy); err != nil {
		return err
	}
	logf.FromContext(ctx).Info("Updated EdgePolicy status", "edgepolicy", policy.Name)
	return nil
}

// releaseServiceFinalizer removes the finalizer this operator placed on the target Service,
// but only once no other live EdgePolicy still references that Service.
func (r *EdgePolicyReconciler) releaseServiceFinalizer(ctx context.Context, policy *securityv1alpha1.EdgePolicy) error {
	log := logf.FromContext(ctx)
	ref := policy.Spec.TargetRef

	// Check for other EdgePolicies that still reference the same Service.
	var policies securityv1alpha1.EdgePolicyList
	if err := r.List(ctx, &policies,
		client.InNamespace(policy.Namespace),
		client.MatchingFields{targetRefField: targetRefKey(ref.APIVersion, ref.Kind, ref.Name)},
	); err != nil {
		return err
	}
	for i := range policies.Items {
		other := &policies.Items[i]
		if other.UID == policy.UID {
			continue
		}
		// Another policy that is not being deleted still needs the Service protected.
		if other.DeletionTimestamp.IsZero() {
			log.Info("Keeping Service finalizer, still referenced by another EdgePolicy",
				"service", ref.Name, "edgepolicy", other.Name)
			return nil
		}
	}

	// No other live policy references the Service; remove our finalizer from it.
	service := &corev1.Service{}
	serviceKey := types.NamespacedName{Namespace: policy.Namespace, Name: ref.Name}
	if err := r.Get(ctx, serviceKey, service); err != nil {
		// Service already gone; nothing to release.
		return client.IgnoreNotFound(err)
	}
	if controllerutil.RemoveFinalizer(service, serviceFinalizer) {
		if err := r.Update(ctx, service); err != nil {
			return err
		}
		log.Info("Removed finalizer from Service", "service", service.Name)
	}
	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *EdgePolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Index EdgePolicies by the apiVersion/kind/name they reference so target events can be mapped back.
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &securityv1alpha1.EdgePolicy{}, targetRefField,
		func(obj client.Object) []string {
			ref := obj.(*securityv1alpha1.EdgePolicy).Spec.TargetRef
			if ref.Name == "" {
				return nil
			}
			return []string{targetRefKey(ref.APIVersion, ref.Kind, ref.Name)}
		}); err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1alpha1.EdgePolicy{}).
		Watches(
			&corev1.Service{},
			handler.EnqueueRequestsFromMapFunc(r.edgePoliciesForService),
			builder.WithPredicates(loadBalancerServicePredicate()),
		).
		Named("edgepolicy").
		Complete(r)
}

// loadBalancerServicePredicate restricts Service events to those involving a
// LoadBalancer Service. Update events pass when either the old or new object is
// a LoadBalancer, so a Service that transitions away from LoadBalancer still
// triggers a reconcile that can clean up.
func loadBalancerServicePredicate() predicate.Predicate {
	return predicate.Funcs{
		CreateFunc:  func(e event.CreateEvent) bool { return isLoadBalancerService(e.Object) },
		DeleteFunc:  func(e event.DeleteEvent) bool { return isLoadBalancerService(e.Object) },
		GenericFunc: func(e event.GenericEvent) bool { return isLoadBalancerService(e.Object) },
		UpdateFunc: func(e event.UpdateEvent) bool {
			return isLoadBalancerService(e.ObjectOld) || isLoadBalancerService(e.ObjectNew)
		},
	}
}

// isLoadBalancerService reports whether obj is a Service of type LoadBalancer.
func isLoadBalancerService(obj client.Object) bool {
	service, ok := obj.(*corev1.Service)
	return ok && service.Spec.Type == corev1.ServiceTypeLoadBalancer
}

// targetRefKey builds the index key for a target reference.
func targetRefKey(apiVersion, kind, name string) string {
	return apiVersion + "/" + kind + "/" + name
}

// edgePoliciesForService maps a Service to the EdgePolicies that reference it via spec.targetRef.
func (r *EdgePolicyReconciler) edgePoliciesForService(ctx context.Context, obj client.Object) []reconcile.Request {
	var policies securityv1alpha1.EdgePolicyList
	if err := r.List(ctx, &policies,
		client.InNamespace(obj.GetNamespace()),
		client.MatchingFields{targetRefField: targetRefKey("v1", "Service", obj.GetName())},
	); err != nil {
		return nil
	}

	requests := make([]reconcile.Request, 0, len(policies.Items))
	for i := range policies.Items {
		requests = append(requests, reconcile.Request{
			Name:      policies.Items[i].Name,
			Namespace: policies.Items[i].Namespace,
		})
	}
	return requests
}
