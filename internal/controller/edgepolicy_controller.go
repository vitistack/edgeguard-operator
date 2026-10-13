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
	"errors"
	"fmt"
	"net"
	"time"

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

// upstreamRetryInterval is how long to wait before retrying after a transient
// upstream report failure (DNS, connectivity, 5xx). Such failures are logged
// softly and requeued rather than surfaced as a hard reconcile error with a
// stack trace, since they are expected and self-healing.
const upstreamRetryInterval = 30 * time.Second

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

	// conditionTypeUpstreamReady reports whether upstream port reporting is
	// configured (i.e. a BaseURL is set from UPSTREAM_API_URL). It is only
	// evaluated for policies that enable filter reporting.
	conditionTypeUpstreamReady = "UpstreamReady"

	reasonUpstreamNotConfigured = "UpstreamNotConfigured"
	reasonUpstreamReportFailed  = "UpstreamReportFailed"
	reasonUpstreamIncomplete    = "UpstreamReportIncomplete"
	reasonUpstreamRejected      = "UpstreamReportRejected"
)

// rejectedReportMessage is the stable status message used whenever a report is in the
// terminal Rejected state (freshly rejected or suppressed as an unchanged retry). It
// omits the volatile HTTP status so re-asserting it is a no-op, which lets the
// suppressed reconcile reach a quiet fixpoint instead of rewriting the status. The
// concrete status code is logged rather than stored on the condition.
const rejectedReportMessage = "Upstream rejected the report; not retried until the report content changes"

// errReportSuppressed signals that a report identical to one the upstream already
// rejected (same idempotency key) was withheld rather than re-sent.
var errReportSuppressed = errors.New("report suppressed: unchanged since the upstream rejected it")

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
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get

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

	// Handle EdgePolicy deletion: withdraw ports upstream, release the Service
	// finalizer, then drop our own.
	if !policy.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(&policy, edgePolicyFinalizer) {
			// Withdraw the policy's ports upstream before we let the object go. A
			// transient failure holds the finalizer and requeues so the delete is
			// retried rather than leaving stale upstream state. A withdrawal we cannot
			// even form (missing credential or addresses) or one the upstream refuses
			// with a 4xx is skipped so deletion is never blocked on a precondition that
			// retrying will not satisfy.
			if err := r.deletePortsUpstream(ctx, &policy, policy.Spec.TargetRef.Name); err != nil {
				switch {
				case errors.Is(err, upstream.ErrIncompleteReport):
					log.Info("Skipped upstream withdrawal during deletion; required fields missing",
						"edgepolicy", policy.Name, "detail", err.Error())
				case errors.Is(err, upstream.ErrUpstreamRejected):
					log.Info("Skipped upstream withdrawal during deletion; upstream rejected it",
						"edgepolicy", policy.Name, "detail", err.Error())
				default:
					log.Info("Could not withdraw ports upstream during deletion; will retry",
						"edgepolicy", policy.Name, "retryAfter", upstreamRetryInterval.String(), "error", err.Error())
					return ctrl.Result{RequeueAfter: upstreamRetryInterval}, nil
				}
			}
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
		return r.deactivatePolicy(ctx, &policy, service, reasonServiceTerminating,
			fmt.Sprintf("Target Service %q is being deleted", service.Name), "terminating Service")
	}

	// Only Services of type LoadBalancer are managed by this operator. If the target
	// is any other type, release any finalizer we previously placed and mark the policy
	// inactive without discovering or reporting ports.
	if service.Spec.Type != corev1.ServiceTypeLoadBalancer {
		return r.deactivatePolicy(ctx, &policy, service, reasonServiceNotLoadBalancer,
			fmt.Sprintf("Target Service %q is not of type LoadBalancer", service.Name), "non-LoadBalancer Service")
	}

	// Add the finalizer to the Service if not already present.
	if controllerutil.AddFinalizer(service, serviceFinalizer) {
		if err := r.Update(ctx, service); err != nil {
			log.Error(err, "Failed to add finalizer to Service", "service", service.Name)
			return ctrl.Result{}, err
		}
		log.Info("Added finalizer to Service", "service", service.Name)
	}

	return r.reconcileProtectedService(ctx, &policy, service)
}

// reconcileProtectedService records the discovered ports and IPs of a protected
// LoadBalancer Service on the policy status, reports them upstream when filter is
// enabled, and persists the status only when something actually changed.
//
// A transient upstream report failure is treated as soft: it is logged at Info
// level and requeued after upstreamRetryInterval rather than returned as an error,
// so the controller does not emit a noisy ERROR with a stack trace for an expected,
// self-healing condition.
func (r *EdgePolicyReconciler) reconcileProtectedService(ctx context.Context,
	policy *securityv1alpha1.EdgePolicy, service *corev1.Service) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// Capture whether the spec changed since our last status write before any
	// status mutation below advances ObservedGeneration. A spec change (e.g. an
	// edit to datacenter or filter.additionalPortList) must re-trigger a report
	// even when the discovered ports and IPs are unchanged.
	generationChanged := policy.Generation != policy.Status.ObservedGeneration

	// Resolve the IPAM secret (when filter reporting is enabled) and surface its
	// state on the status. A missing Secret is tolerated: the policy reports a
	// not-found condition but reconciliation continues with an empty credential.
	var ipamSecret string
	secretChanged := false
	upstreamChanged := false
	upstreamConfigured := false
	if filterEnabled(policy) {
		value, state, err := r.resolveIpamSecret(ctx, service)
		if err != nil {
			log.Error(err, "Failed to resolve IPAM secret", "service", service.Name)
			return ctrl.Result{}, err
		}
		ipamSecret = value
		secretChanged = setIpamSecretCondition(policy, service, state)

		// Surface a missing UPSTREAM_API_URL on the status. When an endpoint *is*
		// configured the UpstreamReady condition is driven by the report outcome
		// below (removed on success, set to a failure reason otherwise), so it is left
		// untouched here — re-deriving it every reconcile would churn the condition and
		// defeat the suppression of an already-rejected report.
		upstreamConfigured = reporterConfigured(r.Reporter)
		if !upstreamConfigured {
			upstreamChanged = setUpstreamConfiguredCondition(policy, false)
		}
	} else {
		// No reporting configured; drop any stale secret / upstream conditions and
		// forget any remembered rejection.
		secretChanged = meta.RemoveStatusCondition(&policy.Status.Conditions, conditionTypeIpamSecretReady)
		upstreamChanged = meta.RemoveStatusCondition(&policy.Status.Conditions, conditionTypeUpstreamReady)
		if policy.Status.RejectedReportKey != "" {
			policy.Status.RejectedReportKey = ""
			upstreamChanged = true
		}
	}

	// Record the discovered Service ports and load balancer IPs. Report them
	// upstream before persisting the change so a failed report is retried on the
	// next reconcile instead of being masked by an already-updated status.
	desiredPorts := observedPortsFromService(service)
	desiredIPs := loadBalancerIPs(service)
	portsChanged := !observedPortsEqual(policy.Status.ObservedPorts, desiredPorts)
	ipsChanged := !stringSlicesEqual(policy.Status.ObservedIPs, desiredIPs)
	if portsChanged || ipsChanged || generationChanged {
		if filterEnabled(policy) && upstreamConfigured {
			key, err := r.reportPortsUpstream(ctx, policy, service, ipamSecret, desiredPorts, desiredIPs)
			switch {
			case errors.Is(err, errReportSuppressed):
				// Identical to a report the upstream already rejected: keep the terminal
				// Rejected status without re-sending, persisting ports, or requeuing. A
				// changed report produces a different key and is attempted afresh.
				return r.markReportRejected(ctx, policy, secretChanged || upstreamChanged)
			case errors.Is(err, upstream.ErrUpstreamRejected):
				// Remember the rejected payload so an identical retry is suppressed.
				policy.Status.RejectedReportKey = key
				return r.handleReportFailure(ctx, policy, err, secretChanged || upstreamChanged)
			case err != nil:
				// Missing required fields (UpstreamReportIncomplete) or a transient
				// delivery failure (UpstreamReportFailed). Both are soft: ObservedPorts is
				// left unwritten so the retry re-sends once the cause clears.
				return r.handleReportFailure(ctx, policy, err, secretChanged || upstreamChanged)
			}
			// Accepted: forget any prior rejection and clear the UpstreamReady condition
			// so the status reads healthy again.
			policy.Status.RejectedReportKey = ""
			if meta.RemoveStatusCondition(&policy.Status.Conditions, conditionTypeUpstreamReady) {
				upstreamChanged = true
			}
		}
		policy.Status.ObservedPorts = desiredPorts
		policy.Status.ObservedIPs = desiredIPs
	}

	// The target Service is protected and its last report (if any) was accepted.
	condChanged := setReadyCondition(policy, metav1.ConditionTrue, reasonServiceProtected,
		fmt.Sprintf("Finalizer present on Service %q", service.Name))

	return ctrl.Result{}, r.writeStatus(ctx, policy,
		condChanged || secretChanged || upstreamChanged || portsChanged || ipsChanged)
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

// filterEnabled reports whether the policy opts into upstream port reporting via
// spec.filter.enable.
func filterEnabled(policy *securityv1alpha1.EdgePolicy) bool {
	return policy.Spec.Filter != nil && policy.Spec.Filter.Enable
}

// additionalPorts maps the policy's declared spec.filter.additionalPortList into the
// upstream payload representation.
func additionalPorts(policy *securityv1alpha1.EdgePolicy) []upstream.Port {
	if policy.Spec.Filter == nil || len(policy.Spec.Filter.AdditionalPortList) == 0 {
		return nil
	}
	ports := make([]upstream.Port, 0, len(policy.Spec.Filter.AdditionalPortList))
	for _, p := range policy.Spec.Filter.AdditionalPortList {
		ports = append(ports, upstream.Port{
			Name:     p.Name,
			Port:     p.Port,
			Protocol: p.Protocol,
		})
	}
	return ports
}

// reportPortsUpstream sends the discovered ports to the external system via the
// configured Reporter. It is a no-op when no Reporter is configured. The caller
// supplies the already-resolved ipamSecret so secret resolution and its status
// condition are handled in one place. It returns the report's idempotency key so the
// caller can remember a rejected payload; when that key matches a previously rejected
// report the call is short-circuited with errReportSuppressed instead of re-sending.
func (r *EdgePolicyReconciler) reportPortsUpstream(ctx context.Context, policy *securityv1alpha1.EdgePolicy,
	service *corev1.Service, ipamSecret string, ports []securityv1alpha1.ObservedPort, ips []string) (string, error) {
	if r.Reporter == nil {
		return "", nil
	}

	clusterID, err := r.clusterUID(ctx)
	if err != nil {
		return "", fmt.Errorf("resolving cluster ID: %w", err)
	}

	ipv4, ipv6 := splitIPFamilies(ips)
	report := upstream.PortReport{
		ClusterID:             clusterID,
		EdgePolicyNamespaceID: r.namespaceUID(ctx, policy.Namespace),
		EdgePolicyID:          string(policy.UID),
		ServiceName:           service.Name,
		Datacenter:            policy.Spec.Datacenter,
		IpamZone:              service.Annotations[zoneAnnotation],
		IpamSecret:            ipamSecret,
		IPv4Addresses:         ipv4,
		IPv6Addresses:         ipv6,
		ObservedPorts:         make([]upstream.Port, 0, len(ports)),
		AdditionalPorts:       additionalPorts(policy),
	}
	for _, p := range ports {
		report.ObservedPorts = append(report.ObservedPorts, upstream.Port{
			Name:     p.Name,
			Port:     p.Port,
			Protocol: string(p.Protocol),
		})
	}
	// The upstream requires the IPAM credential and at least one load balancer
	// address on every report; without them the report is not sent.
	if err := report.Validate(); err != nil {
		return "", err
	}
	// Once the upstream has rejected a report with a 4xx, an identical payload will be
	// rejected again. Short-circuit it so the policy settles on its terminal Rejected
	// status instead of re-POSTing on every reconcile and Service event.
	key := report.IdempotencyKey()
	if policy.Status.RejectedReportKey != "" && policy.Status.RejectedReportKey == key {
		return key, errReportSuppressed
	}
	if err := r.Reporter.ReportPorts(ctx, report); err != nil {
		return key, err
	}
	log := logf.FromContext(ctx)
	if reportingDisabled(r.Reporter) {
		log.Info("Skipped upstream report (reporting disabled)",
			"edgepolicy", policy.Name, "service", service.Name, "ports", len(ports), "ips", len(ips))
	} else {
		log.Info("Reported discovered ports upstream",
			"edgepolicy", policy.Name, "service", service.Name, "ports", len(ports), "ips", len(ips))
	}
	return key, nil
}

// deactivatePolicy releases the operator's hold on a Service that is no longer
// managed (it is terminating or is no longer a LoadBalancer): it withdraws any
// previously reported ports upstream, removes the Service finalizer, and marks the
// policy inactive with the given reason/message. A transient upstream withdraw
// failure requeues after upstreamRetryInterval and keeps the finalizer so the
// delete is retried rather than leaving stale upstream state. note labels the log
// lines with the triggering transition.
func (r *EdgePolicyReconciler) deactivatePolicy(ctx context.Context, policy *securityv1alpha1.EdgePolicy,
	service *corev1.Service, reason, message, note string) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	hadState := len(policy.Status.ObservedPorts) > 0 || len(policy.Status.ObservedIPs) > 0
	if hadState {
		if err := r.deletePortsUpstream(ctx, policy, service.Name); err != nil {
			switch {
			case errors.Is(err, upstream.ErrIncompleteReport):
				// Nothing valid to withdraw (missing credential or addresses); do not
				// hold the Service finalizer on a precondition that will not be met.
				log.Info("Skipped upstream withdrawal; required fields missing",
					"service", service.Name, "transition", note, "detail", err.Error())
			case errors.Is(err, upstream.ErrUpstreamRejected):
				// A 4xx will not succeed on retry; proceed rather than holding the
				// Service finalizer indefinitely.
				log.Info("Skipped upstream withdrawal; upstream rejected it",
					"service", service.Name, "transition", note, "detail", err.Error())
			default:
				log.Info("Could not withdraw ports upstream; will retry",
					"service", service.Name, "transition", note,
					"retryAfter", upstreamRetryInterval.String(), "error", err.Error())
				return ctrl.Result{RequeueAfter: upstreamRetryInterval}, nil
			}
		}
	}
	if controllerutil.RemoveFinalizer(service, serviceFinalizer) {
		if err := r.Update(ctx, service); err != nil {
			log.Error(err, "Failed to remove finalizer from Service", "service", service.Name, "transition", note)
			return ctrl.Result{}, err
		}
		log.Info("Removed finalizer from Service", "service", service.Name, "transition", note)
	}
	changed := setReadyCondition(policy, metav1.ConditionFalse, reason, message)
	if hadState {
		policy.Status.ObservedPorts = nil
		policy.Status.ObservedIPs = nil
		changed = true
	}
	return ctrl.Result{}, r.writeStatus(ctx, policy, changed)
}

// deletePortsUpstream withdraws a policy's previously reported ports from the
// upstream system when the policy or its target Service is removed. The report is
// reconstructed from the policy status (last observed ports and IPs) plus the
// datacenter and declared additional ports from the spec. The upstream requires the
// IPAM credential on the withdrawal too, so it is resolved best-effort from the
// target Service's ipam.vitistack.io/secret annotation; when the Service is already
// gone the credential (and zone) are simply omitted. It is a no-op unless the policy
// enables filter reporting and the Reporter is configured.
func (r *EdgePolicyReconciler) deletePortsUpstream(ctx context.Context,
	policy *securityv1alpha1.EdgePolicy, serviceName string) error {
	if !filterEnabled(policy) || !reporterConfigured(r.Reporter) || r.Reporter == nil {
		return nil
	}

	clusterID, err := r.clusterUID(ctx)
	if err != nil {
		return fmt.Errorf("resolving cluster ID: %w", err)
	}

	ipamSecret, ipamZone := r.ipamCredentialForDelete(ctx, policy.Namespace, serviceName)

	ipv4, ipv6 := splitIPFamilies(policy.Status.ObservedIPs)
	report := upstream.PortReport{
		ClusterID:             clusterID,
		EdgePolicyNamespaceID: r.namespaceUID(ctx, policy.Namespace),
		EdgePolicyID:          string(policy.UID),
		ServiceName:           serviceName,
		Datacenter:            policy.Spec.Datacenter,
		IpamZone:              ipamZone,
		IpamSecret:            ipamSecret,
		IPv4Addresses:         ipv4,
		IPv6Addresses:         ipv6,
		ObservedPorts:         make([]upstream.Port, 0, len(policy.Status.ObservedPorts)),
		AdditionalPorts:       additionalPorts(policy),
	}
	for _, p := range policy.Status.ObservedPorts {
		report.ObservedPorts = append(report.ObservedPorts, upstream.Port{
			Name:     p.Name,
			Port:     p.Port,
			Protocol: string(p.Protocol),
		})
	}
	// The upstream requires the IPAM credential and at least one load balancer
	// address on a withdrawal too; without them there is nothing it can act on, so
	// the DELETE is not sent.
	if err := report.Validate(); err != nil {
		return err
	}
	if err := r.Reporter.DeletePorts(ctx, report); err != nil {
		return err
	}
	logf.FromContext(ctx).Info("Withdrew ports upstream",
		"edgepolicy", policy.Name, "service", serviceName)
	return nil
}

// ipamCredentialForDelete resolves the IPAM credential and zone for a withdrawal
// payload from the target Service's annotations. Withdrawal runs while the Service
// may already be deleting or gone, so every failure (a missing Service, an
// unresolvable Secret, an API error) is soft: it yields empty values and a V(1) log
// rather than blocking the withdraw. The credential is never logged.
func (r *EdgePolicyReconciler) ipamCredentialForDelete(
	ctx context.Context, namespace, serviceName string) (secret, zone string) {
	var service corev1.Service
	key := types.NamespacedName{Namespace: namespace, Name: serviceName}
	if err := r.Get(ctx, key, &service); err != nil {
		logf.FromContext(ctx).V(1).Info("Could not read target Service for withdrawal credential",
			"service", serviceName, "error", err.Error())
		return "", ""
	}
	value, _, err := r.resolveIpamSecret(ctx, &service)
	if err != nil {
		logf.FromContext(ctx).V(1).Info("Could not resolve IPAM credential for withdrawal",
			"service", serviceName, "error", err.Error())
		return "", service.Annotations[zoneAnnotation]
	}
	return value, service.Annotations[zoneAnnotation]
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

// namespaceUID returns the UID of the named namespace, used to identify the
// EdgePolicy's namespace upstream. A missing or unreadable namespace yields an
// empty string rather than failing the report, since the UID is informational.
func (r *EdgePolicyReconciler) namespaceUID(ctx context.Context, name string) string {
	var ns corev1.Namespace
	if err := r.Get(ctx, types.NamespacedName{Name: name}, &ns); err != nil {
		logf.FromContext(ctx).V(1).Info("Could not resolve namespace UID", "namespace", name, "error", err.Error())
		return ""
	}
	return string(ns.UID)
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

// reporterConfigured reports whether the configured Reporter can actually deliver
// reports. A nil Reporter is treated as not configured. Reporters that advertise a
// Configured() method (the HTTP reporter) are asked directly; any other Reporter
// (e.g. a test fake) is assumed ready.
func reporterConfigured(r upstream.Reporter) bool {
	if r == nil {
		return false
	}
	if c, ok := r.(interface{ Configured() bool }); ok {
		return c.Configured()
	}
	return true
}

// reportingDisabled reports whether the configured Reporter is a disabled/no-op
// sink that accepts reports without actually delivering them, so the caller can
// log accordingly instead of claiming a real upstream delivery.
func reportingDisabled(r upstream.Reporter) bool {
	d, ok := r.(interface{ Disabled() bool })
	return ok && d.Disabled()
}

// setUpstreamConfiguredCondition surfaces whether upstream reporting is configured.
// When configured, any stale UpstreamReady condition is removed to keep the status
// clean; when not, a False/UpstreamNotConfigured condition is set so the missing
// UPSTREAM_API_URL is visible. It returns whether the status changed.
func setUpstreamConfiguredCondition(policy *securityv1alpha1.EdgePolicy, configured bool) bool {
	if configured {
		return meta.RemoveStatusCondition(&policy.Status.Conditions, conditionTypeUpstreamReady)
	}
	return meta.SetStatusCondition(&policy.Status.Conditions, metav1.Condition{
		Type:               conditionTypeUpstreamReady,
		Status:             metav1.ConditionFalse,
		Reason:             reasonUpstreamNotConfigured,
		Message:            "No upstream API URL configured (set UPSTREAM_API_URL)",
		ObservedGeneration: policy.Generation,
	})
}

// setUpstreamReportFailedCondition marks UpstreamReady as False/UpstreamReportFailed
// while a transient upstream delivery failure is being retried, so the failure is
// visible on the status. It returns whether the status changed. A later successful
// reconcile clears the condition via setUpstreamConfiguredCondition.
func setUpstreamReportFailedCondition(policy *securityv1alpha1.EdgePolicy, reportErr error) bool {
	return meta.SetStatusCondition(&policy.Status.Conditions, metav1.Condition{
		Type:               conditionTypeUpstreamReady,
		Status:             metav1.ConditionFalse,
		Reason:             reasonUpstreamReportFailed,
		Message:            fmt.Sprintf("Failed to report ports upstream: %v", reportErr),
		ObservedGeneration: policy.Generation,
	})
}

// setUpstreamIncompleteCondition marks UpstreamReady as False/UpstreamReportIncomplete
// when a report cannot be sent because it is missing fields the upstream requires (the
// IPAM credential and at least one load balancer address). It returns whether the
// status changed. A later reconcile that resolves the missing fields clears the
// condition via setUpstreamConfiguredCondition.
func setUpstreamIncompleteCondition(policy *securityv1alpha1.EdgePolicy, reportErr error) bool {
	return meta.SetStatusCondition(&policy.Status.Conditions, metav1.Condition{
		Type:               conditionTypeUpstreamReady,
		Status:             metav1.ConditionFalse,
		Reason:             reasonUpstreamIncomplete,
		Message:            fmt.Sprintf("Not reporting upstream: %v", reportErr),
		ObservedGeneration: policy.Generation,
	})
}

// setUpstreamRejectedCondition marks UpstreamReady as False/UpstreamReportRejected
// when the upstream refused the report with a 4xx client error. Unlike a transient
// failure this is terminal: the controller stops retrying on the timer and re-attempts
// only when the report content changes. It uses a fixed message (not the error detail)
// so a fresh rejection and a later suppressed reconcile produce byte-identical
// conditions, letting the status reach a quiet fixpoint. It returns whether the status
// changed.
func setUpstreamRejectedCondition(policy *securityv1alpha1.EdgePolicy) bool {
	return meta.SetStatusCondition(&policy.Status.Conditions, metav1.Condition{
		Type:               conditionTypeUpstreamReady,
		Status:             metav1.ConditionFalse,
		Reason:             reasonUpstreamRejected,
		Message:            rejectedReportMessage,
		ObservedGeneration: policy.Generation,
	})
}

// markReportRejected records the terminal Rejected status for a report the upstream
// refused and that is now being suppressed (not re-sent) because its content is
// unchanged. It sets UpstreamReady and Ready to False with the fixed Rejected message,
// writes the status only if something changed, and never requeues on the timer. Because
// the conditions are idempotent and ObservedPorts/RejectedReportKey are already settled,
// a steady-state suppressed reconcile writes nothing — breaking the reconcile loop.
func (r *EdgePolicyReconciler) markReportRejected(ctx context.Context,
	policy *securityv1alpha1.EdgePolicy, baseChanged bool) (ctrl.Result, error) {
	logf.FromContext(ctx).V(1).Info("Suppressing unchanged report the upstream already rejected",
		"edgepolicy", policy.Name)
	upstreamChanged := setUpstreamRejectedCondition(policy)
	readyChanged := setReadyCondition(policy, metav1.ConditionFalse, reasonUpstreamRejected,
		rejectedReportMessage)
	if err := r.writeStatus(ctx, policy, baseChanged || upstreamChanged || readyChanged); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// handleReportFailure records the right status conditions for a report that was not
// delivered. A report rejected for missing required fields (ErrIncompleteReport) is
// surfaced as UpstreamReportIncomplete; a 4xx rejection (ErrUpstreamRejected) is
// terminal and surfaced as UpstreamReportRejected without a timed retry; any other
// failure is treated as a transient delivery error (UpstreamReportFailed) and requeued.
// In every case the policy is marked Ready=False with the same reason, since it is not
// doing its job while a report cannot be delivered. The caller leaves ObservedPorts
// unwritten so a later attempt re-sends once the cause clears.
func (r *EdgePolicyReconciler) handleReportFailure(ctx context.Context,
	policy *securityv1alpha1.EdgePolicy, reportErr error, baseChanged bool) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	var upstreamChanged, readyChanged bool
	switch {
	case errors.Is(reportErr, upstream.ErrIncompleteReport):
		log.Info("Not reporting discovered ports upstream; required fields missing; will retry",
			"retryAfter", upstreamRetryInterval.String(), "detail", reportErr.Error())
		upstreamChanged = setUpstreamIncompleteCondition(policy, reportErr)
		readyChanged = setReadyCondition(policy, metav1.ConditionFalse, reasonUpstreamIncomplete,
			fmt.Sprintf("Not reporting upstream: %v", reportErr))
	case errors.Is(reportErr, upstream.ErrUpstreamRejected):
		// A 4xx will not succeed if retried unchanged, so do not requeue on the timer;
		// an identical report is suppressed next reconcile (see markReportRejected) and a
		// changed report is attempted afresh. The error detail is logged, not stored, so
		// the stored condition matches the suppressed reconcile's and settles quietly.
		log.Info("Upstream rejected the report; not retrying until the report content changes",
			"error", reportErr.Error())
		upstreamChanged = setUpstreamRejectedCondition(policy)
		readyChanged = setReadyCondition(policy, metav1.ConditionFalse, reasonUpstreamRejected,
			rejectedReportMessage)
		if err := r.writeStatus(ctx, policy, baseChanged || upstreamChanged || readyChanged); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	default:
		// Transient upstream failures (DNS, connectivity, 5xx) are expected and
		// self-healing. Log softly rather than returning a hard error (which logs an
		// ERROR with a stack trace).
		log.Info("Could not report discovered ports upstream; will retry",
			"retryAfter", upstreamRetryInterval.String(), "error", reportErr.Error())
		upstreamChanged = setUpstreamReportFailedCondition(policy, reportErr)
		readyChanged = setReadyCondition(policy, metav1.ConditionFalse, reasonUpstreamReportFailed,
			fmt.Sprintf("Failed to report ports upstream: %v", reportErr))
	}
	if err := r.writeStatus(ctx, policy, baseChanged || upstreamChanged || readyChanged); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: upstreamRetryInterval}, nil
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

	// Check for other EdgePolicies that still reference the same Service. We list
	// by namespace and match in-memory rather than via the targetRefField index:
	// this runs on the deletion path where correctness must not depend on the
	// manager cache's field index being available.
	wantKey := targetRefKey(ref.APIVersion, ref.Kind, ref.Name)
	var policies securityv1alpha1.EdgePolicyList
	if err := r.List(ctx, &policies, client.InNamespace(policy.Namespace)); err != nil {
		return err
	}
	for i := range policies.Items {
		other := &policies.Items[i]
		if other.UID == policy.UID {
			continue
		}
		otherRef := other.Spec.TargetRef
		if targetRefKey(otherRef.APIVersion, otherRef.Kind, otherRef.Name) != wantKey {
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
