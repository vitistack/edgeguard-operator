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
	"slices"
	"strings"
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

// conflictRequeueInterval is how soon to requeue after an optimistic-concurrency
// conflict. A conflict means our cached copy was stale, so we re-fetch and retry
// promptly rather than surfacing a noisy error. Requeuing here is essential for the
// upstream status-queue polling retry: its own RequeueAfter would otherwise be
// discarded when the status write conflicts, and because a status-only write is
// suppressed by edgePolicyReconcilePredicate no event re-enqueues the policy, so
// polling of a still-pending job would silently stall until the next resync.
const conflictRequeueInterval = time.Second

// defaultUpstreamPollInterval is how long to wait before polling an in-flight upstream
// report job again, when the reconciler's UpstreamPollInterval is unset. Polling is
// driven by requeues (not a blocking loop), so this is the controller's poll cadence.
const defaultUpstreamPollInterval = 2 * time.Second

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
	// evaluated for policies that declare a filter block.
	conditionTypeUpstreamReady = "UpstreamReady"

	reasonUpstreamNotConfigured = "UpstreamNotConfigured"
	reasonUpstreamReportFailed  = "UpstreamReportFailed"
	reasonUpstreamIncomplete    = "UpstreamReportIncomplete"
	reasonUpstreamRejected      = "UpstreamReportRejected"
	reasonUpstreamPending       = "UpstreamReportPending"
)

// rejectedReportMessage is the stable status message used whenever a report is in the
// terminal Rejected state (freshly rejected or suppressed as an unchanged retry). It
// omits the volatile HTTP status so re-asserting it is a no-op, which lets the
// suppressed reconcile reach a quiet fixpoint instead of rewriting the status. The
// concrete status code is logged rather than stored on the condition.
const rejectedReportMessage = "Upstream rejected the report; not retried until the report content changes"

// maxRejectionDetailLen bounds the upstream rejection detail stored on the status (and
// thus the condition message), so a large upstream response body cannot bloat the object.
const maxRejectionDetailLen = 512

// upstreamRejectionDetail extracts the human-readable detail from a terminal upstream
// rejection error for display on the status: it strips the ErrUpstreamRejected sentinel
// prefix, collapses whitespace onto one line, and truncates (rune-safe) to
// maxRejectionDetailLen. It returns "" for a nil error.
func upstreamRejectionDetail(err error) string {
	if err == nil {
		return ""
	}
	detail := strings.TrimPrefix(err.Error(), upstream.ErrUpstreamRejected.Error()+": ")
	detail = strings.Join(strings.Fields(detail), " ")
	if r := []rune(detail); len(r) > maxRejectionDetailLen {
		detail = string(r[:maxRejectionDetailLen])
	}
	return detail
}

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
	// UpstreamPollInterval overrides how long to wait before polling an in-flight
	// upstream report job again. When zero, defaultUpstreamPollInterval applies. It is
	// sourced from the status-queue poll-interval flag/env so the controller's poll
	// cadence stays configurable.
	UpstreamPollInterval time.Duration
}

// +kubebuilder:rbac:groups=security.vitistack.io,resources=edgepolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.vitistack.io,resources=edgepolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.vitistack.io,resources=edgepolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups=core,resources=services,verbs=get;list;watch;update;patch;delete
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
// noisy error with a stack trace. A NotFound is treated the same way: it means the
// EdgePolicy was deleted after we fetched it (e.g. a status write racing the delete),
// so the request is dropped quietly rather than logged as a reconciler error.
func (r *EdgePolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	log := logf.FromContext(ctx)

	// Soften expected, self-healing outcomes so they are not surfaced as a noisy
	// ERROR with a stack trace. An optimistic-concurrency conflict means the object
	// changed under us, so we requeue quietly on the next event. A NotFound means the
	// EdgePolicy was deleted after we fetched it (commonly a write racing the delete),
	// so there is nothing left to reconcile and we drop the request.
	defer func() {
		switch {
		case apierrors.IsConflict(err):
			// Requeue (quietly, without the error's stack trace) rather than dropping the
			// request: a status-only write is suppressed by edgePolicyReconcilePredicate, so
			// no event would otherwise re-enqueue us and an in-flight retry (e.g. upstream
			// status-queue polling) would stall.
			log.V(1).Info("Reconcile hit an update conflict; requeuing", "conflict", err.Error())
			result, err = ctrl.Result{RequeueAfter: conflictRequeueInterval}, nil
		case apierrors.IsNotFound(err):
			log.Info("EdgePolicy was deleted during reconcile; nothing to do", "detail", err.Error())
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
			// Withdraw the policy's ports upstream before we let the object go. The
			// withdrawal is non-blocking: a queued job is recorded on status and polled on
			// later reconciles (holding this finalizer) until it completes. Only a
			// confirmed withdrawal — a 2xx/completed job, a 404 (the upstream has no record,
			// already gone), or a withdrawal we cannot even form (missing credential or
			// addresses, e.g. the target Service is already gone) — releases the finalizer;
			// a refusal or an unreachable upstream holds it and requeues so the delete is
			// retried rather than leaving stale upstream state.
			result, done, err := r.withdrawUpstream(ctx, &policy, policy.Spec.TargetRef.Name, "during deletion")
			if err != nil {
				return ctrl.Result{}, err
			}
			if !done {
				return result, nil
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
// LoadBalancer Service on the policy status, reports them upstream when the policy
// declares a filter block (with filter.enabled carried through to the report), and
// persists the status only when something actually changed.
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

	// Resolve the IPAM secret (when the policy declares a filter or ddos block) and
	// surface its state on the status. A missing Secret is tolerated: the policy
	// reports a not-found condition but reconciliation continues with an empty
	// credential.
	var ipamSecret string
	secretChanged := false
	upstreamChanged := false
	upstreamConfigured := false
	if reportConfigured(policy) {
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
		// No filter or ddos block; drop any stale secret / upstream conditions and
		// forget any remembered rejection.
		secretChanged = meta.RemoveStatusCondition(&policy.Status.Conditions, conditionTypeIpamSecretReady)
		upstreamChanged = meta.RemoveStatusCondition(&policy.Status.Conditions, conditionTypeUpstreamReady)
		if policy.Status.RejectedReportKey != "" || policy.Status.RejectedReportMessage != "" {
			policy.Status.RejectedReportKey = ""
			policy.Status.RejectedReportMessage = ""
			upstreamChanged = true
		}
	}

	// Record the discovered Service ports and load balancer IPs. When upstream
	// reporting is configured, the report is submitted — and any queued job polled —
	// asynchronously by syncUpstreamReport, which owns ObservedPorts and only advances
	// it once a report is durably accepted. Otherwise we simply track the discovered
	// state here and mark the policy protected.
	desiredPorts := observedPortsFromService(service)
	desiredIPs := loadBalancerIPs(service)
	portsChanged := !observedPortsEqual(policy.Status.ObservedPorts, desiredPorts)
	ipsChanged := !stringSlicesEqual(policy.Status.ObservedIPs, desiredIPs)

	if reportConfigured(policy) && upstreamConfigured {
		return r.syncUpstreamReport(ctx, policy, service, ipamSecret, desiredPorts, desiredIPs,
			portsChanged || ipsChanged || generationChanged, secretChanged || upstreamChanged)
	}

	if portsChanged || ipsChanged {
		policy.Status.ObservedPorts = desiredPorts
		policy.Status.ObservedIPs = desiredIPs
	}

	// The target Service is protected and no upstream report is required.
	condChanged := setReadyCondition(policy, metav1.ConditionTrue, reasonServiceProtected,
		fmt.Sprintf("Finalizer present on Service %q", service.Name))

	return ctrl.Result{}, r.writeStatus(ctx, policy,
		condChanged || secretChanged || upstreamChanged || portsChanged || ipsChanged)
}

// syncUpstreamReport advances the asynchronous upstream report state machine for a
// protected Service whose policy declares a reportable block and whose upstream is
// configured. In one reconcile it does exactly one of: poll an in-flight job, submit a
// (fresh or changed) report, suppress an unchanged already-rejected report, or settle
// as protected when there is nothing to do. Submitting and polling are single upstream
// round-trips — a queued job is recorded on status.PendingReport and polled on later
// reconciles rather than blocking a worker here, so a slow upstream never starves the
// controller.
//
// desiredChanged reports whether the discovered ports/IPs or the spec generation
// changed since the last accepted report; baseChanged carries status changes already
// made by the caller (secret/upstream conditions) so they are persisted even when this
// method would otherwise write nothing.
func (r *EdgePolicyReconciler) syncUpstreamReport(ctx context.Context, policy *securityv1alpha1.EdgePolicy,
	service *corev1.Service, ipamSecret string, desiredPorts []securityv1alpha1.ObservedPort,
	desiredIPs []string, desiredChanged, baseChanged bool) (ctrl.Result, error) {
	pending := policy.Status.PendingReport

	// Nothing in flight and nothing changed: the last accepted report still stands, so
	// just reaffirm the policy as protected and settle at a quiet fixpoint.
	if pending == nil && !desiredChanged {
		return r.settleProtected(ctx, policy, service, baseChanged)
	}

	report, err := r.buildReport(ctx, policy, service, ipamSecret, desiredPorts, desiredIPs)
	if err != nil {
		return ctrl.Result{}, err
	}
	// The upstream requires the IPAM credential and at least one load balancer address
	// on every report; without them the report is not sent.
	if err := report.Validate(); err != nil {
		policy.Status.PendingReport = nil
		return r.handleReportFailure(ctx, policy, err, baseChanged)
	}
	key := report.IdempotencyKey()

	// Once the upstream has rejected a report with a 4xx, an identical payload will be
	// rejected again. Keep the terminal Rejected status without re-sending; a changed
	// report produces a different key and is attempted afresh.
	if policy.Status.RejectedReportKey == key {
		policy.Status.PendingReport = nil
		return r.markReportRejected(ctx, policy, baseChanged)
	}

	// Poll an in-flight job whose payload still matches what we would send; otherwise
	// submit — covering both a changed desired state and a now-stale pending job.
	if pending != nil && pending.Key == key {
		return r.pollPendingReport(ctx, policy, service, pending, baseChanged)
	}
	return r.submitReport(ctx, policy, service, report, key, desiredPorts, desiredIPs, baseChanged)
}

// submitReport submits a report with a single upstream round-trip and records the
// outcome: a synchronous acceptance settles the policy as protected; a queued job is
// recorded on status.PendingReport and polled on the next reconcile; a rejection or
// transient failure is surfaced via handleReportFailure with ObservedPorts left
// unwritten so a retry re-sends once the cause clears.
func (r *EdgePolicyReconciler) submitReport(ctx context.Context, policy *securityv1alpha1.EdgePolicy,
	service *corev1.Service, report upstream.PortReport, key string,
	desiredPorts []securityv1alpha1.ObservedPort, desiredIPs []string, baseChanged bool) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	status, err := r.Reporter.ReportPorts(ctx, report)
	switch {
	case errors.Is(err, upstream.ErrUpstreamRejected):
		// Remember the rejected payload so an identical retry is suppressed, and the
		// upstream's detail so the terminal status explains why.
		policy.Status.RejectedReportKey = key
		policy.Status.RejectedReportMessage = upstreamRejectionDetail(err)
		policy.Status.PendingReport = nil
		return r.handleReportFailure(ctx, policy, err, baseChanged)
	case err != nil:
		// Transient delivery failure (DNS, connectivity, 5xx).
		policy.Status.PendingReport = nil
		return r.handleReportFailure(ctx, policy, err, baseChanged)
	}

	if status.Pending() {
		// The upstream queued the report; record the job (with the ports/IPs it covers)
		// and poll it on the next reconcile instead of blocking a worker here.
		policy.Status.PendingReport = &securityv1alpha1.PendingReport{
			Key:       key,
			StatusURL: status.StatusURL,
			JobID:     status.JobID,
			Ports:     desiredPorts,
			IPs:       desiredIPs,
		}
		log.Info("Queued upstream report job; polling for completion",
			"edgepolicy", policy.Name, "jobId", status.JobID, "statusUrl", status.StatusURL)
		return r.awaitPending(ctx, policy, baseChanged)
	}

	// Accepted synchronously.
	if reportingDisabled(r.Reporter) {
		log.Info("Skipped upstream report (reporting disabled)",
			"edgepolicy", policy.Name, "service", service.Name, "ports", len(desiredPorts), "ips", len(desiredIPs))
	} else {
		log.Info("Reported discovered ports upstream",
			"edgepolicy", policy.Name, "service", service.Name, "ports", len(desiredPorts), "ips", len(desiredIPs))
	}
	r.acceptReport(policy, desiredPorts, desiredIPs)
	return r.settleProtected(ctx, policy, service, true)
}

// pollPendingReport performs a single poll of the in-flight job recorded on
// status.PendingReport. A completed job is accepted (its captured ports become
// ObservedPorts); a failed job is surfaced as a terminal rejection; a transient poll
// failure or a still-running job requeues so polling resumes on the next reconcile,
// without blocking a worker here.
func (r *EdgePolicyReconciler) pollPendingReport(ctx context.Context, policy *securityv1alpha1.EdgePolicy,
	service *corev1.Service, pending *securityv1alpha1.PendingReport, baseChanged bool) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	status, err := r.Reporter.PollReport(ctx, pending.StatusURL)
	switch {
	case errors.Is(err, upstream.ErrUpstreamRejected):
		// The job failed upstream; treat it as a terminal rejection and remember the
		// payload so the identical retry is suppressed until the content changes.
		policy.Status.RejectedReportKey = pending.Key
		policy.Status.RejectedReportMessage = upstreamRejectionDetail(err)
		policy.Status.PendingReport = nil
		return r.handleReportFailure(ctx, policy, err, baseChanged)
	case err != nil:
		// Transient poll failure: keep the job and retry the poll on the next reconcile.
		log.Info("Could not poll upstream report job; will retry",
			"edgepolicy", policy.Name, "jobId", pending.JobID,
			"retryAfter", r.pollInterval().String(), "error", err.Error())
		return r.awaitPending(ctx, policy, baseChanged)
	}

	if status.Done {
		log.Info("Upstream report job completed", "edgepolicy", policy.Name, "jobId", pending.JobID)
		r.acceptReport(policy, pending.Ports, pending.IPs)
		return r.settleProtected(ctx, policy, service, true)
	}

	// Still queued/running: poll again after the interval. Logged at V(1) so steady
	// polling of a slow job does not spam the log.
	log.V(1).Info("Upstream report job still pending; will poll again",
		"edgepolicy", policy.Name, "jobId", pending.JobID, "retryAfter", r.pollInterval().String())
	return r.awaitPending(ctx, policy, baseChanged)
}

// awaitPending marks both UpstreamReady and Ready as False/UpstreamReportPending for an
// in-flight report job, persists the status when changed, and requeues after the poll
// interval so the job is polled again. Ready is set False (not left unchanged) so a
// policy whose report has not yet been confirmed reports Ready=False — visible in the
// printed column — instead of a blank Ready before its first report settles. It is
// restored to True by settleProtected once the job completes.
func (r *EdgePolicyReconciler) awaitPending(ctx context.Context, policy *securityv1alpha1.EdgePolicy,
	baseChanged bool) (ctrl.Result, error) {
	upstreamChanged := setUpstreamPendingCondition(policy)
	readyChanged := setReadyCondition(policy, metav1.ConditionFalse, reasonUpstreamPending,
		"Upstream report queued; awaiting completion")
	if err := r.writeStatus(ctx, policy, upstreamChanged || readyChanged || baseChanged); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: r.pollInterval()}, nil
}

// acceptReport records a durably accepted report: it advances ObservedPorts/IPs to the
// accepted set, forgets any remembered rejection, clears the in-flight job, and drops
// the UpstreamReady condition so the status reads healthy. settleProtected then marks
// the policy Ready and persists the status.
func (r *EdgePolicyReconciler) acceptReport(policy *securityv1alpha1.EdgePolicy,
	ports []securityv1alpha1.ObservedPort, ips []string) {
	policy.Status.ObservedPorts = ports
	policy.Status.ObservedIPs = ips
	policy.Status.PendingReport = nil
	policy.Status.RejectedReportKey = ""
	policy.Status.RejectedReportMessage = ""
	meta.RemoveStatusCondition(&policy.Status.Conditions, conditionTypeUpstreamReady)
}

// settleProtected marks the policy's target Service as protected (Ready=True) and
// persists the status when anything changed. changed carries whether an upstream
// outcome or an earlier condition write already dirtied the status.
func (r *EdgePolicyReconciler) settleProtected(ctx context.Context, policy *securityv1alpha1.EdgePolicy,
	service *corev1.Service, changed bool) (ctrl.Result, error) {
	condChanged := setReadyCondition(policy, metav1.ConditionTrue, reasonServiceProtected,
		fmt.Sprintf("Finalizer present on Service %q", service.Name))
	return ctrl.Result{}, r.writeStatus(ctx, policy, condChanged || changed)
}

// pollInterval is how long to wait before polling an in-flight upstream report job
// again, from the UpstreamPollInterval field when set or the package default otherwise.
func (r *EdgePolicyReconciler) pollInterval() time.Duration {
	if r.UpstreamPollInterval > 0 {
		return r.UpstreamPollInterval
	}
	return defaultUpstreamPollInterval
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

// filterConfigured reports whether the policy declares a filter block at all,
// regardless of whether it is enabled. It gates upstream reporting: a policy with a
// filter block is reported on every content change so the upstream tracks the current
// state, including spec.filter.enabled flipping to false.
func filterConfigured(policy *securityv1alpha1.EdgePolicy) bool {
	return policy.Spec.Filter != nil
}

// ddosConfigured reports whether the policy declares a ddos block at all, regardless
// of whether it is enabled. Like filterConfigured it gates upstream reporting so the
// upstream tracks the DDoS region policy's current state on every change.
func ddosConfigured(policy *securityv1alpha1.EdgePolicy) bool {
	return policy.Spec.DDoS != nil
}

// reportConfigured reports whether the policy declares anything the operator reports
// upstream — a filter block, a ddos block, or both. Reporting (and the secret and
// upstream status conditions that support it) is driven on every content change so
// the upstream tracks the current state of each declared block.
func reportConfigured(policy *securityv1alpha1.EdgePolicy) bool {
	return filterConfigured(policy) || ddosConfigured(policy)
}

// filterEnabled reports whether the policy opts into service port discovery via
// spec.filter.enabled. Its value is carried through to the report's filter.enabled
// flag; it no longer gates whether a report is sent (see filterConfigured).
func filterEnabled(policy *securityv1alpha1.EdgePolicy) bool {
	return policy.Spec.Filter != nil && policy.Spec.Filter.Enabled
}

// ddosReport maps the policy's spec.ddos block into the upstream payload
// representation, or nil when the policy declares no ddos block so the report omits
// the ddos section entirely. The additionalCidrList is always a non-nil slice
// (empty when none are declared) so it serializes as [] rather than null.
func ddosReport(policy *securityv1alpha1.EdgePolicy) *upstream.DDoSReport {
	if policy.Spec.DDoS == nil {
		return nil
	}
	allow := make([]string, 0, len(policy.Spec.DDoS.AdditionalCidrList))
	allow = append(allow, policy.Spec.DDoS.AdditionalCidrList...)
	return &upstream.DDoSReport{
		Enabled:            policy.Spec.DDoS.Enabled,
		Region:             policy.Spec.DDoS.Region,
		AdditionalCidrList: allow,
	}
}

// additionalPorts maps the policy's declared spec.filter.additionalPortList into the
// upstream payload representation. It always returns a non-nil slice (empty when none
// are declared) so the report serializes additionalPorts as [] rather than null.
func additionalPorts(policy *securityv1alpha1.EdgePolicy) []upstream.Port {
	var list []securityv1alpha1.AdditionalPort
	if policy.Spec.Filter != nil {
		list = policy.Spec.Filter.AdditionalPortList
	}
	ports := make([]upstream.Port, 0, len(list))
	for _, p := range list {
		ports = append(ports, upstream.Port{
			Name:     p.Name,
			Port:     p.Port,
			Protocol: p.Protocol,
		})
	}
	return ports
}

// buildReport assembles the upstream PortReport for a policy's current discovered
// ports and load balancer IPs, resolving the cluster and namespace identifiers. The
// caller (syncUpstreamReport) validates, submits, or polls the report; this function
// only constructs it. The caller supplies the already-resolved ipamSecret so secret
// resolution and its status condition are handled in one place.
func (r *EdgePolicyReconciler) buildReport(ctx context.Context, policy *securityv1alpha1.EdgePolicy,
	service *corev1.Service, ipamSecret string, ports []securityv1alpha1.ObservedPort,
	ips []string) (upstream.PortReport, error) {
	clusterID, err := r.clusterUID(ctx)
	if err != nil {
		return upstream.PortReport{}, fmt.Errorf("resolving cluster ID: %w", err)
	}

	ipv4, ipv6 := splitIPFamilies(ips)
	observed := make([]upstream.Port, 0, len(ports))
	for _, p := range ports {
		observed = append(observed, upstream.Port{
			Name:     p.Name,
			Port:     p.Port,
			Protocol: string(p.Protocol),
		})
	}
	return upstream.PortReport{
		ClusterID:             clusterID,
		EdgePolicyNamespaceID: r.namespaceUID(ctx, policy.Namespace),
		EdgePolicyID:          string(policy.UID),
		ServiceName:           service.Name,
		Datacenter:            policy.Spec.Datacenter,
		IpamZone:              service.Annotations[zoneAnnotation],
		IpamSecret:            ipamSecret,
		IPv4Addresses:         ipv4,
		IPv6Addresses:         ipv6,
		Filter: upstream.FilterReport{
			Enabled:         filterEnabled(policy),
			ObservedPorts:   observed,
			AdditionalPorts: additionalPorts(policy),
		},
		DDoS: ddosReport(policy),
	}, nil
}

// deactivatePolicy releases the operator's hold on a Service that is no longer
// managed (it is terminating or is no longer a LoadBalancer): it withdraws any
// previously reported ports upstream, removes the Service finalizer, and marks the
// policy inactive with the given reason/message. The withdrawal is non-blocking: a
// queued job keeps the Service finalizer and requeues (polling until it completes), as
// does a transient/terminal failure, so the delete is retried rather than leaving stale
// upstream state. note labels the log lines with the triggering transition.
func (r *EdgePolicyReconciler) deactivatePolicy(ctx context.Context, policy *securityv1alpha1.EdgePolicy,
	service *corev1.Service, reason, message, note string) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	// Withdraw whatever may be live upstream: an accepted report and/or one still in
	// flight. hasWithdrawalTarget covers both so a policy deactivated mid-report still
	// withdraws the queued payload.
	hadState := hasWithdrawalTarget(policy)
	if hadState {
		result, done, err := r.withdrawUpstream(ctx, policy, service.Name, note)
		if err != nil {
			return ctrl.Result{}, err
		}
		if !done {
			return result, nil
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

// withdrawUpstream advances the asynchronous upstream withdrawal for a policy whose
// object or target Service is going away. In one reconcile it polls an in-flight
// withdrawal job, submits the next withdrawal, or reports there is nothing left to
// withdraw — each a single upstream round-trip. A queued job is recorded on
// status.PendingWithdrawal and polled on later reconciles rather than blocking a worker.
//
// There may be two distinct payloads live upstream at deletion time: the last accepted
// report (ObservedPorts) and a newer report that was still in flight (PendingReport).
// They are withdrawn one at a time — each withdrawn payload is cleared from the status
// as it completes (see advanceWithdrawal), so the next reconcile picks up the remaining
// one — until none remain.
//
// It returns done=true when the upstream holds no (further) record of any report, so the
// caller may release its finalizer. It returns done=false with a Result when a
// withdrawal is not yet complete (a job is in flight, another payload remains, or a
// transient/terminal failure is being retried); the caller must return that Result and
// keep its finalizer so the delete is retried rather than leaving stale upstream state.
// A non-nil error is a hard failure (e.g. a status write) the caller surfaces.
//
// label identifies the triggering transition in log lines (e.g. "during deletion").
func (r *EdgePolicyReconciler) withdrawUpstream(ctx context.Context, policy *securityv1alpha1.EdgePolicy,
	serviceName, label string) (ctrl.Result, bool, error) {
	if !reportConfigured(policy) || !reporterConfigured(r.Reporter) || r.Reporter == nil {
		return ctrl.Result{}, true, nil
	}
	log := logf.FromContext(ctx)

	// Poll an in-flight withdrawal job (for the current head payload) instead of
	// re-submitting.
	if pending := policy.Status.PendingWithdrawal; pending != nil {
		status, err := r.Reporter.PollReport(ctx, pending.StatusURL)
		switch {
		case errors.Is(err, upstream.ErrUpstreamNotFound):
			log.Info("Upstream had no record of the report; treating as already withdrawn",
				"edgepolicy", policy.Name, "transition", label, "detail", err.Error())
			return r.advanceWithdrawal(ctx, policy, label)
		case errors.Is(err, upstream.ErrUpstreamRejected):
			log.Info("Upstream refused the withdrawal; will retry",
				"edgepolicy", policy.Name, "transition", label,
				"retryAfter", upstreamRetryInterval.String(), "error", err.Error())
			return ctrl.Result{RequeueAfter: upstreamRetryInterval}, false, nil
		case err != nil:
			log.Info("Could not poll upstream withdrawal job; will retry",
				"edgepolicy", policy.Name, "transition", label,
				"retryAfter", r.pollInterval().String(), "error", err.Error())
			return ctrl.Result{RequeueAfter: r.pollInterval()}, false, nil
		}
		if status.Done {
			log.Info("Upstream withdrawal job completed",
				"edgepolicy", policy.Name, "transition", label, "jobId", pending.JobID)
			return r.advanceWithdrawal(ctx, policy, label)
		}
		// Still in flight: keep the finalizer and poll again.
		log.V(1).Info("Upstream withdrawal job still pending; will poll again",
			"edgepolicy", policy.Name, "transition", label, "jobId", pending.JobID)
		return ctrl.Result{RequeueAfter: r.pollInterval()}, false, nil
	}

	// No job in flight: submit the next pending withdrawal payload.
	report, ok, err := r.nextWithdrawalReport(ctx, policy, serviceName)
	if err != nil {
		// A transient failure building the report (e.g. the cluster ID lookup); retry.
		log.Info("Could not withdraw ports upstream; will retry",
			"edgepolicy", policy.Name, "transition", label,
			"retryAfter", upstreamRetryInterval.String(), "error", err.Error())
		return ctrl.Result{RequeueAfter: upstreamRetryInterval}, false, nil
	}
	if !ok {
		// Nothing (left) to withdraw.
		return ctrl.Result{}, true, nil
	}
	// The upstream requires the IPAM credential and at least one load balancer address
	// on a withdrawal too; without them there is nothing it can act on, so the DELETE is
	// not sent and deletion proceeds rather than wedging on an unmeetable precondition
	// (e.g. the target Service is already gone, so the credential cannot be resolved —
	// which affects every remaining payload equally).
	if err := report.Validate(); err != nil {
		log.Info("Skipped upstream withdrawal; required fields missing",
			"edgepolicy", policy.Name, "transition", label, "detail", err.Error())
		return ctrl.Result{}, true, nil
	}

	status, err := r.Reporter.DeletePorts(ctx, report)
	switch {
	case errors.Is(err, upstream.ErrUpstreamNotFound):
		// 404: the upstream has no record of this payload — already withdrawn/gone.
		log.Info("Upstream had no record of the report; treating as already withdrawn",
			"edgepolicy", policy.Name, "transition", label, "detail", err.Error())
		return r.advanceWithdrawal(ctx, policy, label)
	case errors.Is(err, upstream.ErrUpstreamRejected):
		// Upstream refused the withdrawal (non-404 4xx): hold the finalizer and retry.
		log.Info("Upstream refused the withdrawal; will retry",
			"edgepolicy", policy.Name, "transition", label,
			"retryAfter", upstreamRetryInterval.String(), "error", err.Error())
		return ctrl.Result{RequeueAfter: upstreamRetryInterval}, false, nil
	case err != nil:
		// Could not be reached (5xx/transport): hold the finalizer and retry.
		log.Info("Could not withdraw ports upstream; will retry",
			"edgepolicy", policy.Name, "transition", label,
			"retryAfter", upstreamRetryInterval.String(), "error", err.Error())
		return ctrl.Result{RequeueAfter: upstreamRetryInterval}, false, nil
	}

	if status.Pending() {
		// The upstream queued the withdrawal; record the job and poll it on the next
		// reconcile, holding the finalizer until it completes.
		policy.Status.PendingWithdrawal = &securityv1alpha1.PendingReport{
			Key:       report.IdempotencyKey(),
			StatusURL: status.StatusURL,
			JobID:     status.JobID,
		}
		log.Info("Queued upstream withdrawal job; polling for completion",
			"edgepolicy", policy.Name, "transition", label, "jobId", status.JobID, "statusUrl", status.StatusURL)
		if err := r.writeStatus(ctx, policy, true); err != nil {
			return ctrl.Result{}, false, err
		}
		return ctrl.Result{RequeueAfter: r.pollInterval()}, false, nil
	}

	log.Info("Withdrew ports upstream",
		"edgepolicy", policy.Name, "service", serviceName, "transition", label)
	return r.advanceWithdrawal(ctx, policy, label)
}

// nextWithdrawalReport builds the withdrawal payload for the current head — the last
// accepted report (ObservedPorts) if present, otherwise an in-flight report
// (PendingReport). It returns ok=false when nothing remains to withdraw.
func (r *EdgePolicyReconciler) nextWithdrawalReport(ctx context.Context,
	policy *securityv1alpha1.EdgePolicy, serviceName string) (upstream.PortReport, bool, error) {
	if !hasWithdrawalTarget(policy) {
		return upstream.PortReport{}, false, nil
	}
	report, err := r.buildWithdrawalReport(ctx, policy, serviceName)
	if err != nil {
		return upstream.PortReport{}, false, err
	}
	return report, true, nil
}

// advanceWithdrawal records that the current head payload was withdrawn: it clears that
// payload (and any in-flight report identical to it) and the in-flight withdrawal job,
// then reports whether another distinct payload still needs withdrawing. When one does,
// it persists the progress and requeues (done=false) so the next reconcile withdraws it
// instead of re-withdrawing the one just handled; otherwise it reports done=true so the
// caller releases its finalizer.
func (r *EdgePolicyReconciler) advanceWithdrawal(ctx context.Context,
	policy *securityv1alpha1.EdgePolicy, label string) (ctrl.Result, bool, error) {
	policy.Status.PendingWithdrawal = nil
	clearWithdrawnHead(policy)
	if !hasWithdrawalTarget(policy) {
		return ctrl.Result{}, true, nil
	}
	// A newer, distinct in-flight report remains. Persist the progress so the next
	// reconcile withdraws it rather than re-withdrawing the payload just handled.
	logf.FromContext(ctx).V(1).Info("Withdrew one report payload; a newer in-flight report remains",
		"edgepolicy", policy.Name, "transition", label)
	if err := r.writeStatus(ctx, policy, true); err != nil {
		return ctrl.Result{}, false, err
	}
	return ctrl.Result{RequeueAfter: r.pollInterval()}, false, nil
}

// hasWithdrawalTarget reports whether the policy still has a report payload that may be
// live upstream and needs withdrawing: an accepted report (ObservedPorts/IPs) or one
// still in flight (PendingReport).
func hasWithdrawalTarget(policy *securityv1alpha1.EdgePolicy) bool {
	return len(policy.Status.ObservedPorts) > 0 || len(policy.Status.ObservedIPs) > 0 ||
		policy.Status.PendingReport != nil
}

// clearWithdrawnHead clears the payload that nextWithdrawalReport just returned — the
// accepted report when one is present (buildWithdrawalReport prefers it), otherwise the
// in-flight report. When the accepted payload is cleared, an identical in-flight report
// is cleared too, since the same content shares the upstream record just withdrawn.
func clearWithdrawnHead(policy *securityv1alpha1.EdgePolicy) {
	if len(policy.Status.ObservedPorts) > 0 || len(policy.Status.ObservedIPs) > 0 {
		obsPorts, obsIPs := policy.Status.ObservedPorts, policy.Status.ObservedIPs
		policy.Status.ObservedPorts = nil
		policy.Status.ObservedIPs = nil
		if pr := policy.Status.PendingReport; pr != nil &&
			observedPortsEqual(pr.Ports, obsPorts) && stringSlicesEqual(pr.IPs, obsIPs) {
			policy.Status.PendingReport = nil
		}
		return
	}
	policy.Status.PendingReport = nil
}

// buildWithdrawalReport reconstructs the withdrawal payload from the policy's last
// observed ports and IPs plus the datacenter and declared additional ports from the
// spec. The upstream requires the IPAM credential on the withdrawal too, so it is
// resolved best-effort from the target Service's ipam.vitistack.io/secret annotation;
// when the Service is already gone the credential (and zone) are simply omitted.
//
// When no report has been accepted yet (ObservedPorts/IPs are empty) but one is still
// in flight — e.g. the policy was deleted while its first report was queued upstream —
// the payload is taken from status.PendingReport instead, so the withdrawal carries the
// same ports/IPs (and therefore the same Idempotency-Key) as the queued report and the
// upstream can cancel it rather than orphaning the programmed state. A newer in-flight
// report over an already-accepted one is not separately withdrawn: the accepted state
// is the primary concern and is what gets withdrawn here.
func (r *EdgePolicyReconciler) buildWithdrawalReport(ctx context.Context,
	policy *securityv1alpha1.EdgePolicy, serviceName string) (upstream.PortReport, error) {
	clusterID, err := r.clusterUID(ctx)
	if err != nil {
		return upstream.PortReport{}, fmt.Errorf("resolving cluster ID: %w", err)
	}

	ipamSecret, ipamZone := r.ipamCredentialForDelete(ctx, policy.Namespace, serviceName)

	ports := policy.Status.ObservedPorts
	ips := policy.Status.ObservedIPs
	if len(ports) == 0 && len(ips) == 0 && policy.Status.PendingReport != nil {
		ports = policy.Status.PendingReport.Ports
		ips = policy.Status.PendingReport.IPs
	}

	ipv4, ipv6 := splitIPFamilies(ips)
	observed := make([]upstream.Port, 0, len(ports))
	for _, p := range ports {
		observed = append(observed, upstream.Port{
			Name:     p.Name,
			Port:     p.Port,
			Protocol: string(p.Protocol),
		})
	}
	return upstream.PortReport{
		ClusterID:             clusterID,
		EdgePolicyNamespaceID: r.namespaceUID(ctx, policy.Namespace),
		EdgePolicyID:          string(policy.UID),
		ServiceName:           serviceName,
		Datacenter:            policy.Spec.Datacenter,
		IpamZone:              ipamZone,
		IpamSecret:            ipamSecret,
		IPv4Addresses:         ipv4,
		IPv6Addresses:         ipv6,
		Filter: upstream.FilterReport{
			Enabled:         filterEnabled(policy),
			ObservedPorts:   observed,
			AdditionalPorts: additionalPorts(policy),
		},
		DDoS: ddosReport(policy),
	}, nil
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

// setUpstreamPendingCondition marks UpstreamReady as False/UpstreamReportPending while
// a queued report job is being polled to completion, so the in-flight state is visible
// on the status. It returns whether the status changed. A later successful poll clears
// the condition via acceptReport; a failed poll replaces it with a failure reason.
func setUpstreamPendingCondition(policy *securityv1alpha1.EdgePolicy) bool {
	return meta.SetStatusCondition(&policy.Status.Conditions, metav1.Condition{
		Type:               conditionTypeUpstreamReady,
		Status:             metav1.ConditionFalse,
		Reason:             reasonUpstreamPending,
		Message:            "Upstream report queued; awaiting completion",
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
// when the upstream refused the report with a 4xx client error (or a failed status-queue
// job). Unlike a transient failure this is terminal: the controller stops retrying on the
// timer and re-attempts only when the report content changes. The message is the fixed
// rejectedReportMessage plus the upstream's detail persisted in status.RejectedReportMessage,
// so it stays byte-identical between a fresh rejection and a later suppressed reconcile
// (both read the same persisted detail), letting the status reach a quiet fixpoint while
// still surfacing why the report was rejected. It returns whether the status changed.
func setUpstreamRejectedCondition(policy *securityv1alpha1.EdgePolicy) bool {
	message := rejectedReportMessage
	if detail := policy.Status.RejectedReportMessage; detail != "" {
		message = fmt.Sprintf("%s: %s", rejectedReportMessage, detail)
	}
	return meta.SetStatusCondition(&policy.Status.Conditions, metav1.Condition{
		Type:               conditionTypeUpstreamReady,
		Status:             metav1.ConditionFalse,
		Reason:             reasonUpstreamRejected,
		Message:            message,
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
		For(&securityv1alpha1.EdgePolicy{}, builder.WithPredicates(edgePolicyReconcilePredicate())).
		Watches(
			&corev1.Service{},
			handler.EnqueueRequestsFromMapFunc(r.edgePoliciesForService),
			builder.WithPredicates(loadBalancerServicePredicate()),
		).
		Named("edgepolicy").
		Complete(r)
}

// edgePolicyReconcilePredicate drops EdgePolicy update events that change only the
// status or other bookkeeping fields (resourceVersion, managedFields), while keeping
// events where the spec (generation), the deletion timestamp, or the finalizers
// changed. This stops the controller's own Status().Update writes from re-triggering a
// reconcile which — combined with informer cache lag — could otherwise re-send an
// upstream report (or withdrawal) that was already delivered. Create and delete events
// are always admitted (unset predicate funcs default to true).
func edgePolicyReconcilePredicate() predicate.Predicate {
	return predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			if e.ObjectOld == nil || e.ObjectNew == nil {
				return true
			}
			// Spec change (bumps generation), entering deletion, or a finalizer
			// add/remove all require reconciliation; a status-only write does not.
			if e.ObjectOld.GetGeneration() != e.ObjectNew.GetGeneration() {
				return true
			}
			if !e.ObjectOld.GetDeletionTimestamp().Equal(e.ObjectNew.GetDeletionTimestamp()) {
				return true
			}
			return !slices.Equal(e.ObjectOld.GetFinalizers(), e.ObjectNew.GetFinalizers())
		},
	}
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
