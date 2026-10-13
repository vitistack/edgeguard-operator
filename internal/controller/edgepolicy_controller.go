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

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	securityv1alpha1 "github.com/vitistack/edgeguard-operator/api/v1alpha1"
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

	reasonServiceProtected   = "ServiceProtected"
	reasonServiceNotFound    = "ServiceNotFound"
	reasonServiceTerminating = "ServiceTerminating"
)

// EdgePolicyReconciler reconciles a EdgePolicy object
type EdgePolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=security.vitistack.io,resources=edgepolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.vitistack.io,resources=edgepolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.vitistack.io,resources=edgepolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups=core,resources=services,verbs=get;list;watch;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the EdgePolicy object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.25.0/pkg/reconcile
func (r *EdgePolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

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
			if err := r.setReadyCondition(ctx, &policy, metav1.ConditionFalse, reasonServiceNotFound,
				fmt.Sprintf("Target Service %q not found", serviceKey.Name)); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
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
		if err := r.setReadyCondition(ctx, &policy, metav1.ConditionFalse, reasonServiceTerminating,
			fmt.Sprintf("Target Service %q is being deleted", service.Name)); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	// Add the finalizer to the Service if not already present.
	if controllerutil.AddFinalizer(service, serviceFinalizer) {
		if err := r.Update(ctx, service); err != nil {
			log.Error(err, "Failed to add finalizer to Service", "service", service.Name)
			return ctrl.Result{}, err
		}
		log.Info("Added finalizer to Service", "service", service.Name)
	}

	// Reflect that the target Service is now protected by this policy.
	if err := r.setReadyCondition(ctx, &policy, metav1.ConditionTrue, reasonServiceProtected,
		fmt.Sprintf("Finalizer present on Service %q", service.Name)); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// setReadyCondition sets the Ready condition and ObservedGeneration on the EdgePolicy
// status, writing to the status subresource only when the status actually changed.
func (r *EdgePolicyReconciler) setReadyCondition(ctx context.Context, policy *securityv1alpha1.EdgePolicy,
	status metav1.ConditionStatus, reason, message string) error {
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
	if !changed {
		return nil
	}
	if err := r.Status().Update(ctx, policy); err != nil {
		return err
	}
	logf.FromContext(ctx).Info("Updated EdgePolicy status",
		"edgepolicy", policy.Name, "ready", status, "reason", reason)
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
		).
		Named("edgepolicy").
		Complete(r)
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
