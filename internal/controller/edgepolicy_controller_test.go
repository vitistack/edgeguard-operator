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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	securityv1alpha1 "github.com/vitistack/edgeguard-operator/api/v1alpha1"
)

var _ = Describe("EdgePolicy Controller", func() {
	Context("When reconciling a resource", func() {
		const (
			resourceName      = "test-resource"
			resourceNamespace = "default"
		)

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: resourceNamespace,
		}
		edgepolicy := &securityv1alpha1.EdgePolicy{}

		BeforeEach(func() {
			By("creating the custom resource for the Kind EdgePolicy")
			err := k8sClient.Get(ctx, typeNamespacedName, edgepolicy)
			if err != nil && errors.IsNotFound(err) {
				resource := &securityv1alpha1.EdgePolicy{
					Name:      resourceName,
					Namespace: resourceNamespace,
					Spec: securityv1alpha1.EdgePolicySpec{
						TargetRef: securityv1alpha1.TargetReference{
							APIVersion: "v1",
							Kind:       "Service",
							Name:       "test-service",
						},
						AllowedRegion: &securityv1alpha1.AllowedRegionSpec{
							Region: "norway",
						},
					},
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}
		})

		AfterEach(func() {
			// TODO(user): Cleanup logic after each test, like removing the resource instance.
			resource := &securityv1alpha1.EdgePolicy{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			Expect(err).NotTo(HaveOccurred())

			By("Cleanup the specific resource instance EdgePolicy")
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
		})
		It("should successfully reconcile the resource", func() {
			By("Reconciling the created resource")
			controllerReconciler := &EdgePolicyReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			// First reconcile adds the EdgePolicy finalizer and returns early.
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			// Second reconcile evaluates the (absent) target Service and records a condition.
			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			By("Checking the Ready condition reflects the missing target Service")
			reconciled := &securityv1alpha1.EdgePolicy{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, reconciled)).To(Succeed())
			ready := meta.FindStatusCondition(reconciled.Status.Conditions, conditionTypeReady)
			Expect(ready).NotTo(BeNil())
			Expect(ready.Status).To(Equal(metav1.ConditionFalse))
			Expect(ready.Reason).To(Equal(reasonServiceNotFound))
		})
	})

	Context("When the target Service is created after the EdgePolicy", func() {
		const (
			policyName  = "late-service-policy"
			namespace   = "default"
			serviceName = "late-service"
		)

		ctx := context.Background()
		policyKey := types.NamespacedName{Name: policyName, Namespace: namespace}
		serviceKey := types.NamespacedName{Name: serviceName, Namespace: namespace}

		It("maps the new Service back to the policy and marks it Ready", func() {
			reconciler := &EdgePolicyReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			By("creating an EdgePolicy that targets a Service which does not exist yet")
			policy := &securityv1alpha1.EdgePolicy{
				Name:      policyName,
				Namespace: namespace,
				Spec: securityv1alpha1.EdgePolicySpec{
					TargetRef: securityv1alpha1.TargetReference{
						APIVersion: "v1",
						Kind:       "Service",
						Name:       serviceName,
					},
					AllowedRegion: &securityv1alpha1.AllowedRegionSpec{Region: "norway"},
				},
			}
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())
			DeferCleanup(func() {
				fetched := &securityv1alpha1.EdgePolicy{}
				if err := k8sClient.Get(ctx, policyKey, fetched); err == nil {
					controllerutil.RemoveFinalizer(fetched, edgePolicyFinalizer)
					Expect(k8sClient.Update(ctx, fetched)).To(Succeed())
					Expect(k8sClient.Delete(ctx, fetched)).To(Succeed())
				}
			})

			By("reconciling while the Service is absent -> Ready=False/ServiceNotFound")
			// First reconcile adds the policy finalizer; second evaluates the missing Service.
			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: policyKey})
			Expect(err).NotTo(HaveOccurred())
			_, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: policyKey})
			Expect(err).NotTo(HaveOccurred())

			notReady := &securityv1alpha1.EdgePolicy{}
			Expect(k8sClient.Get(ctx, policyKey, notReady)).To(Succeed())
			Expect(meta.FindStatusCondition(notReady.Status.Conditions, conditionTypeReady).Reason).
				To(Equal(reasonServiceNotFound))

			By("creating the target Service")
			service := &corev1.Service{
				Name:      serviceName,
				Namespace: namespace,
				Spec: corev1.ServiceSpec{
					Ports: []corev1.ServicePort{{Port: 80}},
				},
			}
			Expect(k8sClient.Create(ctx, service)).To(Succeed())
			DeferCleanup(func() {
				fetched := &corev1.Service{}
				if err := k8sClient.Get(ctx, serviceKey, fetched); err == nil {
					controllerutil.RemoveFinalizer(fetched, serviceFinalizer)
					Expect(k8sClient.Update(ctx, fetched)).To(Succeed())
					Expect(k8sClient.Delete(ctx, fetched)).To(Succeed())
				}
			})

			// In production the Watches(&corev1.Service{}) source fires on this Create event and
			// edgePoliciesForService maps it (via the .spec.targetRef.name field index) back to
			// this policy, enqueuing it. That index lives on the manager's cache, which this
			// direct-client suite does not run, so we drive the follow-up reconcile explicitly.
			By("reconciling now that the Service exists -> Ready=True/ServiceProtected")
			_, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: policyKey})
			Expect(err).NotTo(HaveOccurred())

			ready := &securityv1alpha1.EdgePolicy{}
			Expect(k8sClient.Get(ctx, policyKey, ready)).To(Succeed())
			cond := meta.FindStatusCondition(ready.Status.Conditions, conditionTypeReady)
			Expect(cond).NotTo(BeNil())
			Expect(cond.Status).To(Equal(metav1.ConditionTrue))
			Expect(cond.Reason).To(Equal(reasonServiceProtected))

			By("confirming the finalizer was added to the Service")
			protectedService := &corev1.Service{}
			Expect(k8sClient.Get(ctx, serviceKey, protectedService)).To(Succeed())
			Expect(controllerutil.ContainsFinalizer(protectedService, serviceFinalizer)).To(BeTrue())
		})
	})
})
