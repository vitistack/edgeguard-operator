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
	"github.com/vitistack/edgeguard-operator/internal/upstream"
)

// kindService is the only supported TargetRef kind, reused across test fixtures.
const kindService = "Service"

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
							Kind:       kindService,
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
						Kind:       kindService,
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
					Type:  corev1.ServiceTypeLoadBalancer,
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

			By("confirming the discovered Service ports were recorded on the status")
			Expect(ready.Status.ObservedPorts).To(HaveLen(1))
			Expect(ready.Status.ObservedPorts[0].Port).To(Equal(int32(80)))
			Expect(ready.Status.ObservedPorts[0].Protocol).To(Equal(corev1.ProtocolTCP))

			By("confirming the finalizer was added to the Service")
			protectedService := &corev1.Service{}
			Expect(k8sClient.Get(ctx, serviceKey, protectedService)).To(Succeed())
			Expect(controllerutil.ContainsFinalizer(protectedService, serviceFinalizer)).To(BeTrue())
		})
	})

	Context("When ACL is enabled", func() {
		const (
			policyName  = "acl-policy"
			namespace   = "default"
			serviceName = "acl-service"
		)

		ctx := context.Background()
		policyKey := types.NamespacedName{Name: policyName, Namespace: namespace}
		serviceKey := types.NamespacedName{Name: serviceName, Namespace: namespace}

		It("reports discovered ports upstream once, and not again when unchanged", func() {
			reporter := &fakeReporter{}
			reconciler := &EdgePolicyReconciler{
				Client:   k8sClient,
				Scheme:   k8sClient.Scheme(),
				Reporter: reporter,
			}

			By("creating an EdgePolicy with acl enabled and its target Service")
			aclOn := true
			policy := &securityv1alpha1.EdgePolicy{
				Name:      policyName,
				Namespace: namespace,
				Spec: securityv1alpha1.EdgePolicySpec{
					TargetRef: securityv1alpha1.TargetReference{
						APIVersion: "v1",
						Kind:       kindService,
						Name:       serviceName,
					},
					ACL: &aclOn,
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

			service := &corev1.Service{
				Name:      serviceName,
				Namespace: namespace,
				Annotations: map[string]string{
					"ipam.vitistack.io/zone": "oslo-1",
					secretAnnotation:         "my-secret",
				},
				Spec: corev1.ServiceSpec{
					Type:  corev1.ServiceTypeLoadBalancer,
					Ports: []corev1.ServicePort{{Port: 443}},
				},
			}
			Expect(k8sClient.Create(ctx, service)).To(Succeed())
			By("assigning LoadBalancer ingress IPs on the Service status")
			service.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{
				{IP: "203.0.113.10"},
				{IP: "2001:db8::10"},
			}
			Expect(k8sClient.Status().Update(ctx, service)).To(Succeed())
			DeferCleanup(func() {
				fetched := &corev1.Service{}
				if err := k8sClient.Get(ctx, serviceKey, fetched); err == nil {
					controllerutil.RemoveFinalizer(fetched, serviceFinalizer)
					Expect(k8sClient.Update(ctx, fetched)).To(Succeed())
					Expect(k8sClient.Delete(ctx, fetched)).To(Succeed())
				}
			})

			By("ensuring the kube-system namespace exists so the cluster UID resolves")
			kubeSystem := &corev1.Namespace{Name: "kube-system"}
			if err := k8sClient.Create(ctx, kubeSystem); err != nil {
				Expect(errors.IsAlreadyExists(err)).To(BeTrue())
			}

			By("creating the Secret referenced by the ipam.vitistack.io/secret annotation")
			secret := &corev1.Secret{
				Name:      "my-secret",
				Namespace: namespace,
				Data:      map[string][]byte{"secret": []byte("s3cr3t")},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())
			DeferCleanup(func() {
				_ = k8sClient.Delete(ctx, secret)
			})

			By("reconciling: first adds the policy finalizer, second protects and reports")
			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: policyKey})
			Expect(err).NotTo(HaveOccurred())
			_, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: policyKey})
			Expect(err).NotTo(HaveOccurred())

			By("confirming the enriched report was sent upstream exactly once")
			Expect(reporter.reports).To(HaveLen(1))
			report := reporter.reports[0]
			Expect(report.ServiceName).To(Equal(serviceName))
			Expect(report.PolicyName).To(Equal(policyName))
			Expect(report.IpamZone).To(Equal("oslo-1"))
			Expect(report.IpamSecret).To(Equal("s3cr3t"))
			Expect(report.ClusterUID).NotTo(BeEmpty())
			Expect(report.LoadBalancerIPv4).To(ConsistOf("203.0.113.10"))
			Expect(report.LoadBalancerIPv6).To(ConsistOf("2001:db8::10"))
			Expect(report.Ports).To(HaveLen(1))
			Expect(report.Ports[0].Port).To(Equal(int32(443)))

			By("confirming the observed IPs were recorded on the policy status")
			reconciled := &securityv1alpha1.EdgePolicy{}
			Expect(k8sClient.Get(ctx, policyKey, reconciled)).To(Succeed())
			Expect(reconciled.Status.ObservedIPs).To(ConsistOf("203.0.113.10", "2001:db8::10"))

			By("confirming the IPAM secret resolved cleanly on the status")
			secretCond := meta.FindStatusCondition(reconciled.Status.Conditions, conditionTypeIpamSecretReady)
			Expect(secretCond).NotTo(BeNil())
			Expect(secretCond.Status).To(Equal(metav1.ConditionTrue))
			Expect(secretCond.Reason).To(Equal(reasonSecretResolved))

			By("confirming an unchanged follow-up reconcile does not report again")
			_, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: policyKey})
			Expect(err).NotTo(HaveOccurred())
			Expect(reporter.reports).To(HaveLen(1))
		})
	})

	Context("When the referenced IPAM secret is missing", func() {
		const (
			policyName  = "missing-secret-policy"
			namespace   = "default"
			serviceName = "missing-secret-service"
		)

		ctx := context.Background()
		policyKey := types.NamespacedName{Name: policyName, Namespace: namespace}
		serviceKey := types.NamespacedName{Name: serviceName, Namespace: namespace}

		It("still reports with an empty secret and flags it on the status", func() {
			reporter := &fakeReporter{}
			reconciler := &EdgePolicyReconciler{
				Client:   k8sClient,
				Scheme:   k8sClient.Scheme(),
				Reporter: reporter,
			}

			By("creating an acl-enabled EdgePolicy and a Service referencing an absent Secret")
			aclOn := true
			policy := &securityv1alpha1.EdgePolicy{
				Name:      policyName,
				Namespace: namespace,
				Spec: securityv1alpha1.EdgePolicySpec{
					TargetRef: securityv1alpha1.TargetReference{
						APIVersion: "v1",
						Kind:       kindService,
						Name:       serviceName,
					},
					ACL: &aclOn,
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

			service := &corev1.Service{
				Name:      serviceName,
				Namespace: namespace,
				Annotations: map[string]string{
					secretAnnotation: "does-not-exist",
				},
				Spec: corev1.ServiceSpec{
					Type:  corev1.ServiceTypeLoadBalancer,
					Ports: []corev1.ServicePort{{Port: 443}},
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

			By("reconciling: first adds the policy finalizer, second protects and reports")
			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: policyKey})
			Expect(err).NotTo(HaveOccurred())
			_, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: policyKey})
			Expect(err).NotTo(HaveOccurred())

			By("confirming the report was still sent, with an empty secret")
			Expect(reporter.reports).To(HaveLen(1))
			Expect(reporter.reports[0].IpamSecret).To(BeEmpty())

			By("confirming the missing Secret is surfaced on the status")
			reconciled := &securityv1alpha1.EdgePolicy{}
			Expect(k8sClient.Get(ctx, policyKey, reconciled)).To(Succeed())
			cond := meta.FindStatusCondition(reconciled.Status.Conditions, conditionTypeIpamSecretReady)
			Expect(cond).NotTo(BeNil())
			Expect(cond.Status).To(Equal(metav1.ConditionFalse))
			Expect(cond.Reason).To(Equal(reasonSecretNotFound))
		})
	})

	Context("When the referenced IPAM secret lacks the expected key", func() {
		const (
			policyName  = "invalid-secret-policy"
			namespace   = "default"
			serviceName = "invalid-secret-service"
		)

		ctx := context.Background()
		policyKey := types.NamespacedName{Name: policyName, Namespace: namespace}
		serviceKey := types.NamespacedName{Name: serviceName, Namespace: namespace}

		It("still reports with an empty secret and flags it invalid on the status", func() {
			reporter := &fakeReporter{}
			reconciler := &EdgePolicyReconciler{
				Client:   k8sClient,
				Scheme:   k8sClient.Scheme(),
				Reporter: reporter,
			}

			By("creating an acl-enabled EdgePolicy and a Service referencing the Secret")
			aclOn := true
			policy := &securityv1alpha1.EdgePolicy{
				Name:      policyName,
				Namespace: namespace,
				Spec: securityv1alpha1.EdgePolicySpec{
					TargetRef: securityv1alpha1.TargetReference{
						APIVersion: "v1",
						Kind:       kindService,
						Name:       serviceName,
					},
					ACL: &aclOn,
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

			service := &corev1.Service{
				Name:      serviceName,
				Namespace: namespace,
				Annotations: map[string]string{
					secretAnnotation: "wrong-key-secret",
				},
				Spec: corev1.ServiceSpec{
					Type:  corev1.ServiceTypeLoadBalancer,
					Ports: []corev1.ServicePort{{Port: 443}},
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

			By("creating the referenced Secret without the expected 'secret' key")
			secret := &corev1.Secret{
				Name:      "wrong-key-secret",
				Namespace: namespace,
				Data:      map[string][]byte{"not-secret": []byte("ignored")},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())
			DeferCleanup(func() {
				_ = k8sClient.Delete(ctx, secret)
			})

			By("reconciling: first adds the policy finalizer, second protects and reports")
			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: policyKey})
			Expect(err).NotTo(HaveOccurred())
			_, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: policyKey})
			Expect(err).NotTo(HaveOccurred())

			By("confirming the report was still sent, with an empty secret")
			Expect(reporter.reports).To(HaveLen(1))
			Expect(reporter.reports[0].IpamSecret).To(BeEmpty())

			By("confirming the invalid Secret is surfaced on the status")
			reconciled := &securityv1alpha1.EdgePolicy{}
			Expect(k8sClient.Get(ctx, policyKey, reconciled)).To(Succeed())
			cond := meta.FindStatusCondition(reconciled.Status.Conditions, conditionTypeIpamSecretReady)
			Expect(cond).NotTo(BeNil())
			Expect(cond.Status).To(Equal(metav1.ConditionFalse))
			Expect(cond.Reason).To(Equal(reasonSecretInvalid))
		})
	})

	Context("When the Service has no IPAM secret annotation", func() {
		const (
			policyName  = "no-secret-annotation-policy"
			namespace   = "default"
			serviceName = "no-secret-annotation-service"
		)

		ctx := context.Background()
		policyKey := types.NamespacedName{Name: policyName, Namespace: namespace}
		serviceKey := types.NamespacedName{Name: serviceName, Namespace: namespace}

		It("flags the missing annotation on the status", func() {
			reporter := &fakeReporter{}
			reconciler := &EdgePolicyReconciler{
				Client:   k8sClient,
				Scheme:   k8sClient.Scheme(),
				Reporter: reporter,
			}

			By("creating an acl-enabled EdgePolicy and a Service with no secret annotation")
			aclOn := true
			policy := &securityv1alpha1.EdgePolicy{
				Name:      policyName,
				Namespace: namespace,
				Spec: securityv1alpha1.EdgePolicySpec{
					TargetRef: securityv1alpha1.TargetReference{
						APIVersion: "v1",
						Kind:       kindService,
						Name:       serviceName,
					},
					ACL: &aclOn,
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

			service := &corev1.Service{
				Name:      serviceName,
				Namespace: namespace,
				Spec: corev1.ServiceSpec{
					Type:  corev1.ServiceTypeLoadBalancer,
					Ports: []corev1.ServicePort{{Port: 443}},
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

			By("reconciling: first adds the policy finalizer, second protects and reports")
			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: policyKey})
			Expect(err).NotTo(HaveOccurred())
			_, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: policyKey})
			Expect(err).NotTo(HaveOccurred())

			By("confirming the missing annotation is surfaced on the status")
			reconciled := &securityv1alpha1.EdgePolicy{}
			Expect(k8sClient.Get(ctx, policyKey, reconciled)).To(Succeed())
			cond := meta.FindStatusCondition(reconciled.Status.Conditions, conditionTypeIpamSecretReady)
			Expect(cond).NotTo(BeNil())
			Expect(cond.Status).To(Equal(metav1.ConditionFalse))
			Expect(cond.Reason).To(Equal(reasonSecretNotConfigured))
		})
	})
})

// fakeReporter is a test Reporter that records every report it receives.
type fakeReporter struct {
	reports []upstream.PortReport
	err     error
}

func (f *fakeReporter) ReportPorts(_ context.Context, report upstream.PortReport) error {
	if f.err != nil {
		return f.err
	}
	f.reports = append(f.reports, report)
	return nil
}
