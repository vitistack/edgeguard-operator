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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	securityv1alpha1 "github.com/vitistack/edgeguard-operator/api/v1alpha1"
	"github.com/vitistack/edgeguard-operator/internal/upstream"
)

// kindService is the only supported TargetRef kind, reused across test fixtures.
const kindService = "Service"

// Service names reused across the datacenter/delete fixtures (goconst).
const (
	dcServiceName     = "dc-service"
	deleteServiceName = "delete-service"
	// dcEast is a representative datacenter value reused across fixtures (goconst).
	dcEast = "no-east-az1"
	// queuedJobStatusURL is the placeholder status URL of a queued upstream job, reused
	// across the async report/withdrawal tests (goconst).
	queuedJobStatusURL = "https://upstream.test/jobs/j1"
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
						Datacenter: dcEast,
						TargetRef: securityv1alpha1.TargetReference{
							APIVersion: "v1",
							Kind:       kindService,
							Name:       "test-service",
						},
						DDoS: &securityv1alpha1.DDoSSpec{
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
					Datacenter: dcEast,
					TargetRef: securityv1alpha1.TargetReference{
						APIVersion: "v1",
						Kind:       kindService,
						Name:       serviceName,
					},
					DDoS: &securityv1alpha1.DDoSSpec{Region: "norway"},
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
			policy := &securityv1alpha1.EdgePolicy{
				Name:      policyName,
				Namespace: namespace,
				Spec: securityv1alpha1.EdgePolicySpec{
					Datacenter: dcEast,
					TargetRef: securityv1alpha1.TargetReference{
						APIVersion: "v1",
						Kind:       kindService,
						Name:       serviceName,
					},
					Filter: &securityv1alpha1.FilterSpec{Enabled: true},
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
				Data:      map[string][]byte{secretDataKey: []byte("s3cr3t")},
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
			Expect(report.IpamZone).To(Equal("oslo-1"))
			Expect(report.IpamSecret).To(Equal("s3cr3t"))
			Expect(report.ClusterID).NotTo(BeEmpty())
			Expect(report.IPv4Addresses).To(ConsistOf("203.0.113.10"))
			Expect(report.IPv6Addresses).To(ConsistOf("2001:db8::10"))
			Expect(report.Filter.Enabled).To(BeTrue())
			Expect(report.Filter.ObservedPorts).To(HaveLen(1))
			Expect(report.Filter.ObservedPorts[0].Port).To(Equal(int32(443)))

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

		It("includes the datacenter and additional ports in the upstream report", func() {
			reporter := &fakeReporter{}
			reconciler := &EdgePolicyReconciler{
				Client:   k8sClient,
				Scheme:   k8sClient.Scheme(),
				Reporter: reporter,
			}

			By("creating a filter-enabled EdgePolicy with datacenter and additionalPortList")
			policy := &securityv1alpha1.EdgePolicy{
				Name:      "dc-policy",
				Namespace: namespace,
				Spec: securityv1alpha1.EdgePolicySpec{
					TargetRef: securityv1alpha1.TargetReference{
						APIVersion: "v1",
						Kind:       kindService,
						Name:       dcServiceName,
					},
					Datacenter: dcEast,
					Filter: &securityv1alpha1.FilterSpec{
						Enabled: true,
						AdditionalPortList: []securityv1alpha1.AdditionalPort{
							{Name: "ping", Port: 0, Protocol: "ICMP"},
							{Name: " h", Port: 8080, Protocol: "TCP"},
						},
					},
				},
			}
			dcPolicyKey := types.NamespacedName{Name: "dc-policy", Namespace: namespace}
			dcServiceKey := types.NamespacedName{Name: dcServiceName, Namespace: namespace}
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())
			DeferCleanup(func() {
				fetched := &securityv1alpha1.EdgePolicy{}
				if err := k8sClient.Get(ctx, dcPolicyKey, fetched); err == nil {
					controllerutil.RemoveFinalizer(fetched, edgePolicyFinalizer)
					Expect(k8sClient.Update(ctx, fetched)).To(Succeed())
					Expect(k8sClient.Delete(ctx, fetched)).To(Succeed())
				}
			})

			service := &corev1.Service{
				Name:      dcServiceName,
				Namespace: namespace,
				Annotations: map[string]string{
					secretAnnotation: "dc-secret",
				},
				Spec: corev1.ServiceSpec{
					Type:  corev1.ServiceTypeLoadBalancer,
					Ports: []corev1.ServicePort{{Port: 443}},
				},
			}
			Expect(k8sClient.Create(ctx, service)).To(Succeed())
			service.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "203.0.113.30"}}
			Expect(k8sClient.Status().Update(ctx, service)).To(Succeed())
			DeferCleanup(func() {
				fetched := &corev1.Service{}
				if err := k8sClient.Get(ctx, dcServiceKey, fetched); err == nil {
					controllerutil.RemoveFinalizer(fetched, serviceFinalizer)
					Expect(k8sClient.Update(ctx, fetched)).To(Succeed())
					Expect(k8sClient.Delete(ctx, fetched)).To(Succeed())
				}
			})

			By("creating the Secret the target Service references")
			dcSecret := &corev1.Secret{
				Name:      "dc-secret",
				Namespace: namespace,
				Data:      map[string][]byte{secretDataKey: []byte("dc-cr3d")},
			}
			Expect(k8sClient.Create(ctx, dcSecret)).To(Succeed())
			DeferCleanup(func() {
				_ = k8sClient.Delete(ctx, dcSecret)
			})

			By("reconciling: first adds the finalizer, second protects and reports")
			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: dcPolicyKey})
			Expect(err).NotTo(HaveOccurred())
			_, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: dcPolicyKey})
			Expect(err).NotTo(HaveOccurred())

			By("confirming the report carries the datacenter and additional ports")
			Expect(reporter.reports).To(HaveLen(1))
			report := reporter.reports[0]
			Expect(report.Datacenter).To(Equal(dcEast))
			Expect(report.Filter.ObservedPorts).To(HaveLen(1))
			Expect(report.Filter.AdditionalPorts).To(HaveLen(2))
			Expect(report.Filter.AdditionalPorts[0].Protocol).To(Equal("ICMP"))
			Expect(report.Filter.AdditionalPorts[1].Port).To(Equal(int32(8080)))
		})

		It("reports enabled=false when the filter block is present but disabled", func() {
			reporter := &fakeReporter{}
			reconciler := &EdgePolicyReconciler{
				Client:   k8sClient,
				Scheme:   k8sClient.Scheme(),
				Reporter: reporter,
			}

			const disabledServiceName = "disabled-filter-svc"
			policyKey := types.NamespacedName{Name: "disabled-filter-policy", Namespace: namespace}
			serviceKey := types.NamespacedName{Name: disabledServiceName, Namespace: namespace}

			By("creating an EdgePolicy whose filter block is present but disabled")
			policy := &securityv1alpha1.EdgePolicy{
				Name:      policyKey.Name,
				Namespace: namespace,
				Spec: securityv1alpha1.EdgePolicySpec{
					TargetRef: securityv1alpha1.TargetReference{
						APIVersion: "v1",
						Kind:       kindService,
						Name:       disabledServiceName,
					},
					Datacenter: dcEast,
					Filter:     &securityv1alpha1.FilterSpec{Enabled: false},
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
				Name:        disabledServiceName,
				Namespace:   namespace,
				Annotations: map[string]string{secretAnnotation: "disabled-secret"},
				Spec: corev1.ServiceSpec{
					Type:  corev1.ServiceTypeLoadBalancer,
					Ports: []corev1.ServicePort{{Port: 443}},
				},
			}
			Expect(k8sClient.Create(ctx, service)).To(Succeed())
			service.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "203.0.113.42"}}
			Expect(k8sClient.Status().Update(ctx, service)).To(Succeed())
			DeferCleanup(func() {
				fetched := &corev1.Service{}
				if err := k8sClient.Get(ctx, serviceKey, fetched); err == nil {
					controllerutil.RemoveFinalizer(fetched, serviceFinalizer)
					Expect(k8sClient.Update(ctx, fetched)).To(Succeed())
					Expect(k8sClient.Delete(ctx, fetched)).To(Succeed())
				}
			})

			By("creating the Secret the target Service references")
			secret := &corev1.Secret{
				Name:      "disabled-secret",
				Namespace: namespace,
				Data:      map[string][]byte{secretDataKey: []byte("disabled-cr3d")},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())
			DeferCleanup(func() {
				_ = k8sClient.Delete(ctx, secret)
			})

			By("reconciling: first adds the finalizer, second protects and reports")
			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: policyKey})
			Expect(err).NotTo(HaveOccurred())
			_, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: policyKey})
			Expect(err).NotTo(HaveOccurred())

			By("confirming a report was still sent, carrying filter.enabled=false")
			Expect(reporter.reports).To(HaveLen(1))
			Expect(reporter.reports[0].Filter.Enabled).To(BeFalse())
			Expect(reporter.reports[0].ServiceName).To(Equal(disabledServiceName))
		})

		It("withdraws the reported ports upstream when the policy is deleted", func() {
			reporter := &fakeReporter{}
			reconciler := &EdgePolicyReconciler{
				Client:   k8sClient,
				Scheme:   k8sClient.Scheme(),
				Reporter: reporter,
			}

			By("creating a filter-enabled EdgePolicy and its LoadBalancer Service")
			policy := &securityv1alpha1.EdgePolicy{
				Name:      "delete-policy",
				Namespace: namespace,
				Spec: securityv1alpha1.EdgePolicySpec{
					TargetRef: securityv1alpha1.TargetReference{
						APIVersion: "v1",
						Kind:       kindService,
						Name:       deleteServiceName,
					},
					Datacenter: "no-west-az2",
					Filter:     &securityv1alpha1.FilterSpec{Enabled: true},
				},
			}
			delPolicyKey := types.NamespacedName{Name: "delete-policy", Namespace: namespace}
			delServiceKey := types.NamespacedName{Name: deleteServiceName, Namespace: namespace}
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())

			service := &corev1.Service{
				Name:      deleteServiceName,
				Namespace: namespace,
				Annotations: map[string]string{
					"ipam.vitistack.io/secret": "delete-secret",
					"ipam.vitistack.io/zone":   "oslo-1",
				},
				Spec: corev1.ServiceSpec{
					Type:  corev1.ServiceTypeLoadBalancer,
					Ports: []corev1.ServicePort{{Port: 443}},
				},
			}
			Expect(k8sClient.Create(ctx, service)).To(Succeed())
			service.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "203.0.113.40"}}
			Expect(k8sClient.Status().Update(ctx, service)).To(Succeed())
			DeferCleanup(func() {
				fetched := &corev1.Service{}
				if err := k8sClient.Get(ctx, delServiceKey, fetched); err == nil {
					controllerutil.RemoveFinalizer(fetched, serviceFinalizer)
					Expect(k8sClient.Update(ctx, fetched)).To(Succeed())
					Expect(k8sClient.Delete(ctx, fetched)).To(Succeed())
				}
			})

			By("creating the Secret the target Service references")
			delSecret := &corev1.Secret{
				Name:      "delete-secret",
				Namespace: namespace,
				Data:      map[string][]byte{secretDataKey: []byte("d3l3te-cr3d")},
			}
			Expect(k8sClient.Create(ctx, delSecret)).To(Succeed())
			DeferCleanup(func() {
				_ = k8sClient.Delete(ctx, delSecret)
			})

			By("reconciling so the policy protects the Service and reports once")
			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: delPolicyKey})
			Expect(err).NotTo(HaveOccurred())
			_, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: delPolicyKey})
			Expect(err).NotTo(HaveOccurred())
			Expect(reporter.reports).To(HaveLen(1))

			By("deleting the policy and reconciling the deletion")
			Expect(k8sClient.Delete(ctx, policy)).To(Succeed())
			_, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: delPolicyKey})
			Expect(err).NotTo(HaveOccurred())

			By("confirming a withdraw (DELETE) was sent carrying the service and datacenter")
			Expect(reporter.deletes).To(HaveLen(1))
			del := reporter.deletes[0]
			Expect(del.ServiceName).To(Equal(deleteServiceName))
			Expect(del.Datacenter).To(Equal("no-west-az2"))
			Expect(del.Filter.ObservedPorts).To(HaveLen(1))

			By("confirming the withdraw carries the resolved IPAM credential")
			Expect(del.IpamSecret).To(Equal("d3l3te-cr3d"))
			Expect(del.IpamZone).To(Equal("oslo-1"))

			By("confirming the policy finalizer was released so the object is gone")
			Expect(errors.IsNotFound(k8sClient.Get(ctx, delPolicyKey, &securityv1alpha1.EdgePolicy{}))).To(BeTrue())
		})

		It("holds the finalizer and requeues when the withdrawal is rejected (non-404 4xx)", func() {
			const (
				rejectService    = "delete-reject-service"
				rejectSecretName = "reject-secret"
			)
			reporter := &fakeReporter{
				deleteErr: fmt.Errorf("%w: status 400: Bad Request", upstream.ErrUpstreamRejected),
			}
			reconciler := &EdgePolicyReconciler{
				Client:   k8sClient,
				Scheme:   k8sClient.Scheme(),
				Reporter: reporter,
			}

			rejectPolicyKey := types.NamespacedName{Name: "delete-reject-policy", Namespace: namespace}
			rejectServiceKey := types.NamespacedName{Name: rejectService, Namespace: namespace}

			By("creating a filter-enabled EdgePolicy and its LoadBalancer Service")
			policy := &securityv1alpha1.EdgePolicy{
				Name:      "delete-reject-policy",
				Namespace: namespace,
				Spec: securityv1alpha1.EdgePolicySpec{
					TargetRef: securityv1alpha1.TargetReference{
						APIVersion: "v1",
						Kind:       kindService,
						Name:       rejectService,
					},
					Datacenter: "no-east-az2",
					Filter:     &securityv1alpha1.FilterSpec{Enabled: true},
				},
			}
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())
			DeferCleanup(func() {
				fetched := &securityv1alpha1.EdgePolicy{}
				if err := k8sClient.Get(ctx, rejectPolicyKey, fetched); err == nil {
					controllerutil.RemoveFinalizer(fetched, edgePolicyFinalizer)
					_ = k8sClient.Update(ctx, fetched)
				}
			})

			service := &corev1.Service{
				Name:      rejectService,
				Namespace: namespace,
				Annotations: map[string]string{
					secretAnnotation: rejectSecretName,
					zoneAnnotation:   "bergen-1",
				},
				Spec: corev1.ServiceSpec{
					Type:  corev1.ServiceTypeLoadBalancer,
					Ports: []corev1.ServicePort{{Port: 443}},
				},
			}
			Expect(k8sClient.Create(ctx, service)).To(Succeed())
			service.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "203.0.113.41"}}
			Expect(k8sClient.Status().Update(ctx, service)).To(Succeed())
			DeferCleanup(func() {
				fetched := &corev1.Service{}
				if err := k8sClient.Get(ctx, rejectServiceKey, fetched); err == nil {
					controllerutil.RemoveFinalizer(fetched, serviceFinalizer)
					Expect(k8sClient.Update(ctx, fetched)).To(Succeed())
					Expect(k8sClient.Delete(ctx, fetched)).To(Succeed())
				}
			})

			By("creating the Secret the target Service references")
			secret := &corev1.Secret{
				Name:      rejectSecretName,
				Namespace: namespace,
				Data:      map[string][]byte{secretDataKey: []byte("d3l3te-cr3d")},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())
			DeferCleanup(func() {
				_ = k8sClient.Delete(ctx, secret)
			})

			By("reconciling so the policy protects the Service and reports once")
			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: rejectPolicyKey})
			Expect(err).NotTo(HaveOccurred())
			_, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: rejectPolicyKey})
			Expect(err).NotTo(HaveOccurred())
			Expect(reporter.reports).To(HaveLen(1))

			By("deleting the policy; a rejected withdrawal must hold the finalizer and requeue")
			Expect(k8sClient.Delete(ctx, policy)).To(Succeed())
			res, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: rejectPolicyKey})
			Expect(err).NotTo(HaveOccurred())
			Expect(res.RequeueAfter).To(Equal(upstreamRetryInterval))

			By("confirming the withdrawal was not accepted and the finalizer was NOT removed")
			Expect(reporter.deletes).To(BeEmpty())
			stuck := &securityv1alpha1.EdgePolicy{}
			Expect(k8sClient.Get(ctx, rejectPolicyKey, stuck)).To(Succeed())
			Expect(controllerutil.ContainsFinalizer(stuck, edgePolicyFinalizer)).To(BeTrue())
		})

		It("removes the finalizer when the withdrawal returns 404 (already gone)", func() {
			const (
				goneService    = "delete-gone-service"
				goneSecretName = "gone-secret"
			)
			reporter := &fakeReporter{
				deleteErr: fmt.Errorf("%w: status 404: 404 Not Found", upstream.ErrUpstreamNotFound),
			}
			reconciler := &EdgePolicyReconciler{
				Client:   k8sClient,
				Scheme:   k8sClient.Scheme(),
				Reporter: reporter,
			}

			gonePolicyKey := types.NamespacedName{Name: "delete-gone-policy", Namespace: namespace}
			goneServiceKey := types.NamespacedName{Name: goneService, Namespace: namespace}

			By("creating a filter-enabled EdgePolicy and its LoadBalancer Service")
			policy := &securityv1alpha1.EdgePolicy{
				Name:      "delete-gone-policy",
				Namespace: namespace,
				Spec: securityv1alpha1.EdgePolicySpec{
					TargetRef: securityv1alpha1.TargetReference{
						APIVersion: "v1",
						Kind:       kindService,
						Name:       goneService,
					},
					Datacenter: "no-central-az1",
					Filter:     &securityv1alpha1.FilterSpec{Enabled: true},
				},
			}
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())
			DeferCleanup(func() {
				fetched := &securityv1alpha1.EdgePolicy{}
				if err := k8sClient.Get(ctx, gonePolicyKey, fetched); err == nil {
					controllerutil.RemoveFinalizer(fetched, edgePolicyFinalizer)
					_ = k8sClient.Update(ctx, fetched)
				}
			})

			service := &corev1.Service{
				Name:      goneService,
				Namespace: namespace,
				Annotations: map[string]string{
					secretAnnotation: goneSecretName,
					zoneAnnotation:   "bergen-1",
				},
				Spec: corev1.ServiceSpec{
					Type:  corev1.ServiceTypeLoadBalancer,
					Ports: []corev1.ServicePort{{Port: 443}},
				},
			}
			Expect(k8sClient.Create(ctx, service)).To(Succeed())
			service.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "203.0.113.42"}}
			Expect(k8sClient.Status().Update(ctx, service)).To(Succeed())
			DeferCleanup(func() {
				fetched := &corev1.Service{}
				if err := k8sClient.Get(ctx, goneServiceKey, fetched); err == nil {
					controllerutil.RemoveFinalizer(fetched, serviceFinalizer)
					Expect(k8sClient.Update(ctx, fetched)).To(Succeed())
					Expect(k8sClient.Delete(ctx, fetched)).To(Succeed())
				}
			})

			By("creating the Secret the target Service references")
			secret := &corev1.Secret{
				Name:      goneSecretName,
				Namespace: namespace,
				Data:      map[string][]byte{secretDataKey: []byte("d3l3te-cr3d")},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())
			DeferCleanup(func() {
				_ = k8sClient.Delete(ctx, secret)
			})

			By("reconciling so the policy protects the Service and reports once")
			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: gonePolicyKey})
			Expect(err).NotTo(HaveOccurred())
			_, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: gonePolicyKey})
			Expect(err).NotTo(HaveOccurred())
			Expect(reporter.reports).To(HaveLen(1))

			By("deleting the policy; a 404 withdrawal is treated as already gone, so deletion completes")
			Expect(k8sClient.Delete(ctx, policy)).To(Succeed())
			_, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: gonePolicyKey})
			Expect(err).NotTo(HaveOccurred())

			By("confirming the finalizer was released so the object is gone")
			Expect(errors.IsNotFound(k8sClient.Get(ctx, gonePolicyKey, &securityv1alpha1.EdgePolicy{}))).To(BeTrue())
		})
	})

	Context("When the upstream URL is not configured", func() {
		const (
			policyName  = "no-upstream-policy"
			namespace   = "default"
			serviceName = "no-upstream-service"
		)

		ctx := context.Background()
		policyKey := types.NamespacedName{Name: policyName, Namespace: namespace}
		serviceKey := types.NamespacedName{Name: serviceName, Namespace: namespace}

		It("reports UpstreamReady=False and does not attempt a report", func() {
			By("using an HTTP reporter with no BaseURL, so it is not configured")
			reconciler := &EdgePolicyReconciler{
				Client:   k8sClient,
				Scheme:   k8sClient.Scheme(),
				Reporter: upstream.NewHTTPReporter("", false),
			}

			By("creating an EdgePolicy with acl enabled and its LoadBalancer Service")
			policy := &securityv1alpha1.EdgePolicy{
				Name:      policyName,
				Namespace: namespace,
				Spec: securityv1alpha1.EdgePolicySpec{
					Datacenter: dcEast,
					TargetRef: securityv1alpha1.TargetReference{
						APIVersion: "v1",
						Kind:       kindService,
						Name:       serviceName,
					},
					Filter: &securityv1alpha1.FilterSpec{Enabled: true},
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
			service.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "203.0.113.20"}}
			Expect(k8sClient.Status().Update(ctx, service)).To(Succeed())
			DeferCleanup(func() {
				fetched := &corev1.Service{}
				if err := k8sClient.Get(ctx, serviceKey, fetched); err == nil {
					controllerutil.RemoveFinalizer(fetched, serviceFinalizer)
					Expect(k8sClient.Update(ctx, fetched)).To(Succeed())
					Expect(k8sClient.Delete(ctx, fetched)).To(Succeed())
				}
			})

			By("reconciling: first adds the finalizer, second protects the Service")
			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: policyKey})
			Expect(err).NotTo(HaveOccurred())
			_, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: policyKey})
			Expect(err).NotTo(HaveOccurred())

			By("confirming the status surfaces the missing upstream configuration")
			reconciled := &securityv1alpha1.EdgePolicy{}
			Expect(k8sClient.Get(ctx, policyKey, reconciled)).To(Succeed())
			cond := meta.FindStatusCondition(reconciled.Status.Conditions, conditionTypeUpstreamReady)
			Expect(cond).NotTo(BeNil())
			Expect(cond.Status).To(Equal(metav1.ConditionFalse))
			Expect(cond.Reason).To(Equal(reasonUpstreamNotConfigured))

			By("confirming discovery still recorded the observed ports and IPs")
			Expect(reconciled.Status.ObservedIPs).To(ConsistOf("203.0.113.20"))
			Expect(reconciled.Status.ObservedPorts).To(HaveLen(1))
		})
	})

	Context("When an upstream report fails transiently", func() {
		const (
			policyName  = "report-fail-policy"
			namespace   = "default"
			serviceName = "report-fail-service"
		)

		ctx := context.Background()
		policyKey := types.NamespacedName{Name: policyName, Namespace: namespace}
		serviceKey := types.NamespacedName{Name: serviceName, Namespace: namespace}

		It("surfaces UpstreamReportFailed, requeues, and does not record observed ports", func() {
			By("using a reporter that always fails, as a transient upstream outage would")
			reporter := &fakeReporter{err: fmt.Errorf("dial tcp: lookup ipam-api: no such host")}
			reconciler := &EdgePolicyReconciler{
				Client:   k8sClient,
				Scheme:   k8sClient.Scheme(),
				Reporter: reporter,
			}

			By("creating an EdgePolicy with acl enabled and its LoadBalancer Service")
			policy := &securityv1alpha1.EdgePolicy{
				Name:      policyName,
				Namespace: namespace,
				Spec: securityv1alpha1.EdgePolicySpec{
					Datacenter: dcEast,
					TargetRef: securityv1alpha1.TargetReference{
						APIVersion: "v1",
						Kind:       kindService,
						Name:       serviceName,
					},
					Filter: &securityv1alpha1.FilterSpec{Enabled: true},
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
					secretAnnotation: "failing-report-secret",
				},
				Spec: corev1.ServiceSpec{
					Type:  corev1.ServiceTypeLoadBalancer,
					Ports: []corev1.ServicePort{{Port: 443}},
				},
			}
			Expect(k8sClient.Create(ctx, service)).To(Succeed())
			service.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "203.0.113.30"}}
			Expect(k8sClient.Status().Update(ctx, service)).To(Succeed())
			DeferCleanup(func() {
				fetched := &corev1.Service{}
				if err := k8sClient.Get(ctx, serviceKey, fetched); err == nil {
					controllerutil.RemoveFinalizer(fetched, serviceFinalizer)
					Expect(k8sClient.Update(ctx, fetched)).To(Succeed())
					Expect(k8sClient.Delete(ctx, fetched)).To(Succeed())
				}
			})

			By("creating the Secret the target Service references")
			failSecret := &corev1.Secret{
				Name:      "failing-report-secret",
				Namespace: namespace,
				Data:      map[string][]byte{secretDataKey: []byte("fail-cr3d")},
			}
			Expect(k8sClient.Create(ctx, failSecret)).To(Succeed())
			DeferCleanup(func() {
				_ = k8sClient.Delete(ctx, failSecret)
			})

			By("reconciling: first adds the finalizer, second attempts the failing report")
			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: policyKey})
			Expect(err).NotTo(HaveOccurred())
			result, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: policyKey})

			By("confirming the failure is soft: no error returned, requeued for retry")
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(upstreamRetryInterval))

			By("confirming the failure is surfaced on the status")
			reconciled := &securityv1alpha1.EdgePolicy{}
			Expect(k8sClient.Get(ctx, policyKey, reconciled)).To(Succeed())
			cond := meta.FindStatusCondition(reconciled.Status.Conditions, conditionTypeUpstreamReady)
			Expect(cond).NotTo(BeNil())
			Expect(cond.Status).To(Equal(metav1.ConditionFalse))
			Expect(cond.Reason).To(Equal(reasonUpstreamReportFailed))

			By("confirming Ready is False while the report has not been accepted upstream")
			ready := meta.FindStatusCondition(reconciled.Status.Conditions, conditionTypeReady)
			Expect(ready).NotTo(BeNil())
			Expect(ready.Status).To(Equal(metav1.ConditionFalse))
			Expect(ready.Reason).To(Equal(reasonUpstreamReportFailed))
			Expect(reconciled.Status.ObservedPorts).To(BeEmpty())
			Expect(reconciled.Status.ObservedIPs).To(BeEmpty())
		})
	})

	Context("When the upstream rejects a report with a 4xx", func() {
		const (
			policyName  = "report-reject-policy"
			namespace   = "default"
			serviceName = "report-reject-service"
		)

		ctx := context.Background()
		policyKey := types.NamespacedName{Name: policyName, Namespace: namespace}
		serviceKey := types.NamespacedName{Name: serviceName, Namespace: namespace}

		It("surfaces UpstreamReportRejected as terminal and does not requeue on the timer", func() {
			By("using a reporter that returns a terminal 4xx rejection")
			reporter := &fakeReporter{err: fmt.Errorf("%w: status 400", upstream.ErrUpstreamRejected)}
			reconciler := &EdgePolicyReconciler{
				Client:   k8sClient,
				Scheme:   k8sClient.Scheme(),
				Reporter: reporter,
			}

			By("creating a filter-enabled EdgePolicy and its LoadBalancer Service")
			policy := &securityv1alpha1.EdgePolicy{
				Name:      policyName,
				Namespace: namespace,
				Spec: securityv1alpha1.EdgePolicySpec{
					Datacenter: dcEast,
					TargetRef: securityv1alpha1.TargetReference{
						APIVersion: "v1",
						Kind:       kindService,
						Name:       serviceName,
					},
					Filter: &securityv1alpha1.FilterSpec{Enabled: true},
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
					secretAnnotation: "reject-secret",
				},
				Spec: corev1.ServiceSpec{
					Type:  corev1.ServiceTypeLoadBalancer,
					Ports: []corev1.ServicePort{{Port: 443}},
				},
			}
			Expect(k8sClient.Create(ctx, service)).To(Succeed())
			service.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "203.0.113.40"}}
			Expect(k8sClient.Status().Update(ctx, service)).To(Succeed())
			DeferCleanup(func() {
				fetched := &corev1.Service{}
				if err := k8sClient.Get(ctx, serviceKey, fetched); err == nil {
					controllerutil.RemoveFinalizer(fetched, serviceFinalizer)
					Expect(k8sClient.Update(ctx, fetched)).To(Succeed())
					Expect(k8sClient.Delete(ctx, fetched)).To(Succeed())
				}
			})

			By("creating the Secret the target Service references")
			rejectSecret := &corev1.Secret{
				Name:      "reject-secret",
				Namespace: namespace,
				Data:      map[string][]byte{secretDataKey: []byte("reject-cr3d")},
			}
			Expect(k8sClient.Create(ctx, rejectSecret)).To(Succeed())
			DeferCleanup(func() {
				_ = k8sClient.Delete(ctx, rejectSecret)
			})

			By("reconciling: first adds the finalizer, second attempts the rejected report")
			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: policyKey})
			Expect(err).NotTo(HaveOccurred())
			result, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: policyKey})
			Expect(err).NotTo(HaveOccurred())

			By("confirming the rejection is terminal: no error, and no timed requeue")
			Expect(result.RequeueAfter).To(BeZero())

			By("confirming the rejection is surfaced on the status")
			reconciled := &securityv1alpha1.EdgePolicy{}
			Expect(k8sClient.Get(ctx, policyKey, reconciled)).To(Succeed())
			upCond := meta.FindStatusCondition(reconciled.Status.Conditions, conditionTypeUpstreamReady)
			Expect(upCond).NotTo(BeNil())
			Expect(upCond.Status).To(Equal(metav1.ConditionFalse))
			Expect(upCond.Reason).To(Equal(reasonUpstreamRejected))

			By("confirming the upstream's rejection detail is visible on the CR")
			Expect(reconciled.Status.RejectedReportMessage).To(Equal("status 400"))
			Expect(upCond.Message).To(ContainSubstring(rejectedReportMessage))
			Expect(upCond.Message).To(ContainSubstring("status 400"))

			By("confirming Ready is False for the same reason")
			ready := meta.FindStatusCondition(reconciled.Status.Conditions, conditionTypeReady)
			Expect(ready).NotTo(BeNil())
			Expect(ready.Status).To(Equal(metav1.ConditionFalse))
			Expect(ready.Reason).To(Equal(reasonUpstreamRejected))

			By("confirming observed ports were not recorded, so a change re-reports")
			Expect(reconciled.Status.ObservedPorts).To(BeEmpty())
			Expect(reconciled.Status.ObservedIPs).To(BeEmpty())
		})
	})

	Context("When a rejected report is unchanged on later reconciles", func() {
		const (
			policyName  = "report-suppress-policy"
			namespace   = "default"
			serviceName = "report-suppress-service"
		)

		ctx := context.Background()
		policyKey := types.NamespacedName{Name: policyName, Namespace: namespace}
		serviceKey := types.NamespacedName{Name: serviceName, Namespace: namespace}

		It("suppresses the identical report and re-attempts only when the content changes", func() {
			By("using a reporter that keeps returning a terminal 4xx rejection")
			reporter := &fakeReporter{err: fmt.Errorf("%w: status 400", upstream.ErrUpstreamRejected)}
			reconciler := &EdgePolicyReconciler{
				Client:   k8sClient,
				Scheme:   k8sClient.Scheme(),
				Reporter: reporter,
			}

			By("creating a filter-enabled EdgePolicy and its LoadBalancer Service")
			policy := &securityv1alpha1.EdgePolicy{
				Name:      policyName,
				Namespace: namespace,
				Spec: securityv1alpha1.EdgePolicySpec{
					Datacenter: dcEast,
					TargetRef: securityv1alpha1.TargetReference{
						APIVersion: "v1",
						Kind:       kindService,
						Name:       serviceName,
					},
					Filter: &securityv1alpha1.FilterSpec{Enabled: true},
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
					secretAnnotation: "suppress-secret",
				},
				Spec: corev1.ServiceSpec{
					Type:  corev1.ServiceTypeLoadBalancer,
					Ports: []corev1.ServicePort{{Name: "https", Port: 443}},
				},
			}
			Expect(k8sClient.Create(ctx, service)).To(Succeed())
			service.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "203.0.113.41"}}
			Expect(k8sClient.Status().Update(ctx, service)).To(Succeed())
			DeferCleanup(func() {
				fetched := &corev1.Service{}
				if err := k8sClient.Get(ctx, serviceKey, fetched); err == nil {
					controllerutil.RemoveFinalizer(fetched, serviceFinalizer)
					Expect(k8sClient.Update(ctx, fetched)).To(Succeed())
					Expect(k8sClient.Delete(ctx, fetched)).To(Succeed())
				}
			})

			By("creating the Secret the target Service references")
			suppressSecret := &corev1.Secret{
				Name:      "suppress-secret",
				Namespace: namespace,
				Data:      map[string][]byte{secretDataKey: []byte("suppress-cr3d")},
			}
			Expect(k8sClient.Create(ctx, suppressSecret)).To(Succeed())
			DeferCleanup(func() {
				_ = k8sClient.Delete(ctx, suppressSecret)
			})

			By("reconciling until the report is attempted and rejected")
			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: policyKey})
			Expect(err).NotTo(HaveOccurred())
			_, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: policyKey})
			Expect(err).NotTo(HaveOccurred())
			attemptsAfterReject := reporter.reportAttempts
			Expect(attemptsAfterReject).To(BeNumerically(">=", 1))

			By("confirming the rejected report's key was remembered on the status")
			rejected := &securityv1alpha1.EdgePolicy{}
			Expect(k8sClient.Get(ctx, policyKey, rejected)).To(Succeed())
			Expect(rejected.Status.RejectedReportKey).NotTo(BeEmpty())

			By("reconciling again with unchanged content: the report is suppressed, not re-sent")
			result, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: policyKey})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(BeZero())
			Expect(reporter.reportAttempts).To(Equal(attemptsAfterReject))

			By("reconciling once more: still suppressed and steady (no status churn to re-enqueue)")
			_, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: policyKey})
			Expect(err).NotTo(HaveOccurred())
			Expect(reporter.reportAttempts).To(Equal(attemptsAfterReject))

			By("confirming the terminal Rejected status is still in place")
			stillRejected := &securityv1alpha1.EdgePolicy{}
			Expect(k8sClient.Get(ctx, policyKey, stillRejected)).To(Succeed())
			upCond := meta.FindStatusCondition(stillRejected.Status.Conditions, conditionTypeUpstreamReady)
			Expect(upCond).NotTo(BeNil())
			Expect(upCond.Reason).To(Equal(reasonUpstreamRejected))

			By("changing the Service content: a different report is attempted afresh")
			fetchedSvc := &corev1.Service{}
			Expect(k8sClient.Get(ctx, serviceKey, fetchedSvc)).To(Succeed())
			fetchedSvc.Spec.Ports = append(fetchedSvc.Spec.Ports, corev1.ServicePort{Name: "http", Port: 8080})
			Expect(k8sClient.Update(ctx, fetchedSvc)).To(Succeed())

			_, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: policyKey})
			Expect(err).NotTo(HaveOccurred())
			Expect(reporter.reportAttempts).To(BeNumerically(">", attemptsAfterReject))
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

		It("withholds the report and flags the missing secret on the status", func() {
			reporter := &fakeReporter{}
			reconciler := &EdgePolicyReconciler{
				Client:   k8sClient,
				Scheme:   k8sClient.Scheme(),
				Reporter: reporter,
			}

			By("creating an acl-enabled EdgePolicy and a Service referencing an absent Secret")
			policy := &securityv1alpha1.EdgePolicy{
				Name:      policyName,
				Namespace: namespace,
				Spec: securityv1alpha1.EdgePolicySpec{
					Datacenter: dcEast,
					TargetRef: securityv1alpha1.TargetReference{
						APIVersion: "v1",
						Kind:       kindService,
						Name:       serviceName,
					},
					Filter: &securityv1alpha1.FilterSpec{Enabled: true},
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

			By("confirming no report was sent because the credential is missing")
			Expect(reporter.reports).To(BeEmpty())

			By("confirming the missing Secret is surfaced on the status")
			reconciled := &securityv1alpha1.EdgePolicy{}
			Expect(k8sClient.Get(ctx, policyKey, reconciled)).To(Succeed())
			cond := meta.FindStatusCondition(reconciled.Status.Conditions, conditionTypeIpamSecretReady)
			Expect(cond).NotTo(BeNil())
			Expect(cond.Status).To(Equal(metav1.ConditionFalse))
			Expect(cond.Reason).To(Equal(reasonSecretNotFound))

			By("confirming the report was withheld as incomplete on the status")
			upCond := meta.FindStatusCondition(reconciled.Status.Conditions, conditionTypeUpstreamReady)
			Expect(upCond).NotTo(BeNil())
			Expect(upCond.Status).To(Equal(metav1.ConditionFalse))
			Expect(upCond.Reason).To(Equal(reasonUpstreamIncomplete))

			By("confirming Ready is False while the report is withheld as incomplete")
			ready := meta.FindStatusCondition(reconciled.Status.Conditions, conditionTypeReady)
			Expect(ready).NotTo(BeNil())
			Expect(ready.Status).To(Equal(metav1.ConditionFalse))
			Expect(ready.Reason).To(Equal(reasonUpstreamIncomplete))
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

		It("withholds the report and flags the invalid secret on the status", func() {
			reporter := &fakeReporter{}
			reconciler := &EdgePolicyReconciler{
				Client:   k8sClient,
				Scheme:   k8sClient.Scheme(),
				Reporter: reporter,
			}

			By("creating an acl-enabled EdgePolicy and a Service referencing the Secret")
			policy := &securityv1alpha1.EdgePolicy{
				Name:      policyName,
				Namespace: namespace,
				Spec: securityv1alpha1.EdgePolicySpec{
					Datacenter: dcEast,
					TargetRef: securityv1alpha1.TargetReference{
						APIVersion: "v1",
						Kind:       kindService,
						Name:       serviceName,
					},
					Filter: &securityv1alpha1.FilterSpec{Enabled: true},
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

			By("confirming no report was sent because the credential is missing")
			Expect(reporter.reports).To(BeEmpty())

			By("confirming the invalid Secret is surfaced on the status")
			reconciled := &securityv1alpha1.EdgePolicy{}
			Expect(k8sClient.Get(ctx, policyKey, reconciled)).To(Succeed())
			cond := meta.FindStatusCondition(reconciled.Status.Conditions, conditionTypeIpamSecretReady)
			Expect(cond).NotTo(BeNil())
			Expect(cond.Status).To(Equal(metav1.ConditionFalse))
			Expect(cond.Reason).To(Equal(reasonSecretInvalid))

			By("confirming the report was withheld as incomplete on the status")
			upCond := meta.FindStatusCondition(reconciled.Status.Conditions, conditionTypeUpstreamReady)
			Expect(upCond).NotTo(BeNil())
			Expect(upCond.Status).To(Equal(metav1.ConditionFalse))
			Expect(upCond.Reason).To(Equal(reasonUpstreamIncomplete))

			By("confirming Ready is False while the report is withheld as incomplete")
			ready := meta.FindStatusCondition(reconciled.Status.Conditions, conditionTypeReady)
			Expect(ready).NotTo(BeNil())
			Expect(ready.Status).To(Equal(metav1.ConditionFalse))
			Expect(ready.Reason).To(Equal(reasonUpstreamIncomplete))
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
			policy := &securityv1alpha1.EdgePolicy{
				Name:      policyName,
				Namespace: namespace,
				Spec: securityv1alpha1.EdgePolicySpec{
					Datacenter: dcEast,
					TargetRef: securityv1alpha1.TargetReference{
						APIVersion: "v1",
						Kind:       kindService,
						Name:       serviceName,
					},
					Filter: &securityv1alpha1.FilterSpec{Enabled: true},
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

			By("confirming no report was sent and it is flagged incomplete on the status")
			Expect(reporter.reports).To(BeEmpty())
			upCond := meta.FindStatusCondition(reconciled.Status.Conditions, conditionTypeUpstreamReady)
			Expect(upCond).NotTo(BeNil())
			Expect(upCond.Status).To(Equal(metav1.ConditionFalse))
			Expect(upCond.Reason).To(Equal(reasonUpstreamIncomplete))

			By("confirming Ready is False while the report is withheld as incomplete")
			ready := meta.FindStatusCondition(reconciled.Status.Conditions, conditionTypeReady)
			Expect(ready).NotTo(BeNil())
			Expect(ready.Status).To(Equal(metav1.ConditionFalse))
			Expect(ready.Reason).To(Equal(reasonUpstreamIncomplete))
		})
	})

	Context("When the Service has a secret but no load balancer address", func() {
		const (
			policyName  = "no-ip-policy"
			namespace   = "default"
			serviceName = "no-ip-service"
		)

		ctx := context.Background()
		policyKey := types.NamespacedName{Name: policyName, Namespace: namespace}
		serviceKey := types.NamespacedName{Name: serviceName, Namespace: namespace}

		It("withholds the report and flags it incomplete until an address is assigned", func() {
			reporter := &fakeReporter{}
			reconciler := &EdgePolicyReconciler{
				Client:   k8sClient,
				Scheme:   k8sClient.Scheme(),
				Reporter: reporter,
			}

			By("creating a filter-enabled EdgePolicy and a Service with a resolvable secret")
			policy := &securityv1alpha1.EdgePolicy{
				Name:      policyName,
				Namespace: namespace,
				Spec: securityv1alpha1.EdgePolicySpec{
					Datacenter: dcEast,
					TargetRef: securityv1alpha1.TargetReference{
						APIVersion: "v1",
						Kind:       kindService,
						Name:       serviceName,
					},
					Filter: &securityv1alpha1.FilterSpec{Enabled: true},
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
					secretAnnotation: "no-ip-secret",
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

			By("creating the Secret the target Service references")
			noIPSecret := &corev1.Secret{
				Name:      "no-ip-secret",
				Namespace: namespace,
				Data:      map[string][]byte{secretDataKey: []byte("no-ip-cr3d")},
			}
			Expect(k8sClient.Create(ctx, noIPSecret)).To(Succeed())
			DeferCleanup(func() {
				_ = k8sClient.Delete(ctx, noIPSecret)
			})

			By("reconciling while the Service has no load balancer ingress yet")
			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: policyKey})
			Expect(err).NotTo(HaveOccurred())
			result, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: policyKey})
			Expect(err).NotTo(HaveOccurred())

			By("confirming no report was sent, the status is incomplete, and a retry is queued")
			Expect(reporter.reports).To(BeEmpty())
			Expect(result.RequeueAfter).To(Equal(upstreamRetryInterval))
			reconciled := &securityv1alpha1.EdgePolicy{}
			Expect(k8sClient.Get(ctx, policyKey, reconciled)).To(Succeed())
			upCond := meta.FindStatusCondition(reconciled.Status.Conditions, conditionTypeUpstreamReady)
			Expect(upCond).NotTo(BeNil())
			Expect(upCond.Status).To(Equal(metav1.ConditionFalse))
			Expect(upCond.Reason).To(Equal(reasonUpstreamIncomplete))

			By("confirming Ready is False while the report is withheld as incomplete")
			ready := meta.FindStatusCondition(reconciled.Status.Conditions, conditionTypeReady)
			Expect(ready).NotTo(BeNil())
			Expect(ready.Status).To(Equal(metav1.ConditionFalse))
			Expect(ready.Reason).To(Equal(reasonUpstreamIncomplete))

			By("confirming observed ports were not recorded, so the retry re-reports")
			Expect(reconciled.Status.ObservedPorts).To(BeEmpty())

			By("assigning a load balancer address and reconciling again")
			current := &corev1.Service{}
			Expect(k8sClient.Get(ctx, serviceKey, current)).To(Succeed())
			current.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "203.0.113.50"}}
			Expect(k8sClient.Status().Update(ctx, current)).To(Succeed())
			_, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: policyKey})
			Expect(err).NotTo(HaveOccurred())

			By("confirming the now-complete report was sent with the credential and address")
			Expect(reporter.reports).To(HaveLen(1))
			Expect(reporter.reports[0].IpamSecret).To(Equal("no-ip-cr3d"))
			Expect(reporter.reports[0].IPv4Addresses).To(ConsistOf("203.0.113.50"))

			By("confirming Ready recovers to True once the report is accepted upstream")
			recovered := &securityv1alpha1.EdgePolicy{}
			Expect(k8sClient.Get(ctx, policyKey, recovered)).To(Succeed())
			readyNow := meta.FindStatusCondition(recovered.Status.Conditions, conditionTypeReady)
			Expect(readyNow).NotTo(BeNil())
			Expect(readyNow.Status).To(Equal(metav1.ConditionTrue))
			Expect(readyNow.Reason).To(Equal(reasonServiceProtected))
		})
	})

	Context("When a status write hits an optimistic-concurrency conflict", func() {
		It("requeues quietly so an in-flight retry is not dropped", func() {
			// A conflict on the status subresource must not silently drop the request:
			// status-only writes are suppressed by the reconcile predicate, so without a
			// requeue nothing would re-enqueue the policy and an upstream status-queue
			// poll retry would stall. See conflictRequeueInterval.
			policy := &securityv1alpha1.EdgePolicy{
				Name:       "conflict-policy",
				Namespace:  "default",
				Finalizers: []string{edgePolicyFinalizer},
				Spec: securityv1alpha1.EdgePolicySpec{
					TargetRef: securityv1alpha1.TargetReference{
						APIVersion: "v1",
						Kind:       kindService,
						Name:       "missing-service",
					},
				},
			}

			// Fail every status update with a conflict, driving the reconcile's conflict
			// softening path. The target Service is absent, so the reconcile reaches the
			// ServiceNotFound status write with the least fixture setup.
			conflictClient := fake.NewClientBuilder().
				WithScheme(k8sClient.Scheme()).
				WithObjects(policy).
				WithStatusSubresource(policy).
				WithInterceptorFuncs(interceptor.Funcs{
					SubResourceUpdate: func(_ context.Context, _ client.Client, _ string,
						_ client.Object, _ ...client.SubResourceUpdateOption) error {
						return errors.NewConflict(
							schema.GroupResource{Group: "security.vitistack.io", Resource: "edgepolicies"},
							policy.Name, fmt.Errorf("the object has been modified"))
					},
				}).
				Build()

			reconciler := &EdgePolicyReconciler{
				Client: conflictClient,
				Scheme: conflictClient.Scheme(),
			}

			result, err := reconciler.Reconcile(ctx, reconcile.Request{
				Name: policy.Name, Namespace: policy.Namespace,
			})

			By("softening the conflict to a nil error")
			Expect(err).NotTo(HaveOccurred())

			By("requeuing so the policy is reconciled again rather than stalling")
			Expect(result.RequeueAfter).To(Equal(conflictRequeueInterval))
		})
	})

	Context("When the upstream queues the report for asynchronous processing", func() {
		ctx := context.Background()

		It("records the pending job, polls it without blocking, and settles once it completes", func() {
			reporter := &fakeReporter{
				pending:    upstream.ReportStatus{StatusURL: queuedJobStatusURL, JobID: "j1"},
				pollStatus: upstream.ReportStatus{StatusURL: queuedJobStatusURL}, // still pending
			}
			reconciler := &EdgePolicyReconciler{
				Client:               k8sClient,
				Scheme:               k8sClient.Scheme(),
				Reporter:             reporter,
				UpstreamPollInterval: 40 * time.Millisecond,
			}
			policyKey := provisionProtectedPolicy(ctx, "queued-policy")

			By("reconciling: first adds the finalizer, second submits and queues the report")
			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: policyKey})
			Expect(err).NotTo(HaveOccurred())
			result, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: policyKey})
			Expect(err).NotTo(HaveOccurred())

			By("requeuing after the poll interval rather than blocking on the queued job")
			Expect(result.RequeueAfter).To(Equal(40 * time.Millisecond))
			Expect(reporter.reportAttempts).To(Equal(1))
			Expect(reporter.polls).To(Equal(0))

			By("recording the in-flight job on status.PendingReport without advancing ObservedPorts")
			queued := &securityv1alpha1.EdgePolicy{}
			Expect(k8sClient.Get(ctx, policyKey, queued)).To(Succeed())
			Expect(queued.Status.PendingReport).NotTo(BeNil())
			Expect(queued.Status.PendingReport.StatusURL).To(Equal(queuedJobStatusURL))
			Expect(queued.Status.PendingReport.JobID).To(Equal("j1"))
			Expect(queued.Status.PendingReport.Key).NotTo(BeEmpty())
			Expect(queued.Status.PendingReport.Ports).To(HaveLen(1))
			Expect(queued.Status.ObservedPorts).To(BeEmpty())
			upstreamCond := meta.FindStatusCondition(queued.Status.Conditions, conditionTypeUpstreamReady)
			Expect(upstreamCond).NotTo(BeNil())
			Expect(upstreamCond.Reason).To(Equal(reasonUpstreamPending))

			By("polling again while the job is still pending: no resubmit, requeue again")
			result, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: policyKey})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(40 * time.Millisecond))
			Expect(reporter.reportAttempts).To(Equal(1)) // did not resubmit
			Expect(reporter.polls).To(Equal(1))

			By("completing the job upstream and reconciling once more")
			reporter.pollStatus = upstream.ReportStatus{Done: true}
			result, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: policyKey})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(BeZero())

			By("clearing the pending job, recording ObservedPorts, and marking Ready")
			settled := &securityv1alpha1.EdgePolicy{}
			Expect(k8sClient.Get(ctx, policyKey, settled)).To(Succeed())
			Expect(settled.Status.PendingReport).To(BeNil())
			Expect(settled.Status.ObservedPorts).To(HaveLen(1))
			Expect(settled.Status.ObservedPorts[0].Port).To(Equal(int32(443)))
			Expect(meta.FindStatusCondition(settled.Status.Conditions, conditionTypeUpstreamReady)).To(BeNil())
			ready := meta.FindStatusCondition(settled.Status.Conditions, conditionTypeReady)
			Expect(ready).NotTo(BeNil())
			Expect(ready.Status).To(Equal(metav1.ConditionTrue))
			Expect(ready.Reason).To(Equal(reasonServiceProtected))
			Expect(reporter.reports).To(HaveLen(1)) // exactly one submission across the whole flow
		})

		It("treats a failed queued job as a terminal rejection and then suppresses the identical retry", func() {
			reporter := &fakeReporter{
				pending: upstream.ReportStatus{StatusURL: "https://upstream.test/jobs/j2", JobID: "j2"},
				pollErr: fmt.Errorf("%w: job failed: boom", upstream.ErrUpstreamRejected),
			}
			reconciler := &EdgePolicyReconciler{
				Client:               k8sClient,
				Scheme:               k8sClient.Scheme(),
				Reporter:             reporter,
				UpstreamPollInterval: 40 * time.Millisecond,
			}
			policyKey := provisionProtectedPolicy(ctx, "rejected-job-policy")

			By("reconciling to submit and queue the report")
			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: policyKey})
			Expect(err).NotTo(HaveOccurred())
			_, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: policyKey})
			Expect(err).NotTo(HaveOccurred())

			By("polling the job, which fails: terminal rejection, no timed requeue")
			result, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: policyKey})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(BeZero())

			By("surfacing the rejection and clearing the pending job")
			rejected := &securityv1alpha1.EdgePolicy{}
			Expect(k8sClient.Get(ctx, policyKey, rejected)).To(Succeed())
			Expect(rejected.Status.PendingReport).To(BeNil())
			Expect(rejected.Status.RejectedReportKey).NotTo(BeEmpty())
			upstreamCond := meta.FindStatusCondition(rejected.Status.Conditions, conditionTypeUpstreamReady)
			Expect(upstreamCond).NotTo(BeNil())
			Expect(upstreamCond.Reason).To(Equal(reasonUpstreamRejected))

			By("suppressing the identical report on the next reconcile: no resubmit, no new poll")
			attempts, polls := reporter.reportAttempts, reporter.polls
			_, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: policyKey})
			Expect(err).NotTo(HaveOccurred())
			Expect(reporter.reportAttempts).To(Equal(attempts))
			Expect(reporter.polls).To(Equal(polls))
		})
	})

	Context("When the upstream queues the withdrawal for asynchronous processing", func() {
		ctx := context.Background()

		It("holds the finalizer and polls a queued withdrawal, releasing only once it completes", func() {
			reporter := &fakeReporter{}
			reconciler := &EdgePolicyReconciler{
				Client:               k8sClient,
				Scheme:               k8sClient.Scheme(),
				Reporter:             reporter,
				UpstreamPollInterval: 40 * time.Millisecond,
			}
			policyKey := provisionProtectedPolicy(ctx, "withdraw-policy")

			By("reconciling to a protected steady state with a recorded report")
			for range 2 {
				_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: policyKey})
				Expect(err).NotTo(HaveOccurred())
			}
			protected := &securityv1alpha1.EdgePolicy{}
			Expect(k8sClient.Get(ctx, policyKey, protected)).To(Succeed())
			Expect(protected.Status.ObservedPorts).To(HaveLen(1))

			By("queueing the withdrawal upstream and deleting the EdgePolicy")
			reporter.deletePending = upstream.ReportStatus{StatusURL: "https://upstream.test/withdrawals/w1", JobID: "w1"}
			reporter.pollStatus = upstream.ReportStatus{StatusURL: "https://upstream.test/withdrawals/w1"} // still pending
			Expect(k8sClient.Delete(ctx, protected)).To(Succeed())

			By("reconciling: submits the withdrawal, records the job, and keeps the finalizer")
			result, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: policyKey})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(40 * time.Millisecond))

			deleting := &securityv1alpha1.EdgePolicy{}
			Expect(k8sClient.Get(ctx, policyKey, deleting)).To(Succeed())
			Expect(controllerutil.ContainsFinalizer(deleting, edgePolicyFinalizer)).To(BeTrue())
			Expect(deleting.Status.PendingWithdrawal).NotTo(BeNil())
			Expect(deleting.Status.PendingWithdrawal.StatusURL).To(Equal("https://upstream.test/withdrawals/w1"))
			Expect(deleting.Status.PendingWithdrawal.JobID).To(Equal("w1"))
			Expect(reporter.deletes).To(HaveLen(1))

			By("polling again while the withdrawal is still pending: keep the finalizer, do not resubmit")
			result, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: policyKey})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(40 * time.Millisecond))
			Expect(reporter.deletes).To(HaveLen(1))
			still := &securityv1alpha1.EdgePolicy{}
			Expect(k8sClient.Get(ctx, policyKey, still)).To(Succeed())
			Expect(controllerutil.ContainsFinalizer(still, edgePolicyFinalizer)).To(BeTrue())

			By("completing the withdrawal upstream: the finalizer is released and the object is removed")
			reporter.pollStatus = upstream.ReportStatus{Done: true}
			_, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: policyKey})
			Expect(err).NotTo(HaveOccurred())
			Eventually(func() bool {
				return errors.IsNotFound(k8sClient.Get(ctx, policyKey, &securityv1alpha1.EdgePolicy{}))
			}).Should(BeTrue())
		})

		It("withdraws a report that was still queued when the policy was deleted", func() {
			// The report is accepted asynchronously and the policy is deleted before the
			// job completes, so ObservedPorts was never recorded. The withdrawal must still
			// be sent — reconstructed from the in-flight report's payload — so the queued
			// upstream job is cancelled rather than orphaned.
			reporter := &fakeReporter{
				pending: upstream.ReportStatus{StatusURL: queuedJobStatusURL, JobID: "j1"},
			}
			reconciler := &EdgePolicyReconciler{
				Client:               k8sClient,
				Scheme:               k8sClient.Scheme(),
				Reporter:             reporter,
				UpstreamPollInterval: 40 * time.Millisecond,
			}
			policyKey := provisionProtectedPolicy(ctx, "deleted-while-queued-policy")

			By("reconciling until the first report is queued but not yet accepted")
			for range 2 {
				_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: policyKey})
				Expect(err).NotTo(HaveOccurred())
			}
			queued := &securityv1alpha1.EdgePolicy{}
			Expect(k8sClient.Get(ctx, policyKey, queued)).To(Succeed())
			Expect(queued.Status.PendingReport).NotTo(BeNil())
			Expect(queued.Status.ObservedPorts).To(BeEmpty())
			pendingKey := queued.Status.PendingReport.Key

			By("deleting the EdgePolicy while its first report is still in flight")
			Expect(k8sClient.Delete(ctx, queued)).To(Succeed())

			By("reconciling the deletion: a withdrawal is sent for the still-queued report")
			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: policyKey})
			Expect(err).NotTo(HaveOccurred())
			Expect(reporter.deletes).To(HaveLen(1))

			By("confirming the withdrawal carries the queued report's payload and idempotency key")
			Expect(reporter.deletes[0].IdempotencyKey()).To(Equal(pendingKey))
			Expect(reporter.deletes[0].Filter.ObservedPorts).To(HaveLen(1))
			Expect(reporter.deletes[0].Filter.ObservedPorts[0].Port).To(Equal(int32(443)))
			Expect(reporter.deletes[0].IPv4Addresses).To(ConsistOf("203.0.113.10"))

			By("confirming the object is removed once the withdrawal completes")
			Eventually(func() bool {
				return errors.IsNotFound(k8sClient.Get(ctx, policyKey, &securityv1alpha1.EdgePolicy{}))
			}).Should(BeTrue())
		})

		It("withdraws both the accepted report and a newer in-flight one when deleted", func() {
			// An accepted report (ObservedPorts) and a distinct, still-queued newer report
			// (PendingReport) can both be live upstream at deletion. Each has a different
			// idempotency key, so both must be withdrawn — one per reconcile.
			reporter := &fakeReporter{}
			reconciler := &EdgePolicyReconciler{
				Client:               k8sClient,
				Scheme:               k8sClient.Scheme(),
				Reporter:             reporter,
				UpstreamPollInterval: 40 * time.Millisecond,
			}
			policyKey := provisionProtectedPolicy(ctx, "two-payload-policy")
			serviceKey := types.NamespacedName{Name: "two-payload-policy-svc", Namespace: "default"}

			By("reconciling until the first report is accepted synchronously")
			for range 2 {
				_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: policyKey})
				Expect(err).NotTo(HaveOccurred())
			}
			accepted := &securityv1alpha1.EdgePolicy{}
			Expect(k8sClient.Get(ctx, policyKey, accepted)).To(Succeed())
			Expect(accepted.Status.ObservedPorts).To(HaveLen(1))
			Expect(accepted.Status.PendingReport).To(BeNil())

			By("adding a port and letting the re-report queue without completing")
			reporter.pending = upstream.ReportStatus{StatusURL: queuedJobStatusURL, JobID: "j2"}
			service := &corev1.Service{}
			Expect(k8sClient.Get(ctx, serviceKey, service)).To(Succeed())
			// A Service with more than one port requires each port to be named.
			service.Spec.Ports = []corev1.ServicePort{
				{Name: "https", Port: 443},
				{Name: "alt", Port: 8080},
			}
			Expect(k8sClient.Update(ctx, service)).To(Succeed())
			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: policyKey})
			Expect(err).NotTo(HaveOccurred())

			queued := &securityv1alpha1.EdgePolicy{}
			Expect(k8sClient.Get(ctx, policyKey, queued)).To(Succeed())
			Expect(queued.Status.ObservedPorts).To(HaveLen(1))       // still the accepted single port
			Expect(queued.Status.PendingReport.Ports).To(HaveLen(2)) // the queued two-port report

			By("deleting the policy and reconciling until both payloads are withdrawn")
			Expect(k8sClient.Delete(ctx, queued)).To(Succeed())
			Eventually(func() bool {
				_, _ = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: policyKey})
				return errors.IsNotFound(k8sClient.Get(ctx, policyKey, &securityv1alpha1.EdgePolicy{}))
			}).Should(BeTrue())

			By("confirming two withdrawals were sent with distinct payloads and keys")
			Expect(reporter.deletes).To(HaveLen(2))
			Expect(reporter.deletes[0].Filter.ObservedPorts).To(HaveLen(1)) // accepted payload first
			Expect(reporter.deletes[1].Filter.ObservedPorts).To(HaveLen(2)) // then the in-flight one
			Expect(reporter.deletes[0].IdempotencyKey()).NotTo(Equal(reporter.deletes[1].IdempotencyKey()))
		})
	})
})

// provisionProtectedPolicy creates a filter-enabled EdgePolicy, its LoadBalancer target
// Service (with one ingress IP and an ipam.vitistack.io/secret annotation), the Secret
// that annotation references, and the kube-system namespace used for the cluster UID —
// wiring DeferCleanup for each. It returns the policy key so a test can reconcile and
// assert. Names are derived from the given base so parallel specs do not collide.
func provisionProtectedPolicy(ctx context.Context, name string) types.NamespacedName {
	const namespace = "default"
	serviceName := name + "-svc"
	secretName := name + "-secret"
	policyKey := types.NamespacedName{Name: name, Namespace: namespace}
	serviceKey := types.NamespacedName{Name: serviceName, Namespace: namespace}

	policy := &securityv1alpha1.EdgePolicy{
		Name:      name,
		Namespace: namespace,
		Spec: securityv1alpha1.EdgePolicySpec{
			Datacenter: dcEast,
			TargetRef: securityv1alpha1.TargetReference{
				APIVersion: "v1",
				Kind:       kindService,
				Name:       serviceName,
			},
			Filter: &securityv1alpha1.FilterSpec{Enabled: true},
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
		Name:        serviceName,
		Namespace:   namespace,
		Annotations: map[string]string{secretAnnotation: secretName},
		Spec: corev1.ServiceSpec{
			Type:  corev1.ServiceTypeLoadBalancer,
			Ports: []corev1.ServicePort{{Port: 443}},
		},
	}
	Expect(k8sClient.Create(ctx, service)).To(Succeed())
	service.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "203.0.113.10"}}
	Expect(k8sClient.Status().Update(ctx, service)).To(Succeed())
	DeferCleanup(func() {
		fetched := &corev1.Service{}
		if err := k8sClient.Get(ctx, serviceKey, fetched); err == nil {
			controllerutil.RemoveFinalizer(fetched, serviceFinalizer)
			Expect(k8sClient.Update(ctx, fetched)).To(Succeed())
			Expect(k8sClient.Delete(ctx, fetched)).To(Succeed())
		}
	})

	kubeSystem := &corev1.Namespace{Name: "kube-system"}
	if err := k8sClient.Create(ctx, kubeSystem); err != nil {
		Expect(errors.IsAlreadyExists(err)).To(BeTrue())
	}

	secret := &corev1.Secret{
		Name:      secretName,
		Namespace: namespace,
		Data:      map[string][]byte{secretDataKey: []byte("s3cr3t")},
	}
	Expect(k8sClient.Create(ctx, secret)).To(Succeed())
	DeferCleanup(func() { _ = k8sClient.Delete(ctx, secret) })

	return policyKey
}

// fakeReporter is a test Reporter that records every report and delete it receives.
type fakeReporter struct {
	reports []upstream.PortReport
	deletes []upstream.PortReport
	// reportAttempts counts every ReportPorts call, including ones that return err, so
	// tests can assert a report was (or was not) re-attempted independently of success.
	reportAttempts int
	err            error
	// deleteErr, when set, is returned by DeletePorts (taking precedence over err) so a
	// test can fail a withdrawal while letting the initial report succeed.
	deleteErr error
	// pending, when its StatusURL is set, is returned by a successful ReportPorts to
	// drive the asynchronous status-queue path; otherwise ReportPorts reports Done.
	pending upstream.ReportStatus
	// deletePending, when its StatusURL is set, is returned by a successful DeletePorts
	// to drive the asynchronous withdrawal path; otherwise DeletePorts reports Done.
	deletePending upstream.ReportStatus
	// pollStatus and pollErr are returned by PollReport, and polls counts its calls, so
	// a test can script an in-flight job polling to completion, failure, or still-pending.
	pollStatus upstream.ReportStatus
	pollErr    error
	polls      int
}

func (f *fakeReporter) ReportPorts(_ context.Context, report upstream.PortReport) (upstream.ReportStatus, error) {
	f.reportAttempts++
	if f.err != nil {
		return upstream.ReportStatus{}, f.err
	}
	f.reports = append(f.reports, report)
	if f.pending.StatusURL != "" {
		return f.pending, nil
	}
	return upstream.ReportStatus{Done: true}, nil
}

func (f *fakeReporter) PollReport(_ context.Context, _ string) (upstream.ReportStatus, error) {
	f.polls++
	if f.pollErr != nil {
		return upstream.ReportStatus{}, f.pollErr
	}
	return f.pollStatus, nil
}

func (f *fakeReporter) DeletePorts(_ context.Context, report upstream.PortReport) (upstream.ReportStatus, error) {
	if f.deleteErr != nil {
		return upstream.ReportStatus{}, f.deleteErr
	}
	if f.err != nil {
		return upstream.ReportStatus{}, f.err
	}
	f.deletes = append(f.deletes, report)
	if f.deletePending.StatusURL != "" {
		return f.deletePending, nil
	}
	return upstream.ReportStatus{Done: true}, nil
}
