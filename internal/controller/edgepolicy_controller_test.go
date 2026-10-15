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

// Service names reused across the datacenter/delete fixtures (goconst).
const (
	dcServiceName     = "dc-service"
	deleteServiceName = "delete-service"
	// dcEast is a representative datacenter value reused across fixtures (goconst).
	dcEast = "no-east-az1"
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
})

// fakeReporter is a test Reporter that records every report and delete it receives.
type fakeReporter struct {
	reports []upstream.PortReport
	deletes []upstream.PortReport
	// reportAttempts counts every ReportPorts call, including ones that return err, so
	// tests can assert a report was (or was not) re-attempted independently of success.
	reportAttempts int
	err            error
}

func (f *fakeReporter) ReportPorts(_ context.Context, report upstream.PortReport) error {
	f.reportAttempts++
	if f.err != nil {
		return f.err
	}
	f.reports = append(f.reports, report)
	return nil
}

func (f *fakeReporter) DeletePorts(_ context.Context, report upstream.PortReport) error {
	if f.err != nil {
		return f.err
	}
	f.deletes = append(f.deletes, report)
	return nil
}
