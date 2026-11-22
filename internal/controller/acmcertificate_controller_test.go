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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	certificatesv1alpha1 "github.com/UdhayKaruna/acm-cert-operator/api/v1alpha1"
)

func newTestTLSData() (map[string][]byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test.example.com"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"test.example.com"},
	}

	certificateDER, err := x509.CreateCertificate(
		rand.Reader, template, template, &privateKey.PublicKey, privateKey,
	)
	if err != nil {
		return nil, err
	}

	return map[string][]byte{
		corev1.TLSCertKey: pem.EncodeToMemory(&pem.Block{
			Type: "CERTIFICATE", Bytes: certificateDER,
		}),
		corev1.TLSPrivateKeyKey: pem.EncodeToMemory(&pem.Block{
			Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		}),
	}, nil
}

type fakeACMImporter struct {
	arn string
}

func (f fakeACMImporter) ImportCertificate(
	_ context.Context,
	_, _, _ []byte,
	_ string,
) (string, error) {
	return f.arn, nil
}

var _ = Describe("ACMCertificate Controller", func() {
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
		acmcertificate := &certificatesv1alpha1.ACMCertificate{}

		BeforeEach(func() {
			tlsData, tlsDataErr := newTestTLSData()
			Expect(tlsDataErr).NotTo(HaveOccurred())
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: resourceNamespace,
				},
				Type: corev1.SecretTypeTLS,
				// In the Secret literal:
				Data: tlsData,
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())
			By("creating the custom resource for the Kind ACMCertificate")
			err := k8sClient.Get(ctx, typeNamespacedName, acmcertificate)
			if err != nil && errors.IsNotFound(err) {
				resource := &certificatesv1alpha1.ACMCertificate{
					ObjectMeta: metav1.ObjectMeta{
						Name:      resourceName,
						Namespace: resourceNamespace,
					},
					// TODO(user): Specify other spec details if needed.
					Spec: certificatesv1alpha1.ACMCertificateSpec{
						SecretName: "test-secret",
					},
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}
		})

		AfterEach(func() {
			// TODO(user): Cleanup logic after each test, like removing the resource instance.
			resource := &certificatesv1alpha1.ACMCertificate{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			Expect(err).NotTo(HaveOccurred())

			By("Cleanup the specific resource instance ACMCertificate")
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
			By("Cleanup the test-secret")
			Expect(k8sClient.Delete(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: resourceNamespace,
				},
			})).To(Succeed())
		})
		It("should successfully reconcile the resource", func() {
			By("Reconciling the created resource")
			controllerReconciler := &ACMCertificateReconciler{
				Client:      k8sClient,
				Scheme:      k8sClient.Scheme(),
				ACMImporter: fakeACMImporter{arn: "fake-certificate-arn"},
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			updatedCertificate := &certificatesv1alpha1.ACMCertificate{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updatedCertificate)).To(Succeed())
			By("Checking the Ready condition of the updated certificate")
			readyCondition := meta.FindStatusCondition(
				updatedCertificate.Status.Conditions,
				"Ready",
			)
			Expect(readyCondition).NotTo(BeNil())
			Expect(readyCondition.Status).To(Equal(metav1.ConditionTrue))
			Expect(readyCondition.Reason).To(Equal("CertificateImported"))
			Expect(updatedCertificate.Status.CertificateARN).To(Equal("fake-certificate-arn"))
			// TODO(user): Add more specific assertions depending on your controller's reconciliation logic.
			// Example: If you expect a certain status condition after reconciliation, verify it here.
		})

		It("reports not ready when the Secret is missing", func() {
			certificate := &certificatesv1alpha1.ACMCertificate{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, certificate)).To(Succeed())

			certificate.Spec.SecretName = "missing-secret"
			Expect(k8sClient.Update(ctx, certificate)).To(Succeed())

			controllerReconciler := &ACMCertificateReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			result, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(BeNumerically(">", 0))

			updatedCertificate := &certificatesv1alpha1.ACMCertificate{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updatedCertificate)).To(Succeed())

			readyCondition := meta.FindStatusCondition(updatedCertificate.Status.Conditions, "Ready")
			Expect(readyCondition).NotTo(BeNil())
			Expect(readyCondition.Status).To(Equal(metav1.ConditionFalse))
			Expect(readyCondition.Reason).To(Equal("SecretNotFound"))
		})

		It("reports not ready when TLS data is incomplete", func() {
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "incomplete-secret",
					Namespace: resourceNamespace,
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					corev1.TLSCertKey: []byte("test certificate"),
				},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			certificate := &certificatesv1alpha1.ACMCertificate{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, certificate)).To(Succeed())
			certificate.Spec.SecretName = "incomplete-secret"
			Expect(k8sClient.Update(ctx, certificate)).To(Succeed())

			controllerReconciler := &ACMCertificateReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}
			result, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(BeNumerically(">", 0))

			updatedCertificate := &certificatesv1alpha1.ACMCertificate{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updatedCertificate)).To(Succeed())

			readyCondition := meta.FindStatusCondition(updatedCertificate.Status.Conditions, "Ready")
			Expect(readyCondition).NotTo(BeNil())
			Expect(readyCondition.Status).To(Equal(metav1.ConditionFalse))
			Expect(readyCondition.Reason).To(Equal("InvalidTLSSecret"))
			Expect(k8sClient.Delete(ctx, secret)).To(Succeed())
		})

		It("reports not ready when the certificate is malformed PEM", func() {
			secret := &corev1.Secret{}
			secretKey := types.NamespacedName{
				Name:      "test-secret",
				Namespace: resourceNamespace,
			}
			Expect(k8sClient.Get(ctx, secretKey, secret)).To(Succeed())
			secret.Data[corev1.TLSCertKey] = []byte("not PEM")
			Expect(k8sClient.Update(ctx, secret)).To(Succeed())

			controllerReconciler := &ACMCertificateReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}
			result, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(BeNumerically(">", 0))

			updatedCertificate := &certificatesv1alpha1.ACMCertificate{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updatedCertificate)).To(Succeed())
			readyCondition := meta.FindStatusCondition(updatedCertificate.Status.Conditions, "Ready")
			Expect(readyCondition).NotTo(BeNil())
			Expect(readyCondition.Status).To(Equal(metav1.ConditionFalse))
			Expect(readyCondition.Reason).To(Equal("InvalidTLSSecret"))
		})

		It("reports not ready when the private key does not match the certificate", func() {
			secret := &corev1.Secret{}
			secretKey := types.NamespacedName{
				Name:      "test-secret",
				Namespace: resourceNamespace,
			}
			Expect(k8sClient.Get(ctx, secretKey, secret)).To(Succeed())

			otherTLSData, err := newTestTLSData()
			Expect(err).NotTo(HaveOccurred())
			secret.Data[corev1.TLSPrivateKeyKey] = otherTLSData[corev1.TLSPrivateKeyKey]
			Expect(k8sClient.Update(ctx, secret)).To(Succeed())

			controllerReconciler := &ACMCertificateReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}
			result, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(BeNumerically(">", 0))

			updatedCertificate := &certificatesv1alpha1.ACMCertificate{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updatedCertificate)).To(Succeed())
			readyCondition := meta.FindStatusCondition(updatedCertificate.Status.Conditions, "Ready")
			Expect(readyCondition).NotTo(BeNil())
			Expect(readyCondition.Status).To(Equal(metav1.ConditionFalse))
			Expect(readyCondition.Reason).To(Equal("InvalidTLSSecret"))
		})
	})
})
