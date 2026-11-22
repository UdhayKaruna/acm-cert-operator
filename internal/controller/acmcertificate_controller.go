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
	"crypto/tls"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	corev1 "k8s.io/api/core/v1"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	certificatesv1alpha1 "github.com/UdhayKaruna/acm-cert-operator/api/v1alpha1"
)

// ACMCertificateReconciler reconciles a ACMCertificate object
type ACMImporter interface {
	ImportCertificate(
		ctx context.Context,
		certificatePEM []byte,
		privateKeyPEM []byte,
		certificateChainPEM []byte,
		existingARN string,
	) (string, error)
}

type ACMCertificateReconciler struct {
	client.Client
	Scheme      *runtime.Scheme
	ACMImporter ACMImporter
}

// +kubebuilder:rbac:groups=certificates.ioof.com.au,resources=acmcertificates,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=certificates.ioof.com.au,resources=acmcertificates/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=certificates.ioof.com.au,resources=acmcertificates/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the ACMCertificate object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.25.0/pkg/reconcile

func (r *ACMCertificateReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = logf.FromContext(ctx)

	// TODO(user): your logic here
	certificate := &certificatesv1alpha1.ACMCertificate{}
	if err := r.Get(ctx, req.NamespacedName, certificate); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	secret := &corev1.Secret{}
	secretKey := client.ObjectKey{
		Namespace: certificate.Namespace,
		Name:      certificate.Spec.SecretName,
	}
	if err := r.Get(ctx, secretKey, secret); err != nil {
		if apierrors.IsNotFound(err) {
			if statusErr := r.setReadyCondition(
				ctx,
				certificate,
				metav1.ConditionFalse,
				"SecretNotFound",
				"The referenced TLS Secret was not found",
			); statusErr != nil {
				return ctrl.Result{}, statusErr
			}
			return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
		}
		return ctrl.Result{}, err
	}

	if len(secret.Data[corev1.TLSCertKey]) == 0 ||
		len(secret.Data[corev1.TLSPrivateKeyKey]) == 0 {
		if err := r.setReadyCondition(
			ctx,
			certificate,
			metav1.ConditionFalse,
			"InvalidTLSSecret",
			"The referenced Secret must contain non-empty tls.crt and tls.key",
		); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	if _, err := tls.X509KeyPair(
		secret.Data[corev1.TLSCertKey],
		secret.Data[corev1.TLSPrivateKeyKey],
	); err != nil {
		if err := r.setReadyCondition(
			ctx,
			certificate,
			metav1.ConditionFalse,
			"InvalidTLSSecret",
			"tls.crt and tls.key must be valid PEM data and the key must match the certificate",
		); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	if r.ACMImporter == nil {
		return ctrl.Result{}, fmt.Errorf("ACM importer is not configured")
	}

	arn, err := r.ACMImporter.ImportCertificate(
		ctx,
		secret.Data[corev1.TLSCertKey],
		secret.Data[corev1.TLSPrivateKeyKey],
		secret.Data["ca.crt"],
		certificate.Status.CertificateARN,
	)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("import certificate into ACM: %w", err)
	}
	certificate.Status.CertificateARN = arn

	if err := r.setReadyCondition(
		ctx,
		certificate,
		metav1.ConditionTrue,
		"CertificateImported",
		"The referenced Secret contains tls.crt and tls.key",
	); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ACMCertificateReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&certificatesv1alpha1.ACMCertificate{}).
		Named("acmcertificate").
		Complete(r)
}

func (r *ACMCertificateReconciler) setReadyCondition(
	ctx context.Context,
	certificate *certificatesv1alpha1.ACMCertificate,
	status metav1.ConditionStatus,
	reason string,
	message string,
) error {
	changed := meta.SetStatusCondition(&certificate.Status.Conditions, metav1.Condition{
		Type:               "Ready",
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: certificate.Generation,
	})
	if !changed {
		return nil
	}
	return r.Status().Update(ctx, certificate)
}
