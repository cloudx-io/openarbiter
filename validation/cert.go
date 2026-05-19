package validation

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"time"

	oavalidation "github.com/cloudx-io/openauction/validation"
)

// validateCertificateChain verifies cert against the supplied root pool.
// When roots is nil, it falls back to
// [oavalidation.ValidateCertificateChain], which pins the AWS Nitro
// root — the production path. The roots override exists for tests that
// mint their own attestation chain.
func validateCertificateChain(certB64 string, caBundleB64 []string, attestationTime time.Time, roots *x509.CertPool) error {
	if roots == nil {
		return oavalidation.ValidateCertificateChain(certB64, caBundleB64, attestationTime)
	}
	certDER, err := base64.StdEncoding.DecodeString(certB64)
	if err != nil {
		return fmt.Errorf("decode certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}
	intermediates := x509.NewCertPool()
	for _, caB64 := range caBundleB64 {
		caDER, err := base64.StdEncoding.DecodeString(caB64)
		if err != nil {
			return fmt.Errorf("decode CA certificate: %w", err)
		}
		caCert, err := x509.ParseCertificate(caDER)
		if err != nil {
			return fmt.Errorf("parse CA certificate: %w", err)
		}
		intermediates.AddCert(caCert)
	}
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime:   attestationTime,
	}
	if _, err := cert.Verify(opts); err != nil {
		return fmt.Errorf("certificate chain validation failed: %w", err)
	}
	return nil
}
