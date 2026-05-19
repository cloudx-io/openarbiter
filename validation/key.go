package validation

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cloudx-io/openarbiter/enclaveapi"
)

// KeyValidationResult extends [BaseValidationResult] with the
// public-key-binding check.
type KeyValidationResult struct {
	BaseValidationResult
	PublicKeyMatch bool
}

// IsValid reports whether every base and key-binding check passed.
func (r *KeyValidationResult) IsValid() bool {
	return r.BaseValidationResult.IsValid() && r.PublicKeyMatch
}

// ValidateKeyAttestation verifies an arbiter key attestation.
// expectedPublicKey is the PEM string the caller intends to use to seal
// bid prices; the attestation must bind that same PEM. roots overrides
// the default AWS Nitro root for tests; pass nil in production.
func ValidateKeyAttestation(coseB64 enclaveapi.AttestationCOSEBase64, expectedPublicKey string, knownPCRs []PCRSet, roots *x509.CertPool) (*KeyValidationResult, error) {
	if len(knownPCRs) == 0 {
		return nil, fmt.Errorf("no PCR sets configured")
	}
	base, err := validateCommonAttestation(coseB64, knownPCRs, roots)
	if err != nil {
		return nil, err
	}
	keyDoc, err := parseKeyAttestation(coseB64)
	if err != nil {
		return nil, fmt.Errorf("parse key attestation: %w", err)
	}

	result := &KeyValidationResult{BaseValidationResult: *base}
	switch {
	case keyDoc.UserData == nil, keyDoc.UserData.PublicKey == "":
		result.ValidationDetails = append(result.ValidationDetails, "Public key missing from attestation")
	case strings.TrimSpace(expectedPublicKey) == strings.TrimSpace(keyDoc.UserData.PublicKey):
		result.PublicKeyMatch = true
		result.ValidationDetails = append(result.ValidationDetails, "Public key matches attestation")
	default:
		result.ValidationDetails = append(result.ValidationDetails,
			"Public key mismatch: provided key does not match attested key")
	}
	return result, nil
}

func parseKeyAttestation(coseB64 enclaveapi.AttestationCOSEBase64) (*enclaveapi.KeyAttestationDoc, error) {
	coseBytes, err := coseB64.Decode()
	if err != nil {
		return nil, fmt.Errorf("decode COSE bytes: %w", err)
	}
	attestationDoc, userDataBytes, err := coseBytes.ParseAttestationDoc()
	if err != nil {
		return nil, fmt.Errorf("parse attestation document: %w", err)
	}
	doc := &enclaveapi.KeyAttestationDoc{AttestationDoc: attestationDoc}
	if len(userDataBytes) > 0 {
		var ud enclaveapi.KeyAttestationUserData
		if err := json.Unmarshal(userDataBytes, &ud); err != nil {
			return nil, fmt.Errorf("parse user data: %w", err)
		}
		doc.UserData = &ud
	}
	return doc, nil
}
