package validation

import (
	"crypto/x509"
	"encoding/json"
	"fmt"

	oavalidation "github.com/cloudx-io/openauction/validation"

	"github.com/cloudx-io/openarbiter/enclaveapi"
)

// validateCommonAttestation performs the platform-level checks shared by
// every arbitration validation: PCR matching, certificate-chain
// verification, and COSE signature verification.
//
// knownPCRs lists the PCR sets the validator trusts; pass the result of
// [LoadPCRsFromFile] or the literal slice for a fixed deployment.
//
// roots is the certificate root pool used to verify the attestation
// signing chain; nil falls back to the AWS Nitro root.
func validateCommonAttestation(coseBase64 enclaveapi.AttestationCOSEBase64, knownPCRs []PCRSet, roots *x509.CertPool) (*BaseValidationResult, error) {
	coseBytes, err := coseBase64.Decode()
	if err != nil {
		return nil, fmt.Errorf("decode COSE bytes: %w", err)
	}
	attestationDoc, _, err := coseBytes.ParseAttestationDoc()
	if err != nil {
		return nil, fmt.Errorf("parse attestation document: %w", err)
	}

	result := &BaseValidationResult{ValidationDetails: []string{}}

	// PCRs.
	pcrMatch, matchedSet := oavalidation.ValidatePCRs(attestationDoc.PCRs, knownPCRs)
	result.PCRsValid = pcrMatch
	if !pcrMatch {
		result.ValidationDetails = append(result.ValidationDetails,
			fmt.Sprintf("PCR0: %s (no match)", attestationDoc.PCRs.ImageFileHash),
			fmt.Sprintf("PCR1: %s (no match)", attestationDoc.PCRs.KernelHash),
			fmt.Sprintf("PCR2: %s (no match)", attestationDoc.PCRs.ApplicationHash),
		)
	} else {
		result.ValidationDetails = append(result.ValidationDetails, "PCR measurements valid")
		if matchedSet >= 0 && matchedSet < len(knownPCRs) {
			result.ValidationDetails = append(result.ValidationDetails,
				fmt.Sprintf("Matched PCR set: #%d (commit: %s)", matchedSet, knownPCRs[matchedSet].CommitSHA))
		}
	}

	// Certificate chain.
	switch {
	case attestationDoc.Certificate == "":
		result.CertificateValid = false
		result.ValidationDetails = append(result.ValidationDetails, "Missing certificate")
	case len(attestationDoc.CABundle) == 0:
		result.CertificateValid = false
		result.ValidationDetails = append(result.ValidationDetails, "Missing CA bundle")
	default:
		if err := validateCertificateChain(attestationDoc.Certificate, attestationDoc.CABundle, attestationDoc.Timestamp, roots); err != nil {
			result.CertificateValid = false
			result.ValidationDetails = append(result.ValidationDetails,
				fmt.Sprintf("Certificate chain validation failed: %v", err))
		} else {
			result.CertificateValid = true
			result.ValidationDetails = append(result.ValidationDetails, "Certificate chain verified")
		}
	}

	// COSE signature.
	if err := oavalidation.VerifyCOSESignature(coseBase64, attestationDoc.Certificate); err != nil {
		result.SignatureValid = false
		result.ValidationDetails = append(result.ValidationDetails,
			fmt.Sprintf("COSE signature verification failed: %v", err))
	} else {
		result.SignatureValid = true
		result.ValidationDetails = append(result.ValidationDetails, "COSE signature verified")
	}

	return result, nil
}

// parseArbitrationAttestation extracts an arbiter-specific user-data
// document from a COSE attestation envelope.
func parseArbitrationAttestation(coseBase64 enclaveapi.AttestationCOSEBase64) (*enclaveapi.ArbitrationAttestationDoc, error) {
	coseBytes, err := coseBase64.Decode()
	if err != nil {
		return nil, fmt.Errorf("decode COSE bytes: %w", err)
	}
	attestationDoc, userDataBytes, err := coseBytes.ParseAttestationDoc()
	if err != nil {
		return nil, fmt.Errorf("parse attestation document: %w", err)
	}
	doc := &enclaveapi.ArbitrationAttestationDoc{AttestationDoc: attestationDoc}
	if len(userDataBytes) > 0 {
		var ud enclaveapi.ArbitrationAttestationUserData
		if err := json.Unmarshal(userDataBytes, &ud); err != nil {
			return nil, fmt.Errorf("parse user data: %w", err)
		}
		doc.UserData = &ud
	}
	return doc, nil
}
