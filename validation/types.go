// Package validation verifies COSE attestations emitted by the arbiter
// enclave. It reuses the generic primitives in
// cloudx-io/openauction/validation (PCR matching, certificate-chain
// verification, COSE signature verification) and adds the
// arbitration-specific user-data checks.
package validation

import (
	oavalidation "github.com/cloudx-io/openauction/validation"
)

// PCRSet, PCRConfig: re-exported from openauction so callers see one
// type across both projects.
type (
	// PCRSet is a known-good set of PCR measurements.
	PCRSet = oavalidation.PCRSet
	// PCRConfig is the on-disk JSON schema for a collection of PCR sets.
	PCRConfig = oavalidation.PCRConfig
)

// BaseValidationResult is the common envelope for any attestation
// validation: PCRs, certificate chain, and COSE signature.
type BaseValidationResult struct {
	PCRsValid         bool
	CertificateValid  bool
	SignatureValid    bool
	ValidationDetails []string
}

// IsValid reports whether the base envelope passed all three
// platform-level checks.
func (r *BaseValidationResult) IsValid() bool {
	return r.PCRsValid && r.CertificateValid && r.SignatureValid
}

// ArbitrationValidationResult is the per-arbitration extension of
// [BaseValidationResult] that adds the user-data checks.
type ArbitrationValidationResult struct {
	BaseValidationResult
	// BidHashValid is true when the caller's bid is included in the
	// attested participating-bid hashes (or trivially true on the
	// excluded path).
	BidHashValid bool
	// BidExclusionValid is true when the caller's bid is recorded in
	// the attestation's excluded list under the expected reason (or
	// trivially true on the included path).
	BidExclusionValid bool
	RequestHashValid  bool
	WinnerValid       bool
}

// IsValid reports whether every base and user-data check passed.
func (r *ArbitrationValidationResult) IsValid() bool {
	return r.BaseValidationResult.IsValid() &&
		r.BidHashValid &&
		r.BidExclusionValid &&
		r.RequestHashValid &&
		r.WinnerValid
}
