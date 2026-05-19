package validation

import (
	"crypto/x509"
	"fmt"

	"github.com/cloudx-io/openarbiter/core"
	"github.com/cloudx-io/openarbiter/enclaveapi"
)

// BidExpectation is the caller's expectation about how its bid
// appears in the attestation.
type BidExpectation int

const (
	// ExpectIncluded means the caller expects its bid hash to be among
	// the attested participating bids.
	ExpectIncluded BidExpectation = iota
	// ExpectExcluded means the caller expects its bid to appear in the
	// attestation's excluded list under [ExpectedExclusionReason].
	ExpectExcluded
)

// ArbitrationValidationInput contains everything a caller needs to
// verify that its bid was faithfully arbitrated.
type ArbitrationValidationInput struct {
	// AttestationCOSEGzip is the gzipped attestation envelope shipped
	// alongside the arbitration response.
	AttestationCOSEGzip enclaveapi.AttestationCOSEGzip
	// KnownPCRs lists the PCR measurement sets the validator trusts.
	KnownPCRs []PCRSet
	// RequestID is the arbitration request envelope's ID.
	RequestID string
	// BidID is the caller's bid; the validator checks the attestation
	// either lists its hash among the participants (Expectation =
	// ExpectIncluded) or records it as excluded under the expected
	// reason (Expectation = ExpectExcluded).
	BidID string
	// BidRevenue is the per-impression revenue the caller believes the
	// arbiter saw for its bid (post-decryption). Ignored when
	// Expectation is [ExpectExcluded].
	BidRevenue core.MicroDollars
	// Expectation selects between the included and excluded validation
	// paths. Defaults to [ExpectIncluded].
	Expectation BidExpectation
	// ExpectedExclusionReason is the reason string the caller expects
	// to find on its [core.ExcludedBid] entry when Expectation is
	// [ExpectExcluded] (e.g. [core.ExclusionReasonMalformedBidID]).
	ExpectedExclusionReason string
	// IsWinner is the caller's expectation about the outcome. Only
	// consulted when Expectation is [ExpectIncluded].
	IsWinner bool
	// Roots, if non-nil, overrides the default AWS Nitro root certificate
	// pool used to verify the attestation signing chain. Production
	// callers leave it nil; tests use it to mint synthetic chains.
	Roots *x509.CertPool
}

// ValidateArbitrationAttestation runs the full validation pipeline:
// platform-level checks (PCR, certificate, signature) and arbitration
// user-data checks (bid inclusion, request hash, winner agreement).
func ValidateArbitrationAttestation(input *ArbitrationValidationInput) (*ArbitrationValidationResult, error) {
	if input == nil {
		return nil, fmt.Errorf("nil input")
	}
	if len(input.KnownPCRs) == 0 {
		return nil, fmt.Errorf("no PCR sets configured")
	}

	cose, err := input.AttestationCOSEGzip.Decompress()
	if err != nil {
		return nil, fmt.Errorf("decompress attestation: %w", err)
	}
	coseB64 := cose.EncodeBase64()

	base, err := validateCommonAttestation(coseB64, input.KnownPCRs, input.Roots)
	if err != nil {
		return nil, err
	}

	doc, err := parseArbitrationAttestation(coseB64)
	if err != nil {
		return nil, fmt.Errorf("parse arbitration attestation: %w", err)
	}

	result := &ArbitrationValidationResult{BaseValidationResult: *base}

	if doc.UserData == nil {
		result.ValidationDetails = append(result.ValidationDetails, "Attestation user data missing")
		return result, nil
	}

	switch input.Expectation {
	case ExpectExcluded:
		result.BidExclusionValid = validateBidExclusion(input, doc, result)
		// When the caller expects exclusion they need not assert
		// inclusion or a specific outcome; treat those checks as
		// trivially satisfied so IsValid() reflects the exclusion path.
		result.BidHashValid = true
		result.WinnerValid = true
	default:
		result.BidHashValid = validateBidHash(input, doc, result)
		result.WinnerValid = validateWinner(input, doc, result)
		// Exclusion check is trivially satisfied on the inclusion path.
		result.BidExclusionValid = true
	}
	result.RequestHashValid = validateRequestHash(input, doc, result)

	return result, nil
}

func validateBidExclusion(input *ArbitrationValidationInput, doc *enclaveapi.ArbitrationAttestationDoc, result *ArbitrationValidationResult) bool {
	for _, eb := range doc.UserData.ExcludedBids {
		if eb.BidID == input.BidID {
			if eb.Reason == input.ExpectedExclusionReason {
				result.ValidationDetails = append(result.ValidationDetails,
					fmt.Sprintf("Bid exclusion confirmed: %s (%s)", eb.BidID, eb.Reason))
				return true
			}
			result.ValidationDetails = append(result.ValidationDetails,
				fmt.Sprintf("Bid exclusion reason mismatch: expected %q, attestation has %q", input.ExpectedExclusionReason, eb.Reason))
			return false
		}
	}
	result.ValidationDetails = append(result.ValidationDetails,
		fmt.Sprintf("Bid %s not found among %d attested exclusions", input.BidID, len(doc.UserData.ExcludedBids)))
	return false
}

func validateBidHash(input *ArbitrationValidationInput, doc *enclaveapi.ArbitrationAttestationDoc, result *ArbitrationValidationResult) bool {
	nonce := doc.UserData.BidHashNonce
	if nonce == "" {
		result.ValidationDetails = append(result.ValidationDetails, "Bid hash nonce missing from attestation")
		return false
	}
	computed := core.ComputeBidHash(input.BidID, input.BidRevenue, nonce)
	for _, h := range doc.UserData.BidHashes {
		if h == computed {
			result.ValidationDetails = append(result.ValidationDetails,
				fmt.Sprintf("Bid hash found in attestation: %s", computed))
			return true
		}
	}
	result.ValidationDetails = append(result.ValidationDetails,
		fmt.Sprintf("Bid hash NOT found in attestation. Computed: %s (over %d attested hashes)", computed, len(doc.UserData.BidHashes)))
	return false
}

func validateRequestHash(input *ArbitrationValidationInput, doc *enclaveapi.ArbitrationAttestationDoc, result *ArbitrationValidationResult) bool {
	nonce := doc.UserData.RequestNonce
	if nonce == "" {
		result.ValidationDetails = append(result.ValidationDetails, "Request hash nonce missing from attestation")
		return false
	}
	computed := core.ComputeRequestHash(input.RequestID, nonce)
	if computed == doc.UserData.RequestHash {
		result.ValidationDetails = append(result.ValidationDetails, "Request hash validation passed")
		return true
	}
	result.ValidationDetails = append(result.ValidationDetails,
		fmt.Sprintf("Request hash mismatch: computed %s, attestation has %s", computed, doc.UserData.RequestHash))
	return false
}

func validateWinner(input *ArbitrationValidationInput, doc *enclaveapi.ArbitrationAttestationDoc, result *ArbitrationValidationResult) bool {
	winner := doc.UserData.Winner
	actuallyWon := winner != nil && winner.ID == input.BidID
	if input.IsWinner == actuallyWon {
		switch {
		case actuallyWon:
			result.ValidationDetails = append(result.ValidationDetails,
				fmt.Sprintf("Winner validation passed: bid won as expected (revenue: %d micros)", winner.Revenue))
		default:
			result.ValidationDetails = append(result.ValidationDetails, "Winner validation passed: bid lost as expected")
		}
		return true
	}
	if input.IsWinner && !actuallyWon {
		result.ValidationDetails = append(result.ValidationDetails, "Winner validation failed: expected to win, but did not win")
	} else {
		result.ValidationDetails = append(result.ValidationDetails,
			fmt.Sprintf("Winner validation failed: expected to lose, but won with revenue %d micros", winner.Revenue))
	}
	return false
}
