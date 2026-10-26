package validation

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudx-io/openarbiter/core"
	"github.com/cloudx-io/openarbiter/enclaveapi"
)

func randomNonce(t *testing.T) string {
	t.Helper()
	var b [16]byte
	_, err := rand.Read(b[:])
	require.NoError(t, err)
	return hex.EncodeToString(b[:])
}

// TestIntegration_ArbitrationAttestation_RoundTrip exercises the full
// emit→validate flow:
//
//  1. Build the same ArbitrationAttestationUserData the enclave will
//     emit, computing bid hashes via core.ComputeBidHash.
//  2. Sign it via a synthetic ECDSA-P384 root + leaf chain.
//  3. Hand the gzipped envelope to ValidateArbitrationAttestation.
//
// Pins that enclaveapi (emission) and validation (verification) agree on
// every field touched by attestation: bid hash, request hash, winner ID.
func TestIntegration_ArbitrationAttestation_RoundTrip(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	ca := newSyntheticCA(t, now.Add(-time.Hour), now.Add(time.Hour))

	requestID := uuid.NewString()
	winnerBidID := uuid.NewString()
	loserBidID := uuid.NewString()
	winnerRevenue := core.MicroDollars(2_500_000)
	loserRevenue := core.MicroDollars(500_000)

	bidNonce := randomNonce(t)
	requestNonce := randomNonce(t)

	userData := enclaveapi.ArbitrationAttestationUserData{
		RequestID: requestID,
		BidHashes: []string{
			core.ComputeBidHash(loserBidID, loserRevenue, bidNonce),
			core.ComputeBidHash(winnerBidID, winnerRevenue, bidNonce),
		},
		BidHashNonce: bidNonce,
		RequestHash:  core.ComputeRequestHash(requestID, requestNonce),
		RequestNonce: requestNonce,
		Winner: &enclaveapi.ArbiterBidWithoutSource{
			ID:      winnerBidID,
			Revenue: winnerRevenue,
		},
		Timestamp: now,
	}

	att := signAttestation(t, ca, fixedPCRs, now, userData)

	t.Run("winner perspective passes", func(t *testing.T) {
		t.Parallel()
		result, err := ValidateArbitrationAttestation(&ArbitrationValidationInput{
			AttestationCOSEGzip: att.COSEGzip,
			KnownPCRs:           []PCRSet{fixedPCRs},
			RequestID:           requestID,
			BidID:               winnerBidID,
			BidRevenue:          winnerRevenue,
			IsWinner:            true,
			Roots:               ca.rootPool(),
		})
		require.NoError(t, err)
		assert.True(t, result.IsValid(), "details: %v", result.ValidationDetails)
		assert.True(t, result.PCRsValid)
		assert.True(t, result.CertificateValid)
		assert.True(t, result.SignatureValid)
		assert.True(t, result.BidHashValid)
		assert.True(t, result.RequestHashValid)
		assert.True(t, result.WinnerValid)
	})

	t.Run("loser perspective passes", func(t *testing.T) {
		t.Parallel()
		result, err := ValidateArbitrationAttestation(&ArbitrationValidationInput{
			AttestationCOSEGzip: att.COSEGzip,
			KnownPCRs:           []PCRSet{fixedPCRs},
			RequestID:           requestID,
			BidID:               loserBidID,
			BidRevenue:          loserRevenue,
			IsWinner:            false,
			Roots:               ca.rootPool(),
		})
		require.NoError(t, err)
		assert.True(t, result.IsValid(), "details: %v", result.ValidationDetails)
	})

	t.Run("wrong revenue fails bid hash", func(t *testing.T) {
		t.Parallel()
		result, err := ValidateArbitrationAttestation(&ArbitrationValidationInput{
			AttestationCOSEGzip: att.COSEGzip,
			KnownPCRs:           []PCRSet{fixedPCRs},
			RequestID:           requestID,
			BidID:               winnerBidID,
			BidRevenue:          winnerRevenue + 1,
			IsWinner:            true,
			Roots:               ca.rootPool(),
		})
		require.NoError(t, err)
		assert.False(t, result.BidHashValid)
		assert.False(t, result.IsValid())
	})

	t.Run("wrong request ID fails request hash", func(t *testing.T) {
		t.Parallel()
		result, err := ValidateArbitrationAttestation(&ArbitrationValidationInput{
			AttestationCOSEGzip: att.COSEGzip,
			KnownPCRs:           []PCRSet{fixedPCRs},
			RequestID:           "some-other-request",
			BidID:               winnerBidID,
			BidRevenue:          winnerRevenue,
			IsWinner:            true,
			Roots:               ca.rootPool(),
		})
		require.NoError(t, err)
		assert.False(t, result.RequestHashValid)
		assert.False(t, result.IsValid())
	})

	t.Run("loser claiming win fails winner check", func(t *testing.T) {
		t.Parallel()
		result, err := ValidateArbitrationAttestation(&ArbitrationValidationInput{
			AttestationCOSEGzip: att.COSEGzip,
			KnownPCRs:           []PCRSet{fixedPCRs},
			RequestID:           requestID,
			BidID:               loserBidID,
			BidRevenue:          loserRevenue,
			IsWinner:            true,
			Roots:               ca.rootPool(),
		})
		require.NoError(t, err)
		assert.False(t, result.WinnerValid)
		assert.False(t, result.IsValid())
	})

	t.Run("unknown PCR set fails platform check", func(t *testing.T) {
		t.Parallel()
		other := fixedPCRs
		other.PCR0 = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
		result, err := ValidateArbitrationAttestation(&ArbitrationValidationInput{
			AttestationCOSEGzip: att.COSEGzip,
			KnownPCRs:           []PCRSet{other},
			RequestID:           requestID,
			BidID:               winnerBidID,
			BidRevenue:          winnerRevenue,
			IsWinner:            true,
			Roots:               ca.rootPool(),
		})
		require.NoError(t, err)
		assert.False(t, result.PCRsValid)
		assert.False(t, result.IsValid())
	})
}

// TestIntegration_ArbitrationAttestation_ExcludedBid pins the path
// where a bid the arbiter saw but did not rank is bound to the
// attestation as an exclusion. The caller can then prove their bid
// reached the arbiter without participating.
func TestIntegration_ArbitrationAttestation_ExcludedBid(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	ca := newSyntheticCA(t, now.Add(-time.Hour), now.Add(time.Hour))

	requestID := uuid.NewString()
	winnerBidID := uuid.NewString()
	winnerRevenue := core.MicroDollars(2_500_000)
	excludedBidID := "not-a-uuid"

	bidNonce := randomNonce(t)
	requestNonce := randomNonce(t)

	userData := enclaveapi.ArbitrationAttestationUserData{
		RequestID:    requestID,
		BidHashes:    []string{core.ComputeBidHash(winnerBidID, winnerRevenue, bidNonce)},
		BidHashNonce: bidNonce,
		RequestHash:  core.ComputeRequestHash(requestID, requestNonce),
		RequestNonce: requestNonce,
		Winner: &enclaveapi.ArbiterBidWithoutSource{
			ID:      winnerBidID,
			Revenue: winnerRevenue,
		},
		ExcludedBids: []core.ExcludedBid{{
			BidID:  excludedBidID,
			Reason: core.ExclusionReasonMalformedBidID,
		}},
		Timestamp: now,
	}
	att := signAttestation(t, ca, fixedPCRs, now, userData)

	t.Run("excluded bidder confirms exclusion", func(t *testing.T) {
		t.Parallel()
		result, err := ValidateArbitrationAttestation(&ArbitrationValidationInput{
			AttestationCOSEGzip:     att.COSEGzip,
			KnownPCRs:               []PCRSet{fixedPCRs},
			RequestID:               requestID,
			BidID:                   excludedBidID,
			Expectation:             ExpectExcluded,
			ExpectedExclusionReason: core.ExclusionReasonMalformedBidID,
			Roots:                   ca.rootPool(),
		})
		require.NoError(t, err)
		assert.True(t, result.IsValid(), "details: %v", result.ValidationDetails)
		assert.True(t, result.BidExclusionValid)
	})

	t.Run("wrong exclusion reason fails", func(t *testing.T) {
		t.Parallel()
		result, err := ValidateArbitrationAttestation(&ArbitrationValidationInput{
			AttestationCOSEGzip:     att.COSEGzip,
			KnownPCRs:               []PCRSet{fixedPCRs},
			RequestID:               requestID,
			BidID:                   excludedBidID,
			Expectation:             ExpectExcluded,
			ExpectedExclusionReason: "some other reason",
			Roots:                   ca.rootPool(),
		})
		require.NoError(t, err)
		assert.False(t, result.BidExclusionValid)
		assert.False(t, result.IsValid())
	})

	t.Run("unknown bid id not in exclusions fails", func(t *testing.T) {
		t.Parallel()
		result, err := ValidateArbitrationAttestation(&ArbitrationValidationInput{
			AttestationCOSEGzip:     att.COSEGzip,
			KnownPCRs:               []PCRSet{fixedPCRs},
			RequestID:               requestID,
			BidID:                   "some-other-bid",
			Expectation:             ExpectExcluded,
			ExpectedExclusionReason: core.ExclusionReasonMalformedBidID,
			Roots:                   ca.rootPool(),
		})
		require.NoError(t, err)
		assert.False(t, result.BidExclusionValid)
		assert.False(t, result.IsValid())
	})

	t.Run("winner perspective still passes alongside an exclusion", func(t *testing.T) {
		t.Parallel()
		result, err := ValidateArbitrationAttestation(&ArbitrationValidationInput{
			AttestationCOSEGzip: att.COSEGzip,
			KnownPCRs:           []PCRSet{fixedPCRs},
			RequestID:           requestID,
			BidID:               winnerBidID,
			BidRevenue:          winnerRevenue,
			IsWinner:            true,
			Roots:               ca.rootPool(),
		})
		require.NoError(t, err)
		assert.True(t, result.IsValid(), "details: %v", result.ValidationDetails)
	})
}

// TestIntegration_ArbitrationAttestation_BidIDForms pins that the
// included path accepts any UUID form the enclave's parser accepts:
// the enclave attests the canonical lowercase hyphenated form, so the
// validator canonicalises a parseable caller ID before hashing and
// comparing it with the winner. An ID that does not parse is used as
// given.
func TestIntegration_ArbitrationAttestation_BidIDForms(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	ca := newSyntheticCA(t, now.Add(-time.Hour), now.Add(time.Hour))

	requestID := uuid.NewString()
	winnerBidID := "8f14e45f-ceea-467a-9575-1c3e2b6a7d90"
	loserBidID := "c9f0f895-fb98-4b91-a0e1-d5b7f2a3c4e6"
	rawBidID := "not-a-uuid"
	winnerRevenue := core.MicroDollars(2_500_000)
	loserRevenue := core.MicroDollars(500_000)
	rawRevenue := core.MicroDollars(100_000)

	bidNonce := randomNonce(t)
	requestNonce := randomNonce(t)

	userData := enclaveapi.ArbitrationAttestationUserData{
		RequestID: requestID,
		BidHashes: []string{
			core.ComputeBidHash(winnerBidID, winnerRevenue, bidNonce),
			core.ComputeBidHash(loserBidID, loserRevenue, bidNonce),
			core.ComputeBidHash(rawBidID, rawRevenue, bidNonce),
		},
		BidHashNonce: bidNonce,
		RequestHash:  core.ComputeRequestHash(requestID, requestNonce),
		RequestNonce: requestNonce,
		Winner: &enclaveapi.ArbiterBidWithoutSource{
			ID:      winnerBidID,
			Revenue: winnerRevenue,
		},
		Timestamp: now,
	}
	att := signAttestation(t, ca, fixedPCRs, now, userData)

	tests := []struct {
		name        string
		bidID       string
		revenue     core.MicroDollars
		isWinner    bool
		wantBidHash bool
		wantWinner  bool
	}{
		{"canonical winner", winnerBidID, winnerRevenue, true, true, true},
		{"uppercase winner", "8F14E45F-CEEA-467A-9575-1C3E2B6A7D90", winnerRevenue, true, true, true},
		{"braced winner", "{8f14e45f-ceea-467a-9575-1c3e2b6a7d90}", winnerRevenue, true, true, true},
		{"urn:uuid winner", "urn:uuid:8f14e45f-ceea-467a-9575-1c3e2b6a7d90", winnerRevenue, true, true, true},
		{"unhyphenated winner", "8f14e45fceea467a95751c3e2b6a7d90", winnerRevenue, true, true, true},
		{"uppercase loser", "C9F0F895-FB98-4B91-A0E1-D5B7F2A3C4E6", loserRevenue, false, true, true},
		{"uppercase loser claiming win", "C9F0F895-FB98-4B91-A0E1-D5B7F2A3C4E6", loserRevenue, true, true, false},
		{"unparsable ID matches as given", rawBidID, rawRevenue, false, true, true},
		{"unparsable ID is not case-folded", "NOT-A-UUID", rawRevenue, false, false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result, err := ValidateArbitrationAttestation(&ArbitrationValidationInput{
				AttestationCOSEGzip: att.COSEGzip,
				KnownPCRs:           []PCRSet{fixedPCRs},
				RequestID:           requestID,
				BidID:               tc.bidID,
				BidRevenue:          tc.revenue,
				IsWinner:            tc.isWinner,
				Roots:               ca.rootPool(),
			})
			require.NoError(t, err)
			assert.Equal(t, tc.wantBidHash, result.BidHashValid, "details: %v", result.ValidationDetails)
			assert.Equal(t, tc.wantWinner, result.WinnerValid, "details: %v", result.ValidationDetails)
			assert.Equal(t, tc.wantBidHash && tc.wantWinner, result.IsValid(), "details: %v", result.ValidationDetails)
		})
	}
}

// TestIntegration_KeyAttestation_RoundTrip exercises the public-key
// attestation path. Pins that the enclave's ArbiterKeyAttestationUserData
// (carrying the PEM) round-trips through ValidateKeyAttestation.
func TestIntegration_KeyAttestation_RoundTrip(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	ca := newSyntheticCA(t, now.Add(-time.Hour), now.Add(time.Hour))

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	derBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: derBytes}))

	userData := enclaveapi.ArbiterKeyAttestationUserData{
		AuctionToken: "arbitration-token-1",
	}
	userData.KeyAlgorithm = "RSA-2048"
	userData.PublicKey = pubPEM
	att := signAttestation(t, ca, fixedPCRs, now, userData)

	t.Run("matching key passes", func(t *testing.T) {
		t.Parallel()
		result, err := ValidateKeyAttestation(att.COSEBase64, pubPEM, []PCRSet{fixedPCRs}, ca.rootPool())
		require.NoError(t, err)
		assert.True(t, result.IsValid(), "details: %v", result.ValidationDetails)
		assert.True(t, result.PublicKeyMatch)
	})

	t.Run("different key fails public-key check", func(t *testing.T) {
		t.Parallel()
		otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		otherDER, err := x509.MarshalPKIXPublicKey(&otherKey.PublicKey)
		require.NoError(t, err)
		otherPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: otherDER}))

		result, err := ValidateKeyAttestation(att.COSEBase64, otherPEM, []PCRSet{fixedPCRs}, ca.rootPool())
		require.NoError(t, err)
		assert.False(t, result.PublicKeyMatch)
		assert.False(t, result.IsValid())
	})
}
