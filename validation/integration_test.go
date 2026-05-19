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

// TestIntegration_KeyAttestation_RoundTrip exercises the public-key
// attestation path. Pins that the enclave's KeyAttestationUserData
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

	userData := enclaveapi.KeyAttestationUserData{
		KeyAlgorithm: "RSA-2048",
		PublicKey:    pubPEM,
		AuctionToken: "arbitration-token-1",
	}
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
