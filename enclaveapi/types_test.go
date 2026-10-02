package enclaveapi

import (
	"encoding/json"
	"testing"
	"time"

	oaenclaveapi "github.com/cloudx-io/openauction/enclaveapi"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudx-io/openarbiter/core"
)

// TestEnclaveArbitrationRequest_RoundTrip pins the wire shape of
// host→enclave arbitration requests.
func TestEnclaveArbitrationRequest_RoundTrip(t *testing.T) {
	t.Parallel()
	bidID := uuid.NewString()
	now := time.Date(2026, 3, 24, 11, 20, 27, 0, time.UTC)
	orig := EnclaveArbitrationRequest{
		Type:      "arbitration_request",
		RequestID: "req-1",
		Bids: []WireBid{{
			ID:               bidID,
			Source:           "TEST",
			CleartextRevenue: core.MicroDollars(123_456),
		}},
		Timestamp: now,
	}
	data, err := json.Marshal(orig)
	require.NoError(t, err)

	var back EnclaveArbitrationRequest
	require.NoError(t, json.Unmarshal(data, &back))
	assert.Equal(t, orig.Type, back.Type)
	assert.Equal(t, orig.RequestID, back.RequestID)
	assert.Equal(t, orig.Timestamp.UTC(), back.Timestamp.UTC())
	require.Len(t, back.Bids, 1)
	assert.Equal(t, bidID, back.Bids[0].ID)
	assert.Equal(t, "TEST", back.Bids[0].Source)
	assert.Equal(t, core.MicroDollars(123_456), back.Bids[0].CleartextRevenue)
}

func TestArbitrationAttestationUserData_RoundTrip(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 3, 24, 11, 20, 27, 0, time.UTC)
	orig := ArbitrationAttestationUserData{
		RequestID:    "req-1",
		BidHashes:    []string{"a", "b"},
		BidHashNonce: "n1",
		RequestHash:  "rh",
		RequestNonce: "n2",
		Winner: &ArbiterBidWithoutSource{
			ID:      uuid.NewString(),
			Revenue: core.MicroDollars(2_500_000),
		},
		Timestamp: now,
	}
	data, err := json.Marshal(orig)
	require.NoError(t, err)

	var back ArbitrationAttestationUserData
	require.NoError(t, json.Unmarshal(data, &back))
	assert.Equal(t, orig.RequestID, back.RequestID)
	assert.Equal(t, orig.BidHashes, back.BidHashes)
	assert.Equal(t, orig.BidHashNonce, back.BidHashNonce)
	assert.Equal(t, orig.RequestHash, back.RequestHash)
	assert.Equal(t, orig.RequestNonce, back.RequestNonce)
	require.NotNil(t, back.Winner)
	assert.Equal(t, orig.Winner.ID, back.Winner.ID)
	assert.Equal(t, orig.Winner.Revenue, back.Winner.Revenue)
	assert.Equal(t, orig.Timestamp.UTC(), back.Timestamp.UTC())
}

// TestAliasesShareUnderlyingType pins the contract that every re-export
// in types.go is the same type as its openauction counterpart: each pair
// below is assigned in both directions without conversion, so this file
// stops compiling if an alias becomes a defined type. The arbiter's key
// attestation user data is a separate type on purpose
// ([ArbiterKeyAttestationUserData]) and is not re-exported.
func TestAliasesShareUnderlyingType(t *testing.T) {
	t.Parallel()
	_ = func(v AttestationCOSE) oaenclaveapi.AttestationCOSE { return v }
	_ = func(v oaenclaveapi.AttestationCOSE) AttestationCOSE { return v }
	_ = func(v AttestationCOSEBase64) oaenclaveapi.AttestationCOSEBase64 { return v }
	_ = func(v oaenclaveapi.AttestationCOSEBase64) AttestationCOSEBase64 { return v }
	_ = func(v AttestationCOSEURLBase64) oaenclaveapi.AttestationCOSEURLBase64 { return v }
	_ = func(v oaenclaveapi.AttestationCOSEURLBase64) AttestationCOSEURLBase64 { return v }
	_ = func(v AttestationCOSEGzip) oaenclaveapi.AttestationCOSEGzip { return v }
	_ = func(v oaenclaveapi.AttestationCOSEGzip) AttestationCOSEGzip { return v }
	_ = func(v AttestationDoc) oaenclaveapi.AttestationDoc { return v }
	_ = func(v oaenclaveapi.AttestationDoc) AttestationDoc { return v }
	_ = func(v PCRs) oaenclaveapi.PCRs { return v }
	_ = func(v oaenclaveapi.PCRs) PCRs { return v }
	_ = func(v EncryptedBidPrice) oaenclaveapi.EncryptedBidPrice { return v }
	_ = func(v oaenclaveapi.EncryptedBidPrice) EncryptedBidPrice { return v }
	_ = func(v KeyWithAttestation) oaenclaveapi.KeyWithAttestation { return v }
	_ = func(v oaenclaveapi.KeyWithAttestation) KeyWithAttestation { return v }
	_ = func(v KeyResponse) oaenclaveapi.KeyResponse { return v }
	_ = func(v oaenclaveapi.KeyResponse) KeyResponse { return v }
}

// TestArbiterKeyAttestationUserData_RoundTrip pins the attested key
// user_data wire shape, including auction_token.
func TestArbiterKeyAttestationUserData_RoundTrip(t *testing.T) {
	t.Parallel()
	orig := ArbiterKeyAttestationUserData{
		AuctionToken: "token-1",
	}
	orig.KeyAlgorithm = "RSA-2048"
	orig.PublicKey = "-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----"

	data, err := json.Marshal(orig)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"auction_token":"token-1"`)
	assert.Contains(t, string(data), `"key_algorithm":"RSA-2048"`)

	var back ArbiterKeyAttestationUserData
	require.NoError(t, json.Unmarshal(data, &back))
	assert.Equal(t, orig.KeyAlgorithm, back.KeyAlgorithm)
	assert.Equal(t, orig.PublicKey, back.PublicKey)
	assert.Equal(t, orig.AuctionToken, back.AuctionToken)
}

// TestEnclaveArbitrationResponse_RoundTrip pins the wire shape of the
// enclave→host arbitration response, including the per-bid resolved
// revenue and decryption outcome field.
func TestEnclaveArbitrationResponse_RoundTrip(t *testing.T) {
	t.Parallel()
	winnerID := uuid.NewString()
	loserID := uuid.NewString()
	orig := EnclaveArbitrationResponse{
		Type:    "arbitration_response",
		Success: true,
		Message: "arbitrated 2 bids",
		ExcludedBids: []core.ExcludedBid{
			{BidID: "bad", Reason: core.ExclusionReasonMalformedBidID},
		},
		Bids: []ResolvedBid{
			{ID: winnerID, Source: "WIN", Revenue: core.MicroDollars(5_000), Decrypted: true},
			{ID: loserID, Source: "LOSE", Revenue: core.MicroDollars(100), Decrypted: false},
		},
		ProcessingTimeMS: 7,
	}
	data, err := json.Marshal(orig)
	require.NoError(t, err)

	var back EnclaveArbitrationResponse
	require.NoError(t, json.Unmarshal(data, &back))
	assert.Equal(t, orig.Type, back.Type)
	assert.Equal(t, orig.Success, back.Success)
	assert.Equal(t, orig.ExcludedBids, back.ExcludedBids)
	require.Len(t, back.Bids, 2)
	assert.Equal(t, orig.Bids, back.Bids)
	assert.Equal(t, orig.ProcessingTimeMS, back.ProcessingTimeMS)
}

// TestResolvedBid_JSONTags pins the JSON field names a downstream
// consumer reads.
func TestResolvedBid_JSONTags(t *testing.T) {
	t.Parallel()
	data, err := json.Marshal(ResolvedBid{
		ID:        "id-1",
		Source:    "SRC",
		Revenue:   core.MicroDollars(42),
		Decrypted: true,
	})
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))
	assert.Equal(t, "id-1", m["id"])
	assert.Equal(t, "SRC", m["source"])
	assert.Equal(t, float64(42), m["revenue_micros"])
	assert.Equal(t, true, m["decrypted"])
}
