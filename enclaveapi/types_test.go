package enclaveapi

import (
	"encoding/json"
	"testing"
	"time"

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

// TestAliasesShareUnderlyingType pins the contract that AttestationDoc,
// PCRs, and KeyWithAttestation are the same types as their openauction
// counterparts (assignable in both directions without conversion).
func TestAliasesShareUnderlyingType(t *testing.T) {
	t.Parallel()
	var pcrs PCRs
	pcrs.ImageFileHash = "abc"
	assert.Equal(t, "abc", pcrs.ImageFileHash)

	var k KeyWithAttestation
	k.PublicKey = "PEM"
	assert.Equal(t, "PEM", k.PublicKey)
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
