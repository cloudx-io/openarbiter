package enclave

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudx-io/openarbiter/core"
	"github.com/cloudx-io/openarbiter/enclaveapi"
)

func TestHandleKeyRequest_BindsKeyToAttestation(t *testing.T) {
	t.Parallel()
	km, err := NewKeyManager()
	require.NoError(t, err)

	resp, err := HandleKeyRequest(newFakeAttester(), km)
	require.NoError(t, err)
	assert.Equal(t, "key_response", resp.Type)
	assert.NotEmpty(t, resp.AuctionToken)
	assert.Contains(t, resp.PublicKey, "PUBLIC KEY")

	cose, err := resp.Attestation.Decompress()
	require.NoError(t, err)
	_, userDataBytes, err := cose.ParseAttestationDoc()
	require.NoError(t, err)
	var ud enclaveapi.KeyAttestationUserData
	require.NoError(t, json.Unmarshal(userDataBytes, &ud))
	assert.Equal(t, resp.PublicKey, ud.PublicKey)
	assert.Equal(t, resp.AuctionToken, ud.AuctionToken)
}

func TestHandleArbitrationRequest_RanksAndAttests(t *testing.T) {
	t.Parallel()
	km, err := NewKeyManager()
	require.NoError(t, err)

	winnerID := uuid.NewString()
	loserID := uuid.NewString()
	winnerRevenue := core.MicroDollars(2_500_000)
	loserRevenue := core.MicroDollars(500_000)
	req := enclaveapi.EnclaveArbitrationRequest{
		Type:      "arbitration_request",
		RequestID: "req-1",
		Bids: []enclaveapi.WireBid{
			{ID: loserID, Source: "A", CleartextRevenue: loserRevenue},
			{ID: winnerID, Source: "B", CleartextRevenue: winnerRevenue},
		},
		Timestamp: time.Now().UTC(),
	}

	resp := HandleArbitrationRequest(newFakeAttester(), km, req)
	require.True(t, resp.Success, "message=%s", resp.Message)
	assert.Equal(t, "arbitration_response", resp.Type)

	cose, err := resp.AttestationCOSEBase64.Decode()
	require.NoError(t, err)
	_, userDataBytes, err := cose.ParseAttestationDoc()
	require.NoError(t, err)
	var ud enclaveapi.ArbitrationAttestationUserData
	require.NoError(t, json.Unmarshal(userDataBytes, &ud))
	assert.Equal(t, "req-1", ud.RequestID)
	require.NotNil(t, ud.Winner)
	assert.Equal(t, winnerID, ud.Winner.ID)
	assert.Equal(t, winnerRevenue, ud.Winner.Revenue)
	assert.Len(t, ud.BidHashes, 2)
}

func TestHandleArbitrationRequest_RecordsMalformedBidIDsAsExcluded(t *testing.T) {
	t.Parallel()
	km, err := NewKeyManager()
	require.NoError(t, err)

	goodID := uuid.NewString()
	req := enclaveapi.EnclaveArbitrationRequest{
		RequestID: "req-x",
		Bids: []enclaveapi.WireBid{
			{ID: "not-a-uuid", Source: "A", CleartextRevenue: core.MicroDollars(100)},
			{ID: goodID, Source: "B", CleartextRevenue: core.MicroDollars(200)},
		},
	}
	resp := HandleArbitrationRequest(newFakeAttester(), km, req)
	require.True(t, resp.Success)

	wantExcluded := []core.ExcludedBid{{BidID: "not-a-uuid", Reason: core.ExclusionReasonMalformedBidID}}
	assert.Equal(t, wantExcluded, resp.ExcludedBids,
		"response should surface malformed bid as excluded")

	cose, err := resp.AttestationCOSEBase64.Decode()
	require.NoError(t, err)
	_, userDataBytes, err := cose.ParseAttestationDoc()
	require.NoError(t, err)
	var ud enclaveapi.ArbitrationAttestationUserData
	require.NoError(t, json.Unmarshal(userDataBytes, &ud))
	assert.Len(t, ud.BidHashes, 1)
	require.NotNil(t, ud.Winner)
	assert.Equal(t, goodID, ud.Winner.ID)
	assert.Equal(t, wantExcluded, ud.ExcludedBids,
		"attestation should bind malformed bid as excluded")
}
