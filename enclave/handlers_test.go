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

// TestHandleArbitrationRequest_PopulatesResolvedBids confirms the response
// carries every ranked bid in ranked order (winner first) with its
// Source, resolved revenue, and decryption outcome, and that this new
// field does not appear in the attestation user data.
func TestHandleArbitrationRequest_PopulatesResolvedBids(t *testing.T) {
	t.Parallel()
	km, err := NewKeyManager()
	require.NoError(t, err)

	sealedID := uuid.NewString()
	plainID := uuid.NewString()
	sealedCt, err := core.SealCPMDollars(km.PublicKey, core.DollarsPerMille(5.0))
	require.NoError(t, err)
	req := enclaveapi.EnclaveArbitrationRequest{
		RequestID: "req-r",
		Bids: []enclaveapi.WireBid{
			{ID: plainID, Source: "PLAIN", CleartextRevenue: core.MicroDollars(100)},
			{ID: sealedID, Source: "SEALED", CleartextRevenue: core.MicroDollars(1), EncryptedCPMDollars: sealedCt},
		},
	}

	resp := HandleArbitrationRequest(newFakeAttester(), km, req)
	require.True(t, resp.Success, "message=%s", resp.Message)
	require.Len(t, resp.Bids, 2)

	// Ranked order: sealed bid resolves to 5.0 CPM (5_000 micros) which
	// beats the plaintext 100 micros, so it ranks first.
	assert.Equal(t, sealedID, resp.Bids[0].ID)
	assert.Equal(t, "SEALED", resp.Bids[0].Source)
	assert.Equal(t, core.DollarsPerMille(5.0).Dollars().AsMicros(), resp.Bids[0].Revenue)
	assert.True(t, resp.Bids[0].Decrypted)

	assert.Equal(t, plainID, resp.Bids[1].ID)
	assert.Equal(t, "PLAIN", resp.Bids[1].Source)
	assert.Equal(t, core.MicroDollars(100), resp.Bids[1].Revenue)
	assert.False(t, resp.Bids[1].Decrypted)

	// The new field must not leak into the attestation user data.
	cose, err := resp.AttestationCOSEBase64.Decode()
	require.NoError(t, err)
	_, userDataBytes, err := cose.ParseAttestationDoc()
	require.NoError(t, err)
	assert.NotContains(t, string(userDataBytes), "SEALED")
	assert.NotContains(t, string(userDataBytes), "PLAIN")
	assert.NotContains(t, string(userDataBytes), "decrypted")
}
