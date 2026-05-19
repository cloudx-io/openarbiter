package enclave

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"
	"time"

	edgebit "github.com/edgebitio/nitro-enclaves-sdk-go"
	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudx-io/openarbiter/core"
	"github.com/cloudx-io/openarbiter/enclaveapi"
)

// fakeAttester wraps an attestation options recorder and emits a minimal
// AWS-Nitro-shaped 4-element CBOR array. Tests use it to drive
// [GenerateArbitrationAttestation] / [GenerateKeyAttestation] without
// touching NSM.
type fakeAttester struct {
	Last edgebit.AttestationOptions
	PCRs map[uint64][]byte
}

func newFakeAttester() *fakeAttester {
	return &fakeAttester{
		PCRs: map[uint64][]byte{
			0: bytesRepeat(0xAA, 48),
			1: bytesRepeat(0xBB, 48),
			2: bytesRepeat(0xCC, 48),
		},
	}
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func (f *fakeAttester) Attest(options edgebit.AttestationOptions) ([]byte, error) {
	f.Last = options
	nested := map[string]any{
		"module_id":   "test",
		"digest":      "SHA384",
		"timestamp":   uint64(time.Now().UnixMilli()),
		"pcrs":        f.PCRs,
		"certificate": []byte{},
		"cabundle":    [][]byte{},
		"public_key":  []byte{},
		"user_data":   options.UserData,
		"nonce":       options.Nonce,
	}
	nestedBytes, err := cbor.Marshal(nested)
	if err != nil {
		return nil, err
	}
	coseArray := []any{[]byte{}, map[string]any{}, nestedBytes, []byte{}}
	return cbor.Marshal(coseArray)
}

func TestGenerateArbitrationAttestation_BindsBidsAndWinner(t *testing.T) {
	t.Parallel()
	att := newFakeAttester()

	winnerBid := core.Bid{ID: uuid.New(), Source: "A"}
	loserBid := core.Bid{ID: uuid.New(), Source: "B"}
	resolved := []core.ArbiterBid{
		{Bid: &loserBid, Revenue: core.MicroDollars(500_000)},
		{Bid: &winnerBid, Revenue: core.MicroDollars(2_500_000)},
	}
	req := enclaveapi.EnclaveArbitrationRequest{
		Type:      "arbitration_request",
		RequestID: "req-42",
		Timestamp: time.Now().UTC(),
	}

	cose, err := GenerateArbitrationAttestation(att, req, resolved, &resolved[1], nil)
	require.NoError(t, err)
	require.NotEmpty(t, cose)

	// User data round-trip.
	_, userDataBytes, err := cose.ParseAttestationDoc()
	require.NoError(t, err)
	var ud enclaveapi.ArbitrationAttestationUserData
	require.NoError(t, json.Unmarshal(userDataBytes, &ud))

	assert.Equal(t, "req-42", ud.RequestID)
	assert.Len(t, ud.BidHashes, 2)
	assert.NotEmpty(t, ud.BidHashNonce)
	assert.NotEmpty(t, ud.RequestNonce)
	assert.Equal(t, core.ComputeRequestHash("req-42", ud.RequestNonce), ud.RequestHash)
	require.NotNil(t, ud.Winner)
	assert.Equal(t, winnerBid.ID.String(), ud.Winner.ID)
	assert.Equal(t, core.MicroDollars(2_500_000), ud.Winner.Revenue)

	// Bid hashes recomputable from inputs + nonce.
	want := []string{
		core.ComputeBidHash(loserBid.ID.String(), core.MicroDollars(500_000), ud.BidHashNonce),
		core.ComputeBidHash(winnerBid.ID.String(), core.MicroDollars(2_500_000), ud.BidHashNonce),
	}
	assert.Equal(t, want, ud.BidHashes)
}

func TestGenerateArbitrationAttestation_NoWinner(t *testing.T) {
	t.Parallel()
	att := newFakeAttester()
	cose, err := GenerateArbitrationAttestation(att, enclaveapi.EnclaveArbitrationRequest{RequestID: "r"}, nil, nil, nil)
	require.NoError(t, err)
	_, userDataBytes, err := cose.ParseAttestationDoc()
	require.NoError(t, err)
	var ud enclaveapi.ArbitrationAttestationUserData
	require.NoError(t, json.Unmarshal(userDataBytes, &ud))
	assert.Nil(t, ud.Winner)
	assert.Empty(t, ud.BidHashes)
}

func TestGenerateArbitrationAttestation_NilAttester(t *testing.T) {
	t.Parallel()
	_, err := GenerateArbitrationAttestation(nil, enclaveapi.EnclaveArbitrationRequest{}, nil, nil, nil)
	require.Error(t, err)
}

func TestGenerateKeyAttestation_RoundTrip(t *testing.T) {
	t.Parallel()
	att := newFakeAttester()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	cose, err := GenerateKeyAttestation(att, &priv.PublicKey, "token-abc")
	require.NoError(t, err)

	_, userDataBytes, err := cose.ParseAttestationDoc()
	require.NoError(t, err)
	var ud enclaveapi.KeyAttestationUserData
	require.NoError(t, json.Unmarshal(userDataBytes, &ud))
	assert.Equal(t, "RSA-2048", ud.KeyAlgorithm)
	assert.Equal(t, "token-abc", ud.AuctionToken)
	assert.Contains(t, ud.PublicKey, "PUBLIC KEY")
}

func TestGenerateKeyAttestation_NilAttester(t *testing.T) {
	t.Parallel()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	_, err = GenerateKeyAttestation(nil, &priv.PublicKey, "")
	require.Error(t, err)
}
