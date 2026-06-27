package enclave

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudx-io/openarbiter/core"
)

func newTestKeypair(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return priv, &priv.PublicKey
}

// sealRaw seals an arbitrary plaintext under pub for tests that need to
// exercise post-decrypt behavior on non-standard plaintext (e.g.
// non-JSON).
func sealRaw(t *testing.T, pub *rsa.PublicKey, plaintext []byte) *core.EncryptedRevenue {
	t.Helper()
	aesKey := make([]byte, 32)
	_, err := rand.Read(aesKey)
	require.NoError(t, err)
	block, err := aes.NewCipher(aesKey)
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)
	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	require.NoError(t, err)
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	encKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, aesKey, nil)
	require.NoError(t, err)
	return &core.EncryptedRevenue{
		AESKeyEncrypted:  base64.StdEncoding.EncodeToString(encKey),
		EncryptedPayload: base64.StdEncoding.EncodeToString(ct),
		Nonce:            base64.StdEncoding.EncodeToString(nonce),
		HashAlgorithm:    core.HashAlgorithmSHA256,
	}
}

func sealRevenue(t *testing.T, pub *rsa.PublicKey, dpm core.DollarsPerMille) *core.EncryptedRevenue {
	t.Helper()
	ct, err := core.SealCPMDollars(pub, dpm)
	require.NoError(t, err)
	return ct
}

func corruptCiphertext(t *testing.T, ct *core.EncryptedRevenue) *core.EncryptedRevenue {
	t.Helper()
	payload, err := base64.StdEncoding.DecodeString(ct.EncryptedPayload)
	require.NoError(t, err)
	payload[len(payload)-1] ^= 0xFF
	corrupted := *ct
	corrupted.EncryptedPayload = base64.StdEncoding.EncodeToString(payload)
	return &corrupted
}

func newEncryptedBid(ct *core.EncryptedRevenue, cleartextDPM core.DollarsPerMille) core.Bid {
	return core.Bid{
		ID:                  uuid.New(),
		Source:              "TEST",
		CleartextRevenue:    cleartextDPM.Dollars(),
		EncryptedCPMDollars: ct,
	}
}

func expectMicros(dpm core.DollarsPerMille) core.MicroDollars {
	return dpm.Dollars().AsMicros()
}

// ─── NewArbiter ───────────────────────────────────────

func TestNewArbiter_ValidKey(t *testing.T) {
	t.Parallel()
	priv, _ := newTestKeypair(t)
	arb, err := NewArbiter(priv)
	require.NoError(t, err)
	require.NotNil(t, arb)
	assert.NotNil(t, arb.priv, "priv should be stored")
}

func TestNewArbiter_NilKey(t *testing.T) {
	t.Parallel()
	arb, err := NewArbiter(nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, core.ErrNoKey)
	require.NotNil(t, arb)
	assert.Nil(t, arb.priv)
}

// ─── Arbiter.GetRevenue ─────────────────────────────────

func TestArbiter_GetRevenue_PlaintextBid(t *testing.T) {
	t.Parallel()
	arb, _ := NewArbiter(nil)
	bid := core.Bid{ID: uuid.New(), Source: "TEST", CleartextRevenue: core.DollarsPerMille(2.0).Dollars()}
	assert.Equal(t, expectMicros(2.0), arb.GetRevenue(bid).AsMicros())
}

func TestArbiter_GetRevenue_EncryptedBid(t *testing.T) {
	t.Parallel()
	priv, pub := newTestKeypair(t)
	arb, err := NewArbiter(priv)
	require.NoError(t, err)
	bid := newEncryptedBid(sealRevenue(t, pub, core.DollarsPerMille(1.5)), 0)
	assert.Equal(t, expectMicros(1.5), arb.GetRevenue(bid).AsMicros())
}

func TestArbiter_GetRevenue_WrongKey_FallsBackToPlaintext(t *testing.T) {
	t.Parallel()
	_, pubA := newTestKeypair(t)
	privB, _ := newTestKeypair(t)
	arb, err := NewArbiter(privB)
	require.NoError(t, err)

	bid := newEncryptedBid(sealRevenue(t, pubA, core.DollarsPerMille(1.5)), core.DollarsPerMille(0.10))
	assert.Equal(t, expectMicros(0.10), arb.GetRevenue(bid).AsMicros(),
		"unable to decrypt → fall back to cleartext")
}

func TestArbiter_GetRevenue_NoKey_FallsBackToPlaintext(t *testing.T) {
	t.Parallel()
	_, pub := newTestKeypair(t)
	arb, _ := NewArbiter(nil)

	bid := newEncryptedBid(sealRevenue(t, pub, core.DollarsPerMille(1.5)), core.DollarsPerMille(0.25))
	assert.Equal(t, expectMicros(0.25), arb.GetRevenue(bid).AsMicros())
}

func TestArbiter_GetRevenue_CorruptedCiphertext_FallsBackToPlaintext(t *testing.T) {
	t.Parallel()
	priv, pub := newTestKeypair(t)
	arb, err := NewArbiter(priv)
	require.NoError(t, err)

	ct := corruptCiphertext(t, sealRevenue(t, pub, core.DollarsPerMille(1.5)))
	bid := newEncryptedBid(ct, core.DollarsPerMille(0.50))
	assert.Equal(t, expectMicros(0.50), arb.GetRevenue(bid).AsMicros())
}

func TestArbiter_GetRevenue_NonJSONPlaintext(t *testing.T) {
	t.Parallel()
	priv, pub := newTestKeypair(t)
	arb, err := NewArbiter(priv)
	require.NoError(t, err)

	bid := newEncryptedBid(sealRaw(t, pub, []byte("not-a-number")), core.DollarsPerMille(0.75))
	assert.Equal(t, expectMicros(0.75), arb.GetRevenue(bid).AsMicros())
}

func TestArbiter_GetRevenue_EncryptedTakesPrecedenceOverPlaintext(t *testing.T) {
	t.Parallel()
	priv, pub := newTestKeypair(t)
	arb, err := NewArbiter(priv)
	require.NoError(t, err)

	bid := newEncryptedBid(sealRevenue(t, pub, core.DollarsPerMille(1.5)), core.DollarsPerMille(99))
	assert.Equal(t, expectMicros(1.5), arb.GetRevenue(bid).AsMicros())
}

func TestArbiter_GetRevenue_NilCleartextOnDecryptFailure(t *testing.T) {
	t.Parallel()
	priv, pub := newTestKeypair(t)
	arb, err := NewArbiter(priv)
	require.NoError(t, err)

	bid := core.Bid{
		ID:                  uuid.New(),
		Source:              "TEST",
		EncryptedCPMDollars: corruptCiphertext(t, sealRevenue(t, pub, core.DollarsPerMille(1.5))),
	}
	assert.Equal(t, core.MicroDollars(0), arb.GetRevenue(bid).AsMicros())
}

// ─── Arbiter.Arbitrate ──────────────────────────────────

func TestArbitrate_EndToEnd(t *testing.T) {
	t.Parallel()
	priv, pub := newTestKeypair(t)
	arb, err := NewArbiter(priv)
	require.NoError(t, err)

	winnerCt := sealRevenue(t, pub, core.DollarsPerMille(2.50))
	loserCt := sealRevenue(t, pub, core.DollarsPerMille(0.50))
	winnerID := uuid.New()
	loserID := uuid.New()

	resp := arb.Arbitrate([]core.Bid{
		{ID: loserID, Source: "TEST", EncryptedCPMDollars: loserCt},
		{ID: winnerID, Source: "TEST", EncryptedCPMDollars: winnerCt},
	}, nil)
	require.NotNil(t, resp.Winner)
	assert.Equal(t, winnerID, resp.Winner.Bid.ID)
	assert.Equal(t, expectMicros(2.50), resp.Winner.Revenue)
	require.Len(t, resp.Bids, 2)
}

func TestArbitrate_DoesNotMutateInput(t *testing.T) {
	t.Parallel()
	arb, _ := NewArbiter(nil)
	bids := []core.Bid{
		{ID: uuid.New(), Source: "A", CleartextRevenue: core.MicroDollars(1_000_000)},
		{ID: uuid.New(), Source: "B", CleartextRevenue: core.MicroDollars(5_000_000)},
		{ID: uuid.New(), Source: "C", CleartextRevenue: core.MicroDollars(2_000_000)},
	}
	before := make([]uuid.UUID, len(bids))
	for i, b := range bids {
		before[i] = b.ID
	}
	_ = arb.Arbitrate(bids, nil)
	for i, b := range bids {
		assert.Equalf(t, before[i], b.ID,
			"Arbitrate mutated caller slice at index %d", i)
	}
}

// TestArbitrate_DecryptedFlag confirms Arbitrate marks each ranked bid as
// decrypted when its sealed price opened, and as fallback otherwise
// (missing ciphertext, wrong key, corrupted ciphertext).
func TestArbitrate_DecryptedFlag(t *testing.T) {
	t.Parallel()
	priv, pub := newTestKeypair(t)
	_, otherPub := newTestKeypair(t)
	arb, err := NewArbiter(priv)
	require.NoError(t, err)

	sealedID := uuid.New()
	wrongKeyID := uuid.New()
	corruptID := uuid.New()
	plainID := uuid.New()

	resp := arb.Arbitrate([]core.Bid{
		{ID: sealedID, Source: "S", EncryptedCPMDollars: sealRevenue(t, pub, core.DollarsPerMille(2.0))},
		{ID: wrongKeyID, Source: "S", CleartextRevenue: core.DollarsPerMille(0.10).Dollars(), EncryptedCPMDollars: sealRevenue(t, otherPub, core.DollarsPerMille(9.0))},
		{ID: corruptID, Source: "S", CleartextRevenue: core.DollarsPerMille(0.20).Dollars(), EncryptedCPMDollars: corruptCiphertext(t, sealRevenue(t, pub, core.DollarsPerMille(9.0)))},
		{ID: plainID, Source: "S", CleartextRevenue: core.DollarsPerMille(0.30).Dollars()},
	}, nil)

	byID := map[uuid.UUID]core.ArbiterBid{}
	for _, ab := range resp.Bids {
		require.NotNil(t, ab.Bid)
		byID[ab.Bid.ID] = ab
	}
	assert.True(t, byID[sealedID].Decrypted, "sealed bid should be decrypted")
	assert.False(t, byID[wrongKeyID].Decrypted, "wrong-key bid should fall back")
	assert.False(t, byID[corruptID].Decrypted, "corrupted bid should fall back")
	assert.False(t, byID[plainID].Decrypted, "cleartext-only bid should fall back")
}
