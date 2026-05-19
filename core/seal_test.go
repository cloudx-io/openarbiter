package core

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestPubKey(t *testing.T) *rsa.PublicKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return &priv.PublicKey
}

func pubPEM(t *testing.T, pub *rsa.PublicKey) []byte {
	t.Helper()
	derBytes, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: derBytes})
}

func TestSealCPMDollars_NilPubKey(t *testing.T) {
	t.Parallel()
	ct, err := SealCPMDollars(nil, DollarsPerMille(1.50))
	assert.Nil(t, ct)
	assert.ErrorIs(t, err, ErrNoKey)
}

// TestSealCPMDollars_HidesPriceRepetition guards against a same-price
// oracle: each seal of the same price must produce distinct AESKeyEncrypted,
// Nonce, and EncryptedPayload bytes.
func TestSealCPMDollars_HidesPriceRepetition(t *testing.T) {
	t.Parallel()
	pub := newTestPubKey(t)
	const price = DollarsPerMille(4.20)
	const seals = 8

	cts := make([]*EncryptedRevenue, seals)
	for i := range cts {
		ct, err := SealCPMDollars(pub, price)
		require.NoError(t, err)
		cts[i] = ct
	}
	for i := range seals {
		for j := i + 1; j < seals; j++ {
			assert.NotEqualf(t, cts[i].AESKeyEncrypted, cts[j].AESKeyEncrypted,
				"AESKeyEncrypted repeated between seals %d and %d", i, j)
			assert.NotEqualf(t, cts[i].Nonce, cts[j].Nonce,
				"Nonce repeated between seals %d and %d (catastrophic for GCM)", i, j)
			assert.NotEqualf(t, cts[i].EncryptedPayload, cts[j].EncryptedPayload,
				"EncryptedPayload repeated between seals %d and %d", i, j)
		}
	}
}

func TestParsePublicKey_Empty(t *testing.T) {
	t.Parallel()
	pub, err := ParsePublicKey(nil)
	assert.Nil(t, pub)
	assert.ErrorIs(t, err, ErrNoKey)
}

func TestParsePublicKey_NoPEMBlock(t *testing.T) {
	t.Parallel()
	pub, err := ParsePublicKey([]byte("not a PEM block"))
	assert.Nil(t, pub)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no PEM block")
}

func TestParsePublicKey_MalformedDER(t *testing.T) {
	t.Parallel()
	bad := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{0x01, 0x02, 0x03}})
	pub, err := ParsePublicKey(bad)
	assert.Nil(t, pub)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PKIX RSA public key")
}

func TestParsePublicKey_RoundTrip(t *testing.T) {
	t.Parallel()
	pub := newTestPubKey(t)
	loaded, err := ParsePublicKey(pubPEM(t, pub))
	require.NoError(t, err)
	require.NotNil(t, loaded)
	assert.Equal(t, pub.N, loaded.N)
	assert.Equal(t, pub.E, loaded.E)
}
