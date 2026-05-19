package enclave

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewKeyManager_GeneratesUsableKeypair(t *testing.T) {
	t.Parallel()
	km, err := NewKeyManager()
	require.NoError(t, err)
	require.NotNil(t, km.PrivateKey())
	require.NotNil(t, km.PublicKey)
	assert.Equal(t, rsaKeyBits, km.PrivateKey().N.BitLen())
	assert.Same(t, &km.PrivateKey().PublicKey, km.PublicKey)
}

func TestKeyManager_PublicKeyPEM_RoundTrip(t *testing.T) {
	t.Parallel()
	km, err := NewKeyManager()
	require.NoError(t, err)

	pemStr, err := km.PublicKeyPEM()
	require.NoError(t, err)

	block, _ := pem.Decode([]byte(pemStr))
	require.NotNil(t, block)
	assert.Equal(t, "PUBLIC KEY", block.Type)

	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	pub, ok := parsed.(*rsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, km.PublicKey.N, pub.N)
	assert.Equal(t, km.PublicKey.E, pub.E)
}
