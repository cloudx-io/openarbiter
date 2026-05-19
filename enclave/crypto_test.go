package enclave

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudx-io/openarbiter/core"
)

func TestDecryptCPMDollars_NilKey(t *testing.T) {
	t.Parallel()
	dpm, err := decryptCPMDollars(nil, &core.EncryptedRevenue{})
	assert.Equal(t, core.DollarsPerMille(0), dpm)
	assert.ErrorIs(t, err, core.ErrNoKey)
}

func TestDecryptCPMDollars_NoCiphertext(t *testing.T) {
	t.Parallel()
	priv, _ := newTestKeypair(t)
	dpm, err := decryptCPMDollars(priv, nil)
	assert.Equal(t, core.DollarsPerMille(0), dpm)
	assert.ErrorIs(t, err, core.ErrNoEncryptedRevenue)
}

func TestDecryptCPMDollars_RoundTrip(t *testing.T) {
	t.Parallel()
	priv, pub := newTestKeypair(t)
	ct := sealRevenue(t, pub, core.DollarsPerMille(1.50))
	dpm, err := decryptCPMDollars(priv, ct)
	require.NoError(t, err)
	assert.Equal(t, core.DollarsPerMille(1.50), dpm)
}

func TestDecryptCPMDollars_AEADFailure(t *testing.T) {
	t.Parallel()
	priv, pub := newTestKeypair(t)
	ct := corruptCiphertext(t, sealRevenue(t, pub, core.DollarsPerMille(1.50)))

	dpm, err := decryptCPMDollars(priv, ct)
	assert.Equal(t, core.DollarsPerMille(0), dpm)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AES-GCM open")
}

func TestDecryptCPMDollars_NonJSONPlaintext(t *testing.T) {
	t.Parallel()
	priv, pub := newTestKeypair(t)
	ct := sealRaw(t, pub, []byte("not-a-number"))
	dpm, err := decryptCPMDollars(priv, ct)
	assert.Equal(t, core.DollarsPerMille(0), dpm)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unmarshal revenue payload")
}

func TestDecryptCPMDollars_UnsupportedHashAlgorithm(t *testing.T) {
	t.Parallel()
	priv, pub := newTestKeypair(t)
	ct := sealRevenue(t, pub, core.DollarsPerMille(1.50))
	ct.HashAlgorithm = "SHA-1"
	dpm, err := decryptCPMDollars(priv, ct)
	assert.Equal(t, core.DollarsPerMille(0), dpm)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported RSA-OAEP hash algorithm")
}

func TestDecryptCPMDollars_EmptyHashAlgorithmDefaultsToSHA256(t *testing.T) {
	t.Parallel()
	priv, pub := newTestKeypair(t)
	ct := sealRevenue(t, pub, core.DollarsPerMille(1.50))
	ct.HashAlgorithm = ""
	dpm, err := decryptCPMDollars(priv, ct)
	require.NoError(t, err)
	assert.Equal(t, core.DollarsPerMille(1.50), dpm)
}
