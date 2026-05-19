package validation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
	"github.com/veraison/go-cose"

	"github.com/cloudx-io/openarbiter/enclaveapi"
)

// syntheticCA bundles the ECDSA P-384 root CA + leaf signing cert used to
// mint attestations for tests. The root pool produced by [poolForRoot]
// is what callers pass into the validator's Roots override.
type syntheticCA struct {
	rootCert    *x509.Certificate
	rootKey     *ecdsa.PrivateKey
	leafCertDER []byte
	leafKey     *ecdsa.PrivateKey
	caBundleDER [][]byte
}

func newSyntheticCA(t *testing.T, notBefore, notAfter time.Time) *syntheticCA {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "openarbiter-test-root"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)
	rootCert, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "openarbiter-test-attestation-leaf"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, rootCert, &leafKey.PublicKey, rootKey)
	require.NoError(t, err)

	return &syntheticCA{
		rootCert:    rootCert,
		rootKey:     rootKey,
		leafCertDER: leafDER,
		leafKey:     leafKey,
		caBundleDER: [][]byte{rootDER},
	}
}

func (ca *syntheticCA) rootPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca.rootCert)
	return pool
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

// fixedPCRs is a reusable PCR set whose hex values resemble a real Nitro
// measurement. Tests configure their validator to trust this set.
var fixedPCRs = PCRSet{
	PCR0:      "0a71879536b641527b61da93792e1b89f903e6afc879ba0a95cf3ffec86bbb5f2ebc5a55c46e0d2c2102725c64ec0734",
	PCR1:      "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
	PCR2:      "238f49b566190e54f82d12face72bb1d8d163d8f3512bd0a651b5bf976ff39187ed2536745ea7a7ec03c57a39d47fe3a",
	CommitSHA: "test",
}

// signedAttestation packages a COSE_Sign1 attestation envelope together
// with its gzip form, ready to feed into the validator.
type signedAttestation struct {
	COSEBase64 enclaveapi.AttestationCOSEBase64
	COSEGzip   enclaveapi.AttestationCOSEGzip
}

// signAttestation builds a synthetic COSE_Sign1 attestation: nested CBOR
// document with the supplied PCRs and user_data, signed under ca's leaf
// key with ES384. Mirrors the AWS Nitro 4-element-array layout that the
// validator parses.
func signAttestation(t *testing.T, ca *syntheticCA, pcrs PCRSet, timestamp time.Time, userData any) signedAttestation {
	t.Helper()

	userDataBytes, err := json.Marshal(userData)
	require.NoError(t, err)

	nested := map[string]any{
		"module_id":   "openarbiter-test",
		"digest":      "SHA384",
		"timestamp":   uint64(timestamp.UnixMilli()),
		"pcrs":        map[uint64][]byte{0: mustHex(t, pcrs.PCR0), 1: mustHex(t, pcrs.PCR1), 2: mustHex(t, pcrs.PCR2)},
		"certificate": ca.leafCertDER,
		"cabundle":    ca.caBundleDER,
		"public_key":  []byte{},
		"user_data":   userDataBytes,
		"nonce":       []byte(""),
	}
	nestedBytes, err := cbor.Marshal(nested)
	require.NoError(t, err)

	// Protected headers: {1: -35} (alg=ES384), CBOR-encoded.
	protectedMap := map[int]int{1: int(cose.AlgorithmES384)}
	protectedBytes, err := cbor.Marshal(protectedMap)
	require.NoError(t, err)

	sigStructure := []any{
		"Signature1",
		protectedBytes,
		[]byte{},
		nestedBytes,
	}
	toBeSigned, err := cbor.Marshal(sigStructure)
	require.NoError(t, err)

	signer, err := cose.NewSigner(cose.AlgorithmES384, ca.leafKey)
	require.NoError(t, err)
	signature, err := signer.Sign(rand.Reader, toBeSigned)
	require.NoError(t, err)

	coseArray := []any{protectedBytes, map[string]any{}, nestedBytes, signature}
	coseBytes, err := cbor.Marshal(coseArray)
	require.NoError(t, err)

	coseEnvelope := enclaveapi.AttestationCOSE(coseBytes)
	b64 := enclaveapi.AttestationCOSEBase64(base64.StdEncoding.EncodeToString(coseBytes))
	gz, err := coseEnvelope.CompressGzip()
	require.NoError(t, err)

	return signedAttestation{COSEBase64: b64, COSEGzip: gz}
}
