package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"github.com/cloudx-io/openauction/enclaveapi"
)

// HashAlgorithmSHA256 is the only RSA-OAEP hash the arbiter accepts. It
// matches the value in [enclaveapi.EncryptedBidPrice.HashAlgorithm].
const HashAlgorithmSHA256 = "SHA-256"

// EncryptedRevenue is the wire shape of a sealed CPM revenue: hybrid
// RSA-OAEP-SHA256 + AES-256-GCM.
//
// It is a type alias for [enclaveapi.EncryptedBidPrice] from
// cloudx-io/openauction so a single wire schema (and a single audit)
// covers both projects. The plaintext inside EncryptedPayload is a JSON
// object {"price": <DPM float>}.
type EncryptedRevenue = enclaveapi.EncryptedBidPrice

// PricePayload is the JSON shape sealed inside
// [EncryptedRevenue.EncryptedPayload]. The same type is consumed by the
// enclave-side decryption path so the wire-level JSON is
// byte-identical end to end.
type PricePayload struct {
	Price DollarsPerMille `json:"price"`
}

// ParsePublicKey parses a PEM-encoded "PUBLIC KEY" block whose body is a
// PKIX RSA public key — the same format the arbiter enclave exposes via
// [enclaveapi.KeyWithAttestation.PublicKey] — into an [*rsa.PublicKey]
// for use with [SealCPMDollars].
func ParsePublicKey(pemBytes []byte) (*rsa.PublicKey, error) {
	if len(pemBytes) == 0 {
		return nil, ErrNoKey
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("parse RSA public key: no PEM block found")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKIX RSA public key: %w", err)
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("parse PKIX RSA public key: wanted *rsa.PublicKey, got %T", parsed)
	}
	return pub, nil
}

// SealCPMDollars seals dpm under pub using hybrid RSA-OAEP + AES-256-GCM.
// pub is the recipient arbiter's public key, typically obtained via
// [enclaveapi.KeyWithAttestation.PublicKey] and decoded with
// [ParsePublicKey].
func SealCPMDollars(pub *rsa.PublicKey, dpm DollarsPerMille) (*EncryptedRevenue, error) {
	if pub == nil {
		return nil, ErrNoKey
	}
	plaintext, err := json.Marshal(PricePayload{Price: dpm})
	if err != nil {
		return nil, fmt.Errorf("marshal revenue payload: %w", err)
	}

	// Fresh AES-256 content key per seal.
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return nil, fmt.Errorf("generate AES key: %w", err)
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("new AES cipher: %w", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new GCM: %w", err)
	}
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate GCM nonce: %w", err)
	}
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

	encryptedAESKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, aesKey, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA-OAEP encrypt AES key: %w", err)
	}

	return &EncryptedRevenue{
		AESKeyEncrypted:  base64.StdEncoding.EncodeToString(encryptedAESKey),
		EncryptedPayload: base64.StdEncoding.EncodeToString(ciphertext),
		Nonce:            base64.StdEncoding.EncodeToString(nonce),
		HashAlgorithm:    HashAlgorithmSHA256,
	}, nil
}
