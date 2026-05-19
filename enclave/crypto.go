package enclave

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/cloudx-io/openarbiter/core"
)

// decryptCPMDollars opens a [core.EncryptedRevenue] under priv and
// parses the inner JSON payload back into a [core.DollarsPerMille].
// Returns a distinct error for each failure mode so operators have a
// signal when ciphertext is being silently rejected.
func decryptCPMDollars(priv *rsa.PrivateKey, ct *core.EncryptedRevenue) (core.DollarsPerMille, error) {
	if priv == nil {
		return 0, core.ErrNoKey
	}
	if ct == nil {
		return 0, core.ErrNoEncryptedRevenue
	}
	switch ct.HashAlgorithm {
	case "", core.HashAlgorithmSHA256:
		// SHA-256 (or unspecified, treated as SHA-256).
	default:
		return 0, fmt.Errorf("unsupported RSA-OAEP hash algorithm %q", ct.HashAlgorithm)
	}

	encryptedAESKey, err := base64.StdEncoding.DecodeString(ct.AESKeyEncrypted)
	if err != nil {
		return 0, fmt.Errorf("base64-decode encrypted AES key: %w", err)
	}
	encryptedPayload, err := base64.StdEncoding.DecodeString(ct.EncryptedPayload)
	if err != nil {
		return 0, fmt.Errorf("base64-decode encrypted payload: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(ct.Nonce)
	if err != nil {
		return 0, fmt.Errorf("base64-decode nonce: %w", err)
	}

	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, encryptedAESKey, nil)
	if err != nil {
		return 0, fmt.Errorf("RSA-OAEP decrypt AES key: %w", err)
	}
	if len(aesKey) != 32 {
		return 0, fmt.Errorf("decrypted AES key has wrong length: got %d, want 32", len(aesKey))
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return 0, fmt.Errorf("new AES cipher: %w", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return 0, fmt.Errorf("new GCM: %w", err)
	}
	if len(nonce) != aesgcm.NonceSize() {
		return 0, fmt.Errorf("nonce has wrong length: got %d, want %d", len(nonce), aesgcm.NonceSize())
	}
	plaintext, err := aesgcm.Open(nil, nonce, encryptedPayload, nil)
	if err != nil {
		return 0, fmt.Errorf("AES-GCM open: %w", err)
	}

	var p core.PricePayload
	if err := json.Unmarshal(plaintext, &p); err != nil {
		return 0, fmt.Errorf("unmarshal revenue payload %q: %w", plaintext, err)
	}
	return p.Price, nil
}
