package enclave

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// rsaKeyBits is the modulus size of the in-enclave keypair.
const rsaKeyBits = 2048

// generateRSAKeypair produces a fresh RSA-2048 keypair. In a Nitro
// enclave, crypto/rand draws from the NSM-enhanced entropy pool.
func generateRSAKeypair() (*rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return nil, fmt.Errorf("generate RSA keypair: %w", err)
	}
	return priv, nil
}

// KeyManager owns the enclave's long-lived RSA keypair. The private
// half is unexported so the only operations the enclave can perform on
// it are the ones [KeyManager] exposes; the public half is published
// (with an attestation binding) so off-enclave callers can seal bid
// prices to the arbiter.
type KeyManager struct {
	privateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

// NewKeyManager generates a fresh keypair and returns a KeyManager
// that holds it.
func NewKeyManager() (*KeyManager, error) {
	priv, err := generateRSAKeypair()
	if err != nil {
		return nil, fmt.Errorf("new key manager: %w", err)
	}
	return &KeyManager{privateKey: priv, PublicKey: &priv.PublicKey}, nil
}

// PrivateKey returns the enclave's private key. Callers should keep
// the returned pointer inside the enclave process.
func (km *KeyManager) PrivateKey() *rsa.PrivateKey {
	return km.privateKey
}

// PublicKeyPEM returns the public key as a PKIX-encoded "PUBLIC KEY"
// PEM block, the format the arbiter publishes via
// [enclaveapi.KeyWithAttestation.PublicKey].
func (km *KeyManager) PublicKeyPEM() (string, error) {
	derBytes, err := x509.MarshalPKIXPublicKey(km.PublicKey)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: derBytes})), nil
}
