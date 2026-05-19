package enclave

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"

	edgebit "github.com/edgebitio/nitro-enclaves-sdk-go"

	"github.com/cloudx-io/openarbiter/core"
	"github.com/cloudx-io/openarbiter/enclaveapi"
)

// EnclaveAttester is the subset of AWS Nitro's NSM API that the arbiter
// consumes. Production code passes a handle from
// github.com/edgebitio/nitro-enclaves-sdk-go; tests pass a fake.
type EnclaveAttester interface {
	Attest(options edgebit.AttestationOptions) ([]byte, error)
}

// generateNonce returns a fresh, hex-encoded 256-bit random nonce.
func generateNonce() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// publicKeyToPEM marshals pub as a PKIX-encoded "PUBLIC KEY" PEM block.
func publicKeyToPEM(pub *rsa.PublicKey) (string, error) {
	derBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: derBytes})), nil
}

// GenerateArbitrationAttestation builds the arbiter's per-request
// attestation: bid hashes (one per resolved bid), a request hash, and a
// winner descriptor, all bound under freshly-generated nonces. The
// caller is the enclave's arbitration handler.
func GenerateArbitrationAttestation(
	attester EnclaveAttester,
	req enclaveapi.EnclaveArbitrationRequest,
	resolved []core.ArbiterBid,
	winner *core.ArbiterBid,
) (enclaveapi.AttestationCOSE, error) {
	if attester == nil {
		return nil, fmt.Errorf("nil attester")
	}
	bidNonce, err := generateNonce()
	if err != nil {
		return nil, err
	}
	requestNonce, err := generateNonce()
	if err != nil {
		return nil, err
	}

	bidHashes := make([]string, 0, len(resolved))
	for _, ab := range resolved {
		if ab.Bid == nil {
			continue
		}
		bidHashes = append(bidHashes, core.ComputeBidHash(ab.Bid.ID.String(), ab.Revenue, bidNonce))
	}

	var winnerDescriptor *enclaveapi.ArbiterBidWithoutSource
	if winner != nil && winner.Bid != nil {
		winnerDescriptor = &enclaveapi.ArbiterBidWithoutSource{
			ID:      winner.Bid.ID.String(),
			Revenue: winner.Revenue,
		}
	}

	now := time.Now().UTC()
	userData := enclaveapi.ArbitrationAttestationUserData{
		RequestID:    req.RequestID,
		BidHashes:    bidHashes,
		BidHashNonce: bidNonce,
		RequestHash:  core.ComputeRequestHash(req.RequestID, requestNonce),
		RequestNonce: requestNonce,
		Winner:       winnerDescriptor,
		Timestamp:    now,
	}

	userDataBytes, err := json.Marshal(userData)
	if err != nil {
		return nil, fmt.Errorf("marshal user data: %w", err)
	}
	attestationNonce, err := generateNonce()
	if err != nil {
		return nil, err
	}
	coseBytes, err := attester.Attest(edgebit.AttestationOptions{
		UserData: userDataBytes,
		Nonce:    []byte(attestationNonce),
	})
	if err != nil {
		return nil, fmt.Errorf("NSM attestation: %w", err)
	}
	return enclaveapi.AttestationCOSE(coseBytes), nil
}

// GenerateKeyAttestation builds an attestation binding the arbiter's
// public key to its PCRs. The token is an opaque correlator the host
// echoes back into a subsequent arbitration request (see
// [HandleKeyRequest]); it is not interpreted here.
func GenerateKeyAttestation(
	attester EnclaveAttester,
	publicKey *rsa.PublicKey,
	token string,
) (enclaveapi.AttestationCOSE, error) {
	if attester == nil {
		return nil, fmt.Errorf("nil attester")
	}
	pemStr, err := publicKeyToPEM(publicKey)
	if err != nil {
		return nil, err
	}
	userData := enclaveapi.KeyAttestationUserData{
		KeyAlgorithm: "RSA-2048",
		PublicKey:    pemStr,
		AuctionToken: token,
	}
	userDataBytes, err := json.Marshal(userData)
	if err != nil {
		return nil, fmt.Errorf("marshal key user data: %w", err)
	}
	attestationNonce, err := generateNonce()
	if err != nil {
		return nil, err
	}
	coseBytes, err := attester.Attest(edgebit.AttestationOptions{
		UserData: userDataBytes,
		Nonce:    []byte(attestationNonce),
	})
	if err != nil {
		return nil, fmt.Errorf("NSM key attestation: %w", err)
	}
	return enclaveapi.AttestationCOSE(coseBytes), nil
}
