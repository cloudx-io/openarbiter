package enclave

import (
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/cloudx-io/openarbiter/core"
	"github.com/cloudx-io/openarbiter/enclaveapi"
)

// HandleKeyRequest produces a [enclaveapi.KeyResponse] binding the
// enclave's public key to its PCRs via a fresh attestation. The opaque
// token returned in [enclaveapi.KeyWithAttestation.AuctionToken] is a
// correlator the host may echo back into a subsequent arbitration
// request.
func HandleKeyRequest(attester EnclaveAttester, km *KeyManager) (*enclaveapi.KeyResponse, error) {
	if km == nil {
		return nil, fmt.Errorf("nil key manager")
	}
	pemStr, err := km.PublicKeyPEM()
	if err != nil {
		return nil, fmt.Errorf("export public key: %w", err)
	}
	token := uuid.NewString()
	cose, err := GenerateKeyAttestation(attester, km.PublicKey, token)
	if err != nil {
		return nil, fmt.Errorf("generate key attestation: %w", err)
	}
	gz, err := cose.CompressGzip()
	if err != nil {
		return nil, fmt.Errorf("compress attestation: %w", err)
	}
	return &enclaveapi.KeyResponse{
		KeyWithAttestation: enclaveapi.KeyWithAttestation{
			PublicKey:    pemStr,
			Attestation:  gz,
			AuctionToken: token,
		},
		Type: "key_response",
	}, nil
}

// HandleArbitrationRequest is the enclave's arbitration entry point.
// It decrypts each sealed bid via [Arbiter], ranks them, then asks the
// attester to bind the resolved inputs and chosen winner to the
// enclave's PCRs.
func HandleArbitrationRequest(
	attester EnclaveAttester,
	km *KeyManager,
	req enclaveapi.EnclaveArbitrationRequest,
) enclaveapi.EnclaveArbitrationResponse {
	start := time.Now()

	arb, _ := NewArbiter(km.PrivateKey())
	coreBids, excluded := wireBidsToCoreBids(req.Bids)
	resp := arb.Arbitrate(coreBids, nil)

	cose, err := GenerateArbitrationAttestation(attester, req, resp.Bids, resp.Winner, excluded)
	if err != nil {
		return enclaveapi.EnclaveArbitrationResponse{
			Type:             "arbitration_response",
			Success:          false,
			Message:          fmt.Sprintf("attestation failed: %v", err),
			ProcessingTimeMS: time.Since(start).Milliseconds(),
		}
	}
	return enclaveapi.EnclaveArbitrationResponse{
		Type:                  "arbitration_response",
		Success:               true,
		Message:               fmt.Sprintf("arbitrated %d bids", len(req.Bids)),
		AttestationCOSEBase64: cose.EncodeBase64(),
		ExcludedBids:          excluded,
		ProcessingTimeMS:      time.Since(start).Milliseconds(),
	}
}

// wireBidsToCoreBids converts the JSON-encodable [enclaveapi.WireBid]
// envelope into [core.Bid] instances suitable for [Arbiter.Arbitrate].
// Bids whose IDs fail to parse as UUIDs are returned in the second
// slice as [core.ExcludedBid]s so they remain visible in the
// attestation rather than being silently dropped.
func wireBidsToCoreBids(wire []enclaveapi.WireBid) ([]core.Bid, []core.ExcludedBid) {
	bids := make([]core.Bid, 0, len(wire))
	var excluded []core.ExcludedBid
	for _, wb := range wire {
		id, err := uuid.Parse(wb.ID)
		if err != nil {
			excluded = append(excluded, core.ExcludedBid{
				BidID:  wb.ID,
				Reason: core.ExclusionReasonMalformedBidID,
			})
			continue
		}
		bids = append(bids, core.Bid{
			ID:                  id,
			Source:              wb.Source,
			CleartextRevenue:    wb.CleartextRevenue,
			EncryptedCPMDollars: wb.EncryptedCPMDollars,
		})
	}
	return bids, excluded
}
