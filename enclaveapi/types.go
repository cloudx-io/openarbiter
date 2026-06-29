// Package enclaveapi defines the wire contract between the arbiter
// enclave and its host. It reuses generic attestation primitives from
// cloudx-io/openauction's enclaveapi (PCRs, AttestationDoc,
// AttestationCOSE encodings, KeyWithAttestation, etc.) so a single COSE
// pipeline covers both projects, and adds arbiter-specific request,
// response, and attestation user-data shapes.
package enclaveapi

import (
	"time"

	oaenclaveapi "github.com/cloudx-io/openauction/enclaveapi"

	"github.com/cloudx-io/openarbiter/core"
)

// ─── Re-exports from openauction/enclaveapi ─────────────────────────────
//
// These aliases let consumers depend on a single attestation envelope
// type set across both projects.

// AttestationCOSE is the raw COSE_Sign1 attestation envelope produced by
// AWS Nitro.
type AttestationCOSE = oaenclaveapi.AttestationCOSE

// AttestationCOSEBase64 is a standard base64-encoded AttestationCOSE.
type AttestationCOSEBase64 = oaenclaveapi.AttestationCOSEBase64

// AttestationCOSEURLBase64 is a URL-safe base64-encoded AttestationCOSE.
type AttestationCOSEURLBase64 = oaenclaveapi.AttestationCOSEURLBase64

// AttestationCOSEGzip is a GZIP-compressed, base64url-encoded
// AttestationCOSE — compact enough to ship in URLs or response headers.
type AttestationCOSEGzip = oaenclaveapi.AttestationCOSEGzip

// AttestationDoc is the parsed top-level attestation document common to
// all attestation kinds.
type AttestationDoc = oaenclaveapi.AttestationDoc

// PCRs is the set of Platform Configuration Register measurements that
// pin the enclave's image, kernel, and application binaries.
type PCRs = oaenclaveapi.PCRs

// EncryptedBidPrice is the hybrid-encrypted wire shape of a sealed bid
// price; re-exported from openauction so a single audit covers both
// projects.
type EncryptedBidPrice = oaenclaveapi.EncryptedBidPrice

// KeyAttestationUserData is the user-data payload embedded in a key
// attestation: the enclave's public key plus the algorithm naming it.
type KeyAttestationUserData = oaenclaveapi.KeyAttestationUserData

// KeyAttestationDoc is the attestation document for a public-key
// attestation.
type KeyAttestationDoc = oaenclaveapi.KeyAttestationDoc

// KeyWithAttestation is the arbiter's response to a public-key request:
// the PEM-encoded public key, the COSE attestation binding it to the
// enclave's PCRs, and an arbitration token for replay protection.
type KeyWithAttestation = oaenclaveapi.KeyWithAttestation

// KeyResponse is the wire envelope around [KeyWithAttestation].
type KeyResponse = oaenclaveapi.KeyResponse

// ─── Arbiter-specific wire types ───────────────────────────────────────

// WireBid is the JSON-encodable form of a bid as it appears on the
// host←→enclave wire. It carries the same fields as [core.Bid] except
// that the cleartext revenue is encoded directly as [core.MicroDollars]
// (instead of the broader [core.Currency] interface, which is not
// JSON-friendly).
type WireBid struct {
	ID                  string                 `json:"id"`
	Source              string                 `json:"source"`
	CleartextRevenue    core.MicroDollars      `json:"cleartext_revenue_micros"`
	EncryptedCPMDollars *core.EncryptedRevenue `json:"encrypted_cpm_dollars,omitempty"`
}

// EnclaveArbitrationRequest is the host-→-enclave request envelope. The
// enclave decrypts each [WireBid]'s sealed price (if any), ranks them,
// and returns an [EnclaveArbitrationResponse] with an [AttestationCOSE]
// binding the inputs to the outcome.
type EnclaveArbitrationRequest struct {
	Type      string    `json:"type"`
	RequestID string    `json:"request_id"`
	Bids      []WireBid `json:"bids"`
	Timestamp time.Time `json:"timestamp"`
}

// ArbiterBidWithoutSource is the post-decryption view of a bid as
// attested by the enclave. The opaque [core.Bid.Source] is omitted so
// the attestation user-data does not echo provenance back out of the
// enclave.
type ArbiterBidWithoutSource struct {
	ID      string            `json:"id"`
	Revenue core.MicroDollars `json:"revenue_micros"`
}

// ResolvedBid is the post-decryption view of a single ranked input bid
// on the response wire. Unlike [ArbiterBidWithoutSource], it echoes the
// opaque bid Source and the decryption outcome. ResolvedBid is a plain
// response field only; it is NOT bound to the attestation user data.
type ResolvedBid struct {
	// ID is the wire bid's ID.
	ID string `json:"id"`
	// Source is the opaque provenance string echoed through from the
	// input bid; the arbiter does not interpret it.
	Source string `json:"source"`
	// Revenue is the effective per-impression revenue used in ranking:
	// the decrypted ciphertext when present and valid, else the
	// cleartext fallback.
	Revenue core.MicroDollars `json:"revenue_micros"`
	// Decrypted is true when Revenue came from a successfully decrypted
	// sealed price, and false when it came from the cleartext fallback.
	Decrypted bool `json:"decrypted"`
}

// EnclaveArbitrationResponse is the enclave-→-host response envelope.
type EnclaveArbitrationResponse struct {
	Type                  string                `json:"type"`
	Success               bool                  `json:"success"`
	Message               string                `json:"message,omitempty"`
	AttestationCOSEBase64 AttestationCOSEBase64 `json:"attestation_cose_base64,omitempty"`
	// ExcludedBids enumerates wire bids the arbiter saw but did not
	// rank, alongside the reason. The same slice is bound to the
	// attestation user data (see
	// [ArbitrationAttestationUserData.ExcludedBids]).
	ExcludedBids []core.ExcludedBid `json:"excluded_bids,omitempty"`
	// Bids lists every ranked input bid in ranked order (winner first)
	// with its resolved revenue and decryption outcome. It is a plain
	// response field and is NOT bound to the attestation user data.
	Bids             []ResolvedBid `json:"bids,omitempty"`
	ProcessingTimeMS int64         `json:"processing_time_ms"`
}

// ArbitrationAttestationUserData is the JSON shape embedded in the
// arbiter's attestation user_data field. It binds the participating
// bids, the request envelope, the chosen winner, and any bids the
// arbiter excluded so an off-enclave validator can replay the
// inclusion, exclusion, and outcome checks.
type ArbitrationAttestationUserData struct {
	RequestID    string                   `json:"request_id"`
	BidHashes    []string                 `json:"bid_hashes"`
	BidHashNonce string                   `json:"bid_hash_nonce"`
	RequestHash  string                   `json:"request_hash"`
	RequestNonce string                   `json:"request_nonce"`
	Winner       *ArbiterBidWithoutSource `json:"winner,omitempty"`
	// ExcludedBids lists wire bids the arbiter saw but did not rank,
	// alongside the reason for each exclusion.
	ExcludedBids []core.ExcludedBid `json:"excluded_bids,omitempty"`
	Timestamp    time.Time          `json:"timestamp"`
}

// ArbitrationAttestationDoc is the parsed arbitration attestation: the
// base [AttestationDoc] from AWS Nitro plus the arbiter-specific user
// data.
type ArbitrationAttestationDoc struct {
	AttestationDoc
	UserData *ArbitrationAttestationUserData `json:"user_data"`
}
