// Package core ranks already-resolved bids and defines the wire shapes
// callers exchange with the arbiter. The selection logic here is pure: it
// operates on plaintext [Bid] inputs and never touches a private key.
// Decryption of [Bid.EncryptedCPMDollars] is the responsibility of the
// arbiter enclave (see github.com/cloudx-io/openarbiter/enclave).
package core

import (
	"cmp"
	"errors"
	"math/rand"
	"slices"

	"github.com/google/uuid"
)

var (
	// ErrNoEncryptedRevenue indicates a bid has no encrypted revenue
	// info; callers should use the cleartext revenue instead.
	ErrNoEncryptedRevenue = errors.New("no encrypted revenue data")
	// ErrNoKey indicates a misconfigured arbiter: it has no private key
	// with which to decrypt the revenues encrypted for it.
	ErrNoKey = errors.New("no key to decrypt encrypted revenue")
)

// Bid is the input to arbitration. Bidders seal their preferred revenue
// into [Bid.EncryptedCPMDollars] (via [SealCPMDollars]) under a public
// key obtained from the arbiter enclave's attested key endpoint; the
// arbiter falls back to [Bid.CleartextRevenue] if the ciphertext is
// absent or unrecoverable.
type Bid struct {
	// ID uniquely identifies the bid within its containing request. The
	// arbiter uses it only to give callers a stable handle for mapping
	// the chosen winner back to its original wire representation.
	ID uuid.UUID
	// Source is an opaque identifier for the provenance of this bid. The
	// arbiter does not interpret it; it is passed through unchanged.
	Source string
	// CleartextRevenue is the per-impression revenue the arbiter falls
	// back to when EncryptedCPMDollars is absent, malformed, or sealed
	// for a different recipient key.
	CleartextRevenue Currency
	// EncryptedCPMDollars, if present, is the authoritative revenue: a
	// hybrid RSA-OAEP + AES-256-GCM ciphertext of a JSON {"price": <DPM>}
	// payload (see [EncryptedRevenue]). The arbiter's private key opens
	// it; on any failure the arbiter falls back to [Bid.CleartextRevenue].
	EncryptedCPMDollars *EncryptedRevenue
}

// ArbiterBid is the post-decryption view of an input [Bid] as the
// arbiter saw it.
type ArbiterBid struct {
	// Bid points into the caller's input slice; [RankBids] does not
	// mutate it.
	Bid *Bid
	// Revenue is the effective per-impression revenue: decrypted
	// ciphertext when present and well-formed, else the cleartext
	// fallback.
	Revenue MicroDollars
}

// ArbitrateResponse is the boundary value the arbiter returns. Bids
// contains every input bid annotated with its post-decryption revenue;
// Winner points into Bids at the entry the arbiter chose, or is nil iff
// Bids is empty. Bids is shuffled+sorted for uniform tie-breaking, so do
// not rely on positional alignment with the input.
type ArbitrateResponse struct {
	Bids   []ArbiterBid
	Winner *ArbiterBid
}

// RandSource is the source of randomness used for tie-breaking in
// [RankBids]. Production callers pass nil to use [math/rand]; tests can
// inject a deterministic source.
type RandSource interface {
	Intn(n int) int
	Shuffle(n int, swap func(i, j int))
}

// RankBids returns the input bids annotated with their resolved revenue,
// shuffled and stably sorted by revenue descending. The first entry of
// [ArbitrateResponse.Bids] is also returned as [ArbitrateResponse.Winner]
// (or nil if bids is empty). RankBids does not mutate the input slice.
//
// randSource is consulted only for the initial shuffle (which makes ties
// break uniformly at random). Pass nil to use [math/rand].
func RankBids(bids []ArbiterBid, randSource RandSource) *ArbitrateResponse {
	resp := &ArbitrateResponse{Bids: make([]ArbiterBid, len(bids))}
	copy(resp.Bids, bids)
	if len(resp.Bids) == 0 {
		return resp
	}
	shuffle := rand.Shuffle
	if randSource != nil {
		shuffle = randSource.Shuffle
	}
	shuffle(len(resp.Bids), func(i, j int) {
		resp.Bids[i], resp.Bids[j] = resp.Bids[j], resp.Bids[i]
	})
	slices.SortStableFunc(resp.Bids, func(a, b ArbiterBid) int {
		return cmp.Compare(b.Revenue, a.Revenue)
	})
	resp.Winner = &resp.Bids[0]
	return resp
}
