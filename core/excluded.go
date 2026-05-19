package core

// ExcludedBid records a bid that reached the arbiter but did not
// participate in ranking, along with the reason the arbiter rejected
// it. The enclave binds an ExcludedBid slice to its arbitration
// attestation so callers can prove their bid was seen but excluded,
// not silently dropped.
type ExcludedBid struct {
	// BidID identifies the rejected bid as it appeared on the wire.
	BidID string `json:"bid_id"`
	// Reason is a short, stable description of why the arbiter excluded
	// the bid (e.g. "malformed bid id").
	Reason string `json:"reason"`
}

// ExclusionReason values are the stable strings the enclave uses for
// [ExcludedBid.Reason] so off-enclave validators can recognize them.
const (
	// ExclusionReasonMalformedBidID indicates the wire bid's ID could
	// not be parsed as a UUID.
	ExclusionReasonMalformedBidID = "malformed bid id"
)
