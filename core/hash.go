package core

import (
	"crypto/sha256"
	"fmt"
	"strconv"
)

// ComputeBidHash returns the canonical hash of a bid as it participated
// in arbitration. Both the enclave (when emitting attestation user data)
// and validators (when verifying it after the fact) compute the hash the
// same way, so a bidder can prove that its bid was included in a
// particular arbitration round.
//
// Formula: SHA256(bid_id + "|" + decimal(revenue_micros) + "|" + nonce).
//
// The revenue is bound as an integer in [MicroDollars] so the hash is
// independent of any float formatting.
func ComputeBidHash(bidID string, revenueMicros MicroDollars, nonce string) string {
	data := bidID + "|" + strconv.FormatInt(int64(revenueMicros), 10) + "|" + nonce
	sum := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", sum)
}

// ComputeRequestHash returns the canonical hash of an arbitration
// request envelope. As with [ComputeBidHash], the enclave and validators
// agree on this formula so callers can prove their request reached the
// arbiter unaltered.
//
// Formula: SHA256(request_id + "|" + nonce).
func ComputeRequestHash(requestID, nonce string) string {
	data := requestID + "|" + nonce
	sum := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", sum)
}
