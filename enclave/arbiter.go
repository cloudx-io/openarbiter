// Package enclave hosts the components of the arbiter that must run
// inside a TEE: the RSA private key that opens sealed bid prices, and the
// arbitration entry point that decrypts those bids and ranks them.
//
// In production, the arbiter's private key is generated inside the
// enclave and never leaves it. [Arbiter] is the in-process counterpart
// used both by tests and by the host process while the enclave deployment
// is still being built out.
package enclave

import (
	"crypto/rsa"

	"github.com/cloudx-io/openarbiter/core"
)

// NewArbiter constructs an [Arbiter] using the given RSA private key.
// Passing a nil priv is allowed (plaintext-only operation) but returns
// [core.ErrNoKey] so misconfigurations do not go unnoticed; the returned
// [*Arbiter] is still non-nil and usable for cleartext-only bids.
func NewArbiter(priv *rsa.PrivateKey) (*Arbiter, error) {
	a := &Arbiter{}
	if priv == nil {
		return a, core.ErrNoKey
	}
	a.priv = priv
	return a, nil
}

// Arbiter holds the recipient private key for sealed bid prices and
// drives the per-bid decryption that feeds [core.RankBids].
type Arbiter struct {
	priv *rsa.PrivateKey
}

// GetRevenue returns the bid's effective revenue: the decrypted
// ciphertext when one is present and decryption succeeds, otherwise the
// cleartext amount. Decryption failures fall back to cleartext silently
// — the bid still participates in arbitration.
//
// GetRevenue is not memoized — each call performs the hybrid-RSA
// decryption afresh. Callers ranking many bids should resolve each bid's
// revenue exactly once via [Arbiter.Arbitrate].
func (a *Arbiter) GetRevenue(b core.Bid) core.Currency {
	revenue, err := decryptCPMDollars(a.priv, b.EncryptedCPMDollars)
	if err == nil {
		return revenue.Dollars()
	}
	if b.CleartextRevenue == nil {
		return core.ZeroDollars
	}
	return b.CleartextRevenue
}

// Arbitrate resolves each input bid's revenue exactly once via
// [Arbiter.GetRevenue] and hands the resulting [core.ArbiterBid] slice to
// [core.RankBids]. Does not mutate bids. randSource is forwarded to
// [core.RankBids]; pass nil to use [math/rand] for tie-breaking.
func (a *Arbiter) Arbitrate(bids []core.Bid, randSource core.RandSource) *core.ArbitrateResponse {
	resolved := make([]core.ArbiterBid, len(bids))
	for i := range bids {
		resolved[i] = core.ArbiterBid{
			Bid:     &bids[i],
			Revenue: a.GetRevenue(bids[i]).AsMicros(),
		}
	}
	return core.RankBids(resolved, randSource)
}
