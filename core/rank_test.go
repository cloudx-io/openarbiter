package core

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func resolved(amountMicros int64) ArbiterBid {
	b := Bid{ID: uuid.New(), Source: "FAKE"}
	return ArbiterBid{Bid: &b, Revenue: MicroDollars(amountMicros)}
}

func TestRankBids_Empty(t *testing.T) {
	t.Parallel()
	for _, in := range [][]ArbiterBid{nil, {}} {
		resp := RankBids(in, nil)
		require.NotNil(t, resp)
		assert.Empty(t, resp.Bids)
		assert.Nil(t, resp.Winner)
	}
}

func TestRankBids_Single(t *testing.T) {
	t.Parallel()
	b := resolved(1_000_000)
	resp := RankBids([]ArbiterBid{b}, nil)
	require.NotNil(t, resp.Winner)
	assert.Equal(t, b.Bid.ID, resp.Winner.Bid.ID)
}

func TestRankBids_PicksHighestAmount(t *testing.T) {
	t.Parallel()
	low := resolved(1_000_000)
	mid := resolved(5_000_000)
	high := resolved(10_000_000)

	for i := range 20 {
		resp := RankBids([]ArbiterBid{low, high, mid}, nil)
		require.NotNil(t, resp.Winner)
		assert.Equalf(t, high.Bid.ID, resp.Winner.Bid.ID,
			"iteration %d: picked revenue=%d, want highest=10_000_000",
			i, resp.Winner.Revenue)
	}
}

func TestRankBids_Tie_AllAmongTopArePossible(t *testing.T) {
	t.Parallel()
	a := resolved(5_000_000)
	b := resolved(5_000_000)
	c := resolved(5_000_000)
	low := resolved(1_000_000)

	seen := map[uuid.UUID]int{}
	for range 200 {
		resp := RankBids([]ArbiterBid{low, a, b, c}, nil)
		require.NotNil(t, resp.Winner)
		require.NotEqualf(t, low.Bid.ID, resp.Winner.Bid.ID,
			"RankBids returned the low bid despite a higher tie")
		seen[resp.Winner.Bid.ID]++
	}
	for _, id := range []uuid.UUID{a.Bid.ID, b.Bid.ID, c.Bid.ID} {
		assert.NotZerof(t, seen[id],
			"tie-break never selected %v over 200 trials (seen=%v)", id, seen)
	}
}

// TestRankBids_DoesNotMutateInput pins the no-shuffle-of-caller-slice
// guarantee.
func TestRankBids_DoesNotMutateInput(t *testing.T) {
	t.Parallel()
	in := []ArbiterBid{
		resolved(1_000_000),
		resolved(5_000_000),
		resolved(10_000_000),
		resolved(2_000_000),
	}
	before := make([]uuid.UUID, len(in))
	for i, ab := range in {
		before[i] = ab.Bid.ID
	}
	_ = RankBids(in, nil)
	for i, ab := range in {
		assert.Equalf(t, before[i], ab.Bid.ID,
			"RankBids mutated caller slice at index %d", i)
	}
}

// TestRankBids_ReturnsAllBids exercises the host-facing contract: every
// input bid appears in [ArbitrateResponse.Bids] with its revenue, and
// [ArbitrateResponse.Winner] points into that slice at the highest entry.
func TestRankBids_ReturnsAllBids(t *testing.T) {
	t.Parallel()
	low := resolved(1_000_000)
	mid := resolved(5_000_000)
	high := resolved(10_000_000)

	resp := RankBids([]ArbiterBid{low, mid, high}, nil)
	require.Len(t, resp.Bids, 3)
	require.NotNil(t, resp.Winner)
	assert.Equal(t, high.Bid.ID, resp.Winner.Bid.ID)
	assert.Equal(t, MicroDollars(10_000_000), resp.Winner.Revenue)

	byID := map[uuid.UUID]ArbiterBid{}
	for _, ab := range resp.Bids {
		require.NotNil(t, ab.Bid)
		byID[ab.Bid.ID] = ab
	}
	assert.Equal(t, MicroDollars(1_000_000), byID[low.Bid.ID].Revenue)
	assert.Equal(t, MicroDollars(5_000_000), byID[mid.Bid.ID].Revenue)
	assert.Equal(t, MicroDollars(10_000_000), byID[high.Bid.ID].Revenue)
}

// TestRankBids_PreservesDecryptedFlag confirms RankBids carries the
// per-bid Decrypted flag through the shuffle+sort unchanged.
func TestRankBids_PreservesDecryptedFlag(t *testing.T) {
	t.Parallel()
	sealed := resolved(10_000_000)
	sealed.Decrypted = true
	fallback := resolved(1_000_000)
	fallback.Decrypted = false

	resp := RankBids([]ArbiterBid{fallback, sealed}, nil)
	require.Len(t, resp.Bids, 2)
	// Winner first: highest revenue is the decrypted one.
	assert.Equal(t, sealed.Bid.ID, resp.Bids[0].Bid.ID)
	assert.True(t, resp.Bids[0].Decrypted)
	assert.Equal(t, fallback.Bid.ID, resp.Bids[1].Bid.ID)
	assert.False(t, resp.Bids[1].Decrypted)
}
