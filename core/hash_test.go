package core

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestComputeBidHash_Deterministic(t *testing.T) {
	t.Parallel()
	got := ComputeBidHash("bid_123", MicroDollars(2_500_000), "nonce_456")
	assert.Len(t, got, 64)
	assert.Equal(t, got, ComputeBidHash("bid_123", MicroDollars(2_500_000), "nonce_456"))
}

func TestComputeBidHash_DistinctInputsDistinctHashes(t *testing.T) {
	t.Parallel()
	base := ComputeBidHash("bid_123", MicroDollars(2_500_000), "nonce_456")
	assert.NotEqual(t, base, ComputeBidHash("bid_124", MicroDollars(2_500_000), "nonce_456"))
	assert.NotEqual(t, base, ComputeBidHash("bid_123", MicroDollars(2_500_001), "nonce_456"))
	assert.NotEqual(t, base, ComputeBidHash("bid_123", MicroDollars(2_500_000), "nonce_457"))
}

func TestComputeBidHash_KnownVector(t *testing.T) {
	t.Parallel()
	// Pin the formula so accidental changes show up as test failures.
	expected := sha256.Sum256([]byte("bid_123|2500000|nonce_456"))
	assert.Equal(t,
		fmt.Sprintf("%x", expected),
		ComputeBidHash("bid_123", MicroDollars(2_500_000), "nonce_456"),
	)
}

func TestComputeRequestHash_Deterministic(t *testing.T) {
	t.Parallel()
	got := ComputeRequestHash("req-abc", "nonce_xyz")
	assert.Len(t, got, 64)
	assert.Equal(t, got, ComputeRequestHash("req-abc", "nonce_xyz"))
}

func TestComputeRequestHash_DistinctInputsDistinctHashes(t *testing.T) {
	t.Parallel()
	base := ComputeRequestHash("req-abc", "nonce_xyz")
	assert.NotEqual(t, base, ComputeRequestHash("req-abd", "nonce_xyz"))
	assert.NotEqual(t, base, ComputeRequestHash("req-abc", "nonce_xyy"))
}

func TestComputeRequestHash_KnownVector(t *testing.T) {
	t.Parallel()
	expected := sha256.Sum256([]byte("req-abc|nonce_xyz"))
	assert.Equal(t,
		fmt.Sprintf("%x", expected),
		ComputeRequestHash("req-abc", "nonce_xyz"),
	)
}
