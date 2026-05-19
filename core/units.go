package core

// ZeroDollars is the zero value of [MicroDollars]. It exists so callers
// returning an absent revenue have an obvious sentinel to reach for.
const ZeroDollars = MicroDollars(0)

// Currency is the comparable revenue interface used by the arbiter.
//
// Prefer comparing revenues in microdollars per impression — this is the
// most precise unit any source is expected to report, so normalize to it
// rather than converting to floats.
type Currency interface {
	AsMicros() MicroDollars
}

var _ Currency = MicroDollars(0)

// MicroDollars is a per-impression revenue expressed in millionths of a
// dollar. It is the canonical comparison unit for arbitration.
type MicroDollars int64

// AsMicros returns the receiver unchanged.
func (md MicroDollars) AsMicros() MicroDollars {
	return md
}

// Dollars is a per-impression revenue expressed in dollars.
type Dollars float64

// AsMicros converts a [Dollars] amount into [MicroDollars].
func (d Dollars) AsMicros() MicroDollars {
	return MicroDollars(d * 1_000_000)
}

// DollarsPerMille is a revenue rate expressed in dollars per thousand
// impressions (CPM).
type DollarsPerMille float64

// Dollars converts a [DollarsPerMille] rate into per-impression [Dollars].
func (dpm DollarsPerMille) Dollars() Dollars {
	return Dollars(dpm / 1_000)
}
