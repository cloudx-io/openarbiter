package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMicroDollarsAsMicros(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   MicroDollars
		want MicroDollars
	}{
		{"zero", 0, 0},
		{"positive", 1_500_000, 1_500_000},
		{"negative", -42, -42},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, tc.in.AsMicros())
		})
	}
}

func TestDollarsAsMicros(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   Dollars
		want MicroDollars
	}{
		{"zero", 0, 0},
		{"one_dollar", 1, 1_000_000},
		{"fractional", 0.25, 250_000},
		{"negative", -2.5, -2_500_000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, tc.in.AsMicros())
		})
	}
}

func TestDollarsPerMilleDollars(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   DollarsPerMille
		want Dollars
	}{
		{"zero", 0, 0},
		{"one_thousand_dpm_is_one_dollar", 1_000, 1},
		{"common_cpm", 5, 0.005},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.in.Dollars())
		})
	}
}

func TestDollarsPerMille_RoundTrip(t *testing.T) {
	t.Parallel()
	assert.Equal(t, MicroDollars(5_000), DollarsPerMille(5).Dollars().AsMicros())
}

func TestCurrencyInterface(_ *testing.T) {
	var _ Currency = MicroDollars(0)
	var _ Currency = Dollars(0)
}
