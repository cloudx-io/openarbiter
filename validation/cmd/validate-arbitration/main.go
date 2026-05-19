// Command validate-arbitration verifies an arbiter attestation against
// a set of trusted PCR measurements. It is the off-enclave half of the
// arbitration trust pipeline: bidders run it (or the CI equivalent) to
// confirm the arbiter saw and ranked their bid as expected.
//
// Usage:
//
//	validate-arbitration -pcrs <pcrs.json> \
//	                     -request-id <req-id> \
//	                     -bid-id <bid-id> \
//	                     -revenue-micros <int64> \
//	                     [-is-winner] \
//	                     [-format text|json] \
//	                     <attestation-cose-gzip>
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/cloudx-io/openarbiter/core"
	"github.com/cloudx-io/openarbiter/enclaveapi"
	"github.com/cloudx-io/openarbiter/validation"
)

func main() {
	pcrsPath := flag.String("pcrs", validation.DefaultPCRConfigPath(), "Path to pcrs.json")
	requestID := flag.String("request-id", "", "Arbitration request ID (required)")
	bidID := flag.String("bid-id", "", "Caller's bid ID (required)")
	revenueMicros := flag.Int64("revenue-micros", 0, "Caller's per-impression revenue in MicroDollars")
	isWinner := flag.Bool("is-winner", false, "Whether the caller expects to have won")
	outputFormat := flag.String("format", "text", "Output format: text or json")
	flag.Parse()

	if flag.NArg() != 1 || *requestID == "" || *bidID == "" {
		flag.Usage()
		os.Exit(2)
	}

	knownPCRs, err := validation.LoadPCRsFromFile(*pcrsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load PCR config: %v\n", err)
		os.Exit(2)
	}

	coseGzip := enclaveapi.AttestationCOSEGzip(flag.Arg(0))
	result, err := validation.ValidateArbitrationAttestation(&validation.ArbitrationValidationInput{
		AttestationCOSEGzip: coseGzip,
		KnownPCRs:           knownPCRs,
		RequestID:           *requestID,
		BidID:               *bidID,
		BidRevenue:          core.MicroDollars(*revenueMicros),
		IsWinner:            *isWinner,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "validate: %v\n", err)
		os.Exit(2)
	}

	if *outputFormat == "json" {
		_ = json.NewEncoder(os.Stdout).Encode(result)
	} else {
		fmt.Printf("Valid: %t\n", result.IsValid())
		fmt.Println("Details:")
		for _, d := range result.ValidationDetails {
			fmt.Printf("  - %s\n", d)
		}
	}
	if !result.IsValid() {
		os.Exit(1)
	}
}
