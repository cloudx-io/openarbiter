# CloudX's Open Arbiter

Core arbitration logic and TEE (Trusted Execution Environment) enclave implementation for CloudX revenue arbitration.

https://www.cloudx.ai/

## Overview

This repository contains the arbitration functionality that has been extracted from the main CloudX platform for independent versioning and reusability. The arbiter ranks already-resolved bids whose revenue may be sealed to a public key held only by the enclave. It includes:

- **`core/`**: Core arbitration logic including bid ranking, sealing of encrypted revenue, and wire types
- **`enclaveapi/`**: API types for TEE enclave communication
- **`enclave/`**: AWS Nitro Enclave implementation for secure arbitration and key management
- **`enclave-image/`**: Dockerfile and assets for building the enclave image
- **`cmd/enclave-server/`**: vsock entry point that runs inside the enclave
- **`validation/`**: Host-side attestation, certificate, and PCR validation helpers

## Usage

### Importing in Go

```go
import (
    "github.com/cloudx-io/openarbiter/core"
    "github.com/cloudx-io/openarbiter/enclaveapi"
    "github.com/cloudx-io/openarbiter/enclave"
)
```

### Example: Ranking Bids

```go
bids := []core.ArbiterBid{
    {Bid: &core.Bid{ID: uuid.New(), Source: "bidder-a"}, Revenue: 2_500_000},
    {Bid: &core.Bid{ID: uuid.New(), Source: "bidder-b"}, Revenue: 3_000_000},
}

// RankBids takes a RandSource for tie-breaking shuffling.
// Pass nil to use math/rand (default).
resp := core.RankBids(bids, nil)
fmt.Printf("Winner: %s @ %d\n", resp.Winner.Bid.Source, resp.Winner.Revenue)
```

**Sealed revenue**: Bidders seal their preferred revenue into `Bid.EncryptedCPMDollars` (via `core.SealCPMDollars`) under a public key obtained from the enclave's attested key endpoint. The arbiter inside the enclave decrypts and produces an `ArbiterBid` per input; it falls back to `Bid.CleartextRevenue` when the ciphertext is absent or unrecoverable. The selection logic in `core/` is pure and never touches a private key.

**Tie-breaking**: `RankBids` shuffles before a stable sort by revenue descending, so equal-revenue bids break uniformly at random. Tests can inject a deterministic `RandSource`.

## Development

### Running Tests

```bash
go test ./...
```

### Building the Enclave

The enclave binary can be built using the Dockerfile:

```bash
docker build -f enclave-image/Dockerfile -t arbiter-enclave .
```
