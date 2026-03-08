# Sentinel

Chain-agnostic DeFi security infrastructure. Transaction security analysis, execution patterns, and atomic bundle management.

**Fabrknt DeFi Toolkit** (`fabrknt-defi-toolkit`) — the 5th Fabrknt QuickNode Marketplace add-on.

## Packages

| Package | Description |
|---------|-------------|
| `@sentinel/core` | Guard detector, pattern builders, bundle manager |
| `@sentinel/qn-addon` | QuickNode Marketplace REST add-on (Express) |

## What's Inside

### Guard — Transaction Security Analysis

Chain-agnostic transaction security with chain-specific pattern detection. Pass `chain: "solana"` or `chain: "evm"` on each transaction.

#### Solana Patterns (P-101 – P-108)

| Pattern | ID | Severity |
|---------|----|----------|
| Mint authority kill | P-101 | Critical |
| Freeze authority kill | P-102 | Critical |
| Signer mismatch | P-103 | Warning |
| Dangerous account close | P-104 | Alert |
| Malicious Transfer Hook | P-105 | Critical |
| Unexpected hook execution | P-106 | Alert |
| Hook reentrancy | P-107 | Critical |
| Excessive hook accounts | P-108 | Warning |

#### EVM Patterns (EVM-001 – EVM-004)

| Pattern | ID | Severity |
|---------|----|----------|
| Reentrancy attack | EVM-001 | Critical |
| Flash loan attack | EVM-002 | Critical |
| Front-running / sandwich | EVM-003 | Alert |
| Unauthorized access | EVM-004 | Warning/Critical |

Three enforcement modes (`block`, `warn`) and three risk tolerances (`strict`, `moderate`, `permissive`).

### Patterns — Execution Plan Builders

Chain-agnostic pattern builders for common DeFi operations:

| Pattern | Endpoint | Description |
|---------|----------|-------------|
| Batch Payout | `/v1/pattern/batch-payout` | Optimized multi-recipient payout batching |
| Recurring Payment | `/v1/pattern/recurring-payment` | Payment schedule builder |
| Token Vesting | `/v1/pattern/vesting` | Cliff + linear vesting schedule |
| Grid Trading | `/v1/pattern/grid-trading` | Buy/sell grid level planning |
| DCA | `/v1/pattern/dca` | Dollar-cost averaging schedule |
| Rebalance | `/v1/pattern/rebalance` | Portfolio rebalancing with drift detection |

### Bundle — Atomic Transaction Bundles

Abstract `BaseBundleManager` with chain-specific implementations:

| Chain | Implementation | Description |
|-------|---------------|-------------|
| Solana | `BundleManager` (Jito) | Jito Block Engine submission with tip management |
| EVM | Coming soon | Flashbots / MEV-Share integration |

| Endpoint | Description |
|----------|-------------|
| `/v1/bundle/tip` | Calculate tip amount + random tip account (Solana/Jito) |
| `/v1/bundle/submit` | Submit bundle (Pro) |
| `/v1/bundle/status/:id` | Check bundle confirmation status (Pro) |

## Quick Start

### As SDK

```typescript
import { Guard, buildGridTradingPlan, BundleManager } from "@sentinel/core";

// Analyze a Solana transaction
const guard = new Guard({ mode: "block", riskTolerance: "moderate" });
const result = await guard.validateTransaction({
  id: "tx1",
  chain: "solana",
  status: "pending",
  instructions: [...],
});

// Analyze an EVM transaction
const evmResult = await guard.validateTransaction({
  id: "tx2",
  chain: "evm",
  status: "pending",
  instructions: [...],
});

// Build a grid trading plan (chain-agnostic)
const plan = buildGridTradingPlan({
  pair: { base: SOL, quote: USDC },
  lowerBound: 90,
  upperBound: 110,
  gridLevels: 10,
  amountPerGrid: 1,
  currentPrice: { token: "SOL", price: 100, quoteCurrency: "USDC", timestamp: Date.now() },
});

// Submit a Jito bundle (Solana)
const bundler = new BundleManager({ endpoint: "https://api.mainnet-beta.solana.com" });
const tip = bundler.createTipInstruction(payerPubkey, TipLevel.Medium);
```

### As REST API

```bash
# Analyze transaction security (Solana)
curl -X POST http://localhost:3050/v1/guard/analyze \
  -H "Content-Type: application/json" \
  -d '{"transaction": {"id": "tx1", "chain": "solana", "status": "pending", "instructions": [...]}}'

# Analyze transaction security (EVM)
curl -X POST http://localhost:3050/v1/guard/analyze \
  -H "Content-Type: application/json" \
  -d '{"transaction": {"id": "tx2", "chain": "evm", "status": "pending", "instructions": [...]}}'

# Build a DCA plan (chain-agnostic)
curl -X POST http://localhost:3050/v1/pattern/dca \
  -H "Content-Type: application/json" \
  -d '{"pair": {...}, "totalAmount": 1000, "numberOfOrders": 10, "intervalMs": 86400000}'

# Get a Jito tip account (Solana)
curl -X POST http://localhost:3050/v1/bundle/tip \
  -H "Content-Type: application/json" \
  -d '{"level": "medium", "region": "tokyo"}'
```

## Architecture

```
@sentinel/core
├── guard/
│   ├── detector.ts          # Chain-routing dispatcher
│   ├── solana-detector.ts   # Solana patterns (P-101 – P-108)
│   └── evm-detector.ts      # EVM patterns (EVM-001 – EVM-004)
├── bundle/
│   ├── base.ts              # Abstract BaseBundleManager
│   └── jito.ts              # Solana/Jito implementation
├── patterns/                # Chain-agnostic execution builders
└── types.ts                 # Chain type, Transaction, SecurityWarning
```

## Development

This project uses [pnpm](https://pnpm.io/) (`pnpm@10.31.0`) as its package manager and [Turborepo](https://turbo.build/) (`turbo.json`) for build orchestration, following the unified Fabrknt product suite pattern.

```bash
pnpm install
pnpm build     # Runs turbo across all packages
pnpm test      # Runs turbo across all packages
pnpm dev       # Start server on port 3050
```

## Fabrknt Product Suite

| Product | Slug | Scope |
|---------|------|-------|
| On-Chain Compliance | fabrknt-onchain-compliance | KYC/AML, identity, transfer hooks |
| Off-Chain Compliance | fabrknt-offchain-compliance | Screening, SAR/STR, regulatory queries |
| Data Optimization | fabrknt-data-optimization | Merkle trees, bitfields, order matching |
| Privacy | fabrknt-privacy | Encryption, Shamir, ZK compression |
| **DeFi Toolkit** | **fabrknt-defi-toolkit** | **Guard, patterns, bundles** |

## License

MIT
