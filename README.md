# Sentinel

[![npm version](https://img.shields.io/npm/v/@fabrknt/sentinel-core.svg)](https://www.npmjs.com/package/@fabrknt/sentinel-core)
[![npm downloads](https://img.shields.io/npm/dm/@fabrknt/sentinel-core.svg)](https://www.npmjs.com/package/@fabrknt/sentinel-core)

Chain-agnostic DeFi security infrastructure. Transaction security analysis, execution patterns, and atomic bundle management.

Part of [Fabrknt](https://fabrknt.com) — plug-in compliance for existing DeFi protocols. `npm install @fabrknt/sentinel-core`

## Packages

| Package | Description |
|---------|-------------|
| `@fabrknt/sentinel-core` | Guard detector, simulation sandbox, pattern builders, bundle managers |
| `@fabrknt/sentinel-qn-addon` | QuickNode Marketplace REST add-on (Express) |

## Guard — Transaction Security Analysis

Chain-agnostic pre-execution security analysis with 17 pattern detectors. Pass `chain: "solana"` or `chain: "evm"` on each transaction.

### Solana Patterns (P-101 – P-108)

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

### EVM Patterns (EVM-001 – EVM-009)

| Pattern | ID | Severity |
|---------|----|----------|
| Reentrancy attack | EVM-001 | Critical |
| Flash loan attack | EVM-002 | Critical |
| Front-running / sandwich | EVM-003 | Alert |
| Unauthorized access | EVM-004 | Warning/Critical |
| Price manipulation | EVM-005 | Critical |
| Proxy upgrade | EVM-006 | Alert |
| Approval abuse | EVM-007 | Warning |
| Honeypot token | EVM-008 | Critical |
| Governance attack | EVM-009 | Alert |

Three enforcement modes (`block`, `warn`) and three risk tolerances (`strict`, `moderate`, `permissive`).

### Simulation Sandbox

Pre-execution simulation with automatic fallback:

- **EVM**: `eth_call` → `eth_estimateGas` → `trace_call` (Parity) → `debug_traceCall` (Geth)
- **Solana**: `simulateTransaction` with post-simulation account state comparison

Features: revert reason decoding (`Error(string)`, `Panic(uint256)`), bytecode opcode scanning with PUSH-data skipping, EIP-1167/EIP-1967 proxy detection, honeypot analysis, state change tracking.

### Oracle Registry

Dynamic oracle feed resolution via [Chainlink Feed Registry](https://docs.chain.link/data-feeds/feed-registry) (`0x47Fb2585D2C56Fe188D0E6ec628a38b74fCeeeDf`). Automatically discovers price feeds for known assets (WETH, WBTC, LINK, UNI, AAVE) against USD/BTC denominators and merges them into Guard's oracle address list for price manipulation detection (EVM-005).

## Patterns — Execution Plan Builders

Chain-agnostic pattern builders for common DeFi operations:

| Pattern | Endpoint | Description |
|---------|----------|-------------|
| Batch Payout | `/v1/pattern/batch-payout` | Optimized multi-recipient payout batching |
| Recurring Payment | `/v1/pattern/recurring-payment` | Payment schedule builder |
| Token Vesting | `/v1/pattern/vesting` | Cliff + linear vesting schedule |
| Grid Trading | `/v1/pattern/grid-trading` | Buy/sell grid level planning |
| DCA | `/v1/pattern/dca` | Dollar-cost averaging schedule |
| Rebalance | `/v1/pattern/rebalance` | Portfolio rebalancing with drift detection |

## Bundle — Atomic Transaction Bundles

Abstract `BaseBundleManager` with chain-specific implementations:

| Chain | Implementation | Protocol | Description |
|-------|---------------|----------|-------------|
| Solana | `BundleManager` | Jito Block Engine | Bundle submission with tip management, region routing |
| EVM | `FlashbotsBundleManager` | Flashbots / MEV-Share | Private transaction submission, bundle simulation |

### EVM Bundle Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/bundle/submit` | POST | Submit bundle via Flashbots or MEV-Share |
| `/v1/bundle/simulate` | POST | Simulate bundle via `eth_callBundle` |
| `/v1/bundle/private-tx` | POST | Send single private tx via Flashbots Protect |
| `/v1/bundle/status/:id` | GET | Check bundle status (query `?chain=evm`) |

### Solana Bundle Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/bundle/tip` | POST | Calculate Jito tip amount + random tip account |
| `/v1/bundle/submit` | POST | Submit bundle to Jito Block Engine |
| `/v1/bundle/status/:id` | GET | Check bundle confirmation status |

All bundle endpoints require a **pro** plan. Starter plan gets HTTP 403.

### Flashbots AuthSigner

The Flashbots relay expects `X-Flashbots-Signature: {address}:{signature}` authentication. Set `FLASHBOTS_AUTH_KEY` to a 32-byte hex private key. The add-on implements the full signing protocol:

1. `bodyHash = keccak256(jsonRpcBody)`
2. `message = "\x19Ethereum Signed Message:\n32" + bodyHash` (EIP-191)
3. `msgHash = keccak256(message)`
4. `signature = ECDSA(msgHash, privateKey)` → 65 bytes (r + s + v)

Uses `@noble/hashes` (keccak256) and `@noble/curves` (secp256k1) — audited, zero-dependency, pure JS.

**SDK usage** — bring your own signer:

```typescript
import { FlashbotsBundleManager } from "@fabrknt/sentinel-core";
import type { AuthSigner } from "@fabrknt/sentinel-core";

// With ethers.js v6
import { Wallet, id } from "ethers";
const wallet = new Wallet(privateKey);
const signer: AuthSigner = {
  address: wallet.address,
  sign: (body) => wallet.signMessage(id(body)),
};

// With viem
import { privateKeyToAccount } from "viem/accounts";
import { keccak256, toBytes } from "viem";
const account = privateKeyToAccount(privateKey);
const signer: AuthSigner = {
  address: account.address,
  sign: (body) => account.signMessage({ message: keccak256(toBytes(body)) }),
};

const manager = new FlashbotsBundleManager({
  endpoint: rpcUrl,
  authSigner: signer,
});
```

## QuickNode Marketplace

### PUDD Lifecycle

The add-on implements the full QuickNode Marketplace [PUDD protocol](https://www.quicknode.com/docs/marketplace/add-on-api):

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/provision` | POST | Create new instance |
| `/update` | PUT | Change plan tier |
| `/deactivate_endpoint` | DELETE | Deactivate endpoint |
| `/deprovision` | DELETE | Remove instance |
| `/healthcheck` | GET | Service health check |

PUDD endpoints require Basic Auth (`QN_BASIC_AUTH_USERNAME` / `QN_BASIC_AUTH_PASSWORD`).

### Plan Tiers

| Feature | Starter | Pro |
|---------|---------|-----|
| Guard (17 patterns) | Yes | Yes |
| Simulation sandbox | Yes | Yes |
| Execution patterns | Yes | Yes |
| Bundle submission | No | Yes |
| Rate limit | 100 req/min | 200 req/min |

### Middleware Chain

All `/v1/*` API routes pass through:

1. **instanceLookup** — resolves `X-INSTANCE-ID` header to a provisioned instance
2. **apiLimiter** — plan-aware rate limiting (100/min starter, 200/min pro)
3. **requirePlan("pro")** — bundle routes only, rejects starter plan with 403

## Quick Start

### As SDK

```typescript
import { Guard, buildGridTradingPlan, BundleManager } from "@fabrknt/sentinel-core";

// Analyze a transaction (Solana or EVM)
const guard = new Guard({ mode: "block", riskTolerance: "strict" });
const result = await guard.validateTransaction({
  id: "tx1",
  chain: "evm",
  status: "pending",
  instructions: [
    { programId: "0xContract", keys: [], data: "0x12345678" },
  ],
});

// With simulation enabled
const guardSim = new Guard({
  mode: "block",
  riskTolerance: "strict",
  enableSimulation: true,
  simulationConfig: { rpcUrl: "https://eth-mainnet.example.com" },
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
```

### As REST API

```bash
# Analyze transaction security
curl -X POST http://localhost:3050/v1/guard/analyze \
  -H "Content-Type: application/json" \
  -H "X-INSTANCE-ID: your-endpoint-id" \
  -d '{"transaction": {"id": "tx1", "chain": "evm", "status": "pending", "instructions": [{"programId": "0xContract", "keys": [], "data": "0x12345678"}]}}'

# Build a DCA plan
curl -X POST http://localhost:3050/v1/pattern/dca \
  -H "Content-Type: application/json" \
  -H "X-INSTANCE-ID: your-endpoint-id" \
  -d '{"pair": {"base": {"address": "0xETH", "symbol": "ETH", "decimals": 18}, "quote": {"address": "0xUSDC", "symbol": "USDC", "decimals": 6}}, "totalAmount": 1000, "numberOfOrders": 10, "intervalMs": 86400000}'

# Submit EVM bundle via Flashbots
curl -X POST http://localhost:3050/v1/bundle/submit \
  -H "Content-Type: application/json" \
  -H "X-INSTANCE-ID: your-pro-endpoint-id" \
  -d '{"chain": "evm", "transactions": ["0xSignedTx1"], "blockNumber": 19000000}'

# Submit Solana bundle via Jito
curl -X POST http://localhost:3050/v1/bundle/submit \
  -H "Content-Type: application/json" \
  -H "X-INSTANCE-ID: your-pro-endpoint-id" \
  -d '{"chain": "solana", "transactions": ["base64Tx1", "base64Tx2"]}'

# Get a Jito tip account
curl -X POST http://localhost:3050/v1/bundle/tip \
  -H "Content-Type: application/json" \
  -H "X-INSTANCE-ID: your-pro-endpoint-id" \
  -d '{"level": "medium", "region": "tokyo"}'
```

## Architecture

```
@fabrknt/sentinel-core
├── guard/
│   ├── index.ts               # Guard class with simulation + oracle integration
│   ├── detector.ts            # Chain-routing dispatcher
│   ├── solana-detector.ts     # Solana patterns (P-101 – P-108)
│   ├── evm-detector.ts        # EVM patterns (EVM-001 – EVM-009)
│   └── oracle-registry.ts     # Chainlink Feed Registry resolver
├── simulation/
│   └── index.ts               # SimulationSandbox (EVM + Solana)
├── bundle/
│   ├── base.ts                # Abstract BaseBundleManager
│   ├── jito.ts                # Solana/Jito implementation
│   └── flashbots.ts           # EVM/Flashbots + MEV-Share implementation
├── patterns/
│   └── index.ts               # Chain-agnostic execution builders
└── types.ts                   # Chain type, Transaction, SecurityWarning, etc.

@fabrknt/sentinel-qn-addon
├── server.ts                  # Express app with middleware chain
├── routes/
│   ├── provision.ts           # PUDD lifecycle endpoints
│   ├── guard.ts               # /v1/guard/* routes
│   ├── patterns.ts            # /v1/pattern/* routes
│   └── bundle.ts              # /v1/bundle/* routes (Jito + Flashbots)
├── middleware/
│   ├── basic-auth.ts          # Basic auth for PUDD endpoints
│   ├── instance-lookup.ts     # X-INSTANCE-ID resolution
│   ├── plan-gate.ts           # Plan tier enforcement
│   ├── rate-limit.ts          # Plan-aware rate limiting
│   ├── request-id.ts          # Request ID generation
│   └── error-handler.ts       # Global error handler
└── db/
    └── database.ts            # SQLite instance storage
```

## Development

This project uses [pnpm](https://pnpm.io/) and [Turborepo](https://turbo.build/) for build orchestration.

```bash
pnpm install
pnpm build        # Build all packages
pnpm test         # Run all tests (185 passing)
pnpm dev          # Start server on port 3050
```

### Environment Setup

```bash
cp .env.example .env
# or for the add-on specifically:
cp packages/qn-addon/.env.example packages/qn-addon/.env
```

See [`.env.example`](.env.example) for all configuration options.

### Tests

```bash
# All tests
pnpm test

# Core only (151 tests: guard, simulation, patterns, types, integration)
pnpm --filter @fabrknt/sentinel-core test

# Add-on only (34 tests: routes, auth-signer)
pnpm --filter @fabrknt/sentinel-qn-addon test
```

## Fabrknt Product Suite

| Product | Slug | Scope |
|---------|------|-------|
| On-Chain Compliance | fabrknt-onchain-compliance | KYC/AML, identity, transfer hooks |
| Off-Chain Compliance | fabrknt-offchain-compliance | Screening, SAR/STR, regulatory queries |
| Data Optimization | fabrknt-data-optimization | Merkle trees, bitfields, order matching |
| Privacy | fabrknt-privacy | Encryption, Shamir, ZK compression |
| **DeFi Toolkit** | **fabrknt-defi-toolkit** | **Guard, simulation, patterns, bundles** |

## License

MIT
