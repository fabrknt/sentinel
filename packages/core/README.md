# @fabrknt/sentinel-core

[![npm version](https://img.shields.io/npm/v/@fabrknt/sentinel-core.svg)](https://www.npmjs.com/package/@fabrknt/sentinel-core)
[![npm downloads](https://img.shields.io/npm/dm/@fabrknt/sentinel-core.svg)](https://www.npmjs.com/package/@fabrknt/sentinel-core)

Transaction security analysis, execution pattern builders, and atomic bundle management for Solana and EVM chains.

Not every DeFi protocol needs TradFi compliance -- but if yours does, you shouldn't have to rebuild from scratch. Fabrknt plugs into your existing protocol with composable SDKs and APIs. No permissioned forks, no separate deployments.

## Install

```bash
npm install @fabrknt/sentinel-core
```

## Quick Start

```typescript
import {
  Guard,
  buildDCAPlan,
  FlashbotsBundleManager,
} from '@fabrknt/sentinel-core';

// Analyze a transaction before execution
const guard = new Guard({ mode: 'block', riskTolerance: 'strict' });
const result = await guard.validateTransaction({
  id: 'tx-1',
  chain: 'evm',
  status: 'pending',
  instructions: [{ programId: '0xContract', keys: [], data: '0x...' }],
});

if (!result.allowed) {
  console.log('Blocked:', result.warnings);
}
```

## Features

- 17 security pattern detectors -- 8 Solana-specific (P-101 to P-108), 9 EVM-specific (EVM-001 to EVM-009)
- Pre-execution simulation sandbox -- EVM (`eth_call`, `trace_call`, `debug_traceCall`) and Solana (`simulateTransaction`)
- Three enforcement modes (`block`, `warn`) and risk tolerances (`strict`, `moderate`, `permissive`)
- Chainlink Oracle Registry integration for price manipulation detection
- 6 execution pattern builders -- batch payout, recurring payment, vesting, grid trading, DCA, rebalance
- Jito bundle submission for Solana (tip management, region routing)
- Flashbots/MEV-Share bundle submission for EVM (private transactions, bundle simulation)
- Bring-your-own AuthSigner interface for Flashbots relay authentication

## API Summary

### Guard

| Export | Description |
|--------|-------------|
| `Guard` | Main class -- configure mode, risk tolerance, simulation, oracles |
| `analyzeTransaction` | Standalone analysis function |
| `analyzeSolanaTransaction` | Solana-specific analysis |
| `analyzeEvmTransaction` | EVM-specific analysis |
| `SimulationSandbox` | Pre-execution simulation with automatic RPC fallback |
| `resolveOracleFromRegistry` | Resolve Chainlink price feeds dynamically |

### Patterns

| Export | Description |
|--------|-------------|
| `buildBatchPayout` | Optimized multi-recipient payout batching |
| `buildRecurringPaymentSchedule` | Payment schedule builder |
| `buildVestingSchedule` | Cliff + linear vesting schedule |
| `buildGridTradingPlan` | Buy/sell grid level planning |
| `buildDCAPlan` | Dollar-cost averaging schedule |
| `buildRebalancePlan` | Portfolio rebalancing with drift detection |

### Bundles

| Export | Description |
|--------|-------------|
| `BundleManager` | Solana/Jito bundle submission |
| `FlashbotsBundleManager` | EVM/Flashbots bundle submission and simulation |
| `BaseBundleManager` | Abstract base class for custom implementations |

All pattern and bundle types are fully exported (e.g., `GridTradingConfig`, `FlashbotsBundleConfig`, `AuthSigner`).

## Documentation

Full documentation, REST API reference, and QuickNode add-on details are available in the [main repository README](https://github.com/fabrknt/sentinel#readme).

## License

MIT
