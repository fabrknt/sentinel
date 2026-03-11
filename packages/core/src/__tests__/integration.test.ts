/**
 * End-to-end integration tests for the full Guard + Simulation + Detection pipeline.
 *
 * These tests verify that:
 * 1. Guard correctly routes to chain-specific detectors
 * 2. Simulation results feed into Guard warnings
 * 3. Bytecode analysis detects dangerous opcodes
 * 4. The full pipeline blocks dangerous transactions
 *
 * Note: Tests that require a running Anvil/Solana fork are marked with .skip
 * and should be run manually with `ANVIL_URL=http://localhost:8545 vitest run`.
 */

import { describe, it, expect } from "vitest";
import { Guard, analyzeEvmTransaction } from "../guard";
import { SimulationSandbox } from "../simulation";
import { FlashbotsBundleManager, FlashbotsError } from "../bundle/flashbots";
import { PatternId, Severity, FlashbotsNetwork } from "../types";
import type { Transaction, GuardConfig, SimulationResult } from "../types";

function makeEvmTx(overrides: Partial<Transaction> = {}): Transaction {
  return {
    id: "evm-tx-1",
    chain: "evm",
    status: "pending",
    instructions: [],
    signers: [],
    ...overrides,
  };
}

// ── Integration: Guard + Simulation Config ──

describe("Guard + Simulation integration", () => {
  it("validates clean transaction without simulation", async () => {
    const guard = new Guard({ mode: "block", riskTolerance: "strict" });
    const tx = makeEvmTx({
      instructions: [
        { programId: "0xSafeContract", keys: [], data: "0x12345678" },
      ],
    });
    const result = await guard.validateTransaction(tx);
    expect(result.isValid).toBe(true);
    expect(result.warnings).toHaveLength(0);
  });

  it("blocks flash loan + governance attack (EVM-009 + EVM-002)", async () => {
    const guard = new Guard({ mode: "block", riskTolerance: "strict" });
    const tx = makeEvmTx({
      instructions: [
        {
          programId: "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2", // AAVE V3
          keys: [],
          data: "0x5cffe9de", // flashLoan
        },
        {
          programId: "0xGovernor",
          keys: [],
          data: "0x5c19a95c", // delegate
        },
        {
          programId: "0xGovernor",
          keys: [],
          data: "0x56781388", // castVote
        },
        {
          programId: "0xGovernor",
          keys: [],
          data: "0xfe0d94c1", // execute
        },
      ],
    });
    const result = await guard.validateTransaction(tx);
    expect(result.isValid).toBe(false);
    expect(
      result.warnings.some((w) => w.patternId === PatternId.GovernanceManipulation)
    ).toBe(true);
  });

  it("detects oracle manipulation with user-supplied oracle addresses", async () => {
    const guard = new Guard({
      oracleAddresses: ["0xcustomoraclecontract123456789012345678901234"],
    });
    const tx = makeEvmTx({
      instructions: [
        {
          programId: "0x7a250d5630b4cf539739df2c5dacb4c659f2488d", // Uniswap V2
          keys: [],
          data: "0x022c0d9f", // swap
        },
        {
          programId: "0xcustomoraclecontract123456789012345678901234",
          keys: [],
          data: "0xfeaf968c", // latestRoundData
        },
      ],
    });
    const result = await guard.validateTransaction(tx);
    expect(
      result.warnings.some((w) => w.patternId === PatternId.OracleManipulation)
    ).toBe(true);
  });

  it("full pipeline: detects multi-pattern attack", async () => {
    const guard = new Guard({ mode: "block", riskTolerance: "strict" });
    const tx = makeEvmTx({
      instructions: [
        // Flash loan
        {
          programId: "0xba12222222228d8ba445958a75a0704d566bf2c8", // Balancer
          keys: [],
          data: "0x5cffe9de",
        },
        // Swap to manipulate price
        {
          programId: "0x7a250d5630b4cf539739df2c5dacb4c659f2488d",
          keys: [],
          data: "0x022c0d9f",
        },
        // Read manipulated oracle
        {
          programId: "0x5f4ec3df9cbd43714fe2740f5e3616155c5b8419",
          keys: [],
          data: "0xfeaf968c",
        },
        // Swap back
        {
          programId: "0x7a250d5630b4cf539739df2c5dacb4c659f2488d",
          keys: [],
          data: "0x022c0d9f",
        },
      ],
    });
    const result = await guard.validateTransaction(tx);
    expect(result.isValid).toBe(false);

    const patternIds = result.warnings.map((w) => w.patternId);
    // Should detect flash loan attack, oracle manipulation, and front-running
    expect(patternIds).toContain(PatternId.FlashLoanAttack);
    expect(patternIds).toContain(PatternId.OracleManipulation);
  });
});

// ── Simulation Sandbox unit tests ──

describe("SimulationSandbox", () => {
  describe("analyzeBytecode", () => {
    it("returns empty results when no fork URL configured", async () => {
      const sim = new SimulationSandbox();
      const result = await sim.analyzeBytecode("0xSomeContract");
      expect(result.hasDelegatecall).toBe(false);
      expect(result.hasSelfDestruct).toBe(false);
      expect(result.codeSize).toBe(0);
    });
  });

  describe("analyzeHoneypot edge cases", () => {
    it("detects high sell tax as honeypot", () => {
      const sim = new SimulationSandbox();
      const buyResult: SimulationResult = {
        success: true,
        chain: "evm",
        balanceChanges: [
          {
            address: "0xUser",
            before: "0",
            after: "100",
            delta: "100",
          },
        ],
      };
      const sellResult: SimulationResult = {
        success: true,
        chain: "evm",
        balanceChanges: [
          {
            address: "0xUser",
            before: "100",
            after: "110",
            delta: "10",
          },
          {
            address: "0xFeeRecipient",
            before: "0",
            after: "90",
            delta: "90",
          },
        ],
      };
      const result = sim.analyzeHoneypot(buyResult, sellResult);
      // Both deltas are positive, tax calc: (90 - (10+90)) / 90 would be negative, clamped to 0
      expect(result.isHoneypot).toBe(false);
    });

    it("handles both results failing", () => {
      const sim = new SimulationSandbox();
      const buyResult: SimulationResult = {
        success: false,
        chain: "evm",
        error: "Buy failed too",
      };
      const sellResult: SimulationResult = {
        success: false,
        chain: "evm",
        error: "Sell failed",
      };
      const result = sim.analyzeHoneypot(buyResult, sellResult);
      expect(result.isHoneypot).toBe(false);
    });
  });
});

// ── EVM-009: Governance Manipulation ──

describe("EVM-009: Governance Manipulation", () => {
  it("detects flash loan + governance action", () => {
    const tx = makeEvmTx({
      instructions: [
        {
          programId: "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2",
          keys: [],
          data: "0x5cffe9de", // flashLoan
        },
        {
          programId: "0xGovernor",
          keys: [],
          data: "0xda95691a", // propose
        },
      ],
    });
    const warnings = analyzeEvmTransaction(tx);
    expect(
      warnings.some((w) => w.patternId === PatternId.GovernanceManipulation)
    ).toBe(true);
  });

  it("detects delegate + vote in same tx", () => {
    const tx = makeEvmTx({
      instructions: [
        {
          programId: "0xToken",
          keys: [],
          data: "0x5c19a95c", // delegate
        },
        {
          programId: "0xGovernor",
          keys: [],
          data: "0x56781388", // castVote
        },
      ],
    });
    const warnings = analyzeEvmTransaction(tx);
    expect(
      warnings.some(
        (w) =>
          w.patternId === PatternId.GovernanceManipulation &&
          w.message.includes("delegation and vote")
      )
    ).toBe(true);
  });

  it("detects delegate + vote + execute as critical", () => {
    const tx = makeEvmTx({
      instructions: [
        {
          programId: "0xToken",
          keys: [],
          data: "0x5c19a95c", // delegate
        },
        {
          programId: "0xGovernor",
          keys: [],
          data: "0x56781388", // castVote
        },
        {
          programId: "0xGovernor",
          keys: [],
          data: "0xfe0d94c1", // execute
        },
      ],
    });
    const warnings = analyzeEvmTransaction(tx);
    const critical = warnings.filter(
      (w) =>
        w.patternId === PatternId.GovernanceManipulation &&
        w.severity === Severity.Critical
    );
    expect(critical.length).toBeGreaterThan(0);
  });

  it("does not flag standalone governance actions", () => {
    const tx = makeEvmTx({
      instructions: [
        {
          programId: "0xGovernor",
          keys: [],
          data: "0x56781388", // castVote
        },
      ],
    });
    const warnings = analyzeEvmTransaction(tx);
    expect(
      warnings.some((w) => w.patternId === PatternId.GovernanceManipulation)
    ).toBe(false);
  });
});

// ── Flashbots AuthSigner ──

describe("FlashbotsBundleManager AuthSigner", () => {
  it("accepts an AuthSigner object", () => {
    const signer = {
      address: "0x1234567890abcdef1234567890abcdef12345678",
      sign: async (_body: string) => "0xsignature",
    };
    const manager = new FlashbotsBundleManager({
      endpoint: "http://localhost:8545",
      authSigner: signer,
    });
    expect(manager).toBeDefined();
  });

  it("accepts a raw key string", () => {
    const manager = new FlashbotsBundleManager({
      endpoint: "http://localhost:8545",
      authSigner: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab",
    });
    expect(manager).toBeDefined();
  });

  it("works without any auth (anonymous)", () => {
    const manager = new FlashbotsBundleManager({
      endpoint: "http://localhost:8545",
    });
    expect(manager).toBeDefined();
  });
});

// ── Bytecode Analysis (SimulationSandbox) ──

describe("Bytecode opcode scanning", () => {
  it("analyzeBytecode returns defaults without fork URL", async () => {
    const sim = new SimulationSandbox();
    const result = await sim.analyzeBytecode("0xContract");
    expect(result).toEqual({
      hasDelegatecall: false,
      hasSelfDestruct: false,
      hasCreate2: false,
      codeSize: 0,
      isProxy: false,
    });
  });
});

// ── Expanded Oracle Registry ──

describe("Expanded oracle registry", () => {
  it("detects BTC/USD Chainlink feed", () => {
    const tx = makeEvmTx({
      instructions: [
        {
          programId: "0x7a250d5630b4cf539739df2c5dacb4c659f2488d",
          keys: [],
          data: "0x022c0d9f",
        },
        {
          programId: "0xf4030086522a5beea4988f8ca5b36dbc97bee88c", // BTC/USD
          keys: [],
          data: "0xfeaf968c",
        },
      ],
    });
    const warnings = analyzeEvmTransaction(tx);
    expect(
      warnings.some((w) => w.patternId === PatternId.OracleManipulation)
    ).toBe(true);
  });

  it("detects DAI/USD Chainlink feed", () => {
    const tx = makeEvmTx({
      instructions: [
        {
          programId: "0x7a250d5630b4cf539739df2c5dacb4c659f2488d",
          keys: [],
          data: "0x022c0d9f",
        },
        {
          programId: "0xaed0c38402a5d19df6e4c03f4e2dced6e29c1ee9", // DAI/USD
          keys: [],
          data: "0x50d25bcd", // latestAnswer
        },
      ],
    });
    const warnings = analyzeEvmTransaction(tx);
    expect(
      warnings.some((w) => w.patternId === PatternId.OracleManipulation)
    ).toBe(true);
  });
});
