import { describe, it, expect } from "vitest";
import {
  Guard,
  analyzeTransaction,
  analyzeSolanaTransaction,
  analyzeEvmTransaction,
} from "../guard";
import { PatternId, Severity } from "../types";
import type { Transaction, GuardConfig } from "../types";

// ── Helpers ──

const TOKEN_PROGRAM_ID = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022_PROGRAM_ID = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

/** Encode a byte array as base64 */
function b64(bytes: number[]): string {
  return Buffer.from(bytes).toString("base64");
}

function makeSolanaTx(overrides: Partial<Transaction> = {}): Transaction {
  return {
    id: "tx-1",
    chain: "solana",
    status: "pending",
    instructions: [],
    signers: [],
    ...overrides,
  };
}

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

// ── Guard class tests ──

describe("Guard", () => {
  describe("constructor and config", () => {
    it("uses default config values", () => {
      const guard = new Guard();
      const cfg = guard.getConfig();
      expect(cfg.enablePatternDetection).toBe(true);
      expect(cfg.riskTolerance).toBe("moderate");
      expect(cfg.mode).toBe("block");
      expect(cfg.emergencyStop).toBe(false);
    });

    it("merges custom config", () => {
      const guard = new Guard({ maxSlippage: 0.5, mode: "warn" });
      const cfg = guard.getConfig();
      expect(cfg.maxSlippage).toBe(0.5);
      expect(cfg.mode).toBe("warn");
      expect(cfg.enablePatternDetection).toBe(true);
    });

    it("updateConfig applies partial updates", () => {
      const guard = new Guard();
      guard.updateConfig({ riskTolerance: "strict" });
      expect(guard.getConfig().riskTolerance).toBe("strict");
      expect(guard.getConfig().mode).toBe("block");
    });
  });

  describe("emergency stop", () => {
    it("blocks all transactions when emergency stop is active", async () => {
      const guard = new Guard({ emergencyStop: true });
      const result = await guard.validateTransaction(makeSolanaTx());
      expect(result.isValid).toBe(false);
      expect(result.blockedBy).toContain(PatternId.MintKill);
      expect(result.warnings[0].message).toContain("EMERGENCY STOP");
    });

    it("activateEmergencyStop / deactivateEmergencyStop work", async () => {
      const guard = new Guard();
      guard.activateEmergencyStop();
      expect(guard.getConfig().emergencyStop).toBe(true);
      const r1 = await guard.validateTransaction(makeSolanaTx());
      expect(r1.isValid).toBe(false);

      guard.deactivateEmergencyStop();
      expect(guard.getConfig().emergencyStop).toBe(false);
    });

    it("validate() returns false with no transaction when emergency stop is on", async () => {
      const guard = new Guard({ emergencyStop: true });
      expect(await guard.validate()).toBe(false);
    });

    it("validate() returns true with no transaction when emergency stop is off", async () => {
      const guard = new Guard();
      expect(await guard.validate()).toBe(true);
    });
  });

  describe("warning history", () => {
    it("accumulates warnings across validations", async () => {
      const guard = new Guard();
      // Each MintKill transaction produces a warning that gets recorded
      const mintKillTx = makeSolanaTx({
        instructions: [
          {
            programId: TOKEN_PROGRAM_ID,
            keys: [{ pubkey: "mintABC", isSigner: false, isWritable: true }],
            data: b64([6, 0, 0]),
          },
        ],
      });
      await guard.validateTransaction(mintKillTx);
      await guard.validateTransaction(mintKillTx);
      expect(guard.getWarningHistory().length).toBeGreaterThanOrEqual(2);
    });

    it("clearWarningHistory resets the history", async () => {
      const guard = new Guard({ emergencyStop: true });
      await guard.validateTransaction(makeSolanaTx());
      guard.clearWarningHistory();
      expect(guard.getWarningHistory()).toHaveLength(0);
    });
  });

  describe("slippage check", () => {
    it("returns true when no maxSlippage is set", () => {
      const guard = new Guard();
      expect(guard.isSlippageAcceptable(100)).toBe(true);
    });

    it("returns true for slippage within limit", () => {
      const guard = new Guard({ maxSlippage: 1.0 });
      expect(guard.isSlippageAcceptable(0.5)).toBe(true);
      expect(guard.isSlippageAcceptable(1.0)).toBe(true);
    });

    it("returns false for slippage exceeding limit", () => {
      const guard = new Guard({ maxSlippage: 1.0 });
      expect(guard.isSlippageAcceptable(1.1)).toBe(false);
    });
  });

  describe("mode = warn", () => {
    it("never blocks even on critical warnings", async () => {
      const guard = new Guard({ mode: "warn" });
      // SetAuthority with authorityType=0 (MintAuthority), no new authority -> MintKill
      const tx = makeSolanaTx({
        instructions: [
          {
            programId: TOKEN_PROGRAM_ID,
            keys: [{ pubkey: "mintABC", isSigner: false, isWritable: true }],
            data: b64([6, 0, 0]), // SetAuthority, MintAuthority, no new authority
          },
        ],
      });
      const result = await guard.validateTransaction(tx);
      expect(result.isValid).toBe(true);
      expect(result.warnings.length).toBeGreaterThan(0);
      expect(result.blockedBy).toBeUndefined();
    });
  });

  describe("pattern detection disabled", () => {
    it("returns valid with no warnings when detection is off", async () => {
      const guard = new Guard({ enablePatternDetection: false });
      const tx = makeSolanaTx({
        instructions: [
          {
            programId: TOKEN_PROGRAM_ID,
            keys: [{ pubkey: "mintABC", isSigner: false, isWritable: true }],
            data: b64([6, 0, 0]),
          },
        ],
      });
      const result = await guard.validateTransaction(tx);
      expect(result.isValid).toBe(true);
      expect(result.warnings).toHaveLength(0);
    });
  });

  describe("risk tolerance: permissive", () => {
    it("only blocks MintKill and FreezeKill patterns", async () => {
      const guard = new Guard({ riskTolerance: "permissive" });

      // MintKill should still block
      const mintKillTx = makeSolanaTx({
        instructions: [
          {
            programId: TOKEN_PROGRAM_ID,
            keys: [{ pubkey: "mintABC", isSigner: false, isWritable: true }],
            data: b64([6, 0, 0]),
          },
        ],
      });
      const r = await guard.validateTransaction(mintKillTx);
      expect(r.isValid).toBe(false);
      expect(r.blockedBy).toContain(PatternId.MintKill);
    });
  });
});

// ── analyzeTransaction dispatcher tests ──

describe("analyzeTransaction", () => {
  it("returns empty for transactions with no instructions", () => {
    const tx = makeSolanaTx({ instructions: [] });
    expect(analyzeTransaction(tx)).toEqual([]);
  });

  it("returns empty for transactions with undefined instructions", () => {
    const tx = makeSolanaTx({ instructions: undefined });
    expect(analyzeTransaction(tx)).toEqual([]);
  });

  it("routes solana transactions to solana detector", () => {
    const tx = makeSolanaTx({
      instructions: [
        {
          programId: TOKEN_PROGRAM_ID,
          keys: [{ pubkey: "mintABC", isSigner: false, isWritable: true }],
          data: b64([6, 0, 0]),
        },
      ],
    });
    const warnings = analyzeTransaction(tx);
    expect(warnings.some((w) => w.patternId === PatternId.MintKill)).toBe(true);
  });

  it("routes evm transactions to evm detector", () => {
    const tx = makeEvmTx({
      instructions: [
        {
          programId: "0xSomeContract",
          keys: [],
          data: "0x715018a6", // renounceOwnership
        },
      ],
    });
    const warnings = analyzeTransaction(tx);
    expect(
      warnings.some((w) => w.patternId === PatternId.UnauthorizedAccess)
    ).toBe(true);
  });

  it("returns empty for unknown chain", () => {
    const tx = {
      id: "x",
      chain: "bitcoin" as any,
      status: "pending" as const,
      instructions: [
        { programId: "abc", keys: [], data: "ff" },
      ],
    };
    expect(analyzeTransaction(tx)).toEqual([]);
  });
});

// ── Solana detector tests ──

describe("analyzeSolanaTransaction", () => {
  it("detects MintKill (P-101)", () => {
    const tx = makeSolanaTx({
      instructions: [
        {
          programId: TOKEN_PROGRAM_ID,
          keys: [{ pubkey: "mintABC", isSigner: false, isWritable: true }],
          data: b64([6, 0, 0]), // SetAuthority, authorityType=0 (Mint), no new authority
        },
      ],
    });
    const warnings = analyzeSolanaTransaction(tx);
    expect(warnings).toHaveLength(1);
    expect(warnings[0].patternId).toBe(PatternId.MintKill);
    expect(warnings[0].severity).toBe(Severity.Critical);
    expect(warnings[0].affectedAccount).toBe("mintABC");
  });

  it("detects FreezeKill (P-102)", () => {
    const tx = makeSolanaTx({
      instructions: [
        {
          programId: TOKEN_PROGRAM_ID,
          keys: [{ pubkey: "mintABC", isSigner: false, isWritable: true }],
          data: b64([6, 1, 0]), // SetAuthority, authorityType=1 (Freeze), no new authority
        },
      ],
    });
    const warnings = analyzeSolanaTransaction(tx);
    expect(warnings).toHaveLength(1);
    expect(warnings[0].patternId).toBe(PatternId.FreezeKill);
    expect(warnings[0].severity).toBe(Severity.Critical);
  });

  it("detects SignerMismatch (P-103) when new authority is not a signer", () => {
    const tx = makeSolanaTx({
      signers: ["currentOwner"],
      instructions: [
        {
          programId: TOKEN_PROGRAM_ID,
          keys: [
            { pubkey: "mintABC", isSigner: false, isWritable: true },
            { pubkey: "newOwnerNotSigner", isSigner: false, isWritable: false },
          ],
          data: b64([6, 0, 1]), // SetAuthority, authorityType=0, hasNewAuthority=1
        },
      ],
    });
    const warnings = analyzeSolanaTransaction(tx);
    expect(warnings.some((w) => w.patternId === PatternId.SignerMismatch)).toBe(
      true
    );
  });

  it("does not flag SignerMismatch when new authority is a signer", () => {
    const tx = makeSolanaTx({
      signers: ["currentOwner", "newOwner"],
      instructions: [
        {
          programId: TOKEN_PROGRAM_ID,
          keys: [
            { pubkey: "mintABC", isSigner: false, isWritable: true },
            { pubkey: "newOwner", isSigner: false, isWritable: false },
          ],
          data: b64([6, 0, 1]),
        },
      ],
    });
    const warnings = analyzeSolanaTransaction(tx);
    expect(
      warnings.some((w) => w.patternId === PatternId.SignerMismatch)
    ).toBe(false);
  });

  it("detects DangerousClose (P-104)", () => {
    const tx = makeSolanaTx({
      instructions: [
        {
          programId: TOKEN_PROGRAM_ID,
          keys: [{ pubkey: "account1", isSigner: false, isWritable: true }],
          data: b64([9]), // CloseAccount
        },
      ],
    });
    const warnings = analyzeSolanaTransaction(tx);
    expect(warnings.some((w) => w.patternId === PatternId.DangerousClose)).toBe(
      true
    );
    expect(warnings.find((w) => w.patternId === PatternId.DangerousClose)!.severity).toBe(
      Severity.Alert
    );
  });

  it("detects DangerousClose on Token-2022 program", () => {
    const tx = makeSolanaTx({
      instructions: [
        {
          programId: TOKEN_2022_PROGRAM_ID,
          keys: [{ pubkey: "account1", isSigner: false, isWritable: true }],
          data: b64([9]),
        },
      ],
    });
    const warnings = analyzeSolanaTransaction(tx);
    expect(warnings.some((w) => w.patternId === PatternId.DangerousClose)).toBe(
      true
    );
  });

  it("detects ExcessiveHookAccounts (P-108)", () => {
    const manyKeys = Array.from({ length: 25 }, (_, i) => ({
      pubkey: `key${i}`,
      isSigner: false,
      isWritable: false,
    }));
    const tx = makeSolanaTx({
      instructions: [
        {
          programId: "unknownHookProgram111111111111111111111",
          keys: manyKeys,
          data: b64([0]),
        },
      ],
    });
    const warnings = analyzeSolanaTransaction(tx);
    expect(
      warnings.some((w) => w.patternId === PatternId.ExcessiveHookAccounts)
    ).toBe(true);
  });

  it("detects MaliciousTransferHook (P-105) with many writable accounts", () => {
    const keys = Array.from({ length: 20 }, (_, i) => ({
      pubkey: `key${i}`,
      isSigner: false,
      isWritable: true,
    }));
    const tx = makeSolanaTx({
      instructions: [
        {
          programId: "unknownHookProgram111111111111111111111",
          keys,
          data: b64([0]),
        },
      ],
    });
    const warnings = analyzeSolanaTransaction(tx);
    expect(
      warnings.some((w) => w.patternId === PatternId.MaliciousTransferHook)
    ).toBe(true);
  });

  it("detects HookReentrancy (P-107) when hook is sandwiched between token ops", () => {
    const tx = makeSolanaTx({
      instructions: [
        {
          programId: TOKEN_PROGRAM_ID,
          keys: [{ pubkey: "a", isSigner: false, isWritable: false }],
          data: b64([3]), // transfer
        },
        {
          programId: "suspiciousHook11111111111111111111111",
          keys: Array.from({ length: 5 }, (_, i) => ({
            pubkey: `k${i}`,
            isSigner: false,
            isWritable: false,
          })),
          data: b64([0]),
        },
        {
          programId: TOKEN_PROGRAM_ID,
          keys: [{ pubkey: "b", isSigner: false, isWritable: false }],
          data: b64([3]),
        },
      ],
    });
    const warnings = analyzeSolanaTransaction(tx);
    expect(
      warnings.some((w) => w.patternId === PatternId.HookReentrancy)
    ).toBe(true);
  });

  it("detects HookReentrancy via high invocation count (>6)", () => {
    const hookProgram = "repeatHook111111111111111111111111111";
    const instructions = Array.from({ length: 7 }, () => ({
      programId: hookProgram,
      keys: [{ pubkey: "k1", isSigner: false, isWritable: false }],
      data: b64([0]),
    }));
    const tx = makeSolanaTx({ instructions });
    const warnings = analyzeSolanaTransaction(tx);
    expect(
      warnings.some((w) => w.patternId === PatternId.HookReentrancy)
    ).toBe(true);
  });

  it("skips hook validation when validateTransferHooks is false", () => {
    const keys = Array.from({ length: 25 }, (_, i) => ({
      pubkey: `key${i}`,
      isSigner: false,
      isWritable: true,
    }));
    const tx = makeSolanaTx({
      instructions: [
        {
          programId: "unknownHookProgram111111111111111111111",
          keys,
          data: b64([0]),
        },
      ],
    });
    const config: GuardConfig = { validateTransferHooks: false };
    const warnings = analyzeSolanaTransaction(tx, config);
    expect(
      warnings.some((w) => w.patternId === PatternId.ExcessiveHookAccounts)
    ).toBe(false);
    expect(
      warnings.some((w) => w.patternId === PatternId.MaliciousTransferHook)
    ).toBe(false);
  });

  it("respects allowedHookPrograms", () => {
    const hookId = "customHookProgram111111111111111111111";
    const keys = Array.from({ length: 25 }, (_, i) => ({
      pubkey: `key${i}`,
      isSigner: false,
      isWritable: true,
    }));
    const tx = makeSolanaTx({
      instructions: [
        { programId: hookId, keys, data: b64([0]) },
      ],
    });
    const config: GuardConfig = { allowedHookPrograms: [hookId] };
    const warnings = analyzeSolanaTransaction(tx, config);
    expect(
      warnings.some((w) => w.patternId === PatternId.ExcessiveHookAccounts)
    ).toBe(false);
    expect(
      warnings.some((w) => w.patternId === PatternId.MaliciousTransferHook)
    ).toBe(false);
  });

  it("returns empty for empty instructions", () => {
    expect(analyzeSolanaTransaction(makeSolanaTx())).toEqual([]);
  });
});

// ── EVM detector tests ──

describe("analyzeEvmTransaction", () => {
  it("detects UnauthorizedAccess for renounceOwnership (EVM-004)", () => {
    const tx = makeEvmTx({
      instructions: [
        {
          programId: "0xTargetContract",
          keys: [],
          data: "0x715018a6", // renounceOwnership selector
        },
      ],
    });
    const warnings = analyzeEvmTransaction(tx);
    expect(
      warnings.some((w) => w.patternId === PatternId.UnauthorizedAccess)
    ).toBe(true);
    const w = warnings.find(
      (w) => w.patternId === PatternId.UnauthorizedAccess
    )!;
    expect(w.severity).toBe(Severity.Critical);
  });

  it("detects UnauthorizedAccess for transferOwnership (warning level)", () => {
    const tx = makeEvmTx({
      instructions: [
        {
          programId: "0xTargetContract",
          keys: [],
          data: "0xf2fde38b0000000000000000000000001234",
        },
      ],
    });
    const warnings = analyzeEvmTransaction(tx);
    const w = warnings.find(
      (w) => w.patternId === PatternId.UnauthorizedAccess
    )!;
    expect(w).toBeDefined();
    expect(w.severity).toBe(Severity.Warning);
  });

  it("detects FlashLoanAttack when flash loan + DEX swap (EVM-002)", () => {
    const tx = makeEvmTx({
      instructions: [
        {
          programId: "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2", // AAVE V3
          keys: [],
          data: "0x5cffe9de", // flashLoan
        },
        {
          programId: "0x7a250d5630b4cf539739df2c5dacb4c659f2488d", // Uniswap V2
          keys: [],
          data: "0x022c0d9f", // swap
        },
      ],
    });
    const warnings = analyzeEvmTransaction(tx);
    expect(
      warnings.some((w) => w.patternId === PatternId.FlashLoanAttack)
    ).toBe(true);
  });

  it("detects FrontRunning when same router swapped multiple times (EVM-003)", () => {
    const router = "0x7a250d5630b4cf539739df2c5dacb4c659f2488d";
    const tx = makeEvmTx({
      instructions: [
        { programId: router, keys: [], data: "0x022c0d9f" },
        { programId: "0xSomeOther", keys: [], data: "0x12345678" },
        { programId: router, keys: [], data: "0x022c0d9f" },
      ],
    });
    const warnings = analyzeEvmTransaction(tx);
    expect(
      warnings.some((w) => w.patternId === PatternId.FrontRunning)
    ).toBe(true);
  });

  it("detects ReentrancyAttack when contract called 3+ times with transfers (EVM-001)", () => {
    const contract = "0xabcdef1234567890abcdef1234567890abcdef12";
    const tx = makeEvmTx({
      instructions: [
        { programId: contract, keys: [], data: "0xa9059cbb" }, // transfer
        { programId: contract, keys: [], data: "0xa9059cbb" },
        { programId: contract, keys: [], data: "0xa9059cbb" },
      ],
    });
    const warnings = analyzeEvmTransaction(tx);
    expect(
      warnings.some((w) => w.patternId === PatternId.ReentrancyAttack)
    ).toBe(true);
  });

  it("does not flag reentrancy on known DEX routers", () => {
    const router = "0x7a250d5630b4cf539739df2c5dacb4c659f2488d";
    const tx = makeEvmTx({
      instructions: [
        { programId: router, keys: [], data: "0xa9059cbb" },
        { programId: router, keys: [], data: "0xa9059cbb" },
        { programId: router, keys: [], data: "0xa9059cbb" },
      ],
    });
    const warnings = analyzeEvmTransaction(tx);
    expect(
      warnings.some((w) => w.patternId === PatternId.ReentrancyAttack)
    ).toBe(false);
  });

  it("returns empty for empty instructions", () => {
    expect(analyzeEvmTransaction(makeEvmTx())).toEqual([]);
  });
});
