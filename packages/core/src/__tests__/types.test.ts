import { describe, it, expect } from "vitest";
import {
  PatternId,
  Severity,
  JitoRegion,
  TipLevel,
} from "../types";

describe("PatternId enum", () => {
  it("has the correct Solana pattern IDs", () => {
    expect(PatternId.MintKill).toBe("P-101");
    expect(PatternId.FreezeKill).toBe("P-102");
    expect(PatternId.SignerMismatch).toBe("P-103");
    expect(PatternId.DangerousClose).toBe("P-104");
    expect(PatternId.MaliciousTransferHook).toBe("P-105");
    expect(PatternId.UnexpectedHookExecution).toBe("P-106");
    expect(PatternId.HookReentrancy).toBe("P-107");
    expect(PatternId.ExcessiveHookAccounts).toBe("P-108");
  });

  it("has the correct EVM pattern IDs", () => {
    expect(PatternId.ReentrancyAttack).toBe("EVM-001");
    expect(PatternId.FlashLoanAttack).toBe("EVM-002");
    expect(PatternId.FrontRunning).toBe("EVM-003");
    expect(PatternId.UnauthorizedAccess).toBe("EVM-004");
  });
});

describe("Severity enum", () => {
  it("has three levels", () => {
    expect(Severity.Critical).toBe("critical");
    expect(Severity.Warning).toBe("warning");
    expect(Severity.Alert).toBe("alert");
  });
});

describe("JitoRegion enum", () => {
  it("has the expected regions", () => {
    expect(JitoRegion.Default).toBe("default");
    expect(JitoRegion.Amsterdam).toBe("amsterdam");
    expect(JitoRegion.Frankfurt).toBe("frankfurt");
    expect(JitoRegion.NewYork).toBe("ny");
    expect(JitoRegion.Tokyo).toBe("tokyo");
  });
});

describe("TipLevel enum", () => {
  it("has ascending tip values", () => {
    expect(TipLevel.None).toBe(0);
    expect(TipLevel.Low).toBe(1000);
    expect(TipLevel.Medium).toBe(10000);
    expect(TipLevel.High).toBe(100000);
    expect(TipLevel.VeryHigh).toBe(1000000);
    expect(TipLevel.Turbo).toBe(10000000);
  });

  it("values are strictly ascending", () => {
    const values = [
      TipLevel.None,
      TipLevel.Low,
      TipLevel.Medium,
      TipLevel.High,
      TipLevel.VeryHigh,
      TipLevel.Turbo,
    ];
    for (let i = 1; i < values.length; i++) {
      expect(values[i]).toBeGreaterThan(values[i - 1]);
    }
  });
});
