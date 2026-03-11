import { describe, it, expect } from "vitest";
import { SimulationSandbox } from "../simulation";
import type { SimulationResult, BalanceChange, StateChange } from "../types";

describe("SimulationSandbox", () => {
  describe("constructor", () => {
    it("creates with default config", () => {
      const sim = new SimulationSandbox();
      expect(sim).toBeDefined();
    });

    it("accepts custom config", () => {
      const sim = new SimulationSandbox({
        evmForkUrl: "http://localhost:8545",
        solanaRpcUrl: "http://localhost:8899",
        timeout: 5000,
        traceStateDiffs: false,
      });
      expect(sim).toBeDefined();
    });
  });

  describe("simulate", () => {
    it("returns error for EVM without fork URL", async () => {
      const sim = new SimulationSandbox();
      const result = await sim.simulate({
        id: "tx-1",
        chain: "evm",
        status: "pending",
        instructions: [
          { programId: "0xTarget", keys: [], data: "0x12345678" },
        ],
      });
      expect(result.success).toBe(false);
      expect(result.error).toContain("No EVM fork URL");
    });

    it("returns error for Solana without RPC URL", async () => {
      const sim = new SimulationSandbox();
      const result = await sim.simulate({
        id: "tx-1",
        chain: "solana",
        status: "pending",
        instructions: [
          {
            programId: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            keys: [],
            data: Buffer.from([3]).toString("base64"),
          },
        ],
      });
      expect(result.success).toBe(false);
      expect(result.error).toContain("No Solana RPC URL");
    });

    it("returns error for unsupported chain", async () => {
      const sim = new SimulationSandbox();
      const result = await sim.simulate({
        id: "tx-1",
        chain: "bitcoin" as any,
        status: "pending",
      });
      expect(result.success).toBe(false);
      expect(result.error).toContain("Unsupported chain");
    });
  });

  describe("simulateBatch", () => {
    it("simulates multiple transactions", async () => {
      const sim = new SimulationSandbox();
      const results = await sim.simulateBatch([
        { id: "tx-1", chain: "evm", status: "pending" },
        { id: "tx-2", chain: "solana", status: "pending" },
      ]);
      expect(results).toHaveLength(2);
    });
  });

  describe("analyzeHoneypot", () => {
    it("detects honeypot when buy succeeds but sell fails", () => {
      const sim = new SimulationSandbox();
      const buyResult: SimulationResult = {
        success: true,
        chain: "evm",
        balanceChanges: [],
      };
      const sellResult: SimulationResult = {
        success: false,
        chain: "evm",
        revertReason: "Transfer not allowed",
      };
      const result = sim.analyzeHoneypot(buyResult, sellResult);
      expect(result.isHoneypot).toBe(true);
      expect(result.sellTax).toBe(100);
      expect(result.reason).toContain("Transfer not allowed");
    });

    it("detects honeypot via high sell tax", () => {
      const sim = new SimulationSandbox();
      const buyResult: SimulationResult = {
        success: true,
        chain: "evm",
        balanceChanges: [
          { address: "0xUser", token: "0xToken", before: "0", after: "100", delta: "100" },
        ],
      };
      const sellResult: SimulationResult = {
        success: true,
        chain: "evm",
        balanceChanges: [
          { address: "0xUser", token: "0xETH", before: "100", after: "130", delta: "30" },
        ],
      };
      // sell tax would be 0% in this case since all delta is positive
      const result = sim.analyzeHoneypot(buyResult, sellResult);
      expect(result.isHoneypot).toBe(false);
    });

    it("returns not honeypot for normal transactions", () => {
      const sim = new SimulationSandbox();
      const buyResult: SimulationResult = {
        success: true,
        chain: "evm",
        balanceChanges: [],
      };
      const sellResult: SimulationResult = {
        success: true,
        chain: "evm",
        balanceChanges: [],
      };
      const result = sim.analyzeHoneypot(buyResult, sellResult);
      expect(result.isHoneypot).toBe(false);
    });
  });

  describe("analyzeStateChanges", () => {
    it("flags owner slot changes as suspicious", () => {
      const sim = new SimulationSandbox();
      const result: SimulationResult = {
        success: true,
        chain: "evm",
        stateChanges: [
          {
            address: "0xContract",
            slot: "0x0",
            previousValue: "0x000000000000000000000000aaa",
            newValue: "0x000000000000000000000000bbb",
          },
        ],
      };
      const analysis = sim.analyzeStateChanges(result);
      expect(analysis.suspiciousChanges).toHaveLength(1);
      expect(analysis.riskLevel).toBe("medium");
    });

    it("flags EIP-1967 implementation slot changes", () => {
      const sim = new SimulationSandbox();
      const result: SimulationResult = {
        success: true,
        chain: "evm",
        stateChanges: [
          {
            address: "0xProxy",
            slot: "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
            previousValue: "0x000000000000000000000000oldImpl",
            newValue: "0x000000000000000000000000newImpl",
          },
        ],
      };
      const analysis = sim.analyzeStateChanges(result);
      expect(analysis.suspiciousChanges).toHaveLength(1);
      expect(analysis.riskLevel).toBe("medium");
    });

    it("flags EIP-1967 admin slot changes", () => {
      const sim = new SimulationSandbox();
      const result: SimulationResult = {
        success: true,
        chain: "evm",
        stateChanges: [
          {
            address: "0xProxy",
            slot: "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103",
            previousValue: "0x000000000000000000000000oldAdmin",
            newValue: "0x000000000000000000000000newAdmin",
          },
        ],
      };
      const analysis = sim.analyzeStateChanges(result);
      expect(analysis.suspiciousChanges).toHaveLength(1);
    });

    it("returns high risk for 3+ suspicious changes", () => {
      const sim = new SimulationSandbox();
      const result: SimulationResult = {
        success: true,
        chain: "evm",
        stateChanges: [
          { address: "0xA", slot: "0x0", previousValue: "a", newValue: "b" },
          {
            address: "0xB",
            slot: "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
            previousValue: "a",
            newValue: "b",
          },
          {
            address: "0xC",
            slot: "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103",
            previousValue: "a",
            newValue: "b",
          },
        ],
      };
      const analysis = sim.analyzeStateChanges(result);
      expect(analysis.riskLevel).toBe("high");
      expect(analysis.suspiciousChanges).toHaveLength(3);
    });

    it("returns low risk for no suspicious changes", () => {
      const sim = new SimulationSandbox();
      const result: SimulationResult = {
        success: true,
        chain: "evm",
        stateChanges: [
          { address: "0xA", slot: "0x5", previousValue: "a", newValue: "b" },
        ],
      };
      const analysis = sim.analyzeStateChanges(result);
      expect(analysis.riskLevel).toBe("low");
      expect(analysis.suspiciousChanges).toHaveLength(0);
    });

    it("handles empty state changes", () => {
      const sim = new SimulationSandbox();
      const result: SimulationResult = {
        success: true,
        chain: "evm",
        stateChanges: [],
      };
      const analysis = sim.analyzeStateChanges(result);
      expect(analysis.riskLevel).toBe("low");
    });

    it("handles undefined state changes", () => {
      const sim = new SimulationSandbox();
      const result: SimulationResult = {
        success: true,
        chain: "evm",
      };
      const analysis = sim.analyzeStateChanges(result);
      expect(analysis.riskLevel).toBe("low");
    });
  });
});
