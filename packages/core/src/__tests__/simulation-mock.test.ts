/**
 * Mock-based simulation tests — verify RPC call parsing, state diff handling,
 * revert decoding, and Geth prestate format without real network calls.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { SimulationSandbox } from "../simulation";
import type { Transaction, SimulationResult } from "../types";

// Mock global fetch
const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

function makeEvmTx(overrides: Partial<Transaction> = {}): Transaction {
  return {
    id: "evm-tx-1",
    chain: "evm",
    status: "pending",
    instructions: [
      {
        programId: "0xTargetContract",
        keys: [],
        data: "0xa9059cbb0000000000000000000000001234567890abcdef1234567890abcdef12345678",
      },
    ],
    signers: ["0xSender"],
    ...overrides,
  };
}

function makeSolanaTx(overrides: Partial<Transaction> = {}): Transaction {
  return {
    id: "solana-tx-1",
    chain: "solana",
    status: "pending",
    instructions: [
      {
        programId: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        keys: [
          { pubkey: "AccountA", isSigner: true, isWritable: true },
          { pubkey: "AccountB", isSigner: false, isWritable: true },
        ],
        data: "AQAAAA==",
      },
    ],
    ...overrides,
  };
}

function jsonResponse(data: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 200 ? "OK" : "Error",
    json: () => Promise.resolve(data),
    text: () => Promise.resolve(JSON.stringify(data)),
    headers: new Headers(),
  } as Response;
}

beforeEach(() => {
  mockFetch.mockReset();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("SimulationSandbox EVM mocked", () => {
  it("parses successful eth_call + eth_estimateGas + trace_call (Parity)", async () => {
    const sim = new SimulationSandbox({ evmForkUrl: "http://mock-rpc" });

    mockFetch
      // eth_call
      .mockResolvedValueOnce(
        jsonResponse({ jsonrpc: "2.0", id: 1, result: "0x" })
      )
      // eth_estimateGas
      .mockResolvedValueOnce(
        jsonResponse({ jsonrpc: "2.0", id: 1, result: "0x5208" }) // 21000
      )
      // trace_call (Parity) — returns state diff
      .mockResolvedValueOnce(
        jsonResponse({
          jsonrpc: "2.0",
          id: 1,
          result: {
            stateDiff: {
              "0xcontract": {
                storage: {
                  "0x0": {
                    from: "0x0000000000000000000000000000000000000000000000000000000000000001",
                    to: "0x0000000000000000000000000000000000000000000000000000000000000002",
                  },
                },
              },
            },
          },
        })
      );

    const result = await sim.simulate(makeEvmTx());

    expect(result.success).toBe(true);
    expect(result.chain).toBe("evm");
    expect(result.gasUsed).toBe(21000);
    expect(result.stateChanges).toHaveLength(1);
    expect(result.stateChanges![0]).toEqual({
      address: "0xcontract",
      slot: "0x0",
      previousValue: "0x0000000000000000000000000000000000000000000000000000000000000001",
      newValue: "0x0000000000000000000000000000000000000000000000000000000000000002",
    });
  });

  it("falls back to debug_traceCall (Geth) when trace_call fails", async () => {
    const sim = new SimulationSandbox({ evmForkUrl: "http://mock-rpc" });

    mockFetch
      // eth_call
      .mockResolvedValueOnce(
        jsonResponse({ jsonrpc: "2.0", id: 1, result: "0x" })
      )
      // eth_estimateGas
      .mockResolvedValueOnce(
        jsonResponse({ jsonrpc: "2.0", id: 1, result: "0x7530" }) // 30000
      )
      // trace_call — fails (method not found)
      .mockResolvedValueOnce(
        jsonResponse({
          jsonrpc: "2.0",
          id: 1,
          error: { code: -32601, message: "Method not found" },
        })
      )
      // debug_traceCall — returns Geth prestate diff
      .mockResolvedValueOnce(
        jsonResponse({
          jsonrpc: "2.0",
          id: 1,
          result: {
            pre: {
              "0xcontract": {
                storage: {
                  "0x1": "0xaaa",
                },
              },
            },
            post: {
              "0xcontract": {
                storage: {
                  "0x1": "0xbbb",
                },
              },
            },
          },
        })
      );

    const result = await sim.simulate(makeEvmTx());

    expect(result.success).toBe(true);
    expect(result.gasUsed).toBe(30000);
    expect(result.stateChanges).toHaveLength(1);
    expect(result.stateChanges![0]).toEqual({
      address: "0xcontract",
      slot: "0x1",
      previousValue: "0xaaa",
      newValue: "0xbbb",
    });
  });

  it("gracefully degrades when both trace APIs fail", async () => {
    const sim = new SimulationSandbox({ evmForkUrl: "http://mock-rpc" });

    mockFetch
      .mockResolvedValueOnce(
        jsonResponse({ jsonrpc: "2.0", id: 1, result: "0x" })
      )
      .mockResolvedValueOnce(
        jsonResponse({ jsonrpc: "2.0", id: 1, result: "0x5208" })
      )
      // trace_call fails
      .mockResolvedValueOnce(
        jsonResponse({ jsonrpc: "2.0", id: 1, error: { code: -32601, message: "Not found" } })
      )
      // debug_traceCall fails
      .mockResolvedValueOnce(
        jsonResponse({ jsonrpc: "2.0", id: 1, error: { code: -32601, message: "Not found" } })
      );

    const result = await sim.simulate(makeEvmTx());

    expect(result.success).toBe(true);
    expect(result.stateChanges).toHaveLength(0);
  });

  it("decodes Error(string) revert reason", async () => {
    const sim = new SimulationSandbox({ evmForkUrl: "http://mock-rpc" });

    // "Insufficient balance" encoded as Error(string)
    // selector: 08c379a0
    // offset: 0000000000000000000000000000000000000000000000000000000000000020
    // length: 0000000000000000000000000000000000000000000000000000000000000014
    // data:   "Insufficient balance" = 496e73756666696369656e742062616c616e6365
    const revertData =
      "0x08c379a0" +
      "0000000000000000000000000000000000000000000000000000000000000020" +
      "0000000000000000000000000000000000000000000000000000000000000014" +
      "496e73756666696369656e742062616c616e6365000000000000000000000000";

    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        jsonrpc: "2.0",
        id: 1,
        error: { code: 3, message: "execution reverted", data: revertData },
      })
    );

    const result = await sim.simulate(makeEvmTx());

    expect(result.success).toBe(false);
    expect(result.revertReason).toBe("Insufficient balance");
  });

  it("decodes Panic(uint256) revert reason", async () => {
    const sim = new SimulationSandbox({ evmForkUrl: "http://mock-rpc" });

    // Panic(0x11) = arithmetic overflow
    const panicData =
      "0x4e487b71" +
      "0000000000000000000000000000000000000000000000000000000000000011";

    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        jsonrpc: "2.0",
        id: 1,
        error: { code: 3, message: "execution reverted", data: panicData },
      })
    );

    const result = await sim.simulate(makeEvmTx());

    expect(result.success).toBe(false);
    expect(result.revertReason).toBe("Arithmetic overflow");
  });

  it("handles HTTP error from RPC", async () => {
    const sim = new SimulationSandbox({ evmForkUrl: "http://mock-rpc" });

    mockFetch.mockResolvedValueOnce(
      jsonResponse({ error: "Internal Server Error" }, 500)
    );

    const result = await sim.simulate(makeEvmTx());

    expect(result.success).toBe(false);
    expect(result.error).toContain("HTTP 500");
  });

  it("handles network fetch failure", async () => {
    const sim = new SimulationSandbox({ evmForkUrl: "http://mock-rpc" });

    mockFetch.mockRejectedValueOnce(new Error("fetch failed"));

    const result = await sim.simulate(makeEvmTx());

    expect(result.success).toBe(false);
    expect(result.error).toContain("fetch failed");
  });
});

describe("SimulationSandbox Solana mocked", () => {
  it("parses simulateTransaction with account state changes", async () => {
    const sim = new SimulationSandbox({ solanaRpcUrl: "http://mock-solana" });

    const tx = makeSolanaTx({
      // Long ID triggers simulateTransaction path
      id: "A".repeat(100),
    });

    mockFetch
      // getAccountInfo for TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
      .mockResolvedValueOnce(
        jsonResponse({
          jsonrpc: "2.0",
          id: 1,
          result: {
            value: { lamports: 1000000, owner: "11111111111111111111111111111111", data: ["", "base64"] },
          },
        })
      )
      // getAccountInfo for AccountA
      .mockResolvedValueOnce(
        jsonResponse({
          jsonrpc: "2.0",
          id: 1,
          result: {
            value: { lamports: 5000000, owner: "11111111111111111111111111111111", data: ["", "base64"] },
          },
        })
      )
      // getAccountInfo for AccountB
      .mockResolvedValueOnce(
        jsonResponse({
          jsonrpc: "2.0",
          id: 1,
          result: {
            value: { lamports: 2000000, owner: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", data: ["", "base64"] },
          },
        })
      )
      // simulateTransaction
      .mockResolvedValueOnce(
        jsonResponse({
          jsonrpc: "2.0",
          id: 1,
          result: {
            value: {
              err: null,
              unitsConsumed: 50000,
              logs: ["Program log: Transfer succeeded"],
              accounts: [
                { lamports: 1000000, owner: "11111111111111111111111111111111" },
                { lamports: 4900000, owner: "11111111111111111111111111111111" },
                { lamports: 2100000, owner: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA" },
              ],
            },
          },
        })
      );

    const result = await sim.simulate(tx);

    expect(result.success).toBe(true);
    expect(result.chain).toBe("solana");
    expect(result.computeUnitsUsed).toBe(50000);
    expect(result.logs).toContain("Program log: Transfer succeeded");
    // AccountA lost 100000 lamports
    expect(result.balanceChanges).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          address: "AccountA",
          before: "5000000",
          after: "4900000",
          delta: "-100000",
        }),
        expect.objectContaining({
          address: "AccountB",
          before: "2000000",
          after: "2100000",
          delta: "100000",
        }),
      ])
    );
  });

  it("handles Solana simulation error", async () => {
    const sim = new SimulationSandbox({ solanaRpcUrl: "http://mock-solana" });

    const tx = makeSolanaTx({ id: "B".repeat(100) });

    mockFetch
      .mockResolvedValueOnce(
        jsonResponse({
          jsonrpc: "2.0",
          id: 1,
          result: { value: { lamports: 1000, owner: "System", data: ["", "base64"] } },
        })
      )
      .mockResolvedValueOnce(
        jsonResponse({
          jsonrpc: "2.0",
          id: 1,
          result: { value: { lamports: 5000, owner: "System", data: ["", "base64"] } },
        })
      )
      .mockResolvedValueOnce(
        jsonResponse({
          jsonrpc: "2.0",
          id: 1,
          result: { value: { lamports: 2000, owner: "Token", data: ["", "base64"] } },
        })
      )
      // simulateTransaction returns error
      .mockResolvedValueOnce(
        jsonResponse({
          jsonrpc: "2.0",
          id: 1,
          result: {
            value: {
              err: { InstructionError: [0, { Custom: 1 }] },
              unitsConsumed: 12000,
              logs: ["Program log: Error: insufficient funds"],
              accounts: null,
            },
          },
        })
      );

    const result = await sim.simulate(tx);

    expect(result.success).toBe(false);
    expect(result.computeUnitsUsed).toBe(12000);
    expect(result.error).toContain("InstructionError");
  });
});

describe("SimulationSandbox analyzeBytecode mocked", () => {
  it("detects DELEGATECALL and SELFDESTRUCT opcodes", async () => {
    const sim = new SimulationSandbox({ evmForkUrl: "http://mock-rpc" });

    // Bytecode with: PUSH1 0x00, DELEGATECALL (f4), PUSH1 0x00, SELFDESTRUCT (ff)
    const bytecode = "0x6000f46000ff";

    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        jsonrpc: "2.0",
        id: 1,
        result: bytecode,
      })
    );

    const result = await sim.analyzeBytecode("0xContract");

    expect(result.hasDelegatecall).toBe(true);
    expect(result.hasSelfDestruct).toBe(true);
    expect(result.codeSize).toBe(6);
  });

  it("skips PUSH data to avoid false positives", async () => {
    const sim = new SimulationSandbox({ evmForkUrl: "http://mock-rpc" });

    // PUSH2 with f4 ff as push data (not actual opcodes), followed by STOP (00)
    // 61 f4ff 00
    const bytecode = "0x61f4ff00";

    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        jsonrpc: "2.0",
        id: 1,
        result: bytecode,
      })
    );

    const result = await sim.analyzeBytecode("0xContract");

    expect(result.hasDelegatecall).toBe(false);
    expect(result.hasSelfDestruct).toBe(false);
  });

  it("detects EIP-1167 minimal proxy", async () => {
    const sim = new SimulationSandbox({ evmForkUrl: "http://mock-rpc" });

    // EIP-1167 minimal proxy bytecode (starts with 363d3d373d3d3d363d73)
    // then has delegatecall (f4) later
    const bytecode =
      "0x363d3d373d3d3d363d73" +
      "bebebebebebebebebebebebebebebebebebebebe" +
      "5af43d82803e903d91602b57fd5bf3";

    mockFetch.mockResolvedValueOnce(
      jsonResponse({ jsonrpc: "2.0", id: 1, result: bytecode })
    );

    const result = await sim.analyzeBytecode("0xProxy");

    expect(result.hasDelegatecall).toBe(true);
    expect(result.isProxy).toBe(true);
  });
});

describe("SimulationSandbox Geth prestate diff parsing", () => {
  it("parses new slots in post that don't exist in pre", async () => {
    const sim = new SimulationSandbox({ evmForkUrl: "http://mock-rpc" });

    mockFetch
      .mockResolvedValueOnce(
        jsonResponse({ jsonrpc: "2.0", id: 1, result: "0x" })
      )
      .mockResolvedValueOnce(
        jsonResponse({ jsonrpc: "2.0", id: 1, result: "0x5208" })
      )
      // trace_call fails
      .mockResolvedValueOnce(
        jsonResponse({ jsonrpc: "2.0", id: 1, error: { code: -32601, message: "Not found" } })
      )
      // debug_traceCall returns diff with new slot
      .mockResolvedValueOnce(
        jsonResponse({
          jsonrpc: "2.0",
          id: 1,
          result: {
            pre: {
              "0xcontract": { storage: {} },
            },
            post: {
              "0xcontract": {
                storage: { "0x5": "0x1234" },
              },
            },
          },
        })
      );

    const result = await sim.simulate(makeEvmTx());

    expect(result.stateChanges).toHaveLength(1);
    expect(result.stateChanges![0]).toEqual({
      address: "0xcontract",
      slot: "0x5",
      previousValue: "0x0",
      newValue: "0x1234",
    });
  });
});
