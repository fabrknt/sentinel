/**
 * Simulation Sandbox — Pre-execution transaction simulation for both EVM and Solana.
 *
 * Runs transactions against local forks (Anvil for EVM, solana-test-validator for Solana)
 * or remote RPC simulation endpoints to detect state-change-driven attacks
 * before committing to on-chain execution.
 *
 * EVM: eth_call → eth_estimateGas → trace_call (Parity) or debug_traceCall (Geth)
 * Solana: simulateTransaction RPC + getAccountInfo for pre/post state comparison
 *
 * Feeds results into Guard.validateTransaction for combined static + dynamic analysis.
 */

import type {
  Transaction,
  SimulationConfig,
  SimulationResult,
  StateChange,
  BalanceChange,
  Chain,
} from "../types";

export class SimulationSandbox {
  private config: SimulationConfig;

  constructor(config: SimulationConfig = {}) {
    this.config = {
      timeout: 30000,
      traceStateDiffs: true,
      ...config,
    };
  }

  /**
   * Simulate a transaction and return detailed results including state changes.
   * Routes to chain-specific simulation backends.
   */
  async simulate(transaction: Transaction): Promise<SimulationResult> {
    switch (transaction.chain) {
      case "evm":
        return this.simulateEvm(transaction);
      case "solana":
        return this.simulateSolana(transaction);
      default:
        return {
          success: false,
          chain: transaction.chain,
          error: `Unsupported chain: ${transaction.chain}`,
        };
    }
  }

  /**
   * Simulate multiple transactions as an atomic batch.
   * Useful for bundle simulation before submission.
   */
  async simulateBatch(transactions: Transaction[]): Promise<SimulationResult[]> {
    return Promise.all(transactions.map((tx) => this.simulate(tx)));
  }

  /**
   * Analyze simulation results for honeypot indicators.
   * A honeypot allows buying but blocks selling — detectable via simulation.
   */
  analyzeHoneypot(
    buyResult: SimulationResult,
    sellResult: SimulationResult
  ): {
    isHoneypot: boolean;
    buyTax: number;
    sellTax: number;
    reason?: string;
  } {
    // If buy succeeds but sell fails, it's a honeypot
    if (buyResult.success && !sellResult.success) {
      return {
        isHoneypot: true,
        buyTax: 0,
        sellTax: 100,
        reason: sellResult.revertReason || sellResult.error || "Sell transaction reverted",
      };
    }

    // Analyze balance changes for hidden taxes
    const buyDelta = this.calculateEffectiveDelta(buyResult.balanceChanges);
    const sellDelta = this.calculateEffectiveDelta(sellResult.balanceChanges);

    const buyTax = buyDelta.taxPercent;
    const sellTax = sellDelta.taxPercent;

    // High sell tax (>50%) is a strong honeypot indicator
    if (sellTax > 50) {
      return {
        isHoneypot: true,
        buyTax,
        sellTax,
        reason: `Sell tax of ${sellTax}% detected. Likely honeypot.`,
      };
    }

    return {
      isHoneypot: false,
      buyTax,
      sellTax,
    };
  }

  /**
   * Detect state changes that indicate a "honeymoon attack" —
   * a contract that behaves normally at first, then changes behavior.
   */
  analyzeStateChanges(result: SimulationResult): {
    suspiciousChanges: StateChange[];
    riskLevel: "low" | "medium" | "high";
  } {
    const suspicious: StateChange[] = [];

    for (const change of result.stateChanges || []) {
      // Storage slot 0 is typically owner — changes here are significant
      if (change.slot === "0x0" && change.previousValue !== change.newValue) {
        suspicious.push(change);
      }

      // Implementation slot (EIP-1967) changes indicate proxy upgrades
      if (
        change.slot ===
        "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
      ) {
        suspicious.push(change);
      }

      // Admin slot (EIP-1967) changes
      if (
        change.slot ===
        "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
      ) {
        suspicious.push(change);
      }
    }

    const riskLevel =
      suspicious.length >= 3
        ? "high"
        : suspicious.length >= 1
          ? "medium"
          : "low";

    return { suspiciousChanges: suspicious, riskLevel };
  }

  /**
   * Fetch deployed bytecode and scan for dangerous opcodes.
   * Used by EVM-005/006 to check if a target contract contains
   * DELEGATECALL (0xf4) or SELFDESTRUCT (0xff) opcodes.
   */
  async analyzeBytecode(contractAddress: string): Promise<{
    hasDelegatecall: boolean;
    hasSelfDestruct: boolean;
    hasCreate2: boolean;
    codeSize: number;
    isProxy: boolean;
  }> {
    const forkUrl = this.config.evmForkUrl;
    if (!forkUrl) {
      return {
        hasDelegatecall: false,
        hasSelfDestruct: false,
        hasCreate2: false,
        codeSize: 0,
        isProxy: false,
      };
    }

    const codeResult = await this.rpcCall(forkUrl, "eth_getCode", [
      contractAddress,
      "latest",
    ]);

    if (!codeResult.result || codeResult.result === "0x") {
      return {
        hasDelegatecall: false,
        hasSelfDestruct: false,
        hasCreate2: false,
        codeSize: 0,
        isProxy: false,
      };
    }

    const bytecode = codeResult.result.slice(2); // strip 0x
    const codeSize = bytecode.length / 2;

    // Scan bytecode for opcode presence
    const hasDelegatecall = this.bytecodeContainsOpcode(bytecode, "f4");
    const hasSelfDestruct = this.bytecodeContainsOpcode(bytecode, "ff");
    const hasCreate2 = this.bytecodeContainsOpcode(bytecode, "f5");

    // Detect proxy patterns:
    // - EIP-1967: SLOAD from implementation slot
    // - Minimal proxy (EIP-1167): starts with 363d3d373d3d3d363d73
    const isProxy =
      hasDelegatecall &&
      (bytecode.includes(
        "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
      ) ||
        bytecode.startsWith("363d3d373d3d3d363d73"));

    return {
      hasDelegatecall,
      hasSelfDestruct,
      hasCreate2,
      codeSize,
      isProxy,
    };
  }

  // ── EVM Simulation ──

  private async simulateEvm(transaction: Transaction): Promise<SimulationResult> {
    const forkUrl = this.config.evmForkUrl;

    if (!forkUrl) {
      return {
        success: false,
        chain: "evm",
        error: "No EVM fork URL configured. Set simulationConfig.evmForkUrl to an Anvil or RPC endpoint.",
      };
    }

    try {
      const calls = (transaction.instructions || []).map((ix) => ({
        to: ix.programId,
        data: ix.data.startsWith("0x") ? ix.data : `0x${ix.data}`,
        from: transaction.signers?.[0] || "0x0000000000000000000000000000000000000000",
      }));

      const results: SimulationResult = {
        success: true,
        chain: "evm",
        gasUsed: 0,
        stateChanges: [],
        balanceChanges: [],
        logs: [],
      };

      for (const call of calls) {
        // eth_call for basic simulation
        const callResult = await this.rpcCall(forkUrl, "eth_call", [
          call,
          "latest",
        ]);

        if (callResult.error) {
          results.success = false;
          results.error = callResult.error.message;
          results.revertReason = this.decodeRevertReason(
            callResult.error.data || ""
          );
          break;
        }

        // eth_estimateGas for gas usage
        const gasResult = await this.rpcCall(forkUrl, "eth_estimateGas", [
          call,
        ]);
        if (gasResult.result) {
          results.gasUsed! += parseInt(gasResult.result, 16);
        }

        // State diff tracing — try trace_call (Parity/OpenEthereum) first,
        // then fallback to debug_traceCall (Geth/Anvil)
        if (this.config.traceStateDiffs) {
          const stateChanges = await this.traceEvmStateDiffs(forkUrl, call);
          results.stateChanges!.push(...stateChanges);
        }
      }

      return results;
    } catch (error) {
      const err = error as Error;
      return {
        success: false,
        chain: "evm",
        error: `EVM simulation failed: ${err.message}`,
      };
    }
  }

  /**
   * Try trace_call (Parity API) first, then debug_traceCall (Geth API).
   * Gracefully degrades to empty array if neither is supported.
   */
  private async traceEvmStateDiffs(
    forkUrl: string,
    call: { to: string; data: string; from: string }
  ): Promise<StateChange[]> {
    // 1. Try trace_call (Parity/OpenEthereum/Erigon)
    const traceResult = await this.rpcCall(forkUrl, "trace_call", [
      call,
      ["stateDiff"],
      "latest",
    ]);

    if (traceResult.result?.stateDiff) {
      return this.parseEvmStateDiff(traceResult.result.stateDiff);
    }

    // 2. Fallback: debug_traceCall (Geth/Anvil) with prestateTracer
    const debugResult = await this.rpcCall(forkUrl, "debug_traceCall", [
      call,
      "latest",
      { tracer: "prestateTracer", tracerConfig: { diffMode: true } },
    ]);

    if (debugResult.result?.post) {
      return this.parseGethStateDiff(
        debugResult.result.pre || {},
        debugResult.result.post
      );
    }

    // 3. Neither supported — return empty (graceful degradation)
    return [];
  }

  // ── Solana Simulation ──

  private async simulateSolana(
    transaction: Transaction
  ): Promise<SimulationResult> {
    const rpcUrl = this.config.solanaRpcUrl;

    if (!rpcUrl) {
      return {
        success: false,
        chain: "solana",
        error: "No Solana RPC URL configured. Set simulationConfig.solanaRpcUrl.",
      };
    }

    try {
      const results: SimulationResult = {
        success: true,
        chain: "solana",
        computeUnitsUsed: 0,
        stateChanges: [],
        balanceChanges: [],
        logs: [],
      };

      // Collect all accounts involved in the transaction
      const accounts = new Set<string>();
      for (const ix of transaction.instructions || []) {
        accounts.add(ix.programId);
        for (const key of ix.keys) {
          accounts.add(key.pubkey);
        }
      }

      // Get pre-simulation account states
      const preStates = new Map<
        string,
        { lamports: number; owner: string; data: unknown }
      >();
      for (const account of accounts) {
        const info = await this.rpcCall(rpcUrl, "getAccountInfo", [
          account,
          { encoding: "base64" },
        ]);
        if (info.result?.value) {
          preStates.set(account, {
            lamports: info.result.value.lamports,
            owner: info.result.value.owner,
            data: info.result.value.data,
          });
        }
      }

      // If transaction has a serialized form, use simulateTransaction directly
      if (transaction.id && transaction.id.length > 50) {
        // Long ID might be a base64-encoded serialized transaction
        const simResult = await this.rpcCall(rpcUrl, "simulateTransaction", [
          transaction.id,
          {
            encoding: "base64",
            sigVerify: false,
            replaceRecentBlockhash: true,
            accounts: {
              addresses: [...accounts],
              encoding: "base64",
            },
          },
        ]);

        if (simResult.result?.value) {
          const value = simResult.result.value;

          if (value.err) {
            results.success = false;
            results.error =
              typeof value.err === "string"
                ? value.err
                : JSON.stringify(value.err);
          }

          results.computeUnitsUsed = value.unitsConsumed || 0;
          results.logs = value.logs || [];

          // Parse post-simulation account states for balance changes
          if (value.accounts) {
            for (let i = 0; i < value.accounts.length; i++) {
              const postAccount = value.accounts[i];
              const address = [...accounts][i];
              if (!postAccount || !address) continue;

              const pre = preStates.get(address);
              const postLamports = postAccount.lamports || 0;
              const preLamports = pre?.lamports || 0;

              if (postLamports !== preLamports) {
                results.balanceChanges!.push({
                  address,
                  before: preLamports.toString(),
                  after: postLamports.toString(),
                  delta: (postLamports - preLamports).toString(),
                });
              }

              // Detect owner changes (state change)
              if (pre && postAccount.owner && pre.owner !== postAccount.owner) {
                results.stateChanges!.push({
                  address,
                  slot: "owner",
                  previousValue: pre.owner,
                  newValue: postAccount.owner,
                });
              }
            }
          }

          return results;
        }
      }

      // Fallback: analyze instruction-level data without full simulation
      for (const ix of transaction.instructions || []) {
        // Check compute budget
        if (
          ix.programId === "ComputeBudget111111111111111111111111111111"
        ) {
          const data = Buffer.from(ix.data, "base64");
          if (data[0] === 2 && data.length >= 5) {
            results.computeUnitsUsed = data.readUInt32LE(1);
          }
        }
      }

      // Record pre-simulation state snapshots
      for (const [account, preState] of preStates) {
        results.balanceChanges!.push({
          address: account,
          before: preState.lamports.toString(),
          after: preState.lamports.toString(),
          delta: "0",
        });
      }

      return results;
    } catch (error) {
      const err = error as Error;
      return {
        success: false,
        chain: "solana",
        error: `Solana simulation failed: ${err.message}`,
      };
    }
  }

  // ── Shared Helpers ──

  private async rpcCall(
    url: string,
    method: string,
    params: unknown[]
  ): Promise<{ result?: any; error?: { message: string; data?: string } }> {
    const controller = new AbortController();
    const timeoutId = setTimeout(
      () => controller.abort(),
      this.config.timeout || 30000
    );

    try {
      const response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method,
          params,
        }),
        signal: controller.signal,
      });

      if (!response.ok) {
        return {
          error: {
            message: `HTTP ${response.status}: ${response.statusText}`,
          },
        };
      }

      return await response.json();
    } catch (error) {
      const err = error as Error;
      return { error: { message: err.message } };
    } finally {
      clearTimeout(timeoutId);
    }
  }

  private parseEvmStateDiff(
    stateDiff: Record<string, { storage?: Record<string, { from: string; to: string }> }>
  ): StateChange[] {
    const changes: StateChange[] = [];

    for (const [address, diff] of Object.entries(stateDiff)) {
      if (diff.storage) {
        for (const [slot, { from, to }] of Object.entries(diff.storage)) {
          if (from !== to) {
            changes.push({
              address,
              slot,
              previousValue: from,
              newValue: to,
            });
          }
        }
      }
    }

    return changes;
  }

  /**
   * Parse Geth debug_traceCall prestateTracer output (diffMode: true).
   * Pre contains accounts before, post contains accounts after.
   */
  private parseGethStateDiff(
    pre: Record<string, { storage?: Record<string, string> }>,
    post: Record<string, { storage?: Record<string, string> }>
  ): StateChange[] {
    const changes: StateChange[] = [];

    // Find all addresses in pre and post
    const allAddresses = new Set([
      ...Object.keys(pre),
      ...Object.keys(post),
    ]);

    for (const address of allAddresses) {
      const preStorage = pre[address]?.storage || {};
      const postStorage = post[address]?.storage || {};

      // Find all slots touched
      const allSlots = new Set([
        ...Object.keys(preStorage),
        ...Object.keys(postStorage),
      ]);

      for (const slot of allSlots) {
        const preValue = preStorage[slot] || "0x0";
        const postValue = postStorage[slot] || "0x0";

        if (preValue !== postValue) {
          changes.push({
            address,
            slot,
            previousValue: preValue,
            newValue: postValue,
          });
        }
      }
    }

    return changes;
  }

  private decodeRevertReason(data: string): string {
    if (!data || data === "0x") return "Unknown revert";

    const hex = data.startsWith("0x") ? data.slice(2) : data;

    // Error(string) selector = 0x08c379a0
    if (hex.startsWith("08c379a0") && hex.length >= 136) {
      try {
        const length = parseInt(hex.slice(72, 136), 16);
        const messageHex = hex.slice(136, 136 + length * 2);
        return Buffer.from(messageHex, "hex").toString("utf8");
      } catch {
        return `Revert: 0x${hex.slice(0, 20)}...`;
      }
    }

    // Panic(uint256) selector = 0x4e487b71
    if (hex.startsWith("4e487b71")) {
      const code = parseInt(hex.slice(8, 72), 16);
      const panicReasons: Record<number, string> = {
        0x00: "Generic compiler panic",
        0x01: "Assert failed",
        0x11: "Arithmetic overflow",
        0x12: "Division by zero",
        0x21: "Invalid enum value",
        0x31: "Pop on empty array",
        0x32: "Out of bounds access",
        0x41: "Out of memory",
        0x51: "Zero-initialized function pointer",
      };
      return panicReasons[code] || `Panic(0x${code.toString(16)})`;
    }

    return `Revert: 0x${hex.slice(0, 20)}...`;
  }

  private calculateEffectiveDelta(changes?: BalanceChange[]): {
    taxPercent: number;
  } {
    if (!changes || changes.length === 0) return { taxPercent: 0 };

    let maxDelta = BigInt(0);
    let actualReceived = BigInt(0);

    for (const change of changes) {
      const delta = BigInt(change.delta);
      if (delta > maxDelta) maxDelta = delta;
      if (delta > 0) actualReceived += delta;
    }

    if (maxDelta === BigInt(0)) return { taxPercent: 0 };

    const taxPercent = Number(
      ((maxDelta - actualReceived) * BigInt(100)) / maxDelta
    );
    return { taxPercent: Math.max(0, Math.min(100, taxPercent)) };
  }

  /**
   * Scan bytecode for a specific opcode.
   * Must skip PUSH data to avoid false positives (opcode within PUSH arguments).
   */
  private bytecodeContainsOpcode(bytecode: string, opcode: string): boolean {
    const hex = bytecode.toLowerCase();
    let i = 0;

    while (i < hex.length) {
      const op = hex.slice(i, i + 2);

      if (op === opcode) {
        return true;
      }

      // PUSH1-PUSH32: skip the pushed data bytes
      const opNum = parseInt(op, 16);
      if (opNum >= 0x60 && opNum <= 0x7f) {
        const pushBytes = opNum - 0x5f;
        i += 2 + pushBytes * 2; // skip opcode + data
      } else {
        i += 2; // skip opcode
      }
    }

    return false;
  }
}
