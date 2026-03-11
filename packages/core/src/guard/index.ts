/**
 * Guard — Chain-agnostic transaction security validation and monitoring
 *
 * Solana patterns (P-101 through P-108):
 * - Mint/freeze authority kills, signer mismatch, dangerous close
 * - Transfer hook attacks (malicious, unexpected, reentrancy, excessive accounts)
 *
 * EVM patterns (EVM-001 through EVM-009):
 * - Reentrancy attacks, flash loan attacks, front-running, unauthorized access
 * - Proxy manipulation, selfdestruct abuse, approval exploitation, oracle manipulation
 * - Governance manipulation
 *
 * Three enforcement modes: "block", "warn"
 * Three risk tolerances: "strict", "moderate", "permissive"
 *
 * Optional simulation integration for pre-execution state analysis.
 * simulationRequired mode blocks transactions that haven't been simulated.
 */

import type {
  GuardConfig,
  Transaction,
  ValidationResult,
  SecurityWarning,
  SimulationResult,
} from "../types";
import { PatternId, Severity } from "../types";
import { analyzeTransaction } from "./detector";
import { SimulationSandbox } from "../simulation";
import { resolveOracleBatch, DENOMINATIONS } from "./oracle-registry";

/** Default compute unit budget for Solana transactions */
const DEFAULT_SOLANA_CU_BUDGET = 200_000;
/** Threshold above which CU usage triggers a warning (fraction of budget) */
const CU_EXHAUSTION_THRESHOLD = 0.8;

export class Guard {
  private config: GuardConfig;
  private warningHistory: SecurityWarning[] = [];
  private simulator: SimulationSandbox | null = null;

  constructor(config: GuardConfig = {}) {
    this.config = {
      enablePatternDetection: true,
      riskTolerance: "moderate",
      mode: "block",
      emergencyStop: false,
      ...config,
    };

    if (config.enableSimulation && config.simulationConfig) {
      this.simulator = new SimulationSandbox(config.simulationConfig);
    }
  }

  async validateTransaction(
    transaction: Transaction
  ): Promise<ValidationResult> {
    const warnings: SecurityWarning[] = [];

    if (this.config.emergencyStop) {
      return {
        isValid: false,
        warnings: [
          {
            patternId: PatternId.MintKill,
            severity: Severity.Critical,
            message: "EMERGENCY STOP: All operations are halted",
            timestamp: Date.now(),
          },
        ],
        blockedBy: [PatternId.MintKill],
      };
    }

    if (this.config.enablePatternDetection !== false) {
      const detectedWarnings = analyzeTransaction(transaction, this.config);
      warnings.push(...detectedWarnings);
    }

    // Run simulation if enabled
    let simulation: SimulationResult | undefined;
    if (this.simulator) {
      simulation = await this.simulator.simulate(transaction);

      // Add warnings from simulation results
      if (simulation && !simulation.success) {
        warnings.push({
          patternId: transaction.chain === "evm"
            ? PatternId.ReentrancyAttack
            : PatternId.MaliciousTransferHook,
          severity: Severity.Critical,
          message: `Simulation failed: ${simulation.revertReason || simulation.error || "Transaction would revert"}`,
          timestamp: Date.now(),
        });
      }

      // Analyze state changes for suspicious patterns
      if (simulation?.stateChanges && simulation.stateChanges.length > 0) {
        const analysis = this.simulator.analyzeStateChanges(simulation);
        if (analysis.riskLevel === "high") {
          warnings.push({
            patternId: PatternId.ProxyManipulation,
            severity: Severity.Critical,
            message: `Simulation detected ${analysis.suspiciousChanges.length} suspicious state changes (proxy/owner slot modifications).`,
            timestamp: Date.now(),
          });
        } else if (analysis.riskLevel === "medium") {
          warnings.push({
            patternId: PatternId.ProxyManipulation,
            severity: Severity.Alert,
            message: `Simulation detected ${analysis.suspiciousChanges.length} notable state change(s). Review before execution.`,
            timestamp: Date.now(),
          });
        }
      }

      // Solana CU exhaustion detection
      if (
        transaction.chain === "solana" &&
        simulation?.computeUnitsUsed
      ) {
        const cuBudget = this.getSolanaCuBudget(transaction);
        const cuUsed = simulation.computeUnitsUsed;
        const utilization = cuUsed / cuBudget;

        if (utilization > CU_EXHAUSTION_THRESHOLD) {
          warnings.push({
            patternId: PatternId.MaliciousTransferHook,
            severity: utilization >= 1.0 ? Severity.Critical : Severity.Alert,
            message: `Compute unit usage ${cuUsed}/${cuBudget} (${Math.round(utilization * 100)}%). ${utilization >= 1.0 ? "Transaction will fail due to CU exhaustion." : "Near CU budget limit — vulnerable to CU exhaustion attacks."}`,
            timestamp: Date.now(),
          });
        }
      }
    } else if (this.config.simulationRequired && this.config.mode === "block") {
      // simulationRequired mode: block if no simulation was run
      warnings.push({
        patternId: transaction.chain === "evm"
          ? PatternId.ReentrancyAttack
          : PatternId.MaliciousTransferHook,
        severity: Severity.Critical,
        message: "Simulation required but not configured. Enable simulationConfig to proceed.",
        timestamp: Date.now(),
      });
    }

    const blockedBy = this.determineBlocking(warnings);
    const isValid = blockedBy.length === 0;

    this.warningHistory.push(...warnings);

    return {
      isValid,
      warnings,
      blockedBy: blockedBy.length > 0 ? blockedBy : undefined,
      ...(simulation && { simulation }),
    };
  }

  async validate(transaction?: Transaction): Promise<boolean> {
    if (!transaction) return !this.config.emergencyStop;
    const result = await this.validateTransaction(transaction);
    return result.isValid;
  }

  getConfig(): GuardConfig {
    return { ...this.config };
  }

  updateConfig(updates: Partial<GuardConfig>): void {
    this.config = { ...this.config, ...updates };

    // Re-initialize simulator if simulation config changed
    if (updates.enableSimulation !== undefined || updates.simulationConfig) {
      if (this.config.enableSimulation && this.config.simulationConfig) {
        this.simulator = new SimulationSandbox(this.config.simulationConfig);
      } else {
        this.simulator = null;
      }
    }
  }

  activateEmergencyStop(): void {
    this.config.emergencyStop = true;
  }

  deactivateEmergencyStop(): void {
    this.config.emergencyStop = false;
  }

  getWarningHistory(): SecurityWarning[] {
    return [...this.warningHistory];
  }

  clearWarningHistory(): void {
    this.warningHistory = [];
  }

  isSlippageAcceptable(actualSlippage: number): boolean {
    if (this.config.maxSlippage === undefined) return true;
    return actualSlippage <= this.config.maxSlippage;
  }

  /**
   * Resolve common oracle feed addresses from the Chainlink Feed Registry
   * and add them to the guard's oracleAddresses config.
   *
   * Call this once after construction if oracleRegistryRpcUrl is set.
   * Non-blocking — silently skips feeds that can't be resolved.
   */
  async resolveOracleFeeds(): Promise<string[]> {
    const rpcUrl = this.config.oracleRegistryRpcUrl;
    if (!rpcUrl) return [];

    // Well-known token addresses on mainnet
    const WETH = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
    const WBTC = "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599";
    const LINK = "0x514910771AF9Ca656af840dff83E8264EcF986CA";
    const UNI  = "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984";
    const AAVE = "0x7Fc66500c84A76Ad7e9c93437bFc5Ac33E2DDaE9";

    const pairs = [
      { base: WETH, quote: DENOMINATIONS.USD },
      { base: WBTC, quote: DENOMINATIONS.USD },
      { base: LINK, quote: DENOMINATIONS.USD },
      { base: UNI,  quote: DENOMINATIONS.USD },
      { base: AAVE, quote: DENOMINATIONS.USD },
      { base: WETH, quote: DENOMINATIONS.BTC },
    ];

    const resolved = await resolveOracleBatch(rpcUrl, pairs);
    const feeds = [...resolved.values()].map((addr) => addr.toLowerCase());

    if (feeds.length > 0) {
      const existing = new Set(this.config.oracleAddresses || []);
      for (const feed of feeds) {
        existing.add(feed);
      }
      this.config.oracleAddresses = [...existing];
    }

    return feeds;
  }

  /**
   * Get the simulation sandbox instance (if simulation is enabled).
   * Useful for running standalone simulations (e.g. honeypot checks).
   */
  getSimulator(): SimulationSandbox | null {
    return this.simulator;
  }

  /**
   * Extract the Solana CU budget from transaction instructions.
   * Looks for SetComputeUnitLimit instruction, falls back to default.
   */
  private getSolanaCuBudget(transaction: Transaction): number {
    for (const ix of transaction.instructions || []) {
      if (ix.programId === "ComputeBudget111111111111111111111111111111") {
        try {
          const data = Buffer.from(ix.data, "base64");
          if (data[0] === 2 && data.length >= 5) {
            return data.readUInt32LE(1);
          }
        } catch {
          // ignore parse errors
        }
      }
    }
    return DEFAULT_SOLANA_CU_BUDGET;
  }

  private determineBlocking(warnings: SecurityWarning[]): PatternId[] {
    const mode = this.config.mode || "block";
    const riskTolerance = this.config.riskTolerance || "moderate";

    if (mode === "warn") return [];

    const blockedPatterns: PatternId[] = [];

    for (const warning of warnings) {
      const shouldBlock =
        (warning.severity === Severity.Critical &&
          (riskTolerance === "strict" || riskTolerance === "moderate")) ||
        (riskTolerance === "permissive" &&
          (warning.patternId === PatternId.MintKill ||
            warning.patternId === PatternId.FreezeKill));

      if (shouldBlock && !blockedPatterns.includes(warning.patternId)) {
        blockedPatterns.push(warning.patternId);
      }
    }

    return blockedPatterns;
  }
}

export { analyzeTransaction } from "./detector";
export { analyzeSolanaTransaction } from "./solana-detector";
export { analyzeEvmTransaction } from "./evm-detector";
export {
  resolveOracleFromRegistry,
  resolveOracleBatch,
  DENOMINATIONS,
} from "./oracle-registry";
