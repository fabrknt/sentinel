/**
 * Core types for Sentinel — transaction security and execution patterns
 */

// ── Guard Types ──

export enum PatternId {
  // Solana patterns
  MintKill = "P-101",
  FreezeKill = "P-102",
  SignerMismatch = "P-103",
  DangerousClose = "P-104",
  MaliciousTransferHook = "P-105",
  UnexpectedHookExecution = "P-106",
  HookReentrancy = "P-107",
  ExcessiveHookAccounts = "P-108",

  // EVM patterns
  ReentrancyAttack = "EVM-001",
  FlashLoanAttack = "EVM-002",
  FrontRunning = "EVM-003",
  UnauthorizedAccess = "EVM-004",
  ProxyManipulation = "EVM-005",
  SelfdestructAbuse = "EVM-006",
  ApprovalExploitation = "EVM-007",
  OracleManipulation = "EVM-008",
  GovernanceManipulation = "EVM-009",
}

export enum Severity {
  Critical = "critical",
  Warning = "warning",
  Alert = "alert",
}

export interface SecurityWarning {
  patternId: PatternId;
  severity: Severity;
  message: string;
  affectedAccount?: string;
  timestamp: number;
}

export interface ValidationResult {
  isValid: boolean;
  warnings: SecurityWarning[];
  blockedBy?: PatternId[];
  simulation?: SimulationResult;
}

export interface TransactionInstruction {
  programId: string;
  keys: Array<{
    pubkey: string;
    isSigner: boolean;
    isWritable: boolean;
  }>;
  data: string;
}

export type Chain = "solana" | "evm";

export interface Transaction {
  id: string;
  chain: Chain;
  status: "pending" | "executed" | "failed";
  instructions?: TransactionInstruction[];
  signers?: string[];
  assetAddresses?: string[];
}

export interface GuardConfig {
  maxSlippage?: number;
  emergencyStop?: boolean;
  enablePatternDetection?: boolean;
  riskTolerance?: "strict" | "moderate" | "permissive";
  mode?: "block" | "warn";
  validateTransferHooks?: boolean;
  maxHookAccounts?: number;
  allowedHookPrograms?: string[];
  // EVM-specific
  trustedEvmAddresses?: string[];
  /** User-supplied oracle contract addresses to monitor (lowercase 0x-prefixed) */
  oracleAddresses?: string[];
  /** EVM RPC URL for resolving oracles from Chainlink Feed Registry at runtime */
  oracleRegistryRpcUrl?: string;
  // Simulation
  enableSimulation?: boolean;
  simulationConfig?: SimulationConfig;
  /** When true, blocks transactions that haven't been successfully simulated */
  simulationRequired?: boolean;
}

// ── Simulation Types ──

export interface SimulationConfig {
  /** Fork URL for EVM simulation (e.g. Anvil RPC) */
  evmForkUrl?: string;
  /** Solana RPC URL for simulation */
  solanaRpcUrl?: string;
  /** Block number to fork from (EVM) */
  forkBlockNumber?: number;
  /** Timeout in ms for simulation (default: 30000) */
  timeout?: number;
  /** Whether to trace state changes */
  traceStateDiffs?: boolean;
}

export interface SimulationResult {
  success: boolean;
  chain: Chain;
  gasUsed?: number;
  computeUnitsUsed?: number;
  stateChanges?: StateChange[];
  balanceChanges?: BalanceChange[];
  logs?: string[];
  error?: string;
  revertReason?: string;
}

export interface StateChange {
  address: string;
  slot?: string;
  previousValue?: string;
  newValue?: string;
}

export interface BalanceChange {
  address: string;
  token?: string;
  before: string;
  after: string;
  delta: string;
}

// ── Pattern Types ──

export interface PatternConfig {
  name: string;
  description?: string;
  dryRun?: boolean;
  maxRetries?: number;
  retryDelay?: number;
}

export interface PatternResult {
  success: boolean;
  transactions: Transaction[];
  metrics: PatternMetrics;
  error?: Error;
  metadata?: Record<string, unknown>;
}

export interface PatternMetrics {
  executionTime: number;
  transactionCount: number;
  retries: number;
  estimatedCost?: number;
  actualCost?: number;
  custom?: Record<string, number>;
}

export interface Token {
  address: string;
  symbol: string;
  decimals: number;
  name?: string;
  /** @deprecated Use `address` instead */
  mint?: string;
}

export interface Price {
  token: string;
  price: number;
  quoteCurrency: string;
  timestamp: number;
  source?: string;
}

export interface TradingPair {
  base: Token;
  quote: Token;
  minSize?: number;
  maxSize?: number;
}

export type ExecutionStrategy =
  | "immediate"
  | "twap"
  | "vwap"
  | "conditional"
  | "limit";

// ── Bundle Types ──

export interface BundleResult {
  bundleId: string;
  accepted: boolean;
  signatures?: string[];
  error?: string;
  confirmedAt?: number;
}

export interface BundleStatusResponse {
  status: "pending" | "landed" | "failed" | "invalid";
  landedSlot?: number;
  landedBlock?: number;
  transactions?: string[];
  error?: string;
}

export enum JitoRegion {
  Default = "default",
  Amsterdam = "amsterdam",
  Frankfurt = "frankfurt",
  NewYork = "ny",
  Tokyo = "tokyo",
}

export enum TipLevel {
  None = 0,
  Low = 1000,
  Medium = 10000,
  High = 100000,
  VeryHigh = 1000000,
  Turbo = 10000000,
}

// ── Flashbots Types ──

export enum FlashbotsNetwork {
  Mainnet = "mainnet",
  Goerli = "goerli",
  Sepolia = "sepolia",
}

export interface FlashbotsBundle {
  transactions: string[];
  blockNumber: number;
  minTimestamp?: number;
  maxTimestamp?: number;
  revertingTxHashes?: string[];
}

export interface MevShareBundle {
  transactions: string[];
  blockNumber: number;
  privacy?: {
    hints?: ("calldata" | "contract_address" | "logs" | "function_selector" | "hash")[];
    builders?: string[];
  };
  validity?: {
    refund?: { bodyIdx: number; percent: number }[];
    refundConfig?: { address: string; percent: number }[];
  };
}
