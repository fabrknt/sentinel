/**
 * EVM-specific pattern detection (EVM-001 through EVM-009)
 *
 * Detects dangerous patterns in EVM transactions:
 * - EVM-001: Reentrancy attacks (external calls before state updates)
 * - EVM-002: Flash loan attacks (single-tx borrow + manipulate + repay)
 * - EVM-003: Front-running patterns (sandwich attack indicators)
 * - EVM-004: Unauthorized access (calls to admin functions from non-owner)
 * - EVM-005: Proxy manipulation (upgradeTo, storage collisions, delegatecall to unknown)
 * - EVM-006: Selfdestruct / delegatecall abuse
 * - EVM-007: Token approval exploitation (unlimited approve, approve-then-transfer)
 * - EVM-008: Price oracle manipulation (oracle reads bracketed by swaps)
 * - EVM-009: Governance manipulation (flash loan + governance actions)
 */

import type {
  Transaction,
  TransactionInstruction,
  SecurityWarning,
  GuardConfig,
} from "../types";
import { PatternId as Pattern, Severity as Sev } from "../types";

// Well-known EVM contract selectors (first 4 bytes of keccak256)
const SELECTORS = {
  // ERC20
  transfer: "a9059cbb",
  transferFrom: "23b872dd",
  approve: "095ea7b3",
  increaseAllowance: "39509351",
  // Flash loans
  flashLoan: "5cffe9de", // AAVE
  flashBorrow: "e0232b42",
  // DEX
  swap: "022c0d9f", // Uniswap V2
  swapExact: "38ed1739",
  exactInputSingle: "414bf389", // Uniswap V3
  exactInput: "c04b8d59",
  // Admin
  transferOwnership: "f2fde38b",
  renounceOwnership: "715018a6",
  setAdmin: "704b6c02",
  upgradeTo: "3659cfe6",
  upgradeToAndCall: "4f1ef286",
  // Proxy / Dangerous
  selfdestruct: "ff",
  delegatecall: "f4",
  changeAdmin: "8f283970",
  changeProxyAdmin: "7eff275e",
  // Oracle
  latestRoundData: "feaf968c", // Chainlink
  latestAnswer: "50d25bcd",
  getReserves: "0902f1ac", // Uniswap V2 Pair
  observe: "883bdbfd", // Uniswap V3 Pool
  slot0: "3850c7bd",
  // Multicall
  multicall: "ac9650d8",
  aggregate: "252dba42",
  // Governance
  propose: "da95691a", // Governor.propose
  castVote: "56781388", // Governor.castVote
  castVoteWithReason: "7b3c71d3",
  execute: "fe0d94c1", // Governor.execute (with descriptionHash)
  queue: "ddf0b009", // Governor.queue
  delegate: "5c19a95c", // ERC20Votes.delegate
};

// Known flash loan provider addresses (lowercase)
const FLASH_LOAN_PROVIDERS = new Set([
  "0x7d2768de32b0b80b7a3454c06bdac94a69ddc7a9", // AAVE V2
  "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2", // AAVE V3
  "0x6bdba7d04b19e8f1b7841bbe7313c0c8a69c5eaa", // dYdX
  "0x1eb4cf3a948e7d72a198fe073ccb8c7a948cd853", // Euler
  "0x5c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f", // Uniswap V2 Factory (flash swaps)
  "0xba12222222228d8ba445958a75a0704d566bf2c8", // Balancer Vault
]);

// Known DEX router addresses
const DEX_ROUTERS = new Set([
  "0x7a250d5630b4cf539739df2c5dacb4c659f2488d", // Uniswap V2 Router
  "0xe592427a0aece92de3edee1f18e0157c05861564", // Uniswap V3 Router
  "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45", // Uniswap V3 Router 02
  "0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f", // SushiSwap Router
  "0x1111111254eeb25477b68fb85ed929f73a960582", // 1inch V5
  "0x1111111254fb6c44bac0bed2854e76f90643097d", // 1inch V4
  "0xdef1c0ded9bec7f1a1670819833240f027b25eff", // 0x Exchange Proxy
]);

// Known oracle addresses — Chainlink mainnet price feeds
const ORACLE_CONTRACTS = new Set([
  "0x5f4ec3df9cbd43714fe2740f5e3616155c5b8419", // ETH/USD
  "0x986b5e1e1755e3c2440e960477f25201b0a8bbd4", // USDC/ETH
  "0x2c1d072e956affc0d435cb7ac38ef18d24d9127c", // LINK/USD
  "0xf4030086522a5beea4988f8ca5b36dbc97bee88c", // BTC/USD
  "0x3e7d1eab13ad0104d2750b8863b489d65364e32d", // USDT/USD
  "0x8fffffd4afb6115b954bd326cbe7b4ba576818f6", // USDC/USD
  "0xaed0c38402a5d19df6e4c03f4e2dced6e29c1ee9", // DAI/USD
  "0xcfe54b5cd566ab89272946f602d76ea879cab4a8", // stETH/USD
  "0x547a514d5e3769680ce22b2361c10ea13619e8a9", // AAVE/USD
]);

// Governance-related selectors
const GOVERNANCE_SELECTORS = new Set([
  SELECTORS.propose,
  SELECTORS.castVote,
  SELECTORS.castVoteWithReason,
  SELECTORS.execute,
  SELECTORS.queue,
  SELECTORS.delegate,
]);

// Selectors that indicate oracle price reads
const ORACLE_SELECTORS = new Set([
  SELECTORS.latestRoundData,
  SELECTORS.latestAnswer,
  SELECTORS.getReserves,
  SELECTORS.observe,
  SELECTORS.slot0,
]);

// Selectors that indicate swap/price-moving operations
const SWAP_SELECTORS = new Set([
  SELECTORS.swap,
  SELECTORS.swapExact,
  SELECTORS.exactInputSingle,
  SELECTORS.exactInput,
]);

// Max uint256 approve value prefix — common unlimited approve pattern
const UNLIMITED_APPROVE_PREFIX = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

export function analyzeEvmTransaction(
  transaction: Transaction,
  config?: GuardConfig
): SecurityWarning[] {
  const warnings: SecurityWarning[] = [];

  if (!transaction.instructions || transaction.instructions.length === 0) {
    return warnings;
  }

  warnings.push(...detectReentrancy(transaction));
  warnings.push(...detectFlashLoan(transaction));
  warnings.push(...detectFrontRunning(transaction));
  warnings.push(...detectUnauthorizedAccess(transaction, config));
  warnings.push(...detectProxyManipulation(transaction));
  warnings.push(...detectSelfdestructAbuse(transaction));
  warnings.push(...detectApprovalExploitation(transaction));
  warnings.push(...detectOracleManipulation(transaction, config));
  warnings.push(...detectGovernanceManipulation(transaction));

  return warnings;
}

/**
 * EVM-001: Reentrancy detection
 * Flags transactions where external calls happen before state-changing operations,
 * or where the same contract is called multiple times with value transfers.
 */
function detectReentrancy(transaction: Transaction): SecurityWarning[] {
  const warnings: SecurityWarning[] = [];
  const callTargets = new Map<string, number>();

  for (const ix of transaction.instructions || []) {
    const target = ix.programId.toLowerCase();
    const count = callTargets.get(target) || 0;
    callTargets.set(target, count + 1);

    // Multiple calls to the same non-standard contract with value
    if (count >= 2 && !DEX_ROUTERS.has(target) && !FLASH_LOAN_PROVIDERS.has(target)) {
      const selector = getSelector(ix.data);
      if (selector === SELECTORS.transfer || selector === SELECTORS.transferFrom) {
        warnings.push({
          patternId: Pattern.ReentrancyAttack,
          severity: Sev.Critical,
          message: `Contract ${target} called ${count + 1} times with token transfers. Possible reentrancy.`,
          affectedAccount: target,
          timestamp: Date.now(),
        });
      }
    }
  }

  // State-change ordering analysis: detect interleaved external calls and state writes
  const instructions = transaction.instructions || [];
  if (instructions.length >= 3) {
    const callFlow = analyzeCallFlow(instructions);
    if (callFlow.hasExternalCallBeforeStateUpdate) {
      warnings.push({
        patternId: Pattern.ReentrancyAttack,
        severity: Sev.Alert,
        message: `External call to ${callFlow.externalTarget} precedes state-changing operation. Check-effects-interactions violation.`,
        affectedAccount: callFlow.externalTarget,
        timestamp: Date.now(),
      });
    }
  }

  return warnings;
}

/**
 * Analyze instruction ordering for check-effects-interactions violations.
 * Detects when a call to an external contract precedes a state-changing
 * operation on the originating contract.
 */
function analyzeCallFlow(instructions: TransactionInstruction[]): {
  hasExternalCallBeforeStateUpdate: boolean;
  externalTarget?: string;
} {
  const stateChangingSelectors = new Set([
    SELECTORS.transfer,
    SELECTORS.transferFrom,
    SELECTORS.approve,
  ]);

  // Track contracts that make external calls followed by their own state changes
  const externalCallIndices: { target: string; index: number }[] = [];

  for (let i = 0; i < instructions.length; i++) {
    const selector = getSelector(instructions[i].data);

    // delegatecall to unknown contracts is an external call
    if (selector === SELECTORS.delegatecall) {
      externalCallIndices.push({ target: instructions[i].programId, index: i });
    }

    // call to unknown contract (not a known DEX or flash loan provider)
    const target = instructions[i].programId.toLowerCase();
    if (!DEX_ROUTERS.has(target) && !FLASH_LOAN_PROVIDERS.has(target)) {
      if (selector === SELECTORS.transfer || selector === SELECTORS.transferFrom) {
        // Check if subsequent instructions modify state on same contract
        for (let j = i + 1; j < instructions.length; j++) {
          const laterTarget = instructions[j].programId.toLowerCase();
          const laterSelector = getSelector(instructions[j].data);
          if (laterTarget === target && stateChangingSelectors.has(laterSelector)) {
            return {
              hasExternalCallBeforeStateUpdate: true,
              externalTarget: target,
            };
          }
        }
      }
    }
  }

  return { hasExternalCallBeforeStateUpdate: false };
}

/**
 * EVM-002: Flash loan attack detection
 * Flags transactions that interact with known flash loan providers
 * combined with DEX swaps or price-sensitive operations.
 */
function detectFlashLoan(transaction: Transaction): SecurityWarning[] {
  const warnings: SecurityWarning[] = [];
  const instructions = transaction.instructions || [];

  let hasFlashLoan = false;
  let hasDexSwap = false;
  let hasTransfer = false;
  let hasOracleRead = false;
  let flashLoanProvider = "";

  for (const ix of instructions) {
    const target = ix.programId.toLowerCase();
    const selector = getSelector(ix.data);

    if (FLASH_LOAN_PROVIDERS.has(target) || selector === SELECTORS.flashLoan || selector === SELECTORS.flashBorrow) {
      hasFlashLoan = true;
      flashLoanProvider = target;
    }

    if (DEX_ROUTERS.has(target) || SWAP_SELECTORS.has(selector)) {
      hasDexSwap = true;
    }

    if (selector === SELECTORS.transfer || selector === SELECTORS.transferFrom) {
      hasTransfer = true;
    }

    if (ORACLE_SELECTORS.has(selector) || ORACLE_CONTRACTS.has(target)) {
      hasOracleRead = true;
    }
  }

  if (hasFlashLoan && hasDexSwap) {
    warnings.push({
      patternId: Pattern.FlashLoanAttack,
      severity: Sev.Critical,
      message: `Flash loan from ${flashLoanProvider || "unknown provider"} combined with DEX swap detected. Possible price manipulation attack.`,
      timestamp: Date.now(),
    });
  }

  // Flash loan + oracle read = likely oracle manipulation
  if (hasFlashLoan && hasOracleRead) {
    warnings.push({
      patternId: Pattern.FlashLoanAttack,
      severity: Sev.Critical,
      message: "Flash loan combined with oracle price read. Possible oracle manipulation via borrowed liquidity.",
      timestamp: Date.now(),
    });
  }

  if (hasFlashLoan && hasTransfer && instructions.length > 5) {
    warnings.push({
      patternId: Pattern.FlashLoanAttack,
      severity: Sev.Alert,
      message: `Flash loan with ${instructions.length} operations and token transfers. Review transaction intent.`,
      timestamp: Date.now(),
    });
  }

  return warnings;
}

/**
 * EVM-003: Front-running / sandwich attack detection
 * Flags patterns where a swap is bracketed by related operations
 * on the same pair, or where gas price is abnormally high.
 */
function detectFrontRunning(transaction: Transaction): SecurityWarning[] {
  const warnings: SecurityWarning[] = [];
  const instructions = transaction.instructions || [];

  const swapIndices: number[] = [];

  for (let i = 0; i < instructions.length; i++) {
    const selector = getSelector(instructions[i].data);
    if (SWAP_SELECTORS.has(selector)) {
      swapIndices.push(i);
    }
  }

  // Multiple swaps on same router = potential sandwich
  if (swapIndices.length >= 2) {
    const routers = swapIndices.map((i) => instructions[i].programId.toLowerCase());
    const uniqueRouters = new Set(routers);

    if (uniqueRouters.size < routers.length) {
      warnings.push({
        patternId: Pattern.FrontRunning,
        severity: Sev.Alert,
        message: `${swapIndices.length} swaps on the same router in one transaction. Possible sandwich attack pattern.`,
        timestamp: Date.now(),
      });
    }
  }

  // Detect buy-action-sell sandwich pattern
  if (swapIndices.length >= 2) {
    const firstSwap = swapIndices[0];
    const lastSwap = swapIndices[swapIndices.length - 1];

    // Check if there are non-swap operations between first and last swap
    const middleOps = instructions.slice(firstSwap + 1, lastSwap);
    const hasNonSwapMiddle = middleOps.some(ix => {
      const sel = getSelector(ix.data);
      return !SWAP_SELECTORS.has(sel);
    });

    if (hasNonSwapMiddle && lastSwap - firstSwap >= 2) {
      warnings.push({
        patternId: Pattern.FrontRunning,
        severity: Sev.Warning,
        message: "Swap-action-swap pattern detected. Operations bracketed by swaps may indicate sandwich structure.",
        timestamp: Date.now(),
      });
    }
  }

  return warnings;
}

/**
 * EVM-004: Unauthorized access detection
 * Flags calls to admin/ownership functions that may indicate
 * unauthorized privilege escalation.
 */
function detectUnauthorizedAccess(
  transaction: Transaction,
  config?: GuardConfig
): SecurityWarning[] {
  const warnings: SecurityWarning[] = [];

  const adminSelectors = new Set([
    SELECTORS.transferOwnership,
    SELECTORS.renounceOwnership,
    SELECTORS.setAdmin,
    SELECTORS.upgradeTo,
    SELECTORS.upgradeToAndCall,
    SELECTORS.changeAdmin,
    SELECTORS.changeProxyAdmin,
  ]);

  const trustedAddresses = new Set(
    (config?.trustedEvmAddresses || []).map((a: string) => a.toLowerCase())
  );

  for (const ix of transaction.instructions || []) {
    const selector = getSelector(ix.data);
    const caller = transaction.signers?.[0]?.toLowerCase();
    const target = ix.programId.toLowerCase();

    if (selector === SELECTORS.renounceOwnership) {
      warnings.push({
        patternId: Pattern.UnauthorizedAccess,
        severity: Sev.Critical,
        message: `renounceOwnership() called on ${ix.programId}. This permanently removes admin control.`,
        affectedAccount: ix.programId,
        timestamp: Date.now(),
      });
    } else if (adminSelectors.has(selector)) {
      // If the caller is not in trusted addresses, escalate severity
      const isTrusted = caller && trustedAddresses.has(caller);
      warnings.push({
        patternId: Pattern.UnauthorizedAccess,
        severity: isTrusted ? Sev.Warning : Sev.Alert,
        message: `Admin function (${selector}) called on ${ix.programId}${isTrusted ? "" : " by untrusted caller"}. Verify caller authorization.`,
        affectedAccount: ix.programId,
        timestamp: Date.now(),
      });
    }
  }

  return warnings;
}

/**
 * EVM-005: Proxy manipulation detection
 * Flags upgrade-related calls, implementation changes, and proxy admin modifications
 * that could be used to swap contract logic maliciously.
 */
function detectProxyManipulation(transaction: Transaction): SecurityWarning[] {
  const warnings: SecurityWarning[] = [];
  const instructions = transaction.instructions || [];

  const proxySelectors = new Set([
    SELECTORS.upgradeTo,
    SELECTORS.upgradeToAndCall,
    SELECTORS.changeAdmin,
    SELECTORS.changeProxyAdmin,
  ]);

  let upgradeCount = 0;
  let hasMulticall = false;

  for (const ix of instructions) {
    const selector = getSelector(ix.data);

    if (proxySelectors.has(selector)) {
      upgradeCount++;
    }

    if (selector === SELECTORS.multicall || selector === SELECTORS.aggregate) {
      hasMulticall = true;
    }
  }

  // Multiple proxy upgrades in a single tx is highly suspicious
  if (upgradeCount >= 2) {
    warnings.push({
      patternId: Pattern.ProxyManipulation,
      severity: Sev.Critical,
      message: `${upgradeCount} proxy upgrade operations in a single transaction. Possible coordinated contract takeover.`,
      timestamp: Date.now(),
    });
  }

  // Upgrade inside a multicall is suspicious — hides the upgrade in a batch
  if (upgradeCount > 0 && hasMulticall) {
    warnings.push({
      patternId: Pattern.ProxyManipulation,
      severity: Sev.Alert,
      message: "Proxy upgrade bundled inside multicall/aggregate. Upgrade may be obscured within batch operation.",
      timestamp: Date.now(),
    });
  }

  // Single upgrade with many other operations is unusual
  if (upgradeCount === 1 && instructions.length > 5) {
    warnings.push({
      patternId: Pattern.ProxyManipulation,
      severity: Sev.Warning,
      message: `Proxy upgrade combined with ${instructions.length - 1} other operations. Verify upgrade is intentional.`,
      timestamp: Date.now(),
    });
  }

  return warnings;
}

/**
 * EVM-006: Selfdestruct / delegatecall abuse detection
 * Flags dangerous low-level operations that can destroy contracts
 * or execute arbitrary code.
 */
function detectSelfdestructAbuse(transaction: Transaction): SecurityWarning[] {
  const warnings: SecurityWarning[] = [];

  let hasDelegatecall = false;
  let hasSelfDestruct = false;
  const delegatecallTargets: string[] = [];

  for (const ix of transaction.instructions || []) {
    const selector = getSelector(ix.data);
    const data = normalizeHex(ix.data);

    // Check for selfdestruct opcode presence in calldata
    // selfdestruct = 0xff opcode — flag if the data is very short (raw opcode)
    if (data.length <= 4 && data.startsWith("ff")) {
      hasSelfDestruct = true;
    }

    // Check for delegatecall selector in primary position or nested in calldata
    if (selector.startsWith("f4")) {
      hasDelegatecall = true;
      delegatecallTargets.push(ix.programId);
    }

    // Detect delegatecall/selfdestruct patterns embedded in calldata (nested calls)
    if (data.length > 8) {
      const innerSelectors = extractInnerSelectors(data);
      for (const inner of innerSelectors) {
        if (inner.startsWith("f4")) {
          hasDelegatecall = true;
          delegatecallTargets.push(ix.programId);
        }
      }
    }
  }

  if (hasSelfDestruct) {
    warnings.push({
      patternId: Pattern.SelfdestructAbuse,
      severity: Sev.Critical,
      message: "Transaction contains potential selfdestruct operation. Contract may be permanently destroyed.",
      timestamp: Date.now(),
    });
  }

  if (hasDelegatecall) {
    const targets = [...new Set(delegatecallTargets)];
    warnings.push({
      patternId: Pattern.SelfdestructAbuse,
      severity: Sev.Alert,
      message: `Delegatecall to ${targets.length} contract(s): ${targets.slice(0, 3).join(", ")}. Verify implementation safety.`,
      timestamp: Date.now(),
    });
  }

  return warnings;
}

/**
 * EVM-007: Token approval exploitation detection
 * Flags unlimited approvals, approve-then-transferFrom patterns,
 * and approval to unverified spenders.
 */
function detectApprovalExploitation(transaction: Transaction): SecurityWarning[] {
  const warnings: SecurityWarning[] = [];
  const instructions = transaction.instructions || [];

  const approvals: { index: number; target: string; spender?: string; isUnlimited: boolean }[] = [];
  const transferFroms: { index: number; target: string }[] = [];

  for (let i = 0; i < instructions.length; i++) {
    const ix = instructions[i];
    const selector = getSelector(ix.data);
    const data = normalizeHex(ix.data);

    if (selector === SELECTORS.approve || selector === SELECTORS.increaseAllowance) {
      // Check if the approval amount is unlimited (max uint256)
      const isUnlimited = data.length >= 72 && data.slice(72).startsWith(UNLIMITED_APPROVE_PREFIX.slice(0, 56));

      // Extract spender from calldata (first parameter after selector)
      const spender = data.length >= 72
        ? "0x" + data.slice(32, 72).replace(/^0+/, "")
        : undefined;

      approvals.push({ index: i, target: ix.programId, spender, isUnlimited });
    }

    if (selector === SELECTORS.transferFrom) {
      transferFroms.push({ index: i, target: ix.programId });
    }
  }

  // Flag unlimited approvals
  for (const approval of approvals) {
    if (approval.isUnlimited) {
      warnings.push({
        patternId: Pattern.ApprovalExploitation,
        severity: Sev.Warning,
        message: `Unlimited token approval on ${approval.target}${approval.spender ? ` to spender ${approval.spender}` : ""}. Consider using exact amounts.`,
        affectedAccount: approval.target,
        timestamp: Date.now(),
      });
    }
  }

  // Detect approve-then-transferFrom in same tx (possible drain pattern)
  for (const approval of approvals) {
    const subsequentTransfers = transferFroms.filter(
      tf => tf.index > approval.index && tf.target === approval.target
    );
    if (subsequentTransfers.length > 0) {
      warnings.push({
        patternId: Pattern.ApprovalExploitation,
        severity: Sev.Alert,
        message: `Approve followed by immediate transferFrom on ${approval.target}. Possible token drain pattern.`,
        affectedAccount: approval.target,
        timestamp: Date.now(),
      });
    }
  }

  // Multiple approvals on different tokens in one tx = suspicious
  if (approvals.length >= 3) {
    const uniqueTokens = new Set(approvals.map(a => a.target.toLowerCase()));
    if (uniqueTokens.size >= 3) {
      warnings.push({
        patternId: Pattern.ApprovalExploitation,
        severity: Sev.Alert,
        message: `${approvals.length} token approvals across ${uniqueTokens.size} different tokens in a single transaction. Possible batch approval phishing.`,
        timestamp: Date.now(),
      });
    }
  }

  return warnings;
}

/**
 * EVM-008: Price oracle manipulation detection
 * Flags patterns where oracle price reads are combined with swaps
 * that could move the oracle price within the same transaction.
 */
function detectOracleManipulation(
  transaction: Transaction,
  config?: GuardConfig
): SecurityWarning[] {
  const warnings: SecurityWarning[] = [];
  const instructions = transaction.instructions || [];

  // Merge built-in oracle contracts with user-supplied ones
  const oracleAddresses = new Set(ORACLE_CONTRACTS);
  if (config?.oracleAddresses) {
    for (const addr of config.oracleAddresses) {
      oracleAddresses.add(addr.toLowerCase());
    }
  }

  const oracleReads: { index: number; target: string }[] = [];
  const swapOps: { index: number; target: string }[] = [];

  for (let i = 0; i < instructions.length; i++) {
    const ix = instructions[i];
    const selector = getSelector(ix.data);
    const target = ix.programId.toLowerCase();

    if (ORACLE_SELECTORS.has(selector) || oracleAddresses.has(target)) {
      oracleReads.push({ index: i, target });
    }

    if (SWAP_SELECTORS.has(selector) || DEX_ROUTERS.has(target)) {
      swapOps.push({ index: i, target });
    }
  }

  // Swap before oracle read = potential price manipulation
  for (const oracle of oracleReads) {
    const precedingSwaps = swapOps.filter(s => s.index < oracle.index);
    if (precedingSwaps.length > 0) {
      warnings.push({
        patternId: Pattern.OracleManipulation,
        severity: Sev.Critical,
        message: `DEX swap precedes oracle price read at ${oracle.target}. Possible TWAP/spot price manipulation.`,
        affectedAccount: oracle.target,
        timestamp: Date.now(),
      });
      break; // One warning is enough
    }
  }

  // Oracle read sandwiched between swaps = classic manipulation
  for (const oracle of oracleReads) {
    const swapBefore = swapOps.some(s => s.index < oracle.index);
    const swapAfter = swapOps.some(s => s.index > oracle.index);

    if (swapBefore && swapAfter) {
      warnings.push({
        patternId: Pattern.OracleManipulation,
        severity: Sev.Critical,
        message: `Oracle read sandwiched between swap operations. Classic price oracle manipulation pattern.`,
        affectedAccount: oracle.target,
        timestamp: Date.now(),
      });
      break;
    }
  }

  // Using on-chain DEX reserves as a price source (getReserves) is inherently manipulable
  for (const oracle of oracleReads) {
    const selector = getSelector(instructions[oracle.index].data);
    if (selector === SELECTORS.getReserves && swapOps.length > 0) {
      warnings.push({
        patternId: Pattern.OracleManipulation,
        severity: Sev.Warning,
        message: `Using DEX reserves (getReserves) as price source alongside swap operations. On-chain reserves are flash-loan manipulable.`,
        affectedAccount: oracle.target,
        timestamp: Date.now(),
      });
      break;
    }
  }

  return warnings;
}

/**
 * EVM-009: Governance manipulation detection
 * Flags patterns where flash loans or large token movements are combined
 * with governance actions (propose, vote, execute, delegate).
 * Classic attack vector: borrow tokens → delegate → vote → execute → repay.
 */
function detectGovernanceManipulation(transaction: Transaction): SecurityWarning[] {
  const warnings: SecurityWarning[] = [];
  const instructions = transaction.instructions || [];

  let hasFlashLoan = false;
  let hasGovernanceAction = false;
  let hasDelegation = false;
  const governanceActions: string[] = [];

  for (const ix of instructions) {
    const target = ix.programId.toLowerCase();
    const selector = getSelector(ix.data);

    if (
      FLASH_LOAN_PROVIDERS.has(target) ||
      selector === SELECTORS.flashLoan ||
      selector === SELECTORS.flashBorrow
    ) {
      hasFlashLoan = true;
    }

    if (GOVERNANCE_SELECTORS.has(selector)) {
      hasGovernanceAction = true;
      governanceActions.push(selector);
    }

    if (selector === SELECTORS.delegate) {
      hasDelegation = true;
    }
  }

  // Flash loan + governance = classic governance attack
  if (hasFlashLoan && hasGovernanceAction) {
    warnings.push({
      patternId: Pattern.GovernanceManipulation,
      severity: Sev.Critical,
      message: "Flash loan combined with governance action. Possible flash loan governance attack (e.g. Beanstalk-style).",
      timestamp: Date.now(),
    });
  }

  // Delegation + vote in same tx = suspicious (instant voting power acquisition)
  if (hasDelegation && governanceActions.includes(SELECTORS.castVote)) {
    warnings.push({
      patternId: Pattern.GovernanceManipulation,
      severity: Sev.Alert,
      message: "Token delegation and vote cast in same transaction. Voting power may have been acquired specifically for this vote.",
      timestamp: Date.now(),
    });
  }

  // Delegation + vote + execute in same tx = almost certainly an attack
  if (
    hasDelegation &&
    governanceActions.includes(SELECTORS.castVote) &&
    governanceActions.includes(SELECTORS.execute)
  ) {
    warnings.push({
      patternId: Pattern.GovernanceManipulation,
      severity: Sev.Critical,
      message: "Delegate + vote + execute in a single transaction. Governance manipulation attack pattern.",
      timestamp: Date.now(),
    });
  }

  return warnings;
}

// ── Helpers ──

function getSelector(data: string): string {
  try {
    // EVM calldata is hex-encoded, first 4 bytes = function selector
    const hex = data.startsWith("0x") ? data.slice(2) : data;
    return hex.slice(0, 8).toLowerCase();
  } catch {
    return "";
  }
}

function normalizeHex(data: string): string {
  return (data.startsWith("0x") ? data.slice(2) : data).toLowerCase();
}

/**
 * Extract 4-byte selectors embedded within calldata (for nested calls).
 * Scans for known selector patterns within the data.
 */
function extractInnerSelectors(data: string): string[] {
  const hex = normalizeHex(data);
  const selectors: string[] = [];
  const knownSelectors = new Set(Object.values(SELECTORS));

  // Scan through hex data looking for known selectors
  for (let i = 0; i <= hex.length - 8; i += 2) {
    const candidate = hex.slice(i, i + 8);
    if (knownSelectors.has(candidate)) {
      selectors.push(candidate);
    }
  }

  return selectors;
}
