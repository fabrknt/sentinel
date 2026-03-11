// Types
export * from "./types";

// Guard — chain-agnostic transaction security validation
export {
  Guard,
  analyzeTransaction,
  analyzeSolanaTransaction,
  analyzeEvmTransaction,
  resolveOracleFromRegistry,
  resolveOracleBatch,
  DENOMINATIONS,
} from "./guard";

// Bundle — atomic transaction bundle management
export {
  BaseBundleManager,
  BundleManager,
  JitoError,
  JITO_TIP_ACCOUNTS,
  FlashbotsBundleManager,
  FlashbotsError,
} from "./bundle";
export type {
  BaseBundleConfig,
  JitoBundle,
  JitoBundleConfig,
  BundleConfig,
  FlashbotsBundleConfig,
  AuthSigner,
} from "./bundle";

// Simulation — pre-execution transaction simulation
export { SimulationSandbox } from "./simulation";

// Patterns — execution pattern builders (chain-agnostic)
export {
  buildBatchPayout,
  buildRecurringPaymentSchedule,
  buildVestingSchedule,
  buildGridTradingPlan,
  buildDCAPlan,
  buildRebalancePlan,
} from "./patterns";

export type {
  BatchPayoutConfig,
  BatchPayoutResult,
  RecurringPaymentConfig,
  RecurringPaymentSchedule,
  VestingConfig,
  VestingSchedule,
  GridTradingConfig,
  GridTradingPlan,
  GridLevel,
  DCAConfig,
  DCAPlan,
  RebalanceConfig,
  RebalancePlan,
} from "./patterns";
