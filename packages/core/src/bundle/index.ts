/**
 * Bundle — Chain-agnostic atomic transaction bundle management
 *
 * Base: abstract BaseBundleManager with retry, backoff, and confirmation polling
 * Solana: BundleManager (Jito Block Engine) with tip accounts and simulation
 * EVM: FlashbotsBundleManager (Flashbots Protect / MEV-Share) with private submission
 */

// Abstract base
export { BaseBundleManager } from "./base";
export type { BaseBundleConfig } from "./base";

// Solana / Jito implementation
export {
  BundleManager,
  JitoError,
  JITO_TIP_ACCOUNTS,
} from "./jito";
export type { JitoBundle, JitoBundleConfig, BundleConfig } from "./jito";

// EVM / Flashbots implementation
export {
  FlashbotsBundleManager,
  FlashbotsError,
} from "./flashbots";
export type { FlashbotsBundleConfig, AuthSigner } from "./flashbots";
