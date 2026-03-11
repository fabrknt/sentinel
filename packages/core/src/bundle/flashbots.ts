/**
 * Flashbots Bundle Manager — EVM-specific bundle submission via Flashbots Protect / MEV-Share
 *
 * Provides private transaction submission to prevent front-running and sandwich attacks.
 * Supports both legacy Flashbots bundles and the newer MEV-Share protocol.
 *
 * Auth: Accepts an AuthSigner interface for proper ECDSA signing.
 * Use ethers.js, viem, or any secp256k1 signer implementation.
 */

import type {
  BundleResult,
  BundleStatusResponse,
  FlashbotsBundle,
  MevShareBundle,
} from "../types";
import { FlashbotsNetwork } from "../types";
import { BaseBundleManager } from "./base";
import type { BaseBundleConfig } from "./base";

/**
 * Interface for signing Flashbots payloads.
 *
 * The Flashbots relay expects X-Flashbots-Signature: `{address}:{signature}` where:
 * 1. bodyHash = keccak256(body)
 * 2. message = "\x19Ethereum Signed Message:\n32" + bodyHash
 * 3. msgHash = keccak256(message)
 * 4. signature = ECDSA(msgHash, privateKey) → 65 bytes (r[32] + s[32] + v[1])
 *
 * The `sign(body)` method receives the raw JSON-RPC body string.
 * It must return a 0x-prefixed 130-char hex string (65 bytes).
 *
 * Example with ethers.js v6:
 * ```ts
 * import { Wallet, id } from "ethers";
 * const wallet = new Wallet(privateKey);
 * const signer: AuthSigner = {
 *   address: wallet.address,
 *   sign: (body) => wallet.signMessage(id(body)),
 * };
 * ```
 *
 * Example with viem:
 * ```ts
 * import { privateKeyToAccount } from "viem/accounts";
 * import { keccak256, toBytes } from "viem";
 * const account = privateKeyToAccount(privateKey);
 * const signer: AuthSigner = {
 *   address: account.address,
 *   sign: (body) => account.signMessage({ message: keccak256(toBytes(body)) }),
 * };
 * ```
 */
export interface AuthSigner {
  /** The address of the signing key (0x-prefixed hex) */
  address: string;
  /** Sign a message body and return the signature (0x-prefixed hex) */
  sign(body: string): Promise<string>;
}

export interface FlashbotsBundleConfig extends BaseBundleConfig {
  /** Flashbots Protect relay URL (defaults to mainnet) */
  relayUrl?: string;
  /** MEV-Share relay URL */
  mevShareUrl?: string;
  /** Network for Flashbots (mainnet, goerli, sepolia) */
  network?: FlashbotsNetwork;
  /**
   * Auth signer for Flashbots reputation.
   * Must implement the AuthSigner interface with address + sign().
   * Without this, bundles are submitted anonymously (lower relay priority).
   */
  authSigner?: AuthSigner;
}

const FLASHBOTS_RELAY_URLS: Record<FlashbotsNetwork, string> = {
  [FlashbotsNetwork.Mainnet]: "https://relay.flashbots.net",
  [FlashbotsNetwork.Goerli]: "https://relay-goerli.flashbots.net",
  [FlashbotsNetwork.Sepolia]: "https://relay-sepolia.flashbots.net",
};

const MEV_SHARE_URLS: Record<FlashbotsNetwork, string> = {
  [FlashbotsNetwork.Mainnet]: "https://relay.flashbots.net",
  [FlashbotsNetwork.Goerli]: "https://relay-goerli.flashbots.net",
  [FlashbotsNetwork.Sepolia]: "https://relay-sepolia.flashbots.net",
};

export class FlashbotsError extends Error {
  constructor(
    message: string,
    public code?: string,
    public details?: unknown
  ) {
    super(message);
    this.name = "FlashbotsError";
  }
}

export class FlashbotsBundleManager extends BaseBundleManager {
  private relayUrl: string;
  private mevShareUrl: string;
  private network: FlashbotsNetwork;
  private authSigner: AuthSigner | null;

  constructor(config: FlashbotsBundleConfig) {
    super(config);
    this.network = config.network || FlashbotsNetwork.Mainnet;
    this.relayUrl = config.relayUrl || FLASHBOTS_RELAY_URLS[this.network];
    this.mevShareUrl = config.mevShareUrl || MEV_SHARE_URLS[this.network];
    this.authSigner = config.authSigner || null;
  }

  /**
   * Send a Flashbots bundle to the relay for inclusion in a specific block.
   */
  async sendBundle(
    bundle: FlashbotsBundle,
    retryCount: number = 0
  ): Promise<BundleResult> {
    const payload = {
      jsonrpc: "2.0",
      id: 1,
      method: "eth_sendBundle",
      params: [
        {
          txs: bundle.transactions,
          blockNumber: `0x${bundle.blockNumber.toString(16)}`,
          ...(bundle.minTimestamp && { minTimestamp: bundle.minTimestamp }),
          ...(bundle.maxTimestamp && { maxTimestamp: bundle.maxTimestamp }),
          ...(bundle.revertingTxHashes && {
            revertingTxHashes: bundle.revertingTxHashes,
          }),
        },
      ],
    };

    return this.submitToRelay(this.relayUrl, payload, retryCount);
  }

  /**
   * Send a bundle via MEV-Share for private order flow with configurable privacy hints.
   */
  async sendMevShareBundle(
    bundle: MevShareBundle,
    retryCount: number = 0
  ): Promise<BundleResult> {
    const payload = {
      jsonrpc: "2.0",
      id: 1,
      method: "mev_sendBundle",
      params: [
        {
          version: "v0.1",
          inclusion: {
            block: `0x${bundle.blockNumber.toString(16)}`,
            maxBlock: `0x${(bundle.blockNumber + 25).toString(16)}`,
          },
          body: bundle.transactions.map((tx) => ({
            tx,
            canRevert: false,
          })),
          ...(bundle.privacy && {
            privacy: {
              ...(bundle.privacy.hints && { hints: bundle.privacy.hints }),
              ...(bundle.privacy.builders && {
                builders: bundle.privacy.builders,
              }),
            },
          }),
          ...(bundle.validity && { validity: bundle.validity }),
        },
      ],
    };

    return this.submitToRelay(this.mevShareUrl, payload, retryCount);
  }

  /**
   * Simulate a bundle against the current state without submitting.
   */
  async simulateBundle(bundle: FlashbotsBundle): Promise<{
    success: boolean;
    results: Array<{
      txHash?: string;
      gasUsed?: number;
      revertReason?: string;
    }>;
    totalGasUsed: number;
    stateBlockNumber: number;
  }> {
    const payload = {
      jsonrpc: "2.0",
      id: 1,
      method: "eth_callBundle",
      params: [
        {
          txs: bundle.transactions,
          blockNumber: `0x${bundle.blockNumber.toString(16)}`,
          stateBlockNumber: "latest",
        },
      ],
    };

    const response = await this.fetchRelay(this.relayUrl, payload);
    const data = await response.json();

    if (data.error) {
      throw new FlashbotsError(
        `Simulation failed: ${data.error.message}`,
        data.error.code?.toString(),
        data.error.data
      );
    }

    const result = data.result;
    const results = (result.results || []).map(
      (r: { txHash?: string; gasUsed?: number; revert?: string }) => ({
        txHash: r.txHash,
        gasUsed: r.gasUsed,
        revertReason: r.revert,
      })
    );

    return {
      success: results.every(
        (r: { revertReason?: string }) => !r.revertReason
      ),
      results,
      totalGasUsed: result.totalGasUsed || 0,
      stateBlockNumber: result.stateBlockNumber || bundle.blockNumber,
    };
  }

  /**
   * Get the status of a previously submitted bundle.
   */
  async getBundleStatus(bundleId: string): Promise<BundleStatusResponse> {
    const payload = {
      jsonrpc: "2.0",
      id: 1,
      method: "flashbots_getBundleStatsV2",
      params: [{ bundleHash: bundleId, blockNumber: "latest" }],
    };

    const response = await this.fetchRelay(this.relayUrl, payload);
    const data = await response.json();

    if (data.error) {
      throw new FlashbotsError(
        `Bundle status error: ${data.error.message}`,
        data.error.code?.toString()
      );
    }

    const result = data.result;
    if (!result) return { status: "pending" };

    let status: BundleStatusResponse["status"] = "pending";
    if (result.sealedByBuildersAt?.length > 0) {
      status = "landed";
    }

    return {
      status,
      landedBlock: result.sealedByBuildersAt?.[0]?.blockNumber,
      transactions: result.receivedAt ? [bundleId] : undefined,
      error: undefined,
    };
  }

  /**
   * Cancel a pending bundle (Flashbots Protect only).
   */
  async cancelBundle(bundleId: string): Promise<boolean> {
    const payload = {
      jsonrpc: "2.0",
      id: 1,
      method: "eth_cancelBundle",
      params: [{ txHash: bundleId }],
    };

    const response = await this.fetchRelay(this.relayUrl, payload);
    const data = await response.json();
    return !data.error;
  }

  /**
   * Send a single private transaction via Flashbots Protect.
   * Simplest way to get frontrunning protection without full bundle management.
   */
  async sendPrivateTransaction(
    signedTx: string,
    maxBlockNumber: number
  ): Promise<BundleResult> {
    const payload = {
      jsonrpc: "2.0",
      id: 1,
      method: "eth_sendPrivateTransaction",
      params: [
        {
          tx: signedTx,
          maxBlockNumber: `0x${maxBlockNumber.toString(16)}`,
        },
      ],
    };

    const response = await this.fetchRelay(this.relayUrl, payload);
    const data = await response.json();

    if (data.error) {
      throw new FlashbotsError(
        `Private tx error: ${data.error.message}`,
        data.error.code?.toString()
      );
    }

    return {
      bundleId: data.result,
      accepted: true,
    };
  }

  // ── Private helpers ──

  private async submitToRelay(
    url: string,
    payload: object,
    retryCount: number
  ): Promise<BundleResult> {
    try {
      const response = await this.fetchRelay(url, payload);
      const data = await response.json();

      if (data.error) {
        if (this.isRetriableError(data.error) && retryCount < this.maxRetries) {
          await this.sleep(this.getBackoffDelay(retryCount));
          return this.submitToRelay(url, payload, retryCount + 1);
        }
        throw new FlashbotsError(
          `Flashbots API Error: ${data.error.message}`,
          data.error.code?.toString(),
          data.error.data
        );
      }

      return {
        bundleId: data.result?.bundleHash || data.result,
        accepted: true,
      };
    } catch (error: unknown) {
      const err = error as Error & { name?: string; code?: string };

      if (err.name === "AbortError") {
        if (retryCount < this.maxRetries) {
          await this.sleep(this.getBackoffDelay(retryCount));
          return this.submitToRelay(url, payload, retryCount + 1);
        }
        throw new FlashbotsError("Request timed out", "TIMEOUT", {
          attempts: retryCount + 1,
        });
      }

      if (this.isNetworkError(err) && retryCount < this.maxRetries) {
        await this.sleep(this.getBackoffDelay(retryCount));
        return this.submitToRelay(url, payload, retryCount + 1);
      }

      if (err instanceof FlashbotsError) throw err;

      throw new FlashbotsError(
        `Bundle Error: ${err.message}`,
        "UNKNOWN_ERROR",
        { originalError: err, attempts: retryCount + 1 }
      );
    }
  }

  private async fetchRelay(url: string, payload: object): Promise<Response> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };

    // Flashbots uses X-Flashbots-Signature header for authentication
    const body = JSON.stringify(payload);
    if (this.authSigner) {
      const signature = await this.authSigner.sign(body);
      headers["X-Flashbots-Signature"] = `${this.authSigner.address}:${signature}`;
    }

    try {
      const response = await fetch(url, {
        method: "POST",
        headers,
        body,
        signal: controller.signal,
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new FlashbotsError(
          `Flashbots HTTP Error: ${response.status} ${response.statusText}`,
          `HTTP_${response.status}`,
          { body: errorText }
        );
      }

      return response;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  private isRetriableError(error: { code?: number; message?: string }): boolean {
    if (error.code && [-32000, -32603, 429].includes(error.code)) return true;
    if (error.message?.includes("rate limit")) return true;
    return false;
  }
}
