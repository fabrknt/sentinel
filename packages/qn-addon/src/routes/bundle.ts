import { Router } from "express";
import { keccak_256 } from "@noble/hashes/sha3";
import { secp256k1 } from "@noble/curves/secp256k1";
import {
  TipLevel,
  JITO_TIP_ACCOUNTS,
  JitoRegion,
  FlashbotsBundleManager,
  FlashbotsError,
  FlashbotsNetwork,
  BundleManager,
  JitoError,
} from "@sentinel/core";
import type { FlashbotsBundle, MevShareBundle, AuthSigner } from "@sentinel/core";

export const bundleRoutes = Router();

/**
 * Build an AuthSigner from environment variables.
 * FLASHBOTS_AUTH_KEY: 32-byte hex private key (with or without 0x prefix)
 *
 * Implements Flashbots authentication:
 * 1. Hash the JSON-RPC body with keccak256
 * 2. EIP-191 personal sign: prefix "\x19Ethereum Signed Message:\n32" + bodyHash
 * 3. keccak256 the prefixed message
 * 4. ECDSA sign with secp256k1, return 65-byte (r + s + v) hex signature
 *
 * Uses @noble/hashes (keccak256) and @noble/curves (secp256k1) — audited,
 * zero-dependency, pure JS implementations.
 */
function getFlashbotsAuthSigner(): AuthSigner | undefined {
  const rawKey = process.env.FLASHBOTS_AUTH_KEY;
  if (!rawKey) return undefined;

  const keyHex = rawKey.startsWith("0x") ? rawKey.slice(2) : rawKey;
  if (keyHex.length !== 64) return undefined;

  const privateKeyBytes = hexToBytes(keyHex);

  // Derive the Ethereum address from the private key
  const publicKey = secp256k1.getPublicKey(privateKeyBytes, false); // uncompressed
  // Ethereum address = last 20 bytes of keccak256(publicKey[1:])
  const pubKeyHash = keccak_256(publicKey.slice(1));
  const address = "0x" + bytesToHex(pubKeyHash.slice(12));

  return {
    address,
    sign: async (body: string) => {
      // 1. keccak256 of the body
      const bodyHash = keccak_256(new TextEncoder().encode(body));

      // 2. EIP-191 personal sign prefix
      const prefix = new TextEncoder().encode(
        "\x19Ethereum Signed Message:\n32"
      );
      const prefixedMessage = new Uint8Array(prefix.length + bodyHash.length);
      prefixedMessage.set(prefix);
      prefixedMessage.set(bodyHash, prefix.length);

      // 3. keccak256 the prefixed message
      const msgHash = keccak_256(prefixedMessage);

      // 4. ECDSA sign with recovery bit
      const sig = secp256k1.sign(msgHash, privateKeyBytes);

      // 5. Encode as 65-byte (r[32] + s[32] + v[1]) hex
      const r = sig.r.toString(16).padStart(64, "0");
      const s = sig.s.toString(16).padStart(64, "0");
      const v = (sig.recovery + 27).toString(16).padStart(2, "0");

      return "0x" + r + s + v;
    },
  };
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * POST /v1/bundle/tip
 * Calculate a Jito tip amount and return a random tip account.
 */
bundleRoutes.post("/tip", (req, res) => {
  try {
    const { level = "medium", region = "default", multiplier = 1 } = req.body;

    const tipLevels: Record<string, TipLevel> = {
      low: TipLevel.Low,
      medium: TipLevel.Medium,
      high: TipLevel.High,
      very_high: TipLevel.VeryHigh,
      turbo: TipLevel.Turbo,
    };

    const tipAmount = Math.floor((tipLevels[level] || TipLevel.Medium) * multiplier);
    const jitoRegion = (region as JitoRegion) || JitoRegion.Default;
    const accounts = JITO_TIP_ACCOUNTS[jitoRegion] || JITO_TIP_ACCOUNTS[JitoRegion.Default];
    const tipAccount = accounts[Math.floor(Math.random() * accounts.length)];

    res.json({
      tipAmount,
      tipAmountSol: tipAmount / 1e9,
      tipAccount: tipAccount.address,
      region: jitoRegion,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error";
    res.status(500).json({ error: message });
  }
});

/**
 * POST /v1/bundle/submit
 * Submit a bundle. Supports both Solana (Jito) and EVM (Flashbots).
 */
bundleRoutes.post("/submit", async (req, res) => {
  try {
    const { chain = "solana", transactions, blockNumber, network, privacy } = req.body;

    if (!transactions || !Array.isArray(transactions) || transactions.length === 0) {
      res.status(400).json({ error: "transactions array is required" });
      return;
    }

    if (chain === "evm") {
      if (!blockNumber || typeof blockNumber !== "number") {
        res.status(400).json({ error: "blockNumber is required for EVM bundles" });
        return;
      }

      const rpcEndpoint = process.env.EVM_RPC_URL;
      if (!rpcEndpoint) {
        res.status(503).json({
          error: "EVM bundle submission requires EVM_RPC_URL env var.",
        });
        return;
      }

      const flashbotsNetwork = (network as FlashbotsNetwork) || FlashbotsNetwork.Mainnet;

      const manager = new FlashbotsBundleManager({
        endpoint: rpcEndpoint,
        network: flashbotsNetwork,
        authSigner: getFlashbotsAuthSigner(),
      });

      if (privacy) {
        const bundle: MevShareBundle = { transactions, blockNumber, privacy };
        const result = await manager.sendMevShareBundle(bundle);
        res.json({
          status: "accepted",
          chain: "evm",
          protocol: "mev-share",
          bundleId: result.bundleId,
          accepted: result.accepted,
        });
      } else {
        const bundle: FlashbotsBundle = { transactions, blockNumber };
        const result = await manager.sendBundle(bundle);
        res.json({
          status: "accepted",
          chain: "evm",
          protocol: "flashbots",
          bundleId: result.bundleId,
          accepted: result.accepted,
        });
      }
    } else if (chain === "solana") {
      const solanaRpcUrl = process.env.SOLANA_RPC_URL;
      const jitoBlockEngineUrl = process.env.JITO_BLOCK_ENGINE_URL;

      if (!solanaRpcUrl || !jitoBlockEngineUrl) {
        res.status(503).json({
          error: "Solana bundle submission requires SOLANA_RPC_URL and JITO_BLOCK_ENGINE_URL env vars.",
        });
        return;
      }

      const { region = "default" } = req.body;

      // Jito expects base64-encoded serialized VersionedTransactions.
      // The BundleManager.sendBundle() needs VersionedTransaction objects,
      // so we forward raw base64 txs directly to the Jito Block Engine API.
      const jitoRegion = (region as JitoRegion) || JitoRegion.Default;

      const payload = {
        jsonrpc: "2.0",
        id: 1,
        method: "sendBundle",
        params: [transactions],
      };

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 30000);

      try {
        const response = await fetch(`${jitoBlockEngineUrl}/api/v1/bundles`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
          signal: controller.signal,
        });

        clearTimeout(timeoutId);

        if (!response.ok) {
          const errorText = await response.text();
          res.status(502).json({
            error: `Jito Block Engine error: ${response.status}`,
            details: errorText,
          });
          return;
        }

        const data = await response.json();

        if (data.error) {
          res.status(502).json({
            error: `Jito API error: ${data.error.message}`,
            code: data.error.code?.toString(),
          });
          return;
        }

        res.json({
          status: "accepted",
          chain: "solana",
          protocol: "jito",
          bundleId: data.result,
          accepted: true,
          transactionCount: transactions.length,
          region: jitoRegion,
        });
      } catch (err) {
        clearTimeout(timeoutId);
        throw err;
      }
    } else {
      res.status(400).json({ error: `Unsupported chain: ${chain}. Use "solana" or "evm".` });
    }
  } catch (error) {
    if (error instanceof FlashbotsError) {
      res.status(502).json({ error: error.message, code: error.code, details: error.details });
      return;
    }
    const message = error instanceof Error ? error.message : "Unknown error";
    res.status(500).json({ error: message });
  }
});

/**
 * POST /v1/bundle/simulate
 * Simulate a bundle before submission (EVM only via Flashbots eth_callBundle).
 */
bundleRoutes.post("/simulate", async (req, res) => {
  try {
    const { transactions, blockNumber, network } = req.body;

    if (!transactions || !Array.isArray(transactions) || transactions.length === 0) {
      res.status(400).json({ error: "transactions array is required" });
      return;
    }

    if (!blockNumber || typeof blockNumber !== "number") {
      res.status(400).json({ error: "blockNumber is required" });
      return;
    }

    const rpcEndpoint = process.env.EVM_RPC_URL;
    if (!rpcEndpoint) {
      res.status(503).json({ error: "EVM bundle simulation requires EVM_RPC_URL env var." });
      return;
    }

    const flashbotsNetwork = (network as FlashbotsNetwork) || FlashbotsNetwork.Mainnet;

    const manager = new FlashbotsBundleManager({
      endpoint: rpcEndpoint,
      network: flashbotsNetwork,
      authSigner: getFlashbotsAuthSigner(),
    });

    const result = await manager.simulateBundle({ transactions, blockNumber });

    res.json({
      success: result.success,
      results: result.results,
      totalGasUsed: result.totalGasUsed,
      stateBlockNumber: result.stateBlockNumber,
    });
  } catch (error) {
    if (error instanceof FlashbotsError) {
      res.status(502).json({ error: error.message, code: error.code });
      return;
    }
    const message = error instanceof Error ? error.message : "Unknown error";
    res.status(500).json({ error: message });
  }
});

/**
 * POST /v1/bundle/private-tx
 * Send a single private transaction via Flashbots Protect.
 */
bundleRoutes.post("/private-tx", async (req, res) => {
  try {
    const { signedTx, maxBlockNumber, network } = req.body;

    if (!signedTx || typeof signedTx !== "string") {
      res.status(400).json({ error: "signedTx (hex-encoded signed transaction) is required" });
      return;
    }

    if (!maxBlockNumber || typeof maxBlockNumber !== "number") {
      res.status(400).json({ error: "maxBlockNumber is required" });
      return;
    }

    const rpcEndpoint = process.env.EVM_RPC_URL;
    if (!rpcEndpoint) {
      res.status(503).json({ error: "EVM private transaction requires EVM_RPC_URL env var." });
      return;
    }

    const flashbotsNetwork = (network as FlashbotsNetwork) || FlashbotsNetwork.Mainnet;

    const manager = new FlashbotsBundleManager({
      endpoint: rpcEndpoint,
      network: flashbotsNetwork,
      authSigner: getFlashbotsAuthSigner(),
    });

    const result = await manager.sendPrivateTransaction(signedTx, maxBlockNumber);

    res.json({
      bundleId: result.bundleId,
      accepted: result.accepted,
    });
  } catch (error) {
    if (error instanceof FlashbotsError) {
      res.status(502).json({ error: error.message, code: error.code });
      return;
    }
    const message = error instanceof Error ? error.message : "Unknown error";
    res.status(500).json({ error: message });
  }
});

/**
 * GET /v1/bundle/status/:bundleId
 * Get the status of a submitted bundle. Supports both Jito and Flashbots.
 */
bundleRoutes.get("/status/:bundleId", async (req, res) => {
  try {
    const { bundleId } = req.params;
    const chain = (req.query.chain as string) || "solana";

    if (chain === "evm") {
      const rpcEndpoint = process.env.EVM_RPC_URL;
      if (!rpcEndpoint) {
        res.status(503).json({ error: "EVM bundle status requires EVM_RPC_URL env var." });
        return;
      }

      const manager = new FlashbotsBundleManager({
        endpoint: rpcEndpoint,
        authSigner: getFlashbotsAuthSigner(),
      });

      const status = await manager.getBundleStatus(bundleId);
      res.json({ chain: "evm", bundleId, ...status });
    } else {
      const jitoBlockEngineUrl = process.env.JITO_BLOCK_ENGINE_URL;

      if (!jitoBlockEngineUrl) {
        res.status(503).json({
          error: "Solana bundle status requires JITO_BLOCK_ENGINE_URL env var.",
        });
        return;
      }

      const payload = {
        jsonrpc: "2.0",
        id: 1,
        method: "getBundleStatuses",
        params: [[bundleId]],
      };

      const response = await fetch(`${jitoBlockEngineUrl}/api/v1/bundles`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        res.status(502).json({ error: `Jito status error: ${response.status}` });
        return;
      }

      const data = await response.json();
      const bundleStatus = data.result?.value?.[0];

      if (!bundleStatus) {
        res.json({ chain: "solana", bundleId, status: "pending" });
        return;
      }

      let status: string = "pending";
      if (bundleStatus.confirmation_status === "confirmed") status = "landed";
      else if (bundleStatus.err) status = "failed";

      res.json({
        chain: "solana",
        bundleId,
        status,
        landedSlot: bundleStatus.slot,
        transactions: bundleStatus.transactions,
        error: bundleStatus.err,
      });
    }
  } catch (error) {
    if (error instanceof FlashbotsError) {
      res.status(502).json({ error: error.message, code: error.code });
      return;
    }
    const message = error instanceof Error ? error.message : "Unknown error";
    res.status(500).json({ error: message });
  }
});
