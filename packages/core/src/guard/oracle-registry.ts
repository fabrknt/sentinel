/**
 * Dynamic Oracle Registry — resolves oracle feed addresses from the
 * Chainlink Feed Registry contract on Ethereum mainnet.
 *
 * Feed Registry address: 0x47Fb2585D2C56Fe188D0E6ec628a38b74fCeeeDf
 * Method: getFeed(address base, address quote) → address
 *
 * This supplements the static ORACLE_CONTRACTS set in evm-detector.ts
 * by allowing runtime resolution of oracle feeds for arbitrary token pairs.
 */

/** Chainlink Feed Registry on Ethereum mainnet */
const FEED_REGISTRY = "0x47Fb2585D2C56Fe188D0E6ec628a38b74fCeeeDf";

/** getFeed(address,address) selector */
const GET_FEED_SELECTOR = "0x9a6fc8f5";

/** Chainlink denomination addresses */
export const DENOMINATIONS = {
  ETH: "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE",
  BTC: "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB",
  USD: "0x0000000000000000000000000000000000000348",
} as const;

/**
 * Resolve an oracle feed address from the Chainlink Feed Registry.
 *
 * @param rpcUrl - An Ethereum RPC URL
 * @param base - The base token address (e.g. WETH address)
 * @param quote - The quote denomination address (use DENOMINATIONS.USD etc.)
 * @returns The feed contract address, or null if not found
 */
export async function resolveOracleFromRegistry(
  rpcUrl: string,
  base: string,
  quote: string
): Promise<string | null> {
  const baseParam = base.toLowerCase().replace("0x", "").padStart(64, "0");
  const quoteParam = quote.toLowerCase().replace("0x", "").padStart(64, "0");
  const calldata = GET_FEED_SELECTOR + baseParam + quoteParam;

  try {
    const response = await fetch(rpcUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "eth_call",
        params: [{ to: FEED_REGISTRY, data: calldata }, "latest"],
      }),
    });

    if (!response.ok) return null;

    const data = await response.json();
    if (data.error || !data.result || data.result === "0x") return null;

    // Result is an ABI-encoded address (32 bytes, address in last 20 bytes)
    const hex = data.result.replace("0x", "");
    if (hex.length < 64) return null;

    const addressHex = hex.slice(24, 64);
    if (addressHex === "0".repeat(40)) return null;

    return "0x" + addressHex;
  } catch {
    return null;
  }
}

/**
 * Batch-resolve multiple oracle feeds from the registry.
 * Useful for warming a local oracle address cache on startup.
 */
export async function resolveOracleBatch(
  rpcUrl: string,
  pairs: Array<{ base: string; quote: string }>
): Promise<Map<string, string>> {
  const results = new Map<string, string>();

  const resolved = await Promise.allSettled(
    pairs.map(async ({ base, quote }) => {
      const feed = await resolveOracleFromRegistry(rpcUrl, base, quote);
      return { key: `${base.toLowerCase()}-${quote.toLowerCase()}`, feed };
    })
  );

  for (const result of resolved) {
    if (result.status === "fulfilled" && result.value.feed) {
      results.set(result.value.key, result.value.feed);
    }
  }

  return results;
}
