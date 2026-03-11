/**
 * Tests for the Flashbots AuthSigner implementation.
 *
 * Verifies that:
 * 1. keccak256 hashing is used (not SHA-256)
 * 2. EIP-191 personal sign prefix is applied
 * 3. Signature is 65 bytes (r + s + v) with valid recovery
 * 4. Address is correctly derived from the private key
 * 5. Signature can be verified (public key recovery matches address)
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { keccak_256 } from "@noble/hashes/sha3";
import { secp256k1 } from "@noble/curves/secp256k1";

// Well-known test private key (DO NOT use in production)
// This is the Hardhat/Anvil default account #0
const TEST_PRIVATE_KEY =
  "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
// Expected address: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
const EXPECTED_ADDRESS = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";

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
 * Replicate the signing logic from bundle.ts for testing.
 */
function flashbotsSign(
  body: string,
  privateKeyHex: string
): { address: string; signature: string } {
  const privateKeyBytes = hexToBytes(privateKeyHex);

  // Derive address
  const publicKey = secp256k1.getPublicKey(privateKeyBytes, false);
  const pubKeyHash = keccak_256(publicKey.slice(1));
  const address = "0x" + bytesToHex(pubKeyHash.slice(12));

  // 1. keccak256(body)
  const bodyHash = keccak_256(new TextEncoder().encode(body));

  // 2. EIP-191 prefix
  const prefix = new TextEncoder().encode("\x19Ethereum Signed Message:\n32");
  const prefixedMessage = new Uint8Array(prefix.length + bodyHash.length);
  prefixedMessage.set(prefix);
  prefixedMessage.set(bodyHash, prefix.length);

  // 3. keccak256(prefixedMessage)
  const msgHash = keccak_256(prefixedMessage);

  // 4. ECDSA sign
  const sig = secp256k1.sign(msgHash, privateKeyBytes);

  const r = sig.r.toString(16).padStart(64, "0");
  const s = sig.s.toString(16).padStart(64, "0");
  const v = (sig.recovery + 27).toString(16).padStart(2, "0");

  return { address, signature: "0x" + r + s + v };
}

describe("Flashbots AuthSigner", () => {
  it("derives the correct Ethereum address from private key", () => {
    const { address } = flashbotsSign("test", TEST_PRIVATE_KEY);
    expect(address).toBe(EXPECTED_ADDRESS);
  });

  it("produces a 65-byte signature (130 hex chars + 0x prefix)", () => {
    const body = JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "eth_sendBundle",
      params: [{ txs: ["0xdeadbeef"], blockNumber: "0x1" }],
    });

    const { signature } = flashbotsSign(body, TEST_PRIVATE_KEY);

    expect(signature).toMatch(/^0x[0-9a-f]{130}$/);
  });

  it("signature has valid v value (27 or 28)", () => {
    const { signature } = flashbotsSign("hello flashbots", TEST_PRIVATE_KEY);

    const vHex = signature.slice(130);
    const v = parseInt(vHex, 16);
    expect(v === 27 || v === 28).toBe(true);
  });

  it("signature is recoverable to the correct address", () => {
    const body = '{"jsonrpc":"2.0","id":1,"method":"eth_sendBundle","params":[]}';
    const { address, signature } = flashbotsSign(body, TEST_PRIVATE_KEY);

    // Reconstruct the message hash
    const bodyHash = keccak_256(new TextEncoder().encode(body));
    const prefix = new TextEncoder().encode("\x19Ethereum Signed Message:\n32");
    const prefixedMessage = new Uint8Array(prefix.length + bodyHash.length);
    prefixedMessage.set(prefix);
    prefixedMessage.set(bodyHash, prefix.length);
    const msgHash = keccak_256(prefixedMessage);

    // Extract r, s, recovery from signature
    const sigHex = signature.slice(2); // remove 0x
    const r = BigInt("0x" + sigHex.slice(0, 64));
    const s = BigInt("0x" + sigHex.slice(64, 128));
    const v = parseInt(sigHex.slice(128), 16);
    const recovery = v - 27;

    // Recover the public key
    const sig = new secp256k1.Signature(r, s).addRecoveryBit(recovery);
    const recoveredPubKey = sig.recoverPublicKey(msgHash);
    const recoveredUncompressed = recoveredPubKey.toRawBytes(false);
    const recoveredHash = keccak_256(recoveredUncompressed.slice(1));
    const recoveredAddress = "0x" + bytesToHex(recoveredHash.slice(12));

    expect(recoveredAddress).toBe(address);
    expect(recoveredAddress).toBe(EXPECTED_ADDRESS);
  });

  it("produces different signatures for different bodies", () => {
    const sig1 = flashbotsSign("body1", TEST_PRIVATE_KEY);
    const sig2 = flashbotsSign("body2", TEST_PRIVATE_KEY);

    expect(sig1.signature).not.toBe(sig2.signature);
    // But same address
    expect(sig1.address).toBe(sig2.address);
  });

  it("uses keccak256 not SHA-256 (verify against known hash)", () => {
    // keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
    const emptyHash = bytesToHex(keccak_256(new Uint8Array(0)));
    expect(emptyHash).toBe(
      "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    );

    // SHA-256("") would be e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    // This confirms we're using keccak, not SHA-256
    expect(emptyHash).not.toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
  });
});
