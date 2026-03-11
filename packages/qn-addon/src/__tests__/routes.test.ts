/**
 * Integration tests for qn-addon routes.
 *
 * Uses supertest to make HTTP requests against the Express app.
 * Database is initialized with an in-memory SQLite instance for isolation.
 * Env vars are set before importing the app to configure test behavior.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import supertest from "supertest";
import app from "../server";
import { getDb, closeDb } from "../db/database";

const request = supertest(app);
const basicAuth = "Basic " + Buffer.from("testuser:testpass").toString("base64");

// Provision a test instance that we'll use for API calls
const TEST_INSTANCE = {
  "quicknode-id": "qn-test-123",
  "endpoint-id": "ep-test-456",
  "wss-url": "wss://test.example.com",
  "http-url": "https://test.example.com",
  chain: "ethereum",
  network: "mainnet",
  plan: "starter",
};

const PRO_INSTANCE = {
  "quicknode-id": "qn-pro-789",
  "endpoint-id": "ep-pro-789",
  "wss-url": "wss://pro.example.com",
  "http-url": "https://pro.example.com",
  chain: "ethereum",
  network: "mainnet",
  plan: "pro",
};

beforeAll(async () => {
  // Ensure DB is initialized
  getDb();

  // Provision test instances
  await request
    .post("/provision")
    .set("Authorization", basicAuth)
    .send(TEST_INSTANCE);

  await request
    .post("/provision")
    .set("Authorization", basicAuth)
    .send(PRO_INSTANCE);
});

afterAll(() => {
  closeDb();
});

// ── Healthcheck ──

describe("Healthcheck", () => {
  it("GET /healthcheck returns ok", async () => {
    const res = await request.get("/healthcheck");
    expect(res.status).toBe(200);
    expect(res.body.status).toBe("ok");
    expect(res.body.service).toBe("fabrknt-defi-toolkit");
  });
});

// ── Provisioning PUDD lifecycle ──

describe("Provisioning", () => {
  it("POST /provision creates a new instance", async () => {
    const res = await request
      .post("/provision")
      .set("Authorization", basicAuth)
      .send({
        "quicknode-id": "qn-new-1",
        "endpoint-id": "ep-new-1",
        "wss-url": "wss://new.example.com",
        "http-url": "https://new.example.com",
        chain: "solana",
        network: "mainnet-beta",
        plan: "starter",
      });

    expect(res.status).toBe(200);
    expect(res.body.status).toBe("success");
    expect(res.body["endpoint-id"]).toBe("ep-new-1");
  });

  it("POST /provision rejects duplicate endpoint", async () => {
    const res = await request
      .post("/provision")
      .set("Authorization", basicAuth)
      .send(TEST_INSTANCE);

    expect(res.status).toBe(409);
  });

  it("POST /provision requires auth", async () => {
    const res = await request
      .post("/provision")
      .send(TEST_INSTANCE);

    expect(res.status).toBe(401);
  });

  it("PUT /update changes plan", async () => {
    const res = await request
      .put("/update")
      .set("Authorization", basicAuth)
      .send({
        "quicknode-id": "qn-new-1",
        "endpoint-id": "ep-new-1",
        plan: "pro",
      });

    expect(res.status).toBe(200);
    expect(res.body.plan).toBe("pro");
  });

  it("DELETE /deactivate_endpoint deactivates", async () => {
    const res = await request
      .delete("/deactivate_endpoint")
      .set("Authorization", basicAuth)
      .send({ "quicknode-id": "qn-new-1", "endpoint-id": "ep-new-1" });

    expect(res.status).toBe(200);
    expect(res.body.status).toBe("success");
  });

  it("DELETE /deprovision removes instance", async () => {
    const res = await request
      .delete("/deprovision")
      .set("Authorization", basicAuth)
      .send({ "quicknode-id": "qn-new-1" });

    expect(res.status).toBe(200);
    expect(res.body.status).toBe("success");
  });
});

// ── Guard Routes ──

describe("Guard routes", () => {
  it("POST /v1/guard/analyze validates a clean EVM transaction", async () => {
    const res = await request
      .post("/v1/guard/analyze")
      .set("X-INSTANCE-ID", TEST_INSTANCE["endpoint-id"])
      .send({
        transaction: {
          id: "tx-1",
          chain: "evm",
          status: "pending",
          instructions: [
            { programId: "0xSafeContract", keys: [], data: "0x12345678" },
          ],
        },
      });

    expect(res.status).toBe(200);
    expect(res.body.isValid).toBe(true);
    expect(res.body.warnings).toHaveLength(0);
  });

  it("POST /v1/guard/analyze detects flash loan attack", async () => {
    const res = await request
      .post("/v1/guard/analyze")
      .set("X-INSTANCE-ID", TEST_INSTANCE["endpoint-id"])
      .send({
        transaction: {
          id: "tx-2",
          chain: "evm",
          status: "pending",
          instructions: [
            {
              programId: "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2",
              keys: [],
              data: "0x5cffe9de",
            },
            {
              programId: "0x7a250d5630b4cf539739df2c5dacb4c659f2488d",
              keys: [],
              data: "0x022c0d9f",
            },
          ],
        },
        config: { mode: "block", riskTolerance: "strict" },
      });

    expect(res.status).toBe(200);
    expect(res.body.isValid).toBe(false);
    expect(res.body.warnings.some((w: any) => w.patternId === "EVM-002")).toBe(true);
  });

  it("POST /v1/guard/analyze requires transaction", async () => {
    const res = await request
      .post("/v1/guard/analyze")
      .set("X-INSTANCE-ID", TEST_INSTANCE["endpoint-id"])
      .send({});

    expect(res.status).toBe(400);
    expect(res.body.error).toContain("transaction");
  });

  it("POST /v1/guard/analyze-raw returns warnings without Guard wrapper", async () => {
    const res = await request
      .post("/v1/guard/analyze-raw")
      .set("X-INSTANCE-ID", TEST_INSTANCE["endpoint-id"])
      .send({
        transaction: {
          id: "tx-3",
          chain: "evm",
          status: "pending",
          instructions: [
            {
              programId: "0xToken",
              keys: [],
              data: "0x5c19a95c",
            },
            {
              programId: "0xGovernor",
              keys: [],
              data: "0x56781388",
            },
          ],
        },
      });

    expect(res.status).toBe(200);
    expect(res.body.warnings).toBeDefined();
    expect(res.body.warnings.some((w: any) => w.patternId === "EVM-009")).toBe(true);
  });

  it("requires X-INSTANCE-ID header", async () => {
    const res = await request
      .post("/v1/guard/analyze")
      .send({ transaction: { id: "tx", chain: "evm", status: "pending" } });

    expect(res.status).toBe(400);
    expect(res.body.error).toContain("X-INSTANCE-ID");
  });

  it("rejects unknown instance ID", async () => {
    const res = await request
      .post("/v1/guard/analyze")
      .set("X-INSTANCE-ID", "nonexistent-endpoint")
      .send({ transaction: { id: "tx", chain: "evm", status: "pending" } });

    expect(res.status).toBe(404);
  });
});

// ── Pattern Routes ──

describe("Pattern routes", () => {
  it("POST /v1/pattern/batch-payout builds a plan", async () => {
    const res = await request
      .post("/v1/pattern/batch-payout")
      .set("X-INSTANCE-ID", TEST_INSTANCE["endpoint-id"])
      .send({
        recipients: [
          { address: "0xRecipient1", amount: 100 },
          { address: "0xRecipient2", amount: 200 },
        ],
        token: { address: "0xToken", symbol: "USDC", decimals: 6 },
      });

    expect(res.status).toBe(200);
    expect(res.body.batches).toBeDefined();
  });

  it("POST /v1/pattern/dca builds a DCA plan", async () => {
    const res = await request
      .post("/v1/pattern/dca")
      .set("X-INSTANCE-ID", TEST_INSTANCE["endpoint-id"])
      .send({
        pair: {
          base: { address: "0xBase", symbol: "ETH", decimals: 18 },
          quote: { address: "0xQuote", symbol: "USDC", decimals: 6 },
        },
        totalAmount: 1000,
        numberOfOrders: 10,
        intervalMs: 86400000,
      });

    expect(res.status).toBe(200);
    expect(res.body.orders).toBeDefined();
  });

  it("POST /v1/pattern/batch-payout validates input", async () => {
    const res = await request
      .post("/v1/pattern/batch-payout")
      .set("X-INSTANCE-ID", TEST_INSTANCE["endpoint-id"])
      .send({});

    expect(res.status).toBe(400);
    expect(res.body.error).toContain("recipients");
  });
});

// ── Bundle Routes (plan gating) ──

describe("Bundle routes — plan gating", () => {
  it("rejects bundle requests from starter plan", async () => {
    const res = await request
      .post("/v1/bundle/tip")
      .set("X-INSTANCE-ID", TEST_INSTANCE["endpoint-id"])
      .send({ level: "medium" });

    expect(res.status).toBe(403);
    expect(res.body.error).toContain("pro");
  });

  it("allows bundle requests from pro plan", async () => {
    const res = await request
      .post("/v1/bundle/tip")
      .set("X-INSTANCE-ID", PRO_INSTANCE["endpoint-id"])
      .send({ level: "medium" });

    expect(res.status).toBe(200);
    expect(res.body.tipAmount).toBeDefined();
    expect(res.body.tipAccount).toBeDefined();
  });

  it("POST /v1/bundle/submit validates transactions array", async () => {
    const res = await request
      .post("/v1/bundle/submit")
      .set("X-INSTANCE-ID", PRO_INSTANCE["endpoint-id"])
      .send({ chain: "evm" });

    expect(res.status).toBe(400);
    expect(res.body.error).toContain("transactions");
  });

  it("POST /v1/bundle/submit requires EVM_RPC_URL for evm chain", async () => {
    // EVM_RPC_URL is not set in test env
    const res = await request
      .post("/v1/bundle/submit")
      .set("X-INSTANCE-ID", PRO_INSTANCE["endpoint-id"])
      .send({
        chain: "evm",
        transactions: ["0xabc"],
        blockNumber: 12345,
      });

    expect(res.status).toBe(503);
    expect(res.body.error).toContain("EVM_RPC_URL");
  });

  it("POST /v1/bundle/submit requires JITO env vars for solana chain", async () => {
    const res = await request
      .post("/v1/bundle/submit")
      .set("X-INSTANCE-ID", PRO_INSTANCE["endpoint-id"])
      .send({
        chain: "solana",
        transactions: ["base64tx1"],
      });

    expect(res.status).toBe(503);
    expect(res.body.error).toContain("SOLANA_RPC_URL");
  });

  it("POST /v1/bundle/simulate requires blockNumber", async () => {
    const res = await request
      .post("/v1/bundle/simulate")
      .set("X-INSTANCE-ID", PRO_INSTANCE["endpoint-id"])
      .send({ transactions: ["0xabc"] });

    expect(res.status).toBe(400);
    expect(res.body.error).toContain("blockNumber");
  });

  it("POST /v1/bundle/simulate requires EVM_RPC_URL", async () => {
    const res = await request
      .post("/v1/bundle/simulate")
      .set("X-INSTANCE-ID", PRO_INSTANCE["endpoint-id"])
      .send({ transactions: ["0xabc"], blockNumber: 100 });

    expect(res.status).toBe(503);
    expect(res.body.error).toContain("EVM_RPC_URL");
  });

  it("POST /v1/bundle/private-tx validates input", async () => {
    const res = await request
      .post("/v1/bundle/private-tx")
      .set("X-INSTANCE-ID", PRO_INSTANCE["endpoint-id"])
      .send({});

    expect(res.status).toBe(400);
    expect(res.body.error).toContain("signedTx");
  });

  it("POST /v1/bundle/private-tx requires EVM_RPC_URL", async () => {
    const res = await request
      .post("/v1/bundle/private-tx")
      .set("X-INSTANCE-ID", PRO_INSTANCE["endpoint-id"])
      .send({ signedTx: "0xdeadbeef", maxBlockNumber: 100 });

    expect(res.status).toBe(503);
    expect(res.body.error).toContain("EVM_RPC_URL");
  });

  it("GET /v1/bundle/status/:id requires JITO env for solana", async () => {
    const res = await request
      .get("/v1/bundle/status/test-bundle-id")
      .set("X-INSTANCE-ID", PRO_INSTANCE["endpoint-id"]);

    expect(res.status).toBe(503);
    expect(res.body.error).toContain("JITO_BLOCK_ENGINE_URL");
  });

  it("GET /v1/bundle/status/:id requires EVM_RPC_URL for evm", async () => {
    const res = await request
      .get("/v1/bundle/status/test-bundle-id?chain=evm")
      .set("X-INSTANCE-ID", PRO_INSTANCE["endpoint-id"]);

    expect(res.status).toBe(503);
    expect(res.body.error).toContain("EVM_RPC_URL");
  });

  it("rejects unsupported chain", async () => {
    const res = await request
      .post("/v1/bundle/submit")
      .set("X-INSTANCE-ID", PRO_INSTANCE["endpoint-id"])
      .send({
        chain: "avalanche",
        transactions: ["0xabc"],
      });

    expect(res.status).toBe(400);
    expect(res.body.error).toContain("Unsupported chain");
  });
});
