import { describe, it, expect } from "vitest";
import {
  buildBatchPayout,
  buildRecurringPaymentSchedule,
  buildVestingSchedule,
  buildGridTradingPlan,
  buildDCAPlan,
  buildRebalancePlan,
} from "../patterns";
import type { Token, TradingPair, Price } from "../types";

// ── Helpers ──

function makeToken(overrides: Partial<Token> = {}): Token {
  return {
    address: "So1111111111111111111111111111111111111111",
    symbol: "SOL",
    decimals: 9,
    mint: "So1111111111111111111111111111111111111111",
    ...overrides,
  };
}

function makePair(): TradingPair {
  return {
    base: makeToken({ symbol: "SOL" }),
    quote: makeToken({
      address: "USDC111111111111111111111111111111111111",
      symbol: "USDC",
      decimals: 6,
      mint: "USDC111111111111111111111111111111111111",
    }),
  };
}

function makePrice(price: number): Price {
  return {
    token: "SOL",
    price,
    quoteCurrency: "USDC",
    timestamp: Date.now(),
  };
}

// ── buildBatchPayout ──

describe("buildBatchPayout", () => {
  it("returns correct totals for a small list of recipients", () => {
    const result = buildBatchPayout({
      recipients: [
        { address: "a", amount: 100 },
        { address: "b", amount: 200 },
        { address: "c", amount: 50 },
      ],
      tokenMint: "tokenMint1",
      decimals: 9,
    });

    expect(result.totalRecipients).toBe(3);
    expect(result.totalAmount).toBe(350);
    expect(result.batches).toHaveLength(1);
    expect(result.batches[0].recipients).toEqual(["a", "b", "c"]);
    expect(result.batches[0].amounts).toEqual([100, 200, 50]);
  });

  it("splits into multiple batches of 20", () => {
    const recipients = Array.from({ length: 45 }, (_, i) => ({
      address: `addr${i}`,
      amount: 10,
    }));
    const result = buildBatchPayout({
      recipients,
      tokenMint: "mint",
      decimals: 6,
    });

    expect(result.totalRecipients).toBe(45);
    expect(result.totalAmount).toBe(450);
    expect(result.batches).toHaveLength(3); // 20 + 20 + 5
    expect(result.batches[0].recipients).toHaveLength(20);
    expect(result.batches[1].recipients).toHaveLength(20);
    expect(result.batches[2].recipients).toHaveLength(5);
  });

  it("estimates fee per batch", () => {
    const result = buildBatchPayout({
      recipients: Array.from({ length: 40 }, (_, i) => ({
        address: `addr${i}`,
        amount: 1,
      })),
      tokenMint: "mint",
      decimals: 6,
    });

    expect(result.batches).toHaveLength(2);
    expect(result.estimatedFee).toBeCloseTo(2 * 0.000005);
  });

  it("handles a single recipient", () => {
    const result = buildBatchPayout({
      recipients: [{ address: "solo", amount: 999 }],
      tokenMint: "mint",
      decimals: 6,
    });
    expect(result.totalRecipients).toBe(1);
    expect(result.batches).toHaveLength(1);
  });
});

// ── buildRecurringPaymentSchedule ──

describe("buildRecurringPaymentSchedule", () => {
  it("generates the correct number of payments", () => {
    const schedule = buildRecurringPaymentSchedule({
      recipient: "alice",
      amount: 100,
      tokenMint: "mint",
      intervalMs: 86400000, // 1 day
      totalPayments: 5,
    });

    expect(schedule.payments).toHaveLength(5);
    expect(schedule.totalAmount).toBe(500);
  });

  it("has payments at correct intervals", () => {
    const interval = 3600000; // 1 hour
    const schedule = buildRecurringPaymentSchedule({
      recipient: "bob",
      amount: 50,
      tokenMint: "mint",
      intervalMs: interval,
      totalPayments: 3,
    });

    const t0 = schedule.payments[0].scheduledAt;
    expect(schedule.payments[1].scheduledAt - t0).toBe(interval);
    expect(schedule.payments[2].scheduledAt - t0).toBe(interval * 2);
  });

  it("endDate equals the last payment time", () => {
    const interval = 1000;
    const schedule = buildRecurringPaymentSchedule({
      recipient: "carol",
      amount: 10,
      tokenMint: "mint",
      intervalMs: interval,
      totalPayments: 4,
    });

    expect(schedule.endDate).toBe(schedule.payments[3].scheduledAt);
  });

  it("each payment has the correct index and amount", () => {
    const schedule = buildRecurringPaymentSchedule({
      recipient: "dave",
      amount: 25,
      tokenMint: "mint",
      intervalMs: 1000,
      totalPayments: 3,
    });

    schedule.payments.forEach((p, i) => {
      expect(p.index).toBe(i);
      expect(p.amount).toBe(25);
    });
  });
});

// ── buildVestingSchedule ──

describe("buildVestingSchedule", () => {
  it("computes cliff date and end date correctly", () => {
    const start = 1000000;
    const schedule = buildVestingSchedule({
      beneficiary: "alice",
      totalAmount: 1000,
      tokenMint: "mint",
      startDate: start,
      cliffDuration: 100,
      vestingDuration: 500,
      vestingInterval: 100,
    });

    expect(schedule.cliffDate).toBe(start + 100);
    expect(schedule.endDate).toBe(start + 500);
  });

  it("divides amount evenly across periods", () => {
    const schedule = buildVestingSchedule({
      beneficiary: "bob",
      totalAmount: 1000,
      tokenMint: "mint",
      startDate: 0,
      cliffDuration: 0,
      vestingDuration: 400,
      vestingInterval: 100,
    });

    expect(schedule.totalPeriods).toBe(4);
    expect(schedule.amountPerPeriod).toBe(250);
    expect(schedule.periods).toHaveLength(4);
  });

  it("cumulative amounts add up correctly", () => {
    const schedule = buildVestingSchedule({
      beneficiary: "carol",
      totalAmount: 600,
      tokenMint: "mint",
      startDate: 0,
      cliffDuration: 100,
      vestingDuration: 400,
      vestingInterval: 100,
    });

    // vestingAfterCliff = 300, periods = 3, amountPerPeriod = 200
    expect(schedule.totalPeriods).toBe(3);
    for (let i = 0; i < schedule.periods.length; i++) {
      expect(schedule.periods[i].cumulative).toBeCloseTo(
        schedule.amountPerPeriod * (i + 1)
      );
    }
  });

  it("period unlock dates start at cliff", () => {
    const schedule = buildVestingSchedule({
      beneficiary: "dave",
      totalAmount: 1200,
      tokenMint: "mint",
      startDate: 1000,
      cliffDuration: 200,
      vestingDuration: 800,
      vestingInterval: 200,
    });

    expect(schedule.periods[0].unlockDate).toBe(1200); // startDate + cliff
    expect(schedule.periods[1].unlockDate).toBe(1400);
    expect(schedule.periods[2].unlockDate).toBe(1600);
  });
});

// ── buildGridTradingPlan ──

describe("buildGridTradingPlan", () => {
  it("creates the correct number of grid levels", () => {
    const plan = buildGridTradingPlan({
      pair: makePair(),
      lowerBound: 90,
      upperBound: 110,
      gridLevels: 5,
      amountPerGrid: 10,
      currentPrice: makePrice(100),
    });

    expect(plan.levels).toHaveLength(5);
  });

  it("labels levels below current price as buy, above as sell", () => {
    const plan = buildGridTradingPlan({
      pair: makePair(),
      lowerBound: 80,
      upperBound: 120,
      gridLevels: 5,
      amountPerGrid: 1,
      currentPrice: makePrice(100),
    });

    // levels at 80, 90, 100, 110, 120 => buy: 80, 90; sell: 100, 110, 120
    const buys = plan.levels.filter((l) => l.side === "buy");
    const sells = plan.levels.filter((l) => l.side === "sell");
    expect(buys.length).toBe(2);
    expect(sells.length).toBe(3);
    buys.forEach((b) => expect(b.price).toBeLessThan(100));
    sells.forEach((s) => expect(s.price).toBeGreaterThanOrEqual(100));
  });

  it("computes grid spacing correctly", () => {
    const plan = buildGridTradingPlan({
      pair: makePair(),
      lowerBound: 100,
      upperBound: 200,
      gridLevels: 6,
      amountPerGrid: 5,
      currentPrice: makePrice(150),
    });

    expect(plan.gridSpacing).toBe(20);
  });

  it("totalBuyAmount sums price * amount for buy levels", () => {
    const plan = buildGridTradingPlan({
      pair: makePair(),
      lowerBound: 90,
      upperBound: 110,
      gridLevels: 3,
      amountPerGrid: 2,
      currentPrice: makePrice(105),
    });

    // levels: 90 (buy), 100 (buy), 110 (sell)
    const expectedBuyAmount = 2 * 90 + 2 * 100;
    expect(plan.totalBuyAmount).toBeCloseTo(expectedBuyAmount);
  });

  it("totalSellAmount sums amount for sell levels", () => {
    const plan = buildGridTradingPlan({
      pair: makePair(),
      lowerBound: 90,
      upperBound: 110,
      gridLevels: 3,
      amountPerGrid: 2,
      currentPrice: makePrice(105),
    });

    // sell level: 110 => totalSellAmount = 2
    expect(plan.totalSellAmount).toBeCloseTo(2);
  });
});

// ── buildDCAPlan ──

describe("buildDCAPlan", () => {
  it("divides total amount equally among orders", () => {
    const plan = buildDCAPlan({
      pair: makePair(),
      totalAmount: 1000,
      numberOfOrders: 4,
      intervalMs: 60000,
      strategy: "immediate",
    });

    expect(plan.amountPerOrder).toBe(250);
    expect(plan.orders).toHaveLength(4);
    plan.orders.forEach((o) => expect(o.amount).toBe(250));
  });

  it("schedules orders at correct intervals", () => {
    const interval = 3600000;
    const plan = buildDCAPlan({
      pair: makePair(),
      totalAmount: 500,
      numberOfOrders: 3,
      intervalMs: interval,
      strategy: "twap",
    });

    const t0 = plan.orders[0].scheduledAt;
    expect(plan.orders[1].scheduledAt - t0).toBe(interval);
    expect(plan.orders[2].scheduledAt - t0).toBe(interval * 2);
  });

  it("totalDuration equals interval * (numberOfOrders - 1)", () => {
    const plan = buildDCAPlan({
      pair: makePair(),
      totalAmount: 100,
      numberOfOrders: 5,
      intervalMs: 1000,
      strategy: "limit",
    });

    expect(plan.totalDuration).toBe(4000);
  });

  it("order indices are sequential", () => {
    const plan = buildDCAPlan({
      pair: makePair(),
      totalAmount: 100,
      numberOfOrders: 3,
      intervalMs: 1000,
      strategy: "immediate",
    });
    plan.orders.forEach((o, i) => expect(o.index).toBe(i));
  });
});

// ── buildRebalancePlan ──

describe("buildRebalancePlan", () => {
  const sol = makeToken({ symbol: "SOL", mint: "SOL_MINT" });
  const usdc = makeToken({
    symbol: "USDC",
    mint: "USDC_MINT",
    address: "USDC_MINT",
    decimals: 6,
  });

  it("detects that rebalance is needed when drift exceeds threshold", () => {
    const plan = buildRebalancePlan({
      targetAllocations: [
        { token: sol, targetPct: 50 },
        { token: usdc, targetPct: 50 },
      ],
      currentHoldings: [
        { token: sol, amount: 10, valueUsd: 800 },
        { token: usdc, amount: 200, valueUsd: 200 },
      ],
      rebalanceThreshold: 5,
    });

    expect(plan.needsRebalance).toBe(true);
    expect(plan.maxDrift).toBe(30); // 80% vs 50%
    expect(plan.trades.length).toBeGreaterThan(0);
  });

  it("does not rebalance when drift is within threshold", () => {
    const plan = buildRebalancePlan({
      targetAllocations: [
        { token: sol, targetPct: 50 },
        { token: usdc, targetPct: 50 },
      ],
      currentHoldings: [
        { token: sol, amount: 5, valueUsd: 510 },
        { token: usdc, amount: 490, valueUsd: 490 },
      ],
      rebalanceThreshold: 5,
    });

    expect(plan.needsRebalance).toBe(false);
    expect(plan.trades).toHaveLength(0);
  });

  it("trade value equals the excess/deficit amount", () => {
    const plan = buildRebalancePlan({
      targetAllocations: [
        { token: sol, targetPct: 50 },
        { token: usdc, targetPct: 50 },
      ],
      currentHoldings: [
        { token: sol, amount: 10, valueUsd: 700 },
        { token: usdc, amount: 300, valueUsd: 300 },
      ],
      rebalanceThreshold: 5,
    });

    // total = 1000, target each = 500, SOL excess = 200, USDC deficit = 200
    expect(plan.totalTradeValue).toBeCloseTo(200);
    expect(plan.trades).toHaveLength(1);
    expect(plan.trades[0].from.symbol).toBe("SOL");
    expect(plan.trades[0].to.symbol).toBe("USDC");
  });

  it("handles three-token rebalance", () => {
    const eth = makeToken({
      symbol: "ETH",
      mint: "ETH_MINT",
      address: "ETH_MINT",
      decimals: 18,
    });

    const plan = buildRebalancePlan({
      targetAllocations: [
        { token: sol, targetPct: 33.33 },
        { token: usdc, targetPct: 33.33 },
        { token: eth, targetPct: 33.34 },
      ],
      currentHoldings: [
        { token: sol, amount: 10, valueUsd: 600 },
        { token: usdc, amount: 200, valueUsd: 200 },
        { token: eth, amount: 1, valueUsd: 200 },
      ],
      rebalanceThreshold: 5,
    });

    expect(plan.needsRebalance).toBe(true);
    expect(plan.trades.length).toBeGreaterThanOrEqual(1);
    // SOL is overweight, USDC and ETH are underweight
    expect(plan.trades.every((t) => t.from.symbol === "SOL")).toBe(true);
  });
});
