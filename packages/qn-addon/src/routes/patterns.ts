import { Router } from "express";
import {
  buildBatchPayout,
  buildRecurringPaymentSchedule,
  buildVestingSchedule,
  buildGridTradingPlan,
  buildDCAPlan,
  buildRebalancePlan,
} from "@fabrknt/sentinel-core";
import type {
  BatchPayoutConfig,
  RecurringPaymentConfig,
  VestingConfig,
  GridTradingConfig,
  DCAConfig,
  RebalanceConfig,
} from "@fabrknt/sentinel-core";

export const patternRoutes = Router();

/**
 * POST /v1/pattern/batch-payout
 * Build a batch payout plan with optimized transaction batching.
 */
patternRoutes.post("/batch-payout", (req, res) => {
  try {
    const config = req.body as BatchPayoutConfig;

    if (!config.recipients || !Array.isArray(config.recipients)) {
      res.status(400).json({ error: "recipients array is required" });
      return;
    }

    const result = buildBatchPayout(config);
    res.json(result);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error";
    res.status(500).json({ error: message });
  }
});

/**
 * POST /v1/pattern/recurring-payment
 * Build a recurring payment schedule.
 */
patternRoutes.post("/recurring-payment", (req, res) => {
  try {
    const config = req.body as RecurringPaymentConfig;

    if (!config.recipient || !config.amount || !config.intervalMs) {
      res.status(400).json({
        error: "recipient, amount, intervalMs, and totalPayments are required",
      });
      return;
    }

    const result = buildRecurringPaymentSchedule(config);
    res.json(result);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error";
    res.status(500).json({ error: message });
  }
});

/**
 * POST /v1/pattern/vesting
 * Build a token vesting schedule with cliff and linear unlock.
 */
patternRoutes.post("/vesting", (req, res) => {
  try {
    const config = req.body as VestingConfig;

    if (!config.beneficiary || !config.totalAmount || !config.vestingDuration) {
      res.status(400).json({
        error:
          "beneficiary, totalAmount, startDate, cliffDuration, vestingDuration, and vestingInterval are required",
      });
      return;
    }

    const result = buildVestingSchedule(config);
    res.json(result);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error";
    res.status(500).json({ error: message });
  }
});

/**
 * POST /v1/pattern/grid-trading
 * Build a grid trading plan with buy/sell levels.
 */
patternRoutes.post("/grid-trading", (req, res) => {
  try {
    const config = req.body as GridTradingConfig;

    if (!config.pair || !config.lowerBound || !config.upperBound || !config.gridLevels) {
      res.status(400).json({
        error:
          "pair, lowerBound, upperBound, gridLevels, amountPerGrid, and currentPrice are required",
      });
      return;
    }

    const result = buildGridTradingPlan(config);
    res.json(result);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error";
    res.status(500).json({ error: message });
  }
});

/**
 * POST /v1/pattern/dca
 * Build a DCA (Dollar Cost Averaging) plan.
 */
patternRoutes.post("/dca", (req, res) => {
  try {
    const config = req.body as DCAConfig;

    if (!config.pair || !config.totalAmount || !config.numberOfOrders) {
      res.status(400).json({
        error: "pair, totalAmount, numberOfOrders, and intervalMs are required",
      });
      return;
    }

    const result = buildDCAPlan(config);
    res.json(result);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error";
    res.status(500).json({ error: message });
  }
});

/**
 * POST /v1/pattern/rebalance
 * Build a portfolio rebalance plan.
 */
patternRoutes.post("/rebalance", (req, res) => {
  try {
    const config = req.body as RebalanceConfig;

    if (!config.targetAllocations || !config.currentHoldings) {
      res.status(400).json({
        error:
          "targetAllocations, currentHoldings, and rebalanceThreshold are required",
      });
      return;
    }

    const result = buildRebalancePlan(config);
    res.json(result);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error";
    res.status(500).json({ error: message });
  }
});
