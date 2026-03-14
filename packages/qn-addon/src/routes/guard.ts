import { Router } from "express";
import { Guard, analyzeTransaction } from "@fabrknt/sentinel-core";
import type { Transaction, GuardConfig } from "@fabrknt/sentinel-core";

export const guardRoutes = Router();

/**
 * POST /v1/guard/analyze
 * Analyze a transaction for security patterns.
 *
 * Body: { transaction: Transaction, config?: GuardConfig }
 * Returns: { warnings: SecurityWarning[], isValid: boolean, blockedBy?: PatternId[] }
 */
guardRoutes.post("/analyze", async (req, res) => {
  try {
    const { transaction, config } = req.body as {
      transaction: Transaction;
      config?: GuardConfig;
    };

    if (!transaction) {
      res.status(400).json({ error: "transaction is required" });
      return;
    }

    const guard = new Guard(config || {});
    const result = await guard.validateTransaction(transaction);

    res.json(result);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error";
    res.status(500).json({ error: message });
  }
});

/**
 * POST /v1/guard/analyze-raw
 * Analyze raw transaction instructions without Guard wrapper.
 *
 * Body: { transaction: Transaction, config?: GuardConfig }
 * Returns: { warnings: SecurityWarning[] }
 */
guardRoutes.post("/analyze-raw", (req, res) => {
  try {
    const { transaction, config } = req.body as {
      transaction: Transaction;
      config?: GuardConfig;
    };

    if (!transaction) {
      res.status(400).json({ error: "transaction is required" });
      return;
    }

    const warnings = analyzeTransaction(transaction, config);

    res.json({ warnings });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error";
    res.status(500).json({ error: message });
  }
});
