import rateLimit from "express-rate-limit";
import type { Request } from "express";

/**
 * Plan-aware rate limiting.
 * Starter: 100 req/min, Pro: 200 req/min (matches addon.json).
 */
export const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: (req: Request) => {
    const plan = req.instance?.plan;
    if (plan === "pro") return 200;
    return 100; // starter or unknown
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req: Request) => {
    // Rate limit per instance, fall back to IP
    return req.instance?.endpoint_id || req.ip || "unknown";
  },
  message: { error: "Too many requests, please try again later." },
});

export const provisionLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many provisioning requests, please try again later." },
});
