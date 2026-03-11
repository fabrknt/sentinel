import express from "express";
import cors from "cors";
import morgan from "morgan";
import { config } from "./config";
import { requestId } from "./middleware/request-id";
import { provisionLimiter, apiLimiter } from "./middleware/rate-limit";
import { errorHandler } from "./middleware/error-handler";
import { instanceLookup } from "./middleware/instance-lookup";
import { requirePlan } from "./middleware/plan-gate";

import provisionRoutes from "./routes/provision";
import { guardRoutes } from "./routes/guard";
import { patternRoutes } from "./routes/patterns";
import { bundleRoutes } from "./routes/bundle";

const app = express();

/* ------------------------------------------------------------------ */
/*  Global middleware                                                   */
/* ------------------------------------------------------------------ */
app.use(cors());
app.use(express.json());
app.use(morgan("short"));
app.use(requestId);

/* ------------------------------------------------------------------ */
/*  Routes                                                             */
/* ------------------------------------------------------------------ */

// Healthcheck (public, no auth)
app.get("/healthcheck", (_req, res) => {
  res.json({ status: "ok", service: "fabrknt-defi-toolkit", version: "0.2.0" });
});

// QuickNode provisioning (basic auth, own rate limit)
app.use(provisionRoutes);

// API routes — all require instance lookup for plan-aware rate limiting
// Guard & pattern routes: starter tier (any plan)
app.use("/v1/guard", instanceLookup, apiLimiter, guardRoutes);
app.use("/v1/pattern", instanceLookup, apiLimiter, patternRoutes);

// Bundle routes: pro tier only
app.use("/v1/bundle", instanceLookup, apiLimiter, requirePlan("pro"), bundleRoutes);

/* ------------------------------------------------------------------ */
/*  Error handler (must be last)                                       */
/* ------------------------------------------------------------------ */
app.use(errorHandler);

/* ------------------------------------------------------------------ */
/*  Start server (only when run directly, not when imported for tests) */
/* ------------------------------------------------------------------ */
if (process.env.NODE_ENV !== "test") {
  app.listen(config.port, () => {
    console.log(`Sentinel QN Add-On running on port ${config.port}`);
  });
}

export default app;
