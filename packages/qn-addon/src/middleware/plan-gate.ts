/**
 * Plan-gated middleware — restricts endpoints to specific subscription plans.
 *
 * Uses the instance attached by instanceLookup middleware to check
 * whether the provisioned plan allows access to the requested endpoint.
 */

import { Request, Response, NextFunction } from "express";

/**
 * Creates middleware that restricts access to instances on a specific plan (or higher).
 *
 * Plan hierarchy: starter < pro
 */
export function requirePlan(minimumPlan: "starter" | "pro") {
  const planRank: Record<string, number> = {
    starter: 0,
    pro: 1,
  };

  return (req: Request, res: Response, next: NextFunction): void => {
    const instance = req.instance;

    if (!instance) {
      res.status(400).json({
        error: "No instance context. Ensure X-INSTANCE-ID header is provided.",
      });
      return;
    }

    const instancePlanRank = planRank[instance.plan] ?? -1;
    const requiredPlanRank = planRank[minimumPlan] ?? 0;

    if (instancePlanRank < requiredPlanRank) {
      res.status(403).json({
        error: `This endpoint requires the "${minimumPlan}" plan. Current plan: "${instance.plan}".`,
        upgrade: "Contact support@fabrknt.com to upgrade your plan.",
      });
      return;
    }

    next();
  };
}
