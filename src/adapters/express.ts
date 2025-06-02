import { Request, Response, NextFunction } from "express";
import { SnafCore, SnafContext } from "../core/xss";
import { SnafConfig } from "../config";

export function createExpressMiddleware(core: SnafCore, config: SnafConfig) {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (!config.enabled) {
      return next();
    }

    // Create context from Express request
    const ctx: SnafContext = {
      req,
      res,
      query: req.query,
      body: req.body,
      headers: req.headers,
    };

    try {
      // Run all enabled modules
      const actions = await core.handle(ctx);

      // Check if any module blocked the request
      const blockAction = actions.find((a) => a.action === "block");
      if (blockAction) {
        if (config.onBlock) {
          return config.onBlock(blockAction.reason);
        }
        return res
          .status(403)
          .send({ error: "Blocked", reason: blockAction.reason });
      }

      // Apply any sanitization
      const sanitizeActions = actions.filter((a) => a.action === "sanitize");
      if (sanitizeActions.length > 0) {
        // Apply sanitized values to request
        sanitizeActions.forEach((action) => {
          if (action.action === "sanitize" && action.sanitized) {
            if (action.sanitized.body) req.body = action.sanitized.body;
            if (action.sanitized.query) req.query = action.sanitized.query;
          }
        });

        if (config.onSanitize) {
          config.onSanitize(
            sanitizeActions.map((a) => a.reason).join(", "),
            { originalBody: ctx.body, originalQuery: ctx.query },
            { body: req.body, query: req.query },
          );
        }
      }

      // Continue with the request
      next();
    } catch (error) {
      next(error);
    }
  };
}
