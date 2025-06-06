import { Context, Next } from "koa";
import { SnafContext, SnafCore } from "../core/xss";
import { SnafConfig } from "../config";

export function createKoaMiddleware(core: SnafCore, config: SnafConfig) {
  return async (ctx: Context, next: Next) => {
    if (!config.enabled) {
      return next();
    }

    // Create context from Koa context
    const snafCtx: SnafContext = {
      req: ctx.request,
      res: ctx.response,
      query: ctx.request.query,
      body: ctx.request.body,
      headers: ctx.request.headers,
    };

    // Run all enabled modules
    const actions = await core.handle(snafCtx);

    // Check if any module blocked the request
    const blockAction = actions.find((a) => a.action === "block");
    if (blockAction) {
      if (config.onBlock) {
        return config.onBlock(blockAction.reason);
      }
      ctx.status = 403;
      ctx.body = { error: "Blocked", reason: blockAction.reason };
      return;
    }

    // Apply any sanitization
    const sanitizeActions = actions.filter((a) => a.action === "sanitize");
    if (sanitizeActions.length > 0) {
      // Apply sanitized values to request
      sanitizeActions.forEach((action) => {
        if (action.action === "sanitize" && action.sanitized) {
          if (action.sanitized.body) ctx.request.body = action.sanitized.body;
          if (action.sanitized.query)
            ctx.request.query = action.sanitized.query;
        }
      });

      if (config.onSanitize) {
        config.onSanitize(
          sanitizeActions.map((a) => a.reason).join(", "),
          { originalBody: snafCtx.body, originalQuery: snafCtx.query },
          { body: ctx.request.body, query: ctx.request.query },
        );
      }
    }

    // Continue with the request
    await next();
  };
}
