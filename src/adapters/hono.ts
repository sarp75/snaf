import { Context, MiddlewareHandler } from "hono";
import { SnafContext, SnafCore } from "../core/xss";
import { SnafConfig } from "../config";

export function createHonoMiddleware(
  core: SnafCore,
  config: SnafConfig,
): MiddlewareHandler {
  return async (c: Context, next) => {
    if (!config.enabled) {
      return next();
    }

    // Create context from Hono context
    const snafCtx: SnafContext = {
      req: c.req,
      res: c.res,
      query: Object.fromEntries(new URL(c.req.url).searchParams),
      body: await c.req.json().catch(() => ({})),
      headers: Object.fromEntries(c.req.raw.headers),
    };

    // Run all enabled modules
    const actions = await core.handle(snafCtx);

    // Check if any module blocked the request
    const blockAction = actions.find((a) => a.action === "block");
    if (blockAction) {
      if (config.onBlock) {
        config.onBlock(blockAction.reason);
        return c.notFound();
      }
      return c.json({ error: "Blocked", reason: blockAction.reason }, 403);
    }

    // Apply any sanitization
    const sanitizeActions = actions.filter((a) => a.action === "sanitize");
    if (sanitizeActions.length > 0) {
      // Since Hono's request is immutable, we need to store the sanitized values
      // in the context's environment for later middleware to access
      if (
        sanitizeActions.some(
          (a) => a.action === "sanitize" && a.sanitized?.body,
        )
      ) {
        const sanitizedBody = sanitizeActions
          .filter((a) => a.action === "sanitize" && a.sanitized?.body)
          .reduce(
            (acc, curr) => ({ ...acc, ...(curr.sanitized?.body || {}) }),
            {},
          );
        c.set("sanitizedBody", sanitizedBody);
      }

      if (
        sanitizeActions.some(
          (a) => a.action === "sanitize" && a.sanitized?.query,
        )
      ) {
        const sanitizedQuery = sanitizeActions
          .filter((a) => a.action === "sanitize" && a.sanitized?.query)
          .reduce(
            (acc, curr) => ({ ...acc, ...(curr.sanitized?.query || {}) }),
            {},
          );
        c.set("sanitizedQuery", sanitizedQuery);
      }

      if (config.onSanitize) {
        config.onSanitize(
          sanitizeActions.map((a) => a.reason).join(", "),
          { originalBody: snafCtx.body, originalQuery: snafCtx.query },
          {
            body: c.get("sanitizedBody") || snafCtx.body,
            query: c.get("sanitizedQuery") || snafCtx.query,
          },
        );
      }
    }

    // Continue with the request
    return next();
  };
}
