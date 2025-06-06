import { Plugin, Request, ResponseToolkit, Server } from "@hapi/hapi";
import { SnafContext, SnafCore } from "../core/xss";
import { SnafConfig } from "../config";

export function createHapiPlugin(
  core: SnafCore,
  config: SnafConfig,
): Plugin<any> {
  return {
    name: "snaf",
    register: async function (server: Server) {
      server.ext(
        "onPreHandler",
        async (request: Request, h: ResponseToolkit) => {
          if (!config.enabled) {
            return h.continue;
          }

          // Create context from Hapi request
          const ctx: SnafContext = {
            req: request,
            res: h.response(),
            query: request.query,
            body:
              typeof request.payload === "object" && request.payload !== null
                ? request.payload
                : {},
            headers: request.headers,
          };

          try {
            // Run all enabled modules
            const actions = await core.handle(ctx);

            // Check if any module blocked the request
            const blockAction = actions.find((a) => a.action === "block");
            if (blockAction) {
              if (config.onBlock) {
                config.onBlock(blockAction.reason);
                return h.response().code(403).takeover();
              }
              return h
                .response({ error: "Blocked", reason: blockAction.reason })
                .code(403)
                .takeover();
            }

            // Apply any sanitization
            const sanitizeActions = actions.filter(
              (a) => a.action === "sanitize",
            );
            if (sanitizeActions.length > 0) {
              // Apply sanitized values to request
              sanitizeActions.forEach((action) => {
                if (action.action === "sanitize" && action.sanitized) {
                  if (action.sanitized.body) ctx.body = action.sanitized.body;
                  if (action.sanitized.query)
                    ctx.query = action.sanitized.query;
                }
              });

              if (config.onSanitize) {
                config.onSanitize(
                  sanitizeActions.map((a) => a.reason).join(", "),
                  { originalBody: ctx.body, originalQuery: ctx.query },
                  { body: request.payload, query: request.query },
                );
              }
            }

            return h.continue;
          } catch (error) {
            request.log(["error", "snaf"], String(error));
            return h.continue;
          }
        },
      );
    },
  };
}
