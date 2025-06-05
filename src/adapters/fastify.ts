import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { SnafCore, SnafContext } from "../core/xss";
import { SnafConfig } from "../config";

export function createFastifyPlugin(core: SnafCore, config: SnafConfig) {
  return async function snafFastifyPlugin(fastify: FastifyInstance) {
    if (!config.enabled) {
      return;
    }

    fastify.addHook('preHandler', async (request: FastifyRequest, reply: FastifyReply) => {
      // Create context from Fastify request
      const ctx: SnafContext = {
        req: request,
        res: reply,
        query: request.query as Record<string, any>,
        body: request.body as Record<string, any>,
        headers: request.headers as Record<string, any>,
      };

      try {
        // Run all enabled modules
        const actions = await core.handle(ctx);

        // Check if any module blocked the request
        const blockAction = actions.find((a) => a.action === "block");
        if (blockAction) {
          if (config.onBlock) {
            config.onBlock(blockAction.reason);
          } else {
            reply
              .code(403)
              .send({ error: "Blocked", reason: blockAction.reason });
          }
          return reply;
        }

        // Apply any sanitization
        const sanitizeActions = actions.filter((a) => a.action === "sanitize");
        if (sanitizeActions.length > 0) {
          // Apply sanitized values to request
          sanitizeActions.forEach((action) => {
            if (action.action === "sanitize" && action.sanitized) {
              if (action.sanitized.body) request.body = action.sanitized.body;
              if (action.sanitized.query) request.query = action.sanitized.query;
            }
          });

          if (config.onSanitize) {
            config.onSanitize(
              sanitizeActions.map((a) => a.reason).join(", "),
              { originalBody: ctx.body, originalQuery: ctx.query },
              { body: request.body, query: request.query },
            );
          }
        }
      } catch (error) {
        reply.send(error);
      }
    });
  };
}
