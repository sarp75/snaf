import { NextApiRequest, NextApiResponse, NextApiHandler } from "next";
import { SnafCore, SnafContext } from "../core/xss";
import { SnafConfig } from "../config";

export function createNextMiddleware(core: SnafCore, config: SnafConfig) {
  return (handler: NextApiHandler) =>
    async (req: NextApiRequest, res: NextApiResponse) => {
      if (!config.enabled) {
        return handler(req, res);
      }

      const ctx: SnafContext = {
        req,
        res,
        query: req.query,
        body: req.body,
        headers: req.headers,
      };

      // this ain't useless brochacho
      // eslint-disable-next-line no-useless-catch
      try {
        const actions = await core.handle(ctx);

        // block?
        const blockAction = actions.find((a) => a.action === "block");
        if (blockAction) {
          if (config.onBlock) {
            config.onBlock(blockAction.reason);
          } else {
            res
              .status(403)
              .json({ error: "Blocked", reason: blockAction.reason });
          }
          return;
        }

        // sanitize?
        const sanitizeActions = actions.filter((a) => a.action === "sanitize");
        if (sanitizeActions.length) {
          sanitizeActions.forEach((a) => {
            if (a.sanitized) {
              if (a.sanitized.body) req.body = a.sanitized.body;
              if (a.sanitized.query) req.query = a.sanitized.query;
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

        return handler(req, res);
      } catch (err) {
        throw err;
      }
    };
}
