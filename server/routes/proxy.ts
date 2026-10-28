import { Router } from "express";
import { z } from "zod";
import { TransparentEgressProxy } from "../services/proxy.js";
import { AgentRow } from "../services/registry.js";
import { validateBody } from "../middleware/validation.js";

const proxySchema = z.object({
  targetUrl: z.string().min(1, "Provide targetUrl"),
  method: z.string().min(1, "Provide method"),
  headers: z.record(z.string(), z.any()).optional(),
  body: z.any().optional(),
  actionMapping: z.string().optional(),
});

export function createProxyRouter(
  egressProxy: TransparentEgressProxy,
  authAgentMiddleware: any
): Router {
  const router = Router();

  router.post("/", authAgentMiddleware, validateBody(proxySchema), async (req, res) => {
    try {
      const agent = (req as any).agent as AgentRow;
      const { targetUrl, method, headers, body, actionMapping } = req.body;

      const outcome = await egressProxy.handleProxyRequest(agent, {
        targetUrl,
        method,
        headers,
        body,
        actionMapping,
      });

      res.status(outcome.statusCode).json(outcome.body);
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  return router;
}
