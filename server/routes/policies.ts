import { Router } from "express";
import { z } from "zod";
import { PolicyEngineService } from "../services/policy.js";
import { validateBody, validateQuery } from "../middleware/validation.js";

const policySchema = z.object({
  name: z.string().min(2),
  description: z.string().optional(),
  agentId: z.string().nullable().optional(),
  actionPattern: z.string().min(1),
  resourcePattern: z.string().min(1),
  effect: z.enum(["ALLOW", "DENY", "REQUIRE_APPROVAL"]),
  maxCostUsd: z.number().nonnegative().optional(),
  priority: z.number().int().optional(),
});

const listPolicyQuerySchema = z.object({
  agentId: z.string().optional(),
});

export function createPoliciesRouter(policyService: PolicyEngineService): Router {
  const router = Router();

  router.post("/", validateBody(policySchema), (req, res) => {
    try {
      const policy = policyService.createPolicy(req.body);
      res.status(201).json({ success: true, policy });
    } catch (err: any) {
      res.status(400).json({ success: false, error: err?.message || "Failed to create policy" });
    }
  });

  router.get("/", validateQuery(listPolicyQuerySchema), (req, res) => {
    const agentId = req.query.agentId as string | undefined;
    const policies = policyService.listPolicies(agentId);
    res.json({ success: true, count: policies.length, policies });
  });

  router.delete("/:id", (req, res) => {
    const deleted = policyService.deletePolicy(req.params.id);
    if (!deleted) {
      res.status(404).json({ success: false, error: "Policy not found" });
      return;
    }
    res.json({ success: true, message: `Policy ${req.params.id} deleted` });
  });

  return router;
}
