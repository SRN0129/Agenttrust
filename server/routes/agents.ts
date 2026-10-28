import { Router } from "express";
import { z } from "zod";
import { AgentRegistryService } from "../services/registry.js";
import { AgentDelegationService } from "../services/delegation.js";
import { validateBody } from "../middleware/validation.js";

const registerSchema = z.object({
  name: z.string().min(2, "Name must be at least 2 characters"),
  description: z.string().optional(),
  operatorEmail: z.string().email("Valid operator email required"),
  framework: z.string().optional(),
  allowedCapabilities: z.array(z.string()).min(1, "Must declare at least one capability"),
  rateLimitRpm: z.number().int().positive().optional(),
  spendLimitUsd: z.number().positive().optional(),
});

const statusSchema = z.object({
  status: z.enum(["ACTIVE", "SUSPENDED"]),
});

const revokeSchema = z.object({
  reason: z.string().optional(),
});

const delegateSchema = z.object({
  parentAgentId: z.string().min(1),
  name: z.string().min(2),
  description: z.string().optional(),
  framework: z.string().optional(),
  delegatedCapabilities: z.array(z.string()).min(1),
  allocatedSpendLimitUsd: z.number().positive(),
  allocatedRateLimitRpm: z.number().int().positive(),
});

export function createAgentsRouter(
  registryService: AgentRegistryService,
  delegationService?: AgentDelegationService
): Router {
  const router = Router();

  router.post("/register", validateBody(registerSchema), (req, res) => {
    try {
      const result = registryService.registerAgent(req.body);
      res.status(201).json({
        success: true,
        agent: {
          id: result.agent.id,
          name: result.agent.name,
          description: result.agent.description,
          operatorEmail: result.agent.operator_email,
          framework: result.agent.framework,
          status: result.agent.status,
          apiKeyPrefix: result.agent.api_key_prefix,
          allowedCapabilities: JSON.parse(result.agent.allowed_capabilities),
          rateLimitRpm: result.agent.rate_limit_rpm,
          spendLimitUsd: result.agent.spend_limit_usd,
          currentSpendUsd: result.agent.current_spend_usd,
          createdAt: result.agent.created_at,
        },
        apiKey: result.apiKey,
        warning: "Secure this API key. It cannot be recovered once registered.",
      });
    } catch (err: any) {
      res.status(400).json({ success: false, error: err?.message || "Registration failed" });
    }
  });

  router.post("/delegate", validateBody(delegateSchema), (req, res) => {
    if (!delegationService) {
      res.status(501).json({ success: false, error: "Delegation service not configured" });
      return;
    }
    try {
      const result = delegationService.delegateSubagent(req.body);
      res.status(201).json({
        success: true,
        childAgent: {
          id: result.childAgent.id,
          name: result.childAgent.name,
          allowedCapabilities: JSON.parse(result.childAgent.allowed_capabilities),
          rateLimitRpm: result.childAgent.rate_limit_rpm,
          spendLimitUsd: result.childAgent.spend_limit_usd,
          currentSpendUsd: result.childAgent.current_spend_usd,
          status: result.childAgent.status,
          parentAgentId: req.body.parentAgentId,
        },
        apiKey: result.apiKey,
        message: "Attenuated subagent minted successfully with strictly inherited capability boundaries.",
      });
    } catch (err: any) {
      res.status(400).json({ success: false, error: err.message });
    }
  });

  router.get("/", (req, res) => {
    const rows = registryService.listAgents();
    const sanitized = rows.map((a) => ({
      id: a.id,
      name: a.name,
      description: a.description,
      operatorEmail: a.operator_email,
      framework: a.framework,
      status: a.status,
      apiKeyPrefix: a.api_key_prefix,
      allowedCapabilities: JSON.parse(a.allowed_capabilities),
      rateLimitRpm: a.rate_limit_rpm,
      spendLimitUsd: a.spend_limit_usd,
      currentSpendUsd: a.current_spend_usd,
      createdAt: a.created_at,
      updatedAt: a.updated_at,
      revokedAt: a.revoked_at,
      revocationReason: a.revocation_reason,
    }));
    res.json({ success: true, count: sanitized.length, agents: sanitized });
  });

  router.get("/:id", (req, res) => {
    const agent = registryService.getAgentById(req.params.id);
    if (!agent) {
      res.status(404).json({ success: false, error: "Agent not found" });
      return;
    }
    res.json({
      success: true,
      agent: {
        id: agent.id,
        name: agent.name,
        description: agent.description,
        operatorEmail: agent.operator_email,
        framework: agent.framework,
        status: agent.status,
        apiKeyPrefix: agent.api_key_prefix,
        allowedCapabilities: JSON.parse(agent.allowed_capabilities),
        rateLimitRpm: agent.rate_limit_rpm,
        spendLimitUsd: agent.spend_limit_usd,
        currentSpendUsd: agent.current_spend_usd,
        createdAt: agent.created_at,
        updatedAt: agent.updated_at,
        revokedAt: agent.revoked_at,
        revocationReason: agent.revocation_reason,
      },
    });
  });

  router.get("/:id/subagents", (req, res) => {
    if (!delegationService) {
      res.status(501).json({ success: false, error: "Delegation service not configured" });
      return;
    }
    const subagents = delegationService.listSubagents(req.params.id);
    res.json({
      success: true,
      parentAgentId: req.params.id,
      count: subagents.length,
      subagents: subagents.map((a) => ({
        id: a.id,
        name: a.name,
        status: a.status,
        allowedCapabilities: JSON.parse(a.allowed_capabilities),
        rateLimitRpm: a.rate_limit_rpm,
        spendLimitUsd: a.spend_limit_usd,
        currentSpendUsd: a.current_spend_usd,
      })),
    });
  });

  router.post("/:id/revoke", validateBody(revokeSchema), (req, res) => {
    try {
      const reason = req.body?.reason || "Revoked by administrative operator";
      const revoked = registryService.revokeAgent(req.params.id, reason);
      res.json({
        success: true,
        message: `Agent ${revoked.id} permanently revoked.`,
        agent: {
          id: revoked.id,
          status: revoked.status,
          revokedAt: revoked.revoked_at,
          revocationReason: revoked.revocation_reason,
        },
      });
    } catch (err: any) {
      res.status(400).json({ success: false, error: err.message });
    }
  });

  router.post("/:id/status", validateBody(statusSchema), (req, res) => {
    try {
      const updated = registryService.updateStatus(req.params.id, req.body.status);
      res.json({ success: true, agent: updated });
    } catch (err: any) {
      res.status(400).json({ success: false, error: err.message });
    }
  });

  return router;
}
