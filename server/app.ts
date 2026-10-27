import express, { Request, Response, NextFunction } from "express";
import cors from "cors";
import rateLimit from "express-rate-limit";
import path from "node:path";
import fs from "node:fs";
import { z } from "zod";
import Database from "better-sqlite3";
import { getDatabase, initializeSchema } from "./db/connection.js";
import { AuditLedgerService } from "./services/audit.js";
import { AgentRegistryService, AgentRow } from "./services/registry.js";
import { ApprovalWorkflowService } from "./services/approval.js";
import { PolicyEngineService } from "./services/policy.js";
import { ProtectedToolService } from "./services/tools.js";
import { NotarizationService, CheckpointManifest } from "./services/notarization.js";
import { BlastRadiusAnalyzer } from "./services/blastRadius.js";
import { AgentDelegationService } from "./services/delegation.js";
import { WebhookNotificationService } from "./services/webhooks.js";
import { ComplianceService } from "./services/compliance.js";
import { GlobalKillswitchService } from "./services/killswitch.js";
import { PromptInjectionScanner } from "./services/promptScanner.js";
import { TransparentEgressProxy } from "./services/proxy.js";
import { GoalDriftDetector } from "./services/driftDetector.js";
import { MicroBudgetService } from "./services/microBudget.js";
import { AuditAttestationService } from "./services/tamperAttestation.js";
import { AgentChaosMonkey } from "./services/chaosMonkey.js";
import { AutonomousSelfHealingService } from "./services/selfHealing.js";
import { QuantumTrustService } from "./services/quantumTrust.js";
import { CognitiveAuditor } from "./services/cognitiveAuditor.js";
import { RuntimeVisibilityWatchdog } from "./services/runtimeVisibility.js";
import { OrbitalManager } from "./services/orbitalManager.js";

export function createApp(customDb?: Database.Database) {
  const app = express();
  const db = customDb || getDatabase();
  if (customDb) {
    initializeSchema(customDb);
  }

  const auditService = new AuditLedgerService(db);
  const registryService = new AgentRegistryService(db, auditService);
  const approvalService = new ApprovalWorkflowService(db, auditService);
  const policyService = new PolicyEngineService(db, auditService, approvalService);
  const toolService = new ProtectedToolService(
    db,
    registryService,
    approvalService,
    auditService,
    policyService
  );

  // Enterprise Services
  const notarizationService = new NotarizationService(db, auditService);
  const delegationService = new AgentDelegationService(db, registryService, auditService);
  const webhookService = new WebhookNotificationService();
  const complianceService = new ComplianceService(
    db,
    auditService,
    registryService,
    approvalService,
    notarizationService
  );
  const killswitchService = new GlobalKillswitchService(db, auditService, notarizationService);
  const egressProxy = new TransparentEgressProxy(policyService, auditService);
  const microBudgetService = new MicroBudgetService(db, auditService);
  const attestationService = new AuditAttestationService(db, auditService, notarizationService);
  const chaosMonkeyService = new AgentChaosMonkey(policyService, delegationService);
  const selfHealingService = new AutonomousSelfHealingService(db, auditService);
  const quantumTrustService = new QuantumTrustService(auditService);
  const runtimeWatchdog = new RuntimeVisibilityWatchdog(auditService);
  const orbitalManager = new OrbitalManager(auditService);

  app.use(cors());
  app.use(express.json());

  // Security headers
  app.use((req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("X-XSS-Protection", "1; mode=block");
    next();
  });

  function escapeHtml(str: string): string {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  // Global rate limiter for API endpoints recognized by security scanners
  const apiLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 1000,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, error: "RATE_LIMIT_EXCEEDED: Rate limit exceeded. Try again in 1 minute." },
  });

  app.use("/api/", apiLimiter);

  // Authentication Middleware for Agent Endpoints
  const authenticateAgent = (req: Request, res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization;
    let apiKey = "";

    if (authHeader && authHeader.startsWith("Bearer ")) {
      apiKey = authHeader.substring(7).trim();
    } else if (req.body && req.body.apiKey) {
      apiKey = req.body.apiKey;
    }

    if (!apiKey) {
      res.status(401).json({
        success: false,
        error: "Missing API Key. Provide via 'Authorization: Bearer <key>' header or 'apiKey' body field.",
      });
      return;
    }

    const agent = registryService.authenticate(apiKey);
    if (!agent) {
      res.status(401).json({
        success: false,
        error: "Invalid or inactive Agent API Key.",
      });
      return;
    }

    (req as any).agent = agent;
    next();
  };

  // Authentication Middleware for Human Admin & Security Operators
  const authenticateAdminOrOperator = (req: Request, res: Response, next: NextFunction) => {
    const configuredAdminKey = process.env.ADMIN_KEY;
    // In dev / test mode without ADMIN_KEY explicitly configured, allow with notice
    if (!configuredAdminKey) {
      res.setHeader("x-admin-mode", "unauthenticated-dev");
      next();
      return;
    }

    const authHeader = req.headers.authorization;
    const adminKeyHeader = req.headers["x-admin-key"] as string | undefined;
    const cookieHeader = req.headers.cookie;

    let providedToken = adminKeyHeader || "";
    if (!providedToken && authHeader && authHeader.startsWith("Bearer ")) {
      providedToken = authHeader.substring(7).trim();
    }
    if (!providedToken && cookieHeader && cookieHeader.includes("agenttrust_admin=")) {
      const match = cookieHeader.match(/agenttrust_admin=([^;]+)/);
      if (match) providedToken = match[1];
    }

    if (providedToken === configuredAdminKey) {
      next();
      return;
    }

    res.status(401).json({
      success: false,
      error: "UNAUTHORIZED_ADMIN: Valid administrative credentials required. Pass 'x-admin-key' or 'Authorization: Bearer <ADMIN_KEY>' header.",
    });
  };

  // ----------------------------------------------------
  // Health & System Info
  // ----------------------------------------------------
  app.get("/health", (req, res) => {
    res.json({
      status: "ok",
      timestamp: Date.now(),
      service: "AgentTrust Security Gateway",
      version: "1.0.0",
    });
  });

  app.get("/api/v1/system/database-info", (req, res) => {
    const driver = process.env.DB_DRIVER || (process.env.DATABASE_URL ? "postgres" : "sqlite");
    res.json({
      success: true,
      dialect: driver,
      clusterCapable: driver === "postgres",
      walEnabled: driver === "sqlite",
      timestamp: Date.now(),
    });
  });

  // ----------------------------------------------------
  // Admin & Human Operator Authentication
  // ----------------------------------------------------
  app.post("/api/v1/auth/admin-login", (req, res) => {
    const { adminKey } = req.body || {};
    const configuredKey = process.env.ADMIN_KEY || "agenttrust-admin-dev";

    if (adminKey !== configuredKey) {
      res.status(401).json({ success: false, error: "Invalid administrative key." });
      return;
    }

    res.setHeader("Set-Cookie", `agenttrust_admin=${configuredKey}; Path=/; HttpOnly; SameSite=Strict`);
    res.json({
      success: true,
      role: "SECURITY_OPERATOR",
      token: configuredKey,
      message: "Admin session authenticated successfully.",
    });
  });

  app.get("/api/v1/auth/session", (req, res) => {
    const configuredKey = process.env.ADMIN_KEY;
    if (!configuredKey) {
      res.json({ authenticated: true, role: "SECURITY_OPERATOR", mode: "UNLOCKED_DEV" });
      return;
    }

    const adminKeyHeader = req.headers["x-admin-key"] as string | undefined;
    const authHeader = req.headers.authorization;
    let token = adminKeyHeader || (authHeader?.startsWith("Bearer ") ? authHeader.substring(7).trim() : "");
    if (!token && req.headers.cookie?.includes("agenttrust_admin=")) {
      const match = req.headers.cookie.match(/agenttrust_admin=([^;]+)/);
      if (match) token = match[1];
    }

    if (token === configuredKey) {
      res.json({ authenticated: true, role: "SECURITY_OPERATOR", mode: "PROTECTED_PRODUCTION" });
    } else {
      res.json({ authenticated: false, role: "ANONYMOUS", mode: "PROTECTED_PRODUCTION" });
    }
  });

  // ----------------------------------------------------
  // Agent Registry Endpoints
  // ----------------------------------------------------
  const registerSchema = z.object({
    name: z.string().min(2, "Name must be at least 2 characters"),
    description: z.string().optional(),
    operatorEmail: z.string().email("Valid operator email required"),
    framework: z.string().optional(),
    allowedCapabilities: z.array(z.string()).min(1, "Must declare at least one capability"),
    rateLimitRpm: z.number().int().positive().optional(),
    spendLimitUsd: z.number().positive().optional(),
  });

  app.post("/api/v1/agents/register", (req, res) => {
    try {
      const parsed = registerSchema.parse(req.body);
      const result = registryService.registerAgent(parsed);
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
        apiKey: result.apiKey, // Only returned once at creation!
        warning: "Secure this API key. It cannot be recovered once registered.",
      });
    } catch (err: any) {
      res.status(400).json({ success: false, error: err?.errors || err.message });
    }
  });

  app.get("/api/v1/agents", (req, res) => {
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

  app.get("/api/v1/agents/:id", (req, res) => {
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

  app.post("/api/v1/agents/:id/revoke", (req, res) => {
    try {
      const reason = req.body.reason || "Revoked by administrative operator";
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

  app.post("/api/v1/agents/:id/status", (req, res) => {
    try {
      const { status } = req.body;
      if (status !== "ACTIVE" && status !== "SUSPENDED") {
        res.status(400).json({ success: false, error: "Status must be ACTIVE or SUSPENDED" });
        return;
      }
      const updated = registryService.updateStatus(req.params.id, status);
      res.json({ success: true, agent: updated });
    } catch (err: any) {
      res.status(400).json({ success: false, error: err.message });
    }
  });

  // ----------------------------------------------------
  // Policy Management Endpoints
  // ----------------------------------------------------
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

  app.post("/api/v1/policies", (req, res) => {
    try {
      const parsed = policySchema.parse(req.body);
      const policy = policyService.createPolicy(parsed);
      res.status(201).json({ success: true, policy });
    } catch (err: any) {
      res.status(400).json({ success: false, error: err?.errors || err.message });
    }
  });

  app.get("/api/v1/policies", (req, res) => {
    const agentId = req.query.agentId as string | undefined;
    const policies = policyService.listPolicies(agentId);
    res.json({ success: true, count: policies.length, policies });
  });

  app.delete("/api/v1/policies/:id", (req, res) => {
    const deleted = policyService.deletePolicy(req.params.id);
    if (!deleted) {
      res.status(404).json({ success: false, error: "Policy not found" });
      return;
    }
    res.json({ success: true, message: `Policy ${req.params.id} deleted` });
  });

  // ----------------------------------------------------
  // Policy Authorization Gateway (Action-Specific Scoping & Cognitive Audit)
  // ----------------------------------------------------
  const authzSchema = z.object({
    action: z.string().min(1),
    resource: z.string().min(1),
    parameters: z.record(z.string(), z.any()).optional(),
    estimatedCostUsd: z.number().nonnegative().optional(),
    thoughtProcess: z.string().optional(),
    systemGoal: z.string().optional(),
  });

  app.post("/api/v1/authorize", authenticateAgent, (req, res) => {
    try {
      const parsed = authzSchema.parse(req.body);
      const agent = (req as any).agent as AgentRow;

      // 0a. Space-Based Emergency Kill-Switch Check
      if (orbitalManager.isAgentQuarantined(agent.id)) {
        res.json({
          success: true,
          agentId: agent.id,
          action: parsed.action,
          resource: parsed.resource,
          allowed: false,
          decision: "DENY",
          reason: "ORBITAL_EMERGENCY_QUARANTINE: Agent execution is frozen by an active direct-to-satellite kill-switch directive.",
        });
        return;
      }

      // 0. Prompt Injection & Malicious Content Scanning
      const promptScan = PromptInjectionScanner.scan(parsed.parameters);
      if (!promptScan.safe) {
        auditService.append({
          agentId: agent.id,
          eventType: "ANOMALY",
          action: parsed.action,
          resource: parsed.resource,
          decision: "DENY",
          thoughtProcess: parsed.thoughtProcess,
          payload: {
            threatType: promptScan.threatType,
            reason: promptScan.reason,
            flagged: promptScan.flaggedPatterns,
          },
        });

        res.json({
          success: true,
          agentId: agent.id,
          action: parsed.action,
          resource: parsed.resource,
          allowed: false,
          decision: "DENY",
          reason: `SECURITY_SCAN_VIOLATION: ${promptScan.reason}`,
          threatType: promptScan.threatType,
        });
        return;
      }

      // 1. Semantic Blast Radius Assessment
      const blastRadius = BlastRadiusAnalyzer.analyze(
        parsed.action,
        parsed.resource,
        parsed.parameters,
        parsed.estimatedCostUsd
      );

      let decision = policyService.authorize({
        agent,
        action: parsed.action,
        resource: parsed.resource,
        parameters: parsed.parameters,
        estimatedCostUsd: parsed.estimatedCostUsd,
        thoughtProcess: parsed.thoughtProcess,
        systemGoal: parsed.systemGoal,
      });

      // 2. High Blast Radius Dynamic Escalation:
      if (decision.allowed && blastRadius.escalationRequired) {
        const approval = approvalService.requestApproval({
          agentId: agent.id,
          action: parsed.action,
          resource: parsed.resource,
          parameters: parsed.parameters || {},
          estimatedCostUsd: parsed.estimatedCostUsd,
        });

        const callbackToken = approvalService.generateCallbackToken(approval.id);

        decision = {
          allowed: false,
          decision: "NEEDS_APPROVAL",
          reason: `High Blast Radius (${blastRadius.riskTier} Risk: ${blastRadius.riskScore}): ${blastRadius.reasons.join(" ")} Mandatory human sign-off required.`,
          approvalRequired: true,
          approvalId: approval.id,
        };

        // Notify Slack/Teams with 1-Click callback token
        webhookService.notifyApprovalRequest(approval, agent.name, blastRadius, callbackToken);
      } else if (decision.decision === "NEEDS_APPROVAL" && decision.approvalId) {
        const approval = approvalService.getApprovalById(decision.approvalId);
        if (approval) {
          const callbackToken = approvalService.generateCallbackToken(approval.id);
          webhookService.notifyApprovalRequest(approval, agent.name, blastRadius, callbackToken);
        }
      }

      let orbitalAttestation: any = undefined;
      if (decision.allowed && orbitalManager.isTier0Action(parsed.action, parsed.estimatedCostUsd)) {
        orbitalAttestation = orbitalManager.issueOrbitalAttestation({
          agentId: agent.id,
          action: parsed.action,
          resource: parsed.resource,
          payload: parsed.parameters || {},
        });
      }

      res.json({
        success: true,
        agentId: agent.id,
        action: parsed.action,
        resource: parsed.resource,
        blastRadius,
        orbitalAttestation,
        ...decision,
      });
    } catch (err: any) {
      res.status(400).json({ success: false, error: err?.errors || err.message });
    }
  });

  // ----------------------------------------------------
  // Human Approvals Workflow
  // ----------------------------------------------------
  app.get("/api/v1/approvals/pending", (req, res) => {
    const pending = approvalService.listPending();
    const formatted = pending.map((p) => ({
      id: p.id,
      agentId: p.agent_id,
      action: p.action,
      resource: p.resource,
      parameters: JSON.parse(p.parameters),
      estimatedCostUsd: p.estimated_cost_usd,
      status: p.status,
      requestedAt: p.requested_at,
      expiresAt: p.expires_at,
      timeRemainingSeconds: Math.max(0, Math.floor((p.expires_at - Date.now()) / 1000)),
    }));
    res.json({ success: true, count: formatted.length, approvals: formatted });
  });

  app.get("/api/v1/approvals", (req, res) => {
    const limit = Number(req.query.limit) || 100;
    const all = approvalService.listAll(limit);
    const formatted = all.map((p) => ({
      id: p.id,
      agentId: p.agent_id,
      action: p.action,
      resource: p.resource,
      parameters: JSON.parse(p.parameters),
      estimatedCostUsd: p.estimated_cost_usd,
      status: p.status,
      executionNonce: p.execution_nonce ? `${p.execution_nonce.substring(0, 12)}...` : null,
      requestedAt: p.requested_at,
      expiresAt: p.expires_at,
      decidedAt: p.decided_at,
      decidedBy: p.decided_by,
      decisionReason: p.decision_reason,
      consumedAt: p.consumed_at,
    }));
    res.json({ success: true, count: formatted.length, approvals: formatted });
  });

  // ----------------------------------------------------
  // 1-Click Mobile/Slack Action Callback (must precede :id)
  // ----------------------------------------------------
  app.get("/api/v1/approvals/callback", (req, res) => {
    const { id, token, decision } = req.query as { id: string; token: string; decision: "APPROVE" | "REJECT" };
    if (!id || !token || !decision || (decision !== "APPROVE" && decision !== "REJECT")) {
      res.status(400).send("Invalid callback link parameters.");
      return;
    }

    const safeId = escapeHtml(id);
    const safeDecision = decision === "APPROVE" ? "APPROVED" : "REJECTED";

    const valid = approvalService.verifyCallbackToken(token, id);
    if (!valid) {
      res.status(403).send(`
        <html style="background:#090d16; color:#f87171; font-family:sans-serif; text-align:center; padding:60px;">
          <h2>❌ Invalid or Expired Action Link</h2>
          <p>This 1-click execution link has expired or the signature is invalid.</p>
        </html>
      `);
      return;
    }

    try {
      const updated = approvalService.decide(
        id,
        decision,
        "operator-mobile@enterprise.internal",
        "Signed off via 1-Click Mobile Push Notification"
      );

      res.send(`
        <html style="background:#090d16; color:#f1f5f9; font-family:sans-serif; text-align:center; padding:60px;">
          <div style="max-width:480px; margin:0 auto; background:#0f172a; padding:40px; border-radius:16px; border:1px solid #1e293b;">
            <div style="font-size:48px; margin-bottom:16px;">${decision === "APPROVE" ? "✅" : "❌"}</div>
            <h2 style="color:${decision === "APPROVE" ? "#34d399" : "#f87171"}; margin:0 0 8px 0;">
              Action Request ${safeDecision}
            </h2>
            <p style="color:#94a3b8; font-size:14px; margin-bottom:24px;">
              Request ID: <code>${safeId}</code>
            </p>
            ${
              decision === "APPROVE"
                ? `<p style="color:#cbd5e1; font-size:13px; background:#022c22; padding:12px; border-radius:8px; border:1px solid #065f46;">
                     Single-use execution ticket generated: <code>${escapeHtml(updated.execution_nonce?.substring(0, 16) || "")}...</code><br>
                     Replay protection active. Ticket burns on first tool use.
                   </p>`
                : `<p style="color:#cbd5e1; font-size:13px; background:#450a0a; padding:12px; border-radius:8px; border:1px solid #991b1b;">
                     Agent request permanently denied. Protected tool will not be invoked.
                   </p>`
            }
          </div>
        </html>
      `);
    } catch (err: any) {
      res.status(400).send("Error processing decision: " + escapeHtml(err.message || "Unknown error"));
    }
  });

  app.get("/api/v1/approvals/:id", (req, res) => {
    const approval = approvalService.getApprovalById(req.params.id);
    if (!approval) {
      res.status(404).json({ success: false, error: "Approval request not found" });
      return;
    }
    res.json({
      success: true,
      approval: {
        id: approval.id,
        agentId: approval.agent_id,
        action: approval.action,
        resource: approval.resource,
        parameters: JSON.parse(approval.parameters),
        estimatedCostUsd: approval.estimated_cost_usd,
        status: approval.status,
        executionNonce: approval.execution_nonce, // Note: only returned when querying specific ID
        requestedAt: approval.requested_at,
        expiresAt: approval.expires_at,
        decidedAt: approval.decided_at,
        decidedBy: approval.decided_by,
        decisionReason: approval.decision_reason,
        consumedAt: approval.consumed_at,
      },
    });
  });

  const decideSchema = z.object({
    decision: z.enum(["APPROVE", "REJECT"]),
    reviewerEmail: z.string().email(),
    reason: z.string().optional(),
  });

  app.post("/api/v1/approvals/:id/decide", authenticateAdminOrOperator, (req, res) => {
    try {
      const parsed = decideSchema.parse(req.body);
      const updated = approvalService.decide(
        req.params.id,
        parsed.decision,
        parsed.reviewerEmail,
        parsed.reason
      );
      res.json({
        success: true,
        message: `Approval request ${parsed.decision.toLowerCase()}d.`,
        approval: {
          id: updated.id,
          status: updated.status,
          executionNonce: updated.execution_nonce,
          expiresAt: updated.expires_at,
          decidedAt: updated.decided_at,
          decidedBy: updated.decided_by,
        },
      });
    } catch (err: any) {
      res.status(400).json({ success: false, error: err.message });
    }
  });

  // ----------------------------------------------------
  // Protected Tool Execution
  // ----------------------------------------------------
  const executeToolSchema = z.object({
    toolName: z.string().min(1),
    action: z.string().min(1),
    resource: z.string().min(1),
    parameters: z.record(z.string(), z.any()).default({}),
    approvalId: z.string().optional(),
    executionNonce: z.string().optional(),
    costUsd: z.number().nonnegative().optional(),
  });

  app.post("/api/v1/tools/execute", authenticateAgent, async (req, res) => {
    try {
      const parsed = executeToolSchema.parse(req.body);
      const agent = (req as any).agent as AgentRow;

      const result = await toolService.execute({
        agent,
        toolName: parsed.toolName,
        action: parsed.action,
        resource: parsed.resource,
        parameters: parsed.parameters,
        approvalId: parsed.approvalId,
        executionNonce: parsed.executionNonce,
        costUsd: parsed.costUsd,
      });

      if (!result.success) {
        const isReplay = result.error?.includes("REPLAY_ATTACK_DETECTED");
        res.status(isReplay ? 409 : 403).json({
          success: false,
          error: result.error,
          toolName: result.toolName,
        });
        return;
      }

      res.json(result);
    } catch (err: any) {
      res.status(400).json({ success: false, error: err?.errors || err.message });
    }
  });

  // ----------------------------------------------------
  // Audit Ledger & Integrity Verification
  // ----------------------------------------------------
  app.get("/api/v1/audit", (req, res) => {
    const limit = Math.min(200, Number(req.query.limit) || 50);
    const offset = Number(req.query.offset) || 0;
    const agentId = req.query.agentId as string | undefined;
    const eventType = req.query.eventType as string | undefined;
    const decision = req.query.decision as string | undefined;

    const { total, events } = auditService.listEvents({
      agentId,
      eventType,
      decision,
      limit,
      offset,
    });

    const parsedEvents = events.map((e) => ({
      index: e.index,
      eventId: e.event_id,
      timestamp: e.timestamp,
      agentId: e.agent_id,
      eventType: e.event_type,
      action: e.action,
      resource: e.resource,
      decision: e.decision,
      payload: JSON.parse(e.payload_json),
      payloadHash: e.payload_hash,
      prevHash: e.prev_hash,
      entryHash: e.entry_hash,
    }));

    res.json({
      success: true,
      total,
      limit,
      offset,
      events: parsedEvents,
    });
  });

  app.get("/api/v1/audit/verify", (req, res) => {
    const result = auditService.verifyIntegrity();
    res.json({
      success: true,
      integrity: result,
      tamperResistantStatus: result.valid ? "CHAIN_VERIFIED_INTACT" : "CHAIN_TAMPERED",
      verifiedAt: Date.now(),
      disclaimer: "Cryptographic hash chaining ensures detection of row modifications or deletions within the sequential ledger. It does not replace independent multi-party notarization.",
    });
  });

  app.post("/api/v1/audit/tamper-test", (req, res) => {
    const index = Number(req.body.index);
    const maliciousAction = req.body.maliciousAction || "malicious:tampered_action";
    if (!index) {
      res.status(400).json({ success: false, error: "Provide a valid audit row 'index' to tamper" });
      return;
    }
    auditService.tamperRecordForTesting(index, maliciousAction);
    const check = auditService.verifyIntegrity();
    res.json({
      success: true,
      message: `Directly altered row #${index} in SQLite DB to demonstrate tamper detection.`,
      verificationResult: check,
    });
  });

  app.post("/api/v1/audit/outcome", authenticateAgent, (req, res) => {
    const agent = (req as any).agent as AgentRow;
    const { action, resource, executionStatus, outputSummary, details } = req.body;

    const entry = auditService.append({
      agentId: agent.id,
      eventType: "EXECUTION_OUTCOME",
      action: action || "custom:execute",
      resource: resource || "external",
      decision: executionStatus === "SUCCESS" ? "EXECUTED" : "FAILED",
      payload: {
        outputSummary,
        details,
        reportedByAgent: agent.id,
      },
    });

    res.json({
      success: true,
      auditIndex: entry.index,
      entryHash: entry.entry_hash,
    });
  });

  // ----------------------------------------------------
  // Enterprise Feature 1: Cascading Subagent Delegation
  // ----------------------------------------------------
  const delegateSchema = z.object({
    parentAgentId: z.string().min(1),
    name: z.string().min(2),
    description: z.string().optional(),
    framework: z.string().optional(),
    delegatedCapabilities: z.array(z.string()).min(1),
    allocatedSpendLimitUsd: z.number().positive(),
    allocatedRateLimitRpm: z.number().int().positive(),
  });

  app.post("/api/v1/agents/delegate", (req, res) => {
    try {
      const parsed = delegateSchema.parse(req.body);
      const result = delegationService.delegateSubagent(parsed);
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
          parentAgentId: parsed.parentAgentId,
        },
        apiKey: result.apiKey,
        message: "Attenuated subagent minted successfully with strictly inherited capability boundaries.",
      });
    } catch (err: any) {
      res.status(400).json({ success: false, error: err.message });
    }
  });

  app.get("/api/v1/agents/:id/subagents", (req, res) => {
    const subagents = delegationService.listSubagents(req.params.id);
    res.json({
      success: true,
      parentAgentId: req.params.id,
      count: subagents.length,
      subagents: subagents.map(a => ({
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

  // Space Colonization Swarm Topology Synthesis
  app.post("/api/v1/swarm/synthesize-topology", (req, res) => {
    try {
      const { parentAgentId, tasks } = req.body;
      if (!parentAgentId || !Array.isArray(tasks)) {
        return res.status(400).json({ success: false, error: "parentAgentId and tasks array are required" });
      }
      const topology = delegationService.synthesizeSwarmTopology(parentAgentId, tasks);
      res.json({
        success: true,
        algorithm: "SPACE_COLONIZATION_ALGORITHM_SCA",
        topology,
      });
    } catch (err: any) {
      res.status(400).json({ success: false, error: err.message });
    }
  });

  // Space Colonization Lateral Perimeter & Choke-Point Analysis
  app.post("/api/v1/blast-radius/attack-perimeter", (req, res) => {
    try {
      const { agentId, crownJewels, toolHops } = req.body;
      if (!agentId || !Array.isArray(crownJewels) || !Array.isArray(toolHops)) {
        return res.status(400).json({ success: false, error: "agentId, crownJewels, and toolHops arrays are required" });
      }
      const analysis = delegationService.analyzePerimeterRisk(agentId, crownJewels, toolHops);
      res.json({
        success: true,
        algorithm: "DENDRITIC_LATERAL_PERIMETER_ANALYSIS",
        analysis,
      });
    } catch (err: any) {
      res.status(400).json({ success: false, error: err.message });
    }
  });

  // ----------------------------------------------------
  // Post-Approval Continuous Runtime Visibility & Watchdog (Wiz / Upwind Paradigm)
  // ----------------------------------------------------
  app.post("/api/v1/runtime/session/start", (req, res) => {
    try {
      const { approvalId, agentId, perimeter } = req.body;
      if (!approvalId || !agentId || !perimeter) {
        return res.status(400).json({ success: false, error: "approvalId, agentId, and perimeter object are required." });
      }
      const session = runtimeWatchdog.startSession(approvalId, agentId, perimeter);
      res.status(201).json({
        success: true,
        session,
        message: "Runtime execution session initialized with continuous perimeter monitoring.",
      });
    } catch (err: any) {
      res.status(400).json({ success: false, error: err.message });
    }
  });

  app.post("/api/v1/runtime/session/record-event", (req, res) => {
    try {
      const { sessionId, event } = req.body;
      if (!sessionId || !event || !event.target || !event.operationType) {
        return res.status(400).json({ success: false, error: "sessionId and event (target, operationType) are required." });
      }
      const result = runtimeWatchdog.inspectTelemetry(sessionId, event);
      if (!result.permitted) {
        return res.status(403).json({
          success: false,
          ...result,
        });
      }
      res.json({
        success: true,
        ...result,
      });
    } catch (err: any) {
      res.status(400).json({ success: false, error: err.message });
    }
  });

  app.post("/api/v1/runtime/session/complete", (req, res) => {
    try {
      const { sessionId } = req.body;
      if (!sessionId) {
        return res.status(400).json({ success: false, error: "sessionId is required." });
      }
      const result = runtimeWatchdog.completeSession(sessionId);
      res.json(result);
    } catch (err: any) {
      res.status(400).json({ success: false, error: err.message });
    }
  });

  app.get("/api/v1/runtime/sessions", (req, res) => {
    const sessions = runtimeWatchdog.listActiveSessions();
    res.json({
      success: true,
      activeCount: sessions.length,
      sessions,
    });
  });

  // ----------------------------------------------------
  // Cognitive Reasoning & Chain-of-Thought Inspection
  // ----------------------------------------------------
  app.post("/api/v1/cognitive/analyze-thought", (req, res) => {
    try {
      const { thoughtProcess, action, systemGoal, parameters } = req.body;
      if (!thoughtProcess) {
        return res.status(400).json({ success: false, error: "thoughtProcess text string is required." });
      }
      const analysis = CognitiveAuditor.analyzeReasoning(
        thoughtProcess,
        action || "generic:action",
        systemGoal || "",
        parameters || {}
      );
      res.json({
        success: true,
        analysis,
      });
    } catch (err: any) {
      res.status(400).json({ success: false, error: err.message });
    }
  });

  // ----------------------------------------------------
  // Enterprise Feature 2: Cryptographic Notarization & Checkpoints
  // ----------------------------------------------------
  app.post("/api/v1/notarize/checkpoint", (req, res) => {
    try {
      const manifest = notarizationService.createNotarizedCheckpoint();
      res.status(201).json({
        success: true,
        message: "Ledger tip successfully notarized and signed with ECDSA P-256 Authority key.",
        checkpoint: manifest,
      });
    } catch (err: any) {
      res.status(400).json({ success: false, error: err.message });
    }
  });

  app.get("/api/v1/notarize/checkpoints", (req, res) => {
    const checkpoints = notarizationService.listCheckpoints();
    res.json({
      success: true,
      count: checkpoints.length,
      checkpoints,
    });
  });

  app.post("/api/v1/notarize/verify-offline", (req, res) => {
    try {
      const manifest = req.body as CheckpointManifest;
      const valid = NotarizationService.verifyOfflineCheckpoint(manifest);
      res.json({
        success: true,
        signatureValid: valid,
        verifiedAlgorithm: manifest.signatureAlgorithm,
        notaryIdentity: manifest.notaryIdentity,
        timestamp: manifest.timestamp,
        verificationNote: valid
          ? "Digital signature verified intact using embedded public key certificate. Non-repudiation guaranteed."
          : "INVALID SIGNATURE: Checkpoint manifest has been forged or altered.",
      });
    } catch (err: any) {
      res.status(400).json({ success: false, error: err.message });
    }
  });

  // ----------------------------------------------------
  // Enterprise Feature 3: Compliance Framework Assessment
  // ----------------------------------------------------
  app.get("/api/v1/compliance/report", (req, res) => {
    const report = complianceService.generateReport();
    res.json({
      success: true,
      report,
    });
  });

  // ----------------------------------------------------
  // Enterprise Feature 4: Emergency Global Air-Gap Killswitch
  // ----------------------------------------------------
  const killswitchSchema = z.object({
    reason: z.string().min(5, "Emergency justification required"),
    operatorEmail: z.string().email(),
  });

  app.post("/api/v1/system/killswitch", authenticateAdminOrOperator, (req, res) => {
    try {
      const parsed = killswitchSchema.parse(req.body);
      const result = killswitchService.trigger(parsed.reason, parsed.operatorEmail);
      res.json({
        success: true,
        message: "EMERGENCY GLOBAL KILLSWITCH EXECUTED: All agents revoked, pending approvals burned, forensic checkpoint created.",
        result,
      });
    } catch (err: any) {
      res.status(400).json({ success: false, error: err?.errors || err.message });
    }
  });

  // ----------------------------------------------------
  // Enterprise Feature 5: Webhook Notification Settings
  // ----------------------------------------------------
  app.get("/api/v1/webhooks/config", (req, res) => {
    res.json({ success: true, config: webhookService.getConfig() });
  });

  app.post("/api/v1/webhooks/config", (req, res) => {
    webhookService.setConfig({
      url: req.body.url || "",
      enabled: Boolean(req.body.enabled),
      channelName: req.body.channelName || "#agent-security-approvals",
    });
    res.json({ success: true, config: webhookService.getConfig() });
  });

  // ----------------------------------------------------
  // Enterprise Feature 7: Transparent Egress Proxy Gateway
  // ----------------------------------------------------
  app.post("/api/v1/proxy", authenticateAgent, async (req, res) => {
    try {
      const agent = (req as any).agent as AgentRow;
      const { targetUrl, method, headers, body, actionMapping } = req.body;
      if (!targetUrl || !method) {
        res.status(400).json({ success: false, error: "Provide targetUrl and method" });
        return;
      }

      const outcome = await egressProxy.handleProxyRequest(agent, {
        targetUrl,
        method,
        headers,
        body,
        actionMapping,
      });

      res.status(outcome.statusCode).json(outcome.body);
    } catch (err: any) {
      console.error("Chaos Monkey Error:", err);
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // ----------------------------------------------------
  // Strategic Enterprise Innovation 1: Goal Hijack & Semantic Drift Detection
  // ----------------------------------------------------
  app.post("/api/v1/governance/drift-check", (req, res) => {
    try {
      const { systemGoal, action, resource, parameters, driftThreshold } = req.body;
      if (!systemGoal || !action || !resource) {
        res.status(400).json({ success: false, error: "Provide systemGoal, action, and resource." });
        return;
      }

      const result = GoalDriftDetector.analyzeDrift({
        systemGoal,
        action,
        resource,
        parameters: parameters || {},
        driftThreshold,
      });

      res.json({ success: true, ...result });
    } catch (err: any) {
      console.error("Chaos Monkey Error:", err);
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // ----------------------------------------------------
  // Strategic Enterprise Innovation 2: "Agent Chaos Monkey" Red-Team Audit
  // ----------------------------------------------------
  app.post("/api/v1/chaos/audit", authenticateAgent, async (req, res) => {
    try {
      const agent = (req as any).agent as AgentRow;
      const certificate = await chaosMonkeyService.runChaosAudit(agent);
      res.json({ success: true, certificate });
    } catch (err: any) {
      console.error("Chaos Monkey Error:", err);
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // ----------------------------------------------------
  // Strategic Enterprise Innovation 3: Zero-Knowledge Verifiable Merkle Attestation
  // ----------------------------------------------------
  app.get("/api/v1/audit/attestation/:id", (req, res) => {
    try {
      const entryId = parseInt(req.params.id, 10);
      if (isNaN(entryId)) {
        res.status(400).json({ success: false, error: "Invalid audit entry ID." });
        return;
      }

      const receipt = attestationService.generateReceipt(entryId);
      res.json({ success: true, receipt });
    } catch (err: any) {
      res.status(404).json({ success: false, error: err.message });
    }
  });

  app.post("/api/v1/audit/attestation/verify", apiLimiter, (req, res) => {
    try {
      const receiptSchema = z.object({
        receipt: z.object({
          merkleRoot: z.string().min(1),
          entry: z.object({
            entryHash: z.string().min(1),
          }).passthrough(),
        }).passthrough(),
      });

      const parsed = receiptSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({ success: false, error: "Provide receipt object in body." });
        return;
      }

      const verification = AuditAttestationService.verifyReceipt(parsed.data.receipt as any);
      res.json({ success: true, verification });
    } catch (err: any) {
      res.status(400).json({ success: false, error: err.message });
    }
  });

  // ----------------------------------------------------
  // Strategic Enterprise Innovation 4: Micro-Budgeting & Velocity Circuit Breakers
  // ----------------------------------------------------
  app.post("/api/v1/runs/register", authenticateAgent, (req, res) => {
    try {
      const agent = (req as any).agent as AgentRow;
      const { runId, maxSpendUsdPerRun, maxVelocityRpm, maxSpendRateUsdPerMin } = req.body;

      if (!runId || !maxSpendUsdPerRun) {
        res.status(400).json({ success: false, error: "Provide runId and maxSpendUsdPerRun." });
        return;
      }

      microBudgetService.registerRun({
        agentId: agent.id,
        runId,
        maxSpendUsdPerRun: Number(maxSpendUsdPerRun),
        maxVelocityRpm: Number(maxVelocityRpm || 30),
        maxSpendRateUsdPerMin: Number(maxSpendRateUsdPerMin || 5.0),
      });

      res.json({ success: true, message: `Run '${runId}' registered with micro-budget caps.` });
    } catch (err: any) {
      console.error("Chaos Monkey Error:", err);
      res.status(500).json({ success: false, error: err.message });
    }
  });

  app.post("/api/v1/runs/:id/check", authenticateAgent, (req, res) => {
    try {
      const runId = req.params.id;
      const { estimatedCostUsd = 0 } = req.body;
      const check = microBudgetService.checkAndRecord(runId, Number(estimatedCostUsd));
      res.json({ success: true, check });
    } catch (err: any) {
      console.error("Chaos Monkey Error:", err);
      res.status(500).json({ success: false, error: err.message });
    }
  });

  app.post("/api/v1/runs/:id/reset", authenticateAgent, (req, res) => {
    try {
      const runId = req.params.id;
      const reset = microBudgetService.resetCircuit(runId);
      res.json({ success: reset });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // ----------------------------------------------------
  // Strategic Enterprise Innovation 5: Autonomous Self-Healing & Diagnostics
  // ----------------------------------------------------
  app.get("/api/v1/health/diagnostics", (req, res) => {
    try {
      const report = selfHealingService.diagnose();
      res.json({ success: true, diagnostics: report });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  app.post("/api/v1/health/self-heal", (req, res) => {
    try {
      const result = selfHealingService.executeSelfHealing();
      res.json({ success: true, result });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // ----------------------------------------------------
  // Strategic Enterprise Innovation 6: Quantum AI & Post-Quantum Cryptography (PQC)
  // ----------------------------------------------------
  app.post("/api/v1/quantum/inspect-circuit", (req, res) => {
    try {
      const result = quantumTrustService.inspectCircuit(req.body);
      res.json({ success: true, result });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  app.post("/api/v1/quantum/pqc-attestation", apiLimiter, (req, res) => {
    try {
      const verification = auditService.verifyIntegrity();
      const tipHash = verification.latestHash || "0000000000000000000000000000000000000000000000000000000000000000";
      const classicalSig = notarizationService.signPayload(tipHash);
      const pubKey = notarizationService.getPublicKey();

      const manifest = quantumTrustService.generatePqcAttestation(tipHash, classicalSig, pubKey);
      res.json({ success: true, manifest });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  app.post("/api/v1/quantum/pqc-verify", apiLimiter, (req, res) => {
    try {
      const manifestSchema = z.object({
        manifest: z.object({
          ledgerTipHash: z.string().min(1),
        }).passthrough(),
      });

      const parsed = manifestSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({ success: false, error: "Provide manifest in body." });
        return;
      }
      const valid = QuantumTrustService.verifyPqcManifest(parsed.data.manifest as any);
      res.json({ success: true, valid });
    } catch (err: any) {
      res.status(400).json({ success: false, error: err.message });
    }
  });

  // ----------------------------------------------------
  // SpaceMesh & Orbital Notary Gateway Endpoints
  // ----------------------------------------------------
  app.get("/api/v1/orbital/status", apiLimiter, (req, res) => {
    res.json({
      success: true,
      enabled: orbitalManager.isEnabled(),
      config: orbitalManager.getConfig(),
      constellationCount: orbitalManager.getConstellation().length,
      killSwitchStatus: orbitalManager.getKillSwitchStatus(),
    });
  });

  app.get("/api/v1/orbital/constellation", apiLimiter, (req, res) => {
    const constellation = orbitalManager.getConstellation().map(sat => {
      const pos = orbitalManager.notary.propagateSatellitePosition(sat.id);
      return {
        ...sat,
        currentPosition: pos,
      };
    });
    res.json({
      success: true,
      count: constellation.length,
      satellites: constellation,
    });
  });

  app.post("/api/v1/orbital/notary/attest", apiLimiter, (req, res) => {
    try {
      const { agentId, action, resource, payload, groundLocation } = req.body;
      if (!agentId || !action || !resource) {
        res.status(400).json({ success: false, error: "agentId, action, and resource are required." });
        return;
      }
      const receipt = orbitalManager.issueOrbitalAttestation({
        agentId,
        action,
        resource,
        payload: payload || {},
        groundLocation,
      });
      res.status(201).json({
        success: true,
        receipt,
      });
    } catch (err: any) {
      res.status(400).json({ success: false, error: err.message });
    }
  });

  app.post("/api/v1/orbital/notary/verify", apiLimiter, (req, res) => {
    try {
      const { receipt } = req.body;
      if (!receipt) {
        res.status(400).json({ success: false, error: "receipt object is required." });
        return;
      }
      const result = orbitalManager.verifyOrbitalAttestation(receipt);
      res.json({
        success: true,
        ...result,
      });
    } catch (err: any) {
      res.status(400).json({ success: false, error: err.message });
    }
  });

  app.post("/api/v1/orbital/killswitch/broadcast", apiLimiter, async (req, res) => {
    try {
      const { scope, targetAgentId, reason } = req.body;
      if (!scope || !reason) {
        res.status(400).json({ success: false, error: "scope and reason are required." });
        return;
      }
      const outcome = await orbitalManager.broadcastOrbitalHalt({
        scope,
        targetAgentId,
        reason,
      });
      res.json({
        success: true,
        ...outcome,
      });
    } catch (err: any) {
      res.status(400).json({ success: false, error: err.message });
    }
  });

  app.post("/api/v1/orbital/doppler/verify-position", apiLimiter, (req, res) => {
    try {
      const { agentId, claimedLocation, satelliteState, observation } = req.body;
      if (!agentId || !claimedLocation || !satelliteState || !observation) {
        res.status(400).json({
          success: false,
          error: "agentId, claimedLocation, satelliteState, and observation are required.",
        });
        return;
      }
      const proof = orbitalManager.verifyProofOfSpace(agentId, claimedLocation, satelliteState, observation);
      res.json({
        success: true,
        proof,
      });
    } catch (err: any) {
      res.status(400).json({ success: false, error: err.message });
    }
  });

  app.post("/api/v1/orbital/qkd/verify-entanglement", apiLimiter, (req, res) => {
    try {
      const { agentId, simulatedEavesdropper } = req.body;
      if (!agentId) {
        res.status(400).json({ success: false, error: "agentId is required." });
        return;
      }
      const result = orbitalManager.evaluateQkdSecurity(agentId, !!simulatedEavesdropper);
      res.json({
        success: true,
        ...result,
      });
    } catch (err: any) {
      res.status(400).json({ success: false, error: err.message });
    }
  });

  // Serve static UI in production if built
  const clientDistPath = path.resolve(process.cwd(), "client", "dist");
  if (fs.existsSync(clientDistPath)) {
    const staticLimiter = rateLimit({
      windowMs: 15 * 60 * 1000,
      max: 1000,
      standardHeaders: true,
      legacyHeaders: false,
    });
    app.use(express.static(clientDistPath));
    app.get("*", staticLimiter, (req, res, next) => {
      if (req.path.startsWith("/api") || req.path.startsWith("/health")) {
        return next();
      }
      res.sendFile(path.join(clientDistPath, "index.html"));
    });
  }

  return {
    app,
    db,
    services: {
      auditService,
      registryService,
      approvalService,
      policyService,
      toolService,
      attestationService,
      chaosMonkeyService,
      microBudgetService,
      selfHealingService,
      quantumTrustService,
      runtimeWatchdog,
      orbitalManager,
    },
  };
}
