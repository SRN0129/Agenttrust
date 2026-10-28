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
import { createAgentsRouter } from "./routes/agents.js";
import { createPoliciesRouter } from "./routes/policies.js";
import { createApprovalsRouter } from "./routes/approvals.js";
import { createAuditRouter } from "./routes/audit.js";
import { createProxyRouter } from "./routes/proxy.js";

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
  // Modular Routers: Agents & Policies
  // ----------------------------------------------------
  app.use("/api/v1/agents", createAgentsRouter(registryService, delegationService));
  app.use("/api/v1/policies", createPoliciesRouter(policyService));

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
  // Modular Router: Approvals
  // ----------------------------------------------------
  app.use("/api/v1/approvals", createApprovalsRouter(approvalService, authenticateAdminOrOperator));

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
  // Modular Router: Audit Ledger
  // ----------------------------------------------------
  app.use("/api/v1/audit", createAuditRouter(auditService, authenticateAgent));

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
  // Modular Router: Transparent Egress Proxy Gateway
  // ----------------------------------------------------
  app.use("/api/v1/proxy", createProxyRouter(egressProxy, authenticateAgent));

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

  const orbitalAttestSchema = z.object({
    agentId: z.string().min(1),
    action: z.string().min(1),
    resource: z.string().min(1),
    payload: z.record(z.string(), z.any()).optional(),
    groundLocation: z.object({
      latitude: z.number(),
      longitude: z.number(),
      altitudeMeters: z.number().optional(),
    }).optional(),
  });

  app.post("/api/v1/orbital/notary/attest", apiLimiter, (req, res) => {
    try {
      const parsed = orbitalAttestSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({ success: false, error: parsed.error.issues });
        return;
      }
      const receipt = orbitalManager.issueOrbitalAttestation({
        agentId: parsed.data.agentId,
        action: parsed.data.action,
        resource: parsed.data.resource,
        payload: parsed.data.payload || {},
        groundLocation: parsed.data.groundLocation,
      });
      res.status(201).json({
        success: true,
        receipt,
      });
    } catch (err: any) {
      res.status(400).json({ success: false, error: err.message });
    }
  });

  const orbitalVerifySchema = z.object({
    receipt: z.object({
      receiptId: z.string().min(1),
      satelliteId: z.string().min(1),
    }).passthrough(),
  });

  app.post("/api/v1/orbital/notary/verify", apiLimiter, (req, res) => {
    try {
      const parsed = orbitalVerifySchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({ success: false, error: "receipt object with receiptId and satelliteId required." });
        return;
      }
      const result = orbitalManager.verifyOrbitalAttestation(parsed.data.receipt as any);
      res.json({
        success: true,
        ...result,
      });
    } catch (err: any) {
      res.status(400).json({ success: false, error: err.message });
    }
  });

  const orbitalKillBroadcastSchema = z.object({
    scope: z.enum(["GLOBAL_KILL", "AGENT_SPECIFIC", "CLUSTER_REGION"]),
    targetAgentId: z.string().optional(),
    reason: z.string().min(1),
  });

  app.post("/api/v1/orbital/killswitch/broadcast", apiLimiter, async (req, res) => {
    try {
      const parsed = orbitalKillBroadcastSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({ success: false, error: parsed.error.issues });
        return;
      }
      const outcome = await orbitalManager.broadcastOrbitalHalt({
        scope: parsed.data.scope,
        targetAgentId: parsed.data.targetAgentId,
        reason: parsed.data.reason,
      });
      res.json({
        success: true,
        ...outcome,
      });
    } catch (err: any) {
      res.status(400).json({ success: false, error: err.message });
    }
  });

  const orbitalDopplerSchema = z.object({
    agentId: z.string().min(1),
    claimedLocation: z.object({
      latitude: z.number(),
      longitude: z.number(),
      altitudeMeters: z.number().optional(),
    }),
    satelliteState: z.object({
      satelliteId: z.string(),
      noradId: z.number(),
      epoch: z.number(),
      latitude: z.number(),
      longitude: z.number(),
      altitudeKm: z.number(),
      velocityKmPerSec: z.number(),
      headingDeg: z.number(),
    }),
    observation: z.object({
      nominalCarrierFrequencyHz: z.number(),
      observedFrequencyHz: z.number(),
      observedDopplerShiftHz: z.number(),
      timestamp: z.number(),
    }),
  });

  app.post("/api/v1/orbital/doppler/verify-position", apiLimiter, (req, res) => {
    try {
      const parsed = orbitalDopplerSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({ success: false, error: parsed.error.issues });
        return;
      }
      const proof = orbitalManager.verifyProofOfSpace(
        parsed.data.agentId,
        parsed.data.claimedLocation,
        parsed.data.satelliteState,
        parsed.data.observation
      );
      res.json({
        success: true,
        proof,
      });
    } catch (err: any) {
      res.status(400).json({ success: false, error: err.message });
    }
  });

  const orbitalQkdSchema = z.object({
    agentId: z.string().min(1),
    simulatedEavesdropper: z.boolean().optional(),
  });

  app.post("/api/v1/orbital/qkd/verify-entanglement", apiLimiter, (req, res) => {
    try {
      const parsed = orbitalQkdSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({ success: false, error: "agentId is required." });
        return;
      }
      const result = orbitalManager.evaluateQkdSecurity(parsed.data.agentId, !!parsed.data.simulatedEavesdropper);
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
