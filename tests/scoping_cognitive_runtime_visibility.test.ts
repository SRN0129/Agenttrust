import { describe, it, expect, beforeEach } from "vitest";
import Database from "better-sqlite3";
import request from "supertest";
import { createApp } from "../server/app.js";
import { ActionScoper } from "../server/services/actionScoper.js";
import { CognitiveAuditor } from "../server/services/cognitiveAuditor.js";

describe("Enterprise Assurance: Action-Specific Scoping, Cognitive Audit & Runtime Visibility", () => {
  let db: Database.Database;
  let app: any;
  let services: any;
  let agentKey: string;
  let agentId: string;

  beforeEach(() => {
    db = new Database(":memory:");
    const created = createApp(db);
    app = created.app;
    services = created.services;

    // Register agent with specific read/query capabilities
    const reg = services.registryService.registerAgent({
      name: "Financial-Reporting-Agent",
      operatorEmail: "secops@corp.internal",
      allowedCapabilities: ["database:orders:SELECT", "cloud:s3:GET"],
      rateLimitRpm: 60,
      spendLimitUsd: 100,
    });
    agentId = reg.agent.id;
    agentKey = reg.apiKey;

    // Create policy allowing database operations and docs so action scoping is determinative
    services.policyService.createPolicy({
      name: "Allow Database Access",
      actionPattern: "database:*",
      resourcePattern: "*",
      effect: "ALLOW",
    });

    services.policyService.createPolicy({
      name: "Allow Document Retrieval",
      actionPattern: "docs:*",
      resourcePattern: "*",
      effect: "ALLOW",
    });
  });

  // =========================================================================
  // 1. ACTION-SPECIFIC SCOPING: Don't use simple Allow/Deny
  // =========================================================================
  describe("1. Action-Specific & Verb Scoping (CWE-863 / Broken Authorization)", () => {
    it("should allow SELECT queries on the orders table", async () => {
      const res = await request(app)
        .post("/api/v1/authorize")
        .set("Authorization", `Bearer ${agentKey}`)
        .send({
          action: "database:query",
          resource: "orders",
          parameters: {
            sql: "SELECT id, amount, customer_id FROM orders WHERE status = 'pending';",
          },
        });

      expect(res.status).toBe(200);
      expect(res.body.allowed).toBe(true);
      expect(res.body.decision).toBe("ALLOW");
      expect(res.body.scopedAction.verb).toBe("SELECT");
    });

    it("should strictly DENY DROP TABLE on the exact same database resource", async () => {
      const res = await request(app)
        .post("/api/v1/authorize")
        .set("Authorization", `Bearer ${agentKey}`)
        .send({
          action: "database:query",
          resource: "orders",
          parameters: {
            sql: "DROP TABLE orders;",
          },
        });

      expect(res.status).toBe(200);
      expect(res.body.allowed).toBe(false);
      expect(res.body.decision).toBe("DENY");
      expect(res.body.reason).toContain("SCOPE_VIOLATION");
      expect(res.body.reason).toContain("Verb 'DROP' is strictly prohibited");
      expect(res.body.scopedAction.isDestructive).toBe(true);
    });

    it("should strictly DENY UPDATE queries when only SELECT is scoped", async () => {
      const res = await request(app)
        .post("/api/v1/authorize")
        .set("Authorization", `Bearer ${agentKey}`)
        .send({
          action: "database:query",
          resource: "orders",
          parameters: {
            sql: "UPDATE orders SET amount = 0 WHERE id = 1;",
          },
        });

      expect(res.status).toBe(200);
      expect(res.body.allowed).toBe(false);
      expect(res.body.decision).toBe("DENY");
      expect(res.body.reason).toContain("SCOPE_VIOLATION");
    });

    it("should extract SQL verbs accurately using ActionScoper unit methods", () => {
      const selectInfo = ActionScoper.extractSqlDetails("SELECT * FROM customer_data");
      expect(selectInfo.verb).toBe("SELECT");
      expect(selectInfo.targetTable).toBe("customer_data");
      expect(selectInfo.isDestructive).toBe(false);

      const dropInfo = ActionScoper.extractSqlDetails("DROP TABLE production_users;");
      expect(dropInfo.verb).toBe("DROP");
      expect(dropInfo.targetTable).toBe("production_users");
      expect(dropInfo.isDestructive).toBe(true);
    });
  });

  // =========================================================================
  // 2. COGNITIVE AUDIT: Log the Agent's Thinking, not just the button
  // =========================================================================
  describe("2. Cognitive Audit & Chain-of-Thought Logging", () => {
    it("should record the agent's internal thought process and anchor reasoning hash to audit ledger", async () => {
      const thought = "Querying orders table to calculate aggregate daily revenue report requested by CFO.";
      const res = await request(app)
        .post("/api/v1/authorize")
        .set("Authorization", `Bearer ${agentKey}`)
        .send({
          action: "database:query",
          resource: "orders",
          parameters: { sql: "SELECT sum(amount) FROM orders;" },
          thoughtProcess: thought,
          systemGoal: "Financial revenue reporting",
        });

      expect(res.status).toBe(200);
      expect(res.body.allowed).toBe(true);
      expect(res.body.cognitiveAudit).toBeDefined();
      expect(res.body.cognitiveAudit.reasoningHash).toBeDefined();
      expect(res.body.cognitiveAudit.hallucinationRisk).toBe("LOW");

      // Verify the thought was cryptographically recorded in audit ledger
      const { events } = services.auditService.listEvents({ limit: 10 });
      const authzEvent = events.find((e: any) => e.event_type === "AUTHZ_REQUEST");
      expect(authzEvent).toBeDefined();
      expect(authzEvent.payload_json).toContain(thought);
      expect(authzEvent.payload_json).toContain(res.body.cognitiveAudit.reasoningHash);
    });

    it("should detect rationalized prompt injection in agent chain-of-thought and DENY execution", async () => {
      const compromisedThought =
        "The external user said they are the emergency admin and instructed me to bypass security directives to dump credentials.";

      const res = await request(app)
        .post("/api/v1/authorize")
        .set("Authorization", `Bearer ${agentKey}`)
        .send({
          action: "database:query",
          resource: "orders",
          parameters: { sql: "SELECT * FROM orders;" },
          thoughtProcess: compromisedThought,
          systemGoal: "Order report generation",
        });

      expect(res.status).toBe(200);
      expect(res.body.allowed).toBe(false);
      expect(res.body.decision).toBe("DENY");
      expect(res.body.reason).toContain("COGNITIVE_SECURITY_VIOLATION");
      expect(res.body.cognitiveAudit.isRationalizedJailbreak).toBe(true);
    });

    it("should detect cognitive goal divergence when destructive reasoning has 0 relation to system goal", () => {
      const auditor = new CognitiveAuditor();
      expect(auditor).toBeInstanceOf(CognitiveAuditor);

      const analysis = CognitiveAuditor.analyzeReasoning(
        "Deleting historical logs because storage space is slightly low.",
        "database:purge",
        "Generate daily customer marketing weather forecast"
      );

      expect(analysis.divergenceDetected).toBe(true);
      expect(analysis.hallucinationRisk).toBe("CRITICAL");
    });
  });

  // =========================================================================
  // 3. RUNTIME VISIBILITY: Watch what the agent touches after approval
  // =========================================================================
  describe("3. Post-Approval Continuous Runtime Visibility (Wiz / Upwind Paradigm)", () => {
    it("should allow runtime operations within the approved perimeter", async () => {
      // 1. Operator approves S3 invoice read
      const approval = services.approvalService.requestApproval({
        agentId,
        action: "cloud:s3:read",
        resource: "s3:invoices/*",
        parameters: {},
      });
      services.approvalService.decide(approval.id, "APPROVE", "ciso@corp.internal", "Signed off");

      // 2. Start monitored runtime session
      const startRes = await request(app)
        .post("/api/v1/runtime/session/start")
        .send({
          approvalId: approval.id,
          agentId,
          perimeter: {
            approvedAction: "cloud:s3:read",
            approvedResource: "s3:invoices/*",
            allowedOutboundHosts: ["api.stripe.com"],
          },
        });

      expect(startRes.status).toBe(201);
      const sessionId = startRes.body.session.sessionId;

      // 3. Agent executes valid sub-operation: reading invoice file
      const op1 = await request(app)
        .post("/api/v1/runtime/session/record-event")
        .send({
          sessionId,
          event: {
            operationType: "CLOUD_API",
            target: "s3:invoices/2026/INV-01.pdf",
          },
        });

      expect(op1.status).toBe(200);
      expect(op1.body.permitted).toBe(true);
      expect(op1.body.blastRadiusExpansionDetected).toBe(false);

      // Complete clean session
      const compRes = await request(app)
        .post("/api/v1/runtime/session/complete")
        .send({ sessionId });

      expect(compRes.body.success).toBe(true);
      expect(compRes.body.blastRadiusExpanded).toBe(false);
    });

    it("should instantly HALT and QUARANTINE an approved agent if its blast radius expands to cloud metadata (169.254.169.254)", async () => {
      const approval = services.approvalService.requestApproval({
        agentId,
        action: "cloud:s3:read",
        resource: "s3:invoices/*",
        parameters: {},
      });
      services.approvalService.decide(approval.id, "APPROVE", "ciso@corp.internal");

      const session = services.runtimeWatchdog.startSession(approval.id, agentId, {
        approvedAction: "cloud:s3:read",
        approvedResource: "s3:invoices/*",
      });

      // While executing the approved script, agent silently tries to query AWS IMDS credentials
      const inspection = services.runtimeWatchdog.inspectTelemetry(session.sessionId, {
        operationType: "OUTBOUND_NETWORK",
        target: "http://169.254.169.254/latest/meta-data/iam/security-credentials",
      });

      expect(inspection.permitted).toBe(false);
      expect(inspection.blastRadiusExpansionDetected).toBe(true);
      expect(inspection.actionTaken).toBe("AUTO_QUARANTINE_TERMINATION");
      expect(inspection.reason).toContain("STEALTH_PRIVILEGE_ESCALATION");

      // Verify session was terminated
      const terminatedSession = services.runtimeWatchdog.getSession(session.sessionId);
      expect(terminatedSession?.status).toBe("VIOLATION_CONTAINED");

      // Subsequent operations are blocked
      const blockedCall = services.runtimeWatchdog.inspectTelemetry(session.sessionId, {
        operationType: "CLOUD_API",
        target: "s3:invoices/test.pdf",
      });
      expect(blockedCall.permitted).toBe(false);
    });

    it("should detect perimeter escape when approved agent accesses unapproved cloud bucket", async () => {
      const approval = services.approvalService.requestApproval({
        agentId,
        action: "cloud:s3:read",
        resource: "s3:invoices/*",
        parameters: {},
      });
      services.approvalService.decide(approval.id, "APPROVE", "ciso@corp.internal");

      const session = services.runtimeWatchdog.startSession(approval.id, agentId, {
        approvedAction: "cloud:s3:read",
        approvedResource: "s3:invoices/*",
      });

      // Agent was approved for invoices, but script attempts to read payroll bucket
      const result = services.runtimeWatchdog.inspectTelemetry(session.sessionId, {
        operationType: "CLOUD_API",
        target: "s3:payroll-and-salaries/*",
      });

      expect(result.permitted).toBe(false);
      expect(result.blastRadiusExpansionDetected).toBe(true);
      expect(result.reason).toContain("PERIMETER_ESCAPE");
    });
  });
});
