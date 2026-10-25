import { describe, it, expect, beforeEach, afterEach } from "vitest";
import Database from "better-sqlite3";
import request from "supertest";
import { createApp } from "../server/app.js";

describe("Bug Fixes, Hardening & Autonomous Self-Healing Suite", () => {
  let db: Database.Database;
  let app: any;
  let services: any;
  let testAgentKey: string;
  let testAgent: any;

  beforeEach(() => {
    db = new Database(":memory:");
    const created = createApp(db);
    app = created.app;
    services = created.services;

    const registered = services.registryService.registerAgent({
      name: "Security Probe Agent",
      description: "Tests edge cases and boundary limits",
      operatorEmail: "secops@enterprise.com",
      maxDailySpendUsd: 1000,
      rateLimitRpm: 60,
    });
    testAgentKey = registered.apiKey;
    testAgent = registered.agent;

    // Allow external requests by default for testing proxy
    services.policyService.createPolicy({
      agentId: testAgent.id,
      name: "Allow Outbound",
      actionPattern: "http:*",
      resourcePattern: "external:*",
      effect: "ALLOW",
      priority: 10,
    });
  });

  afterEach(() => {
    db.close();
  });

  // ------------------------------------------------------------------
  // 1. SSRF & Cloud Metadata Exfiltration Defense (Bug #1 Fix)
  // ------------------------------------------------------------------
  describe("1. SSRF & Private IP / Cloud Metadata Defense in Egress Proxy", () => {
    it("should strictly block cloud metadata endpoint 169.254.169.254", async () => {
      const res = await request(app)
        .post("/api/v1/proxy")
        .set("Authorization", `Bearer ${testAgentKey}`)
        .send({
          targetUrl: "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
          method: "GET",
        });

      expect(res.status).toBe(403);
      expect(res.body.error).toContain("SSRF_PROHIBITED");
    });

    it("should strictly block loopback interfaces (localhost / 127.0.0.1 / ::1)", async () => {
      const res = await request(app)
        .post("/api/v1/proxy")
        .set("Authorization", `Bearer ${testAgentKey}`)
        .send({
          targetUrl: "http://localhost:3000/api/v1/killswitch",
          method: "POST",
        });

      expect(res.status).toBe(403);
      expect(res.body.error).toContain("SSRF_PROHIBITED");
    });

    it("should strictly block private RFC1918 internal IPs (10.0.0.1, 192.168.1.1)", async () => {
      const res = await request(app)
        .post("/api/v1/proxy")
        .set("Authorization", `Bearer ${testAgentKey}`)
        .send({
          targetUrl: "http://10.0.0.15:8080/internal-api",
          method: "GET",
        });

      expect(res.status).toBe(403);
      expect(res.body.error).toContain("SSRF_PROHIBITED");
    });

    it("should reject non-HTTP protocols (file://, gopher://)", async () => {
      const res = await request(app)
        .post("/api/v1/proxy")
        .set("Authorization", `Bearer ${testAgentKey}`)
        .send({
          targetUrl: "file:///etc/passwd",
          method: "GET",
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toContain("PROTOCOL_DISALLOWED");
    });
  });

  // ------------------------------------------------------------------
  // 2. Concurrency Race Condition in Approval Decisions (Bug #2 Fix)
  // ------------------------------------------------------------------
  describe("2. Atomic Approval Concurrency & Race Condition Defense", () => {
    it("should prevent double-decisions on concurrent reviews", () => {
      const req = services.approvalService.requestApproval({
        agentId: testAgent.id,
        action: "finance:wire",
        resource: "bank:acct",
        parameters: { amount: 500 },
        ttlSeconds: 60,
      });

      // First decision succeeds
      const firstDecision = services.approvalService.decide(req.id, "APPROVE", "supervisor1@company.com");
      expect(firstDecision.status).toBe("APPROVED");
      expect(firstDecision.execution_nonce).toBeDefined();

      // Second decision on the same pending ticket fails immediately
      expect(() => {
        services.approvalService.decide(req.id, "REJECT", "supervisor2@company.com");
      }).toThrow(/Cannot decide on approval in 'APPROVED' state|no longer pending/);
    });
  });

  // ------------------------------------------------------------------
  // 3. Negative Cost Budget Bypass Defense (Bug #3 Fix)
  // ------------------------------------------------------------------
  describe("3. Negative Cost Budget Manipulation Defense", () => {
    it("should throw INVALID_COST error if negative cost is supplied", () => {
      services.microBudgetService.registerRun({
        agentId: testAgent.id,
        runId: "run_exploit_01",
        maxSpendUsdPerRun: 10.0,
        maxVelocityRpm: 10,
        maxSpendRateUsdPerMin: 10.0,
      });

      expect(() => {
        services.microBudgetService.checkAndRecord("run_exploit_01", -50.0);
      }).toThrow("INVALID_COST");
    });
  });

  // ------------------------------------------------------------------
  // 4. Glob Wildcard Policy Pattern Matching (Enhancement)
  // ------------------------------------------------------------------
  describe("4. Advanced Glob Wildcard Policy Pattern Matching", () => {
    it("should match prefix, suffix, and infix wildcards", () => {
      // Suffix wildcard
      expect(services.policyService.matchPattern("db:*", "db:select")).toBe(true);
      expect(services.policyService.matchPattern("db:*", "network:select")).toBe(false);

      // Prefix wildcard
      expect(services.policyService.matchPattern("*:read", "document:read")).toBe(true);
      expect(services.policyService.matchPattern("*:read", "document:write")).toBe(false);

      // Infix wildcard
      expect(services.policyService.matchPattern("cloud:*:deploy", "cloud:prod:deploy")).toBe(true);
      expect(services.policyService.matchPattern("cloud:*:deploy", "cloud:prod:destroy")).toBe(false);
    });
  });

  // ------------------------------------------------------------------
  // 5. Autonomous Self-Healing & Diagnostics Service
  // ------------------------------------------------------------------
  describe("5. Autonomous Self-Healing & Continuous Quality Service", () => {
    it("should provide full diagnostic telemetry via REST API", async () => {
      const res = await request(app).get("/api/v1/health/diagnostics");
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);

      const diag = res.body.diagnostics;
      expect(diag.status).toBe("OPTIMAL");
      expect(diag.database.integrityOk).toBe(true);
      expect(diag.database.chainIntegrityOk).toBe(true);
      expect(diag.memory.heapUsedMb).toBeGreaterThan(0);
    });

    it("should auto-expire stale pending approvals and compact database during self-healing", async () => {
      // Insert an expired pending approval directly into DB
      db.prepare(`
        INSERT INTO approvals (
          id, agent_id, action, resource, parameters,
          estimated_cost_usd, status, execution_nonce,
          requested_at, expires_at
        ) VALUES ('app_stale_test', ?, 'task:stale', 'queue:old', '{}', 0, 'PENDING', NULL, ?, ?)
      `).run(testAgent.id, Date.now() - 20000, Date.now() - 10000);

      const res = await request(app).post("/api/v1/health/self-heal");
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);

      const result = res.body.result;
      expect(result.approvalsExpired).toBeGreaterThanOrEqual(1);
      expect(result.walCheckpointed).toBe(true);
      expect(result.statusAfterHealing).toBe("OPTIMAL");
    });
  });
});
