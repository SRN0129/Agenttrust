import { describe, it, expect, beforeEach } from "vitest";
import Database from "better-sqlite3";
import { createApp } from "../server/app.js";
import { BlastRadiusAnalyzer } from "../server/services/blastRadius.js";
import request from "supertest";

describe("Enterprise Innovations: Delegation, Blast Radius, Notarization & Killswitch", () => {
  let db: Database.Database;
  let app: any;
  let services: any;
  let parentKey: string;
  let parentId: string;

  beforeEach(() => {
    db = new Database(":memory:");
    const created = createApp(db);
    app = created.app;
    services = created.services;

    // Register parent orchestrator agent
    const reg = services.registryService.registerAgent({
      name: "Orchestrator-Parent-Agent",
      operatorEmail: "lead-architect@corp.internal",
      allowedCapabilities: ["read_notes", "search_docs", "send_payout"],
      rateLimitRpm: 60,
      spendLimitUsd: 500,
    });
    parentId = reg.agent.id;
    parentKey = reg.apiKey;
  });

  describe("Cascading Multi-Agent Delegation & Attenuated Sub-Tokens", () => {
    it("should allow parent to mint an attenuated subagent with subset capabilities", async () => {
      const res = await request(app)
        .post("/api/v1/agents/delegate")
        .send({
          parentAgentId: parentId,
          name: "Research-Worker-Subagent",
          delegatedCapabilities: ["read_notes", "search_docs"], // Valid subset
          allocatedSpendLimitUsd: 50.0,
          allocatedRateLimitRpm: 20,
        });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.childAgent.allowedCapabilities).toEqual(["read_notes", "search_docs"]);
      expect(res.body.childAgent.spendLimitUsd).toBe(50.0);
      expect(res.body.apiKey).toMatch(/^at_live_/);

      // Verify delegation link
      const listRes = await request(app).get(`/api/v1/agents/${parentId}/subagents`);
      expect(listRes.body.count).toBe(1);
      expect(listRes.body.subagents[0].id).toBe(res.body.childAgent.id);
    });

    it("should reject delegation when parent attempts to grant a capability it does not possess (Attenuation Violation)", async () => {
      const res = await request(app)
        .post("/api/v1/agents/delegate")
        .send({
          parentAgentId: parentId,
          name: "Privilege-Escalation-Attempt",
          delegatedCapabilities: ["read_notes", "admin:drop_database"], // Parent lacks admin:drop_database!
          allocatedSpendLimitUsd: 50.0,
          allocatedRateLimitRpm: 20,
        });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error).toContain("Attenuation Violation");
      expect(res.body.error).toContain("Parent cannot delegate capability");
    });

    it("should reject delegation when allocated budget exceeds parent's remaining budget", async () => {
      const res = await request(app)
        .post("/api/v1/agents/delegate")
        .send({
          parentAgentId: parentId,
          name: "Over-Budget-Subagent",
          delegatedCapabilities: ["read_notes"],
          allocatedSpendLimitUsd: 9999.0, // Exceeds parent $500 budget!
          allocatedRateLimitRpm: 20,
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toContain("exceeds parent's remaining budget");
    });
  });

  describe("Semantic Blast Radius & Pre-Flight Risk Evaluation", () => {
    it("should evaluate low blast radius for read-only query operations", () => {
      const assessment = BlastRadiusAnalyzer.analyze("read_customer_notes", "customer:101", {}, 0);
      expect(assessment.riskTier).toBe("LOW");
      expect(assessment.riskScore).toBeLessThan(0.35);
      expect(assessment.escalationRequired).toBe(false);
    });

    it("should evaluate critical blast radius for permanent database drop on production perimeter", () => {
      const assessment = BlastRadiusAnalyzer.analyze("drop_customer_table", "database:prod_customer_records", {}, 0);
      expect(assessment.riskTier).toBe("CRITICAL");
      expect(assessment.riskScore).toBeGreaterThanOrEqual(0.65);
      expect(assessment.escalationRequired).toBe(true);
      expect(assessment.reasons.some(r => r.includes("Permanent destructive action"))).toBe(true);
    });

    it("should automatically escalate high blast radius action to human approval", async () => {
      // Create broad policy that would otherwise allow deploy
      services.policyService.createPolicy({
        name: "Broad Deploy Policy",
        actionPattern: "deploy:*",
        resourcePattern: "*",
        effect: "ALLOW",
      });

      // Update parent capability to include deploy
      services.registryService.updateStatus(parentId, "ACTIVE");
      db.prepare("UPDATE agents SET allowed_capabilities = ? WHERE id = ?").run(
        JSON.stringify(["deploy:production_service"]),
        parentId
      );

      const res = await request(app)
        .post("/api/v1/authorize")
        .set("Authorization", `Bearer ${parentKey}`)
        .send({
          action: "deploy:production_service",
          resource: "production:payment_gateway",
          estimatedCostUsd: 150,
        });

      expect(res.status).toBe(200);
      expect(res.body.decision).toBe("NEEDS_APPROVAL");
      expect(res.body.blastRadius.escalationRequired).toBe(true);
      expect(res.body.reason).toContain("High Blast Radius");
    });
  });

  describe("Cryptographic ECDSA P-256 Notarization & Offline Verification", () => {
    it("should notarize ledger tip and verify signature offline", async () => {
      // 1. Create notarized checkpoint
      const res = await request(app).post("/api/v1/notarize/checkpoint");
      expect(res.status).toBe(201);
      expect(res.body.checkpoint.signatureHex).toBeDefined();
      expect(res.body.checkpoint.publicKeyPem).toContain("BEGIN PUBLIC KEY");

      const manifest = res.body.checkpoint;

      // 2. Perform offline verification using the embedded certificate
      const verifyRes = await request(app)
        .post("/api/v1/notarize/verify-offline")
        .send(manifest);

      expect(verifyRes.status).toBe(200);
      expect(verifyRes.body.signatureValid).toBe(true);
      expect(verifyRes.body.verificationNote).toContain("Digital signature verified intact");

      // 3. Forged manifest should fail verification
      const forgedManifest = { ...manifest, tipEntryHash: "forged_malicious_tip_hash_value" };
      const forgedCheck = await request(app)
        .post("/api/v1/notarize/verify-offline")
        .send(forgedManifest);

      expect(forgedCheck.body.signatureValid).toBe(false);
    });
  });

  describe("Emergency Global Air-Gap Killswitch", () => {
    it("should atomically revoke all agents, cancel pending approvals, and create a forensic checkpoint", async () => {
      // Create a pending approval
      services.approvalService.requestApproval({
        agentId: parentId,
        action: "send_payout",
        resource: "accounts:1",
        parameters: {},
      });

      // Trigger killswitch
      const killRes = await request(app)
        .post("/api/v1/system/killswitch")
        .send({
          reason: "Suspected system-wide autonomous prompt exfiltration",
          operatorEmail: "chief-security-officer@corp.internal",
        });

      expect(killRes.status).toBe(200);
      expect(killRes.body.result.revokedAgentsCount).toBeGreaterThanOrEqual(1);
      expect(killRes.body.result.canceledApprovalsCount).toBeGreaterThanOrEqual(1);
      expect(killRes.body.result.forensicCheckpoint).toBeDefined();

      // Verify parent agent is now REVOKED
      const agentCheck = services.registryService.getAgentById(parentId);
      expect(agentCheck.status).toBe("REVOKED");

      // Verify authorization requests fail closed
      const authzAttempt = await request(app)
        .post("/api/v1/authorize")
        .set("Authorization", `Bearer ${parentKey}`)
        .send({ action: "read_notes", resource: "notes:1" });

      expect(authzAttempt.body.allowed).toBe(false);
      expect(authzAttempt.body.decision).toBe("DENY");
    });
  });

  describe("EU AI Act & NIST Compliance Mapping", () => {
    it("should generate structured compliance report", async () => {
      const res = await request(app).get("/api/v1/compliance/report");
      expect(res.status).toBe(200);
      expect(res.body.report.frameworks.euAiAct.status).toBe("COMPLIANT");
      expect(res.body.report.frameworks.euAiAct.article14HumanOversight).toBeDefined();
      expect(res.body.report.frameworks.euAiAct.article12Traceability).toBeDefined();
      expect(res.body.report.frameworks.nistAiRmf.status).toBe("COMPLIANT");
    });
  });
});
