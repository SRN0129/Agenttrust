import { describe, it, expect, beforeEach } from "vitest";
import Database from "better-sqlite3";
import { createApp } from "../server/app.js";
import request from "supertest";

describe("E2E User Journey & End-to-End System Verification", () => {
  let db: Database.Database;
  let app: any;
  let services: any;

  beforeEach(() => {
    db = new Database(":memory:");
    const created = createApp(db);
    app = created.app;
    services = created.services;
  });

  it("completes full lifecycle: registration -> policy -> execution -> approval -> replay defense -> tamper verification", async () => {
    // 1. Register new agent
    const regRes = await request(app)
      .post("/api/v1/agents/register")
      .send({
        name: "Payment-Settlement-Agent",
        description: "Automated settlements bot",
        operatorEmail: "treasury@enterprise.internal",
        framework: "CrewAI",
        allowedCapabilities: ["read_customer_notes", "send_wire_transfer"],
        rateLimitRpm: 20,
        spendLimitUsd: 1000.0,
      });

    expect(regRes.status).toBe(201);
    const agentId = regRes.body.agent.id;
    const apiKey = regRes.body.apiKey;
    expect(agentId).toBeDefined();
    expect(apiKey).toMatch(/^at_live_/);

    // 2. Create approval policy
    const polRes = await request(app)
      .post("/api/v1/policies")
      .send({
        name: "Approval Required for Wire Transfers",
        actionPattern: "send_wire_transfer",
        resourcePattern: "accounts:*",
        effect: "REQUIRE_APPROVAL",
        priority: 100,
      });
    expect(polRes.status).toBe(201);

    // Also create auto-allow policy for read_customer_notes
    await request(app)
      .post("/api/v1/policies")
      .send({
        name: "Auto Allow Read Notes",
        actionPattern: "read_customer_notes",
        resourcePattern: "customer:*",
        effect: "ALLOW",
        priority: 50,
      });

    // 3. Low-risk execution: read notes
    const readAuthz = await request(app)
      .post("/api/v1/authorize")
      .set("Authorization", `Bearer ${apiKey}`)
      .send({
        action: "read_customer_notes",
        resource: "customer:101",
      });
    expect(readAuthz.body.allowed).toBe(true);
    expect(readAuthz.body.decision).toBe("ALLOW");

    const readTool = await request(app)
      .post("/api/v1/tools/execute")
      .set("Authorization", `Bearer ${apiKey}`)
      .send({
        toolName: "read_customer_notes",
        action: "read_customer_notes",
        resource: "customer:101",
        parameters: { customerId: "cust_101" },
      });
    expect(readTool.body.success).toBe(true);
    expect(readTool.body.output.customerId).toBe("cust_101");

    // 4. High-risk execution: send wire transfer -> NEEDS_APPROVAL
    const wireAuthz = await request(app)
      .post("/api/v1/authorize")
      .set("Authorization", `Bearer ${apiKey}`)
      .send({
        action: "send_wire_transfer",
        resource: "accounts:supplier_vault",
        parameters: { amount: 350.0, recipient: "Supplier Corp" },
        estimatedCostUsd: 350.0,
      });
    expect(wireAuthz.body.allowed).toBe(false);
    expect(wireAuthz.body.decision).toBe("NEEDS_APPROVAL");
    const approvalId = wireAuthz.body.approvalId;
    expect(approvalId).toBeDefined();

    // 5. Admin reviews and approves in dashboard
    const decideRes = await request(app)
      .post(`/api/v1/approvals/${approvalId}/decide`)
      .send({
        decision: "APPROVE",
        reviewerEmail: "cfo-approver@enterprise.internal",
        reason: "Valid verified vendor invoice",
      });
    expect(decideRes.status).toBe(200);
    const executionNonce = decideRes.body.approval.executionNonce;
    expect(executionNonce).toBeDefined();

    // 6. Agent executes with single-use ticket
    const wireExec = await request(app)
      .post("/api/v1/tools/execute")
      .set("Authorization", `Bearer ${apiKey}`)
      .send({
        toolName: "send_wire_transfer",
        action: "send_wire_transfer",
        resource: "accounts:supplier_vault",
        parameters: { amount: 350.0, recipient: "Supplier Corp" },
        approvalId,
        executionNonce,
        costUsd: 350.0,
      });
    expect(wireExec.status).toBe(200);
    expect(wireExec.body.success).toBe(true);
    expect(wireExec.body.consumedTicket).toBe(true);

    // 7. Replay attack fails
    const replayExec = await request(app)
      .post("/api/v1/tools/execute")
      .set("Authorization", `Bearer ${apiKey}`)
      .send({
        toolName: "send_wire_transfer",
        action: "send_wire_transfer",
        resource: "accounts:supplier_vault",
        parameters: { amount: 350.0, recipient: "Supplier Corp" },
        approvalId,
        executionNonce,
      });
    expect(replayExec.status).toBe(409);
    expect(replayExec.body.error).toContain("REPLAY_ATTACK_DETECTED");

    // 8. Audit ledger verification
    const verifyRes = await request(app).get("/api/v1/audit/verify");
    expect(verifyRes.body.integrity.valid).toBe(true);
    expect(verifyRes.body.tamperResistantStatus).toBe("CHAIN_VERIFIED_INTACT");

    // 9. Instant revocation
    const revokeRes = await request(app)
      .post(`/api/v1/agents/${agentId}/revoke`)
      .send({ reason: "End of lifecycle decommissioning" });
    expect(revokeRes.body.agent.status).toBe("REVOKED");

    // Attempt action with revoked key fails immediately
    const revokedAttempt = await request(app)
      .post("/api/v1/authorize")
      .set("Authorization", `Bearer ${apiKey}`)
      .send({
        action: "read_customer_notes",
        resource: "customer:101",
      });
    expect(revokedAttempt.body.allowed).toBe(false);
    expect(revokedAttempt.body.reason).toContain("permanently revoked");
  });
});
