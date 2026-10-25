import { describe, it, expect, beforeEach } from "vitest";
import Database from "better-sqlite3";
import { createApp } from "../server/app.js";
import request from "supertest";

describe("Agent Credential Revocation & State Management", () => {
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

    const reg = services.registryService.registerAgent({
      name: "Compromise-Candidate-Agent",
      operatorEmail: "ops@corp.internal",
      allowedCapabilities: ["data:read", "data:write"],
    });
    agentId = reg.agent.id;
    agentKey = reg.apiKey;

    services.policyService.createPolicy({
      name: "Allow Data Read",
      actionPattern: "data:read",
      resourcePattern: "*",
      effect: "ALLOW",
    });
  });

  it("should authorize active agent before revocation", async () => {
    const res = await request(app)
      .post("/api/v1/authorize")
      .set("Authorization", `Bearer ${agentKey}`)
      .send({ action: "data:read", resource: "records:1" });

    expect(res.body.allowed).toBe(true);
  });

  it("should instantly DENY authorization requests after revocation", async () => {
    // Revoke agent
    const revokeRes = await request(app)
      .post(`/api/v1/agents/${agentId}/revoke`)
      .send({ reason: "Compromised API key suspected in pastebin" });

    expect(revokeRes.status).toBe(200);
    expect(revokeRes.body.agent.status).toBe("REVOKED");

    // Attempt authorization with old key
    const authzRes = await request(app)
      .post("/api/v1/authorize")
      .set("Authorization", `Bearer ${agentKey}`)
      .send({ action: "data:read", resource: "records:1" });

    expect(authzRes.body.allowed).toBe(false);
    expect(authzRes.body.decision).toBe("DENY");
    expect(authzRes.body.reason).toContain("permanently revoked");
  });

  it("should disallow status changes on permanently revoked agents", async () => {
    // Revoke
    services.registryService.revokeAgent(agentId, "Permanent ban");

    // Attempt reactivate
    const statusRes = await request(app)
      .post(`/api/v1/agents/${agentId}/status`)
      .send({ status: "ACTIVE" });

    expect(statusRes.status).toBe(400);
    expect(statusRes.body.error).toContain("Cannot change status of a permanently revoked agent");
  });

  it("should block suspended agents from authorizing until unsuspended", async () => {
    // Suspend
    await request(app)
      .post(`/api/v1/agents/${agentId}/status`)
      .send({ status: "SUSPENDED" });

    const suspendedCheck = await request(app)
      .post("/api/v1/authorize")
      .set("Authorization", `Bearer ${agentKey}`)
      .send({ action: "data:read", resource: "records:1" });

    expect(suspendedCheck.body.allowed).toBe(false);
    expect(suspendedCheck.body.reason).toContain("SUSPENDED");

    // Unsuspend
    await request(app)
      .post(`/api/v1/agents/${agentId}/status`)
      .send({ status: "ACTIVE" });

    const resumedCheck = await request(app)
      .post("/api/v1/authorize")
      .set("Authorization", `Bearer ${agentKey}`)
      .send({ action: "data:read", resource: "records:1" });

    expect(resumedCheck.body.allowed).toBe(true);
  });
});
