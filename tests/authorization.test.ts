import { describe, it, expect, beforeEach } from "vitest";
import Database from "better-sqlite3";
import { createApp } from "../server/app.js";
import request from "supertest";

describe("Agent Authorization & Deny-by-Default Policy Engine", () => {
  let db: Database.Database;
  let app: any;
  let services: any;
  let activeAgentKey: string;
  let activeAgentId: string;

  beforeEach(() => {
    db = new Database(":memory:");
    const created = createApp(db);
    app = created.app;
    services = created.services;

    const reg = services.registryService.registerAgent({
      name: "Security-Tester-Agent",
      operatorEmail: "sec-test@corp.internal",
      framework: "LangChain",
      allowedCapabilities: ["docs:read", "database:query", "payment:transfer"],
      rateLimitRpm: 100,
      spendLimitUsd: 500,
    });
    activeAgentId = reg.agent.id;
    activeAgentKey = reg.apiKey;
  });

  it("should DENY by default when no policy matches the requested action and resource", async () => {
    const res = await request(app)
      .post("/api/v1/authorize")
      .set("Authorization", `Bearer ${activeAgentKey}`)
      .send({
        action: "docs:read",
        resource: "internal:sensitive_vault",
      });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.allowed).toBe(false);
    expect(res.body.decision).toBe("DENY");
    expect(res.body.reason).toContain("Deny by default");
  });

  it("should DENY when requested action is outside declared agent capabilities", async () => {
    // Even if a global policy exists, capability boundary must reject first
    services.policyService.createPolicy({
      name: "Global Allow Shell",
      actionPattern: "system:exec",
      resourcePattern: "*",
      effect: "ALLOW",
    });

    const res = await request(app)
      .post("/api/v1/authorize")
      .set("Authorization", `Bearer ${activeAgentKey}`)
      .send({
        action: "system:exec",
        resource: "server:root",
      });

    expect(res.status).toBe(200);
    expect(res.body.allowed).toBe(false);
    expect(res.body.decision).toBe("DENY");
    expect(res.body.reason).toContain("outside agent's assigned capabilities");
  });

  it("should ALLOW when capability and matching ALLOW policy are present", async () => {
    services.policyService.createPolicy({
      name: "Allow Documentation Read",
      actionPattern: "docs:read",
      resourcePattern: "docs:*",
      effect: "ALLOW",
    });

    const res = await request(app)
      .post("/api/v1/authorize")
      .set("Authorization", `Bearer ${activeAgentKey}`)
      .send({
        action: "docs:read",
        resource: "docs:guides",
      });

    expect(res.status).toBe(200);
    expect(res.body.allowed).toBe(true);
    expect(res.body.decision).toBe("ALLOW");
  });

  it("should prioritize higher priority explicit DENY policy over lower priority ALLOW", async () => {
    services.policyService.createPolicy({
      name: "Broad Allow Database",
      actionPattern: "database:query",
      resourcePattern: "db:*",
      effect: "ALLOW",
      priority: 10,
    });

    services.policyService.createPolicy({
      name: "High Priority Deny Master DB",
      actionPattern: "database:query",
      resourcePattern: "db:master_secrets",
      effect: "DENY",
      priority: 100, // Higher priority wins
    });

    const res = await request(app)
      .post("/api/v1/authorize")
      .set("Authorization", `Bearer ${activeAgentKey}`)
      .send({
        action: "database:query",
        resource: "db:master_secrets",
      });

    expect(res.status).toBe(200);
    expect(res.body.allowed).toBe(false);
    expect(res.body.decision).toBe("DENY");
    expect(res.body.reason).toContain("High Priority Deny Master DB");
  });

  it("should fail closed and reject requests without valid authentication", async () => {
    const res = await request(app)
      .post("/api/v1/authorize")
      .send({
        action: "docs:read",
        resource: "docs:any",
      });

    expect(res.status).toBe(401);
    expect(res.body.success).toBe(false);
  });

  it("should strictly block /api/v1/tools/execute on the server when policy denies, preventing tool execution", async () => {
    // Attempt to invoke protected tool directly for forbidden action
    const res = await request(app)
      .post("/api/v1/tools/execute")
      .set("Authorization", `Bearer ${activeAgentKey}`)
      .send({
        toolName: "drop_customer_table",
        action: "drop_customer_table",
        resource: "database:customers",
      });

    expect(res.status).toBe(403);
    expect(res.body.success).toBe(false);
    expect(res.body.error).toContain("Execution blocked by server policy");
  });
});
