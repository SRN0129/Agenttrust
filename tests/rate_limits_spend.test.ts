import { describe, it, expect, beforeEach } from "vitest";
import Database from "better-sqlite3";
import { createApp } from "../server/app.js";
import request from "supertest";

describe("Rate Limits & Budget Spending Controls", () => {
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
      name: "Throttled-Agent",
      operatorEmail: "throttled@corp.internal",
      allowedCapabilities: ["query:data"],
      rateLimitRpm: 3, // strictly 3 requests per minute
      spendLimitUsd: 50.0, // max $50
    });
    agentId = reg.agent.id;
    agentKey = reg.apiKey;

    services.policyService.createPolicy({
      name: "Allow Data Query",
      actionPattern: "query:data",
      resourcePattern: "*",
      effect: "ALLOW",
    });
  });

  it("should enforce per-minute sliding rate limits", async () => {
    // 3 requests should succeed
    for (let i = 0; i < 3; i++) {
      const res = await request(app)
        .post("/api/v1/authorize")
        .set("Authorization", `Bearer ${agentKey}`)
        .send({ action: "query:data", resource: "records" });
      expect(res.body.allowed).toBe(true);
    }

    // 4th request must be DENIED due to rate limiting
    const rateLimitExceeded = await request(app)
      .post("/api/v1/authorize")
      .set("Authorization", `Bearer ${agentKey}`)
      .send({ action: "query:data", resource: "records" });

    expect(rateLimitExceeded.body.allowed).toBe(false);
    expect(rateLimitExceeded.body.decision).toBe("DENY");
    expect(rateLimitExceeded.body.reason).toContain("Rate limit of 3 requests/min exceeded");
  });

  it("should enforce financial spend budget limits", async () => {
    // Request within budget ($30 <= $50)
    const allowedSpend = await request(app)
      .post("/api/v1/authorize")
      .set("Authorization", `Bearer ${agentKey}`)
      .send({
        action: "query:data",
        resource: "records",
        estimatedCostUsd: 30.0,
      });
    expect(allowedSpend.body.allowed).toBe(true);

    // Record $30 spend
    services.registryService.recordSpend(agentId, 30.0);

    // Request exceeding remaining budget ($25 > $20 remaining)
    const rejectedSpend = await request(app)
      .post("/api/v1/authorize")
      .set("Authorization", `Bearer ${agentKey}`)
      .send({
        action: "query:data",
        resource: "records",
        estimatedCostUsd: 25.0,
      });

    expect(rejectedSpend.body.allowed).toBe(false);
    expect(rejectedSpend.body.decision).toBe("DENY");
    expect(rejectedSpend.body.reason).toContain("exceeds remaining budget");
  });
});
