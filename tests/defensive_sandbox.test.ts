import { describe, it, expect, beforeEach } from "vitest";
import Database from "better-sqlite3";
import { createApp } from "../server/app.js";
import { IsolatedSandboxRunner } from "../server/services/sandbox.js";
import request from "supertest";

describe("Defensive Sandboxing & Runtime Hardening (Anti-RCE / Anti-DDoS)", () => {
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
      name: "Hardened-Tester-Bot",
      operatorEmail: "sec-ops@defense.test",
      allowedCapabilities: ["read_customer_notes"],
    });
    agentId = reg.agent.id;
    agentKey = reg.apiKey;

    services.policyService.createPolicy({
      name: "Allow Notes",
      actionPattern: "read_customer_notes",
      resourcePattern: "*",
      effect: "ALLOW",
    });
  });

  it("should strip malicious prototype pollution vectors from tool parameters", async () => {
    let capturedParams: any = null;

    const mockTool = (params: any) => {
      capturedParams = params;
      return { result: { safe: true }, summary: "Sanitized" };
    };

    const maliciousInput = {
      customerId: "cust_999",
      __proto__: { isAdmin: true },
      constructor: { role: "root" },
    };

    const outcome = await IsolatedSandboxRunner.executeSafely("test_tool", mockTool, maliciousInput);
    expect(outcome.success).toBe(true);
    expect(capturedParams.customerId).toBe("cust_999");
    expect(Object.prototype.hasOwnProperty.call(capturedParams, "__proto__")).toBe(false);
  });

  it("should contain tool runtime crashes without crashing the AgentTrust gateway", async () => {
    const crashingTool = () => {
      throw new Error("Simulated core memory fault / segmentation panic");
    };

    const outcome = await IsolatedSandboxRunner.executeSafely("faulty_tool", crashingTool, {});
    expect(outcome.success).toBe(false);
    expect(outcome.error).toContain("Sandbox Defense Blocked Execution");
  });

  it("should enforce hard execution timeout limits to prevent infinite loops and resource exhaustion", async () => {
    const slowTool = async () => {
      await new Promise(r => setTimeout(r, 150));
      return { result: {}, summary: "Done" };
    };

    // Imposing a 50ms strict ceiling
    const outcome = await IsolatedSandboxRunner.executeSafely("slow_tool", slowTool, {}, { timeoutMs: 50 });
    expect(outcome.success).toBe(false);
    expect(outcome.error).toContain("timed out");
  });

  it("should safely execute protected tools through HTTP gateway with sandbox verification", async () => {
    const res = await request(app)
      .post("/api/v1/tools/execute")
      .set("Authorization", `Bearer ${agentKey}`)
      .send({
        toolName: "read_customer_notes",
        action: "read_customer_notes",
        resource: "customer:101",
        parameters: { customerId: "cust_101" },
      });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.output.customerId).toBe("cust_101");

    // Verify audit entry notes sandboxing
    const auditRes = await request(app).get("/api/v1/audit?eventType=TOOL_EXECUTION");
    expect(auditRes.body.events[0].payload.sandboxed).toBe(true);
  });
});
