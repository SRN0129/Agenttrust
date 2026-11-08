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
      allowedCapabilities: ["read_customer_notes", "calculate_risk_index"],
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

  describe("Subprocess Containment & Hardened Process Isolation", () => {
    it("should execute code in an isolated subprocess with zero ambient environment credentials", async () => {
      // Script tries to inspect process.env for sensitive tokens
      const script = "return { capturedSecret: process.env.ADMIN_KEY || process.env.DATABASE_URL || 'NONE', sum: input.a + input.b };";
      const outcome = await IsolatedSandboxRunner.executeInSubprocess(script, { a: 40, b: 2 });

      expect(outcome.success).toBe(true);
      expect(outcome.isolationTier).toBe("SUBPROCESS_HARDENED");
      expect(outcome.output.sum).toBe(42);
      expect(outcome.output.capturedSecret).toBe("NONE"); // Empty env verified!
    });

    it("should terminate runaway subprocesses with hard timeout containment", async () => {
      // Infinite busy loop
      const runawayScript = "const start = Date.now(); while (true) {}";
      const outcome = await IsolatedSandboxRunner.executeInSubprocess(runawayScript, {}, { timeoutMs: 100 });

      expect(outcome.success).toBe(false);
      expect(outcome.isolationTier).toBe("SUBPROCESS_HARDENED");
      expect(outcome.error).toContain("timed out after 100ms");
    });

    it("should register dynamic custom tools and execute them inside hardened subprocess sandbox", async () => {
      // 1. List tools
      const listRes = await request(app).get("/api/v1/tools");
      expect(listRes.status).toBe(200);
      expect(listRes.body.tools).toContain("read_customer_notes");

      // 2. Register dynamic custom tool
      const regRes = await request(app)
        .post("/api/v1/tools/register")
        .send({
          name: "calculate_risk_index",
          scriptCode: "return { riskIndex: input.score * 1.5, verified: true };",
        });
      expect(regRes.status).toBe(200);
      expect(regRes.body.availableTools).toContain("calculate_risk_index");

      // 3. Allow capability & policy
      services.policyService.createPolicy({
        name: "Allow Risk Calculation",
        actionPattern: "calculate_risk_index",
        resourcePattern: "*",
        effect: "ALLOW",
      });

      // 4. Execute custom tool through gateway
      const execRes = await request(app)
        .post("/api/v1/tools/execute")
        .set("Authorization", `Bearer ${agentKey}`)
        .send({
          toolName: "calculate_risk_index",
          action: "calculate_risk_index",
          resource: "analytics:portfolio",
          parameters: { score: 20 },
        });

      expect(execRes.status).toBe(200);
      expect(execRes.body.success).toBe(true);
      expect(execRes.body.output.riskIndex).toBe(30);

      // Verify audit trail logged SUBPROCESS_HARDENED tier
      const auditRes = await request(app).get("/api/v1/audit?eventType=TOOL_EXECUTION");
      const latest = auditRes.body.events[0];
      expect(latest.payload.isolationTier).toBe("SUBPROCESS_HARDENED");
    });
  });
});
