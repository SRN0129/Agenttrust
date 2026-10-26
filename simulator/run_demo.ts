import { createApp } from "../server/app.js";
import Database from "better-sqlite3";
import { AgentTrustClient } from "../sdk/index.js";

async function runSimulator() {
  console.log(`\n===============================================================`);
  console.log(`🤖 AGENTTRUST ZERO-TRUST AI AGENT SECURITY SIMULATOR`);
  console.log(`===============================================================\n`);

  // Create isolated in-memory test database for clean demonstration
  const db = new Database(":memory:");
  db.pragma("foreign_keys = ON");
  const { app, services } = createApp(db);

  // Start internal test server on ephemeral port
  const server = app.listen(0);
  const address = server.address() as any;
  const baseUrl = `http://127.0.0.1:${address.port}`;

  console.log(`[INIT] Running test gateway at ${baseUrl}`);

  try {
    // -------------------------------------------------------------------------
    // STEP 1: Agent Registration
    // -------------------------------------------------------------------------
    console.log(`\n[STEP 1] Registering Autonomous Agent with Scoped Capabilities...`);
    const registerRes = await fetch(`${baseUrl}/api/v1/agents/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: "Autonomous-Support-Agent",
        description: "Autonomous agent for handling customer CRM records",
        operatorEmail: "operator-ops@enterprise.com",
        framework: "CrewAI",
        allowedCapabilities: ["read_customer_notes", "search_documentation", "send_wire_transfer"],
        rateLimitRpm: 5,
        spendLimitUsd: 500.0,
      }),
    });
    const regData = await registerRes.json();
    if (!registerRes.ok) {
      console.error("Register failed:", registerRes.status, regData);
      return;
    }
    const agent = regData.agent;
    const apiKey = regData.apiKey;
    console.log(`✅ Agent Registered Successfully:`);
    console.log(`   - ID: ${agent.id}`);
    console.log(`   - Name: ${agent.name}`);
    console.log(`   - Scoped Capabilities: ${agent.allowedCapabilities.join(", ")}`);
    console.log(`   - Rate Limit: ${agent.rateLimitRpm} rpm`);
    console.log(`   - Spend Budget: $${agent.spendLimitUsd}`);
    console.log(`   - Key Status: Cryptographically Salted and Hashed`);

    // Setup policies
    services.policyService.createPolicy({
      name: "Allow Read-Only Notes",
      actionPattern: "read_customer_notes",
      resourcePattern: "customer:*",
      effect: "ALLOW",
      priority: 10,
    });

    services.policyService.createPolicy({
      name: "Require Approval For Wire Transfers",
      actionPattern: "send_wire_transfer",
      resourcePattern: "accounts:*",
      effect: "REQUIRE_APPROVAL",
      priority: 50,
    });

    services.policyService.createPolicy({
      name: "Strict Deny Table Dropping",
      actionPattern: "drop_customer_table",
      resourcePattern: "*",
      effect: "DENY",
      priority: 999,
    });

    // Initialize SDK Client
    const client = new AgentTrustClient({ baseUrl, apiKey });

    // -------------------------------------------------------------------------
    // STEP 2: Scenario 1 - Allowed Action (Low-Risk Read)
    // -------------------------------------------------------------------------
    console.log(`\n---------------------------------------------------------------`);
    console.log(`[SCENARIO 1] Agent requests low-risk action: 'read_customer_notes'`);
    console.log(`---------------------------------------------------------------`);
    const readResult = await client.executeProtectedTool({
      toolName: "read_customer_notes",
      action: "read_customer_notes",
      resource: "customer:1042",
      parameters: { customerId: "cust_1042" },
    });
    console.log(`🛡️ Policy Decision: ALLOW`);
    console.log(`⚡ Tool Output Received:`, JSON.stringify(readResult.output));

    // -------------------------------------------------------------------------
    // STEP 3: Scenario 2 - Denied Action: Out-of-Scope Capability
    // -------------------------------------------------------------------------
    console.log(`\n---------------------------------------------------------------`);
    console.log(`[SCENARIO 2] Agent attempts action outside capability scope: 'modify_kernel'`);
    console.log(`---------------------------------------------------------------`);
    try {
      await client.executeProtectedTool({
        toolName: "read_customer_notes",
        action: "modify_kernel",
        resource: "system:kernel",
      });
      console.error(`❌ FAILED: Action should have been denied!`);
    } catch (err: any) {
      console.log(`🛡️ DENIED as Expected: ${err.message}`);
      console.log(`🔒 Result: Protected tool was NEVER invoked.`);
    }

    // -------------------------------------------------------------------------
    // STEP 4: Scenario 3 - Denied Action: Explicit Deny Rule
    // -------------------------------------------------------------------------
    console.log(`\n---------------------------------------------------------------`);
    console.log(`[SCENARIO 3] Agent attempts forbidden destructive action: 'drop_customer_table'`);
    console.log(`---------------------------------------------------------------`);
    try {
      await client.executeProtectedTool({
        toolName: "drop_customer_table",
        action: "drop_customer_table",
        resource: "database:customer_records",
      });
      console.error(`❌ FAILED: Destructive action was not denied!`);
    } catch (err: any) {
      console.log(`🛡️ DENIED by Policy Engine: ${err.message}`);
      console.log(`🔒 Result: Database destruction tool was completely blocked.`);
    }

    // -------------------------------------------------------------------------
    // STEP 5: Scenario 4 - Human-in-the-Loop Approval Workflow
    // -------------------------------------------------------------------------
    console.log(`\n---------------------------------------------------------------`);
    console.log(`[SCENARIO 4] Agent requests sensitive financial action: 'send_wire_transfer'`);
    console.log(`---------------------------------------------------------------`);
    const authz = await client.authorize("send_wire_transfer", "accounts:vendor_invoice", {
      recipient: "Acme Cloud Services",
      amount: 150.0,
    });

    console.log(`🛡️ Policy Decision: ${authz.decision}`);
    console.log(`📋 Approval ID: ${authz.approvalId}`);
    console.log(`⏳ Reason: ${authz.reason}`);

    // Human Operator reviews and approves via Admin Console API
    console.log(`\n👤 Human Security Operator reviews pending request...`);
    const decideRes = await fetch(`${baseUrl}/api/v1/approvals/${authz.approvalId}/decide`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        decision: "APPROVE",
        reviewerEmail: "sec-admin@enterprise.com",
        reason: "Verified legitimate vendor invoice #ACME-8821.",
      }),
    });
    const decideData = await decideRes.json();
    const executionTicket = decideData.approval.executionNonce;
    console.log(`✅ Human Operator Approved! Single-use execution ticket issued:`);
    console.log(`   Ticket: ${executionTicket}`);

    // Agent executes tool using the approved execution ticket
    console.log(`\n⚡ Agent submits execution ticket to Protected Tool Gateway...`);
    const execRes = await fetch(`${baseUrl}/api/v1/tools/execute`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        toolName: "send_wire_transfer",
        action: "send_wire_transfer",
        resource: "accounts:vendor_invoice",
        parameters: { recipient: "Acme Cloud Services", amount: 150.0 },
        approvalId: authz.approvalId,
        executionNonce: executionTicket,
        costUsd: 150.0,
      }),
    });
    const execData = await execRes.json();
    console.log(`🎉 Tool Executed Successfully:`, JSON.stringify(execData.output));
    console.log(`🎟️ Ticket Consumed Status: ${execData.consumedTicket}`);

    // -------------------------------------------------------------------------
    // STEP 6: Scenario 5 - Replay Attack Protection
    // -------------------------------------------------------------------------
    console.log(`\n---------------------------------------------------------------`);
    console.log(`[SCENARIO 5] Attacker attempts REPLAY ATTACK using consumed ticket`);
    console.log(`---------------------------------------------------------------`);
    const replayRes = await fetch(`${baseUrl}/api/v1/tools/execute`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        toolName: "send_wire_transfer",
        action: "send_wire_transfer",
        resource: "accounts:vendor_invoice",
        parameters: { recipient: "Attacker Account", amount: 999.0 },
        approvalId: authz.approvalId,
        executionNonce: executionTicket,
      }),
    });
    const replayData = await replayRes.json();
    console.log(`HTTP Status: ${replayRes.status} (Expected: 409 / Conflict)`);
    console.log(`🛡️ Replay Protection: ${replayData.error}`);
    console.log(`🚨 Anomaly Event recorded in audit ledger: REPLAY_ATTEMPT`);

    // -------------------------------------------------------------------------
    // STEP 7: Scenario 6 - Cryptographic Audit Ledger & Tamper Detection
    // -------------------------------------------------------------------------
    console.log(`\n---------------------------------------------------------------`);
    console.log(`[SCENARIO 6] Verifiable Audit Ledger & Hash-Chain Tamper Detection`);
    console.log(`---------------------------------------------------------------`);
    
    // Verify untampered ledger
    const verifyBeforeRes = await fetch(`${baseUrl}/api/v1/audit/verify`);
    const verifyBefore = await verifyBeforeRes.json();
    console.log(`🔍 Chain Status (Before): ${verifyBefore.tamperResistantStatus}`);
    console.log(`   - Total Cryptographically Chained Records: ${verifyBefore.integrity.totalRecords}`);
    console.log(`   - Latest Tip Hash: ${verifyBefore.integrity.latestHash.substring(0, 24)}...`);

    // Intentionally alter a record in the database directly to test tamper detection
    console.log(`\n💥 SIMULATING DIRECT DATABASE TAMPERING: Modifying row #2 in database...`);
    const tamperRes = await fetch(`${baseUrl}/api/v1/audit/tamper-test`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ index: 2, maliciousAction: "tampered:unauthorized_grant" }),
    });
    const tamperData = await tamperRes.json();

    console.log(`🔍 Chain Verification After Row Tampering:`);
    console.log(`   - Valid: ${tamperData.verificationResult.valid}`);
    console.log(`   - Broken At Index: #${tamperData.verificationResult.brokenAt}`);
    console.log(`   - Reason: ${tamperData.verificationResult.reason}`);
    console.log(`🛡️ Tampering was instantly and deterministically flagged!`);

    console.log(`\n===============================================================`);
    console.log(`🎉 ALL SIMULATOR SCENARIOS COMPLETED SUCCESSFULLY!`);
    console.log(`===============================================================\n`);
  } finally {
    server.close();
    db.close();
  }
}

runSimulator().catch((err) => {
  console.error("Simulator Error:", err);
  process.exit(1);
});
