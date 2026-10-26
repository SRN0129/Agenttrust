import { getDatabase } from "./connection.js";
import { AuditLedgerService } from "../services/audit.js";
import { AgentRegistryService } from "../services/registry.js";
import { ApprovalWorkflowService } from "../services/approval.js";
import { PolicyEngineService } from "../services/policy.js";

export function seedDatabase(customDb?: any) {
  const db = customDb || getDatabase();
  const auditService = new AuditLedgerService(db);
  const registryService = new AgentRegistryService(db, auditService);
  const approvalService = new ApprovalWorkflowService(db, auditService);
  const policyService = new PolicyEngineService(db, auditService, approvalService);

  // Check if already seeded
  const existingAgents = registryService.listAgents();
  if (existingAgents.length > 0) {
    return {
      message: "Database already seeded.",
      agentsCount: existingAgents.length,
    };
  }

  console.log("🌱 Seeding AgentTrust Database with initial zero-trust environment...");

  // 1. Register Demo Agents
  // Agent A: Customer Support Bot (Scoped to read_data and search_docs, $20 budget)
  const agentA = registryService.registerAgent({
    name: "SupportAssistant-AI",
    description: "L1 Support agent assisting with customer notes and FAQ queries",
    operatorEmail: "support-ops@example.com",
    framework: "LangChain",
    allowedCapabilities: ["read_customer_notes", "search_documentation"],
    rateLimitRpm: 10,
    spendLimitUsd: 25.0,
  });

  // Agent B: Financial Settlement Agent (Scoped for wire transfers, high risk, requires approvals)
  const agentB = registryService.registerAgent({
    name: "FinOps-Settlement-Bot",
    description: "Autonomous finance reconciliation and vendor payment agent",
    operatorEmail: "treasury@example.com",
    framework: "CrewAI",
    allowedCapabilities: ["send_wire_transfer", "read_customer_notes"],
    rateLimitRpm: 30,
    spendLimitUsd: 1000.0,
  });

  // Agent C: DevOps Deployment Agent (Scoped for cloud deployments, requiring approvals)
  const agentC = registryService.registerAgent({
    name: "DevOps-Deployer",
    description: "Continuous release agent for staging and production microservices",
    operatorEmail: "devops-leads@example.com",
    framework: "AutoGen",
    allowedCapabilities: ["deploy_service_version"],
    rateLimitRpm: 5,
    spendLimitUsd: 50.0,
  });

  // Agent D: Rogue / Revoked Compromised Agent
  const agentD = registryService.registerAgent({
    name: "Legacy-Scraper-V1",
    description: "Deprecated crawler detected violating egress perimeter",
    operatorEmail: "legacy@example.com",
    framework: "Custom",
    allowedCapabilities: ["read_customer_notes"],
    rateLimitRpm: 60,
    spendLimitUsd: 10.0,
  });
  registryService.revokeAgent(agentD.agent.id, "Security Incident #SEC-409: Suspected prompt injection credential leak");

  // 2. Define Granular Policies
  // Policy 1: Auto-allow low-risk read operations
  policyService.createPolicy({
    name: "Allow Read-Only Customer Notes",
    description: "Permits read_customer_notes across general customer partitions with zero cost",
    actionPattern: "read_customer_notes",
    resourcePattern: "customer:*",
    effect: "ALLOW",
    maxCostUsd: 0.0,
    priority: 50,
  });

  policyService.createPolicy({
    name: "Allow Documentation Search",
    description: "Auto-allows doc search queries across docs:*",
    actionPattern: "search_documentation",
    resourcePattern: "docs:*",
    effect: "ALLOW",
    maxCostUsd: 0.0,
    priority: 50,
  });

  // Policy 2: Mandatory Human Approval for Wire Transfers
  policyService.createPolicy({
    name: "Require Approval for Wire Transfers",
    description: "All wire transfers regardless of amount require explicit Human-in-the-Loop review",
    actionPattern: "send_wire_transfer",
    resourcePattern: "accounts:*",
    effect: "REQUIRE_APPROVAL",
    priority: 100,
  });

  // Policy 3: Mandatory Human Approval for Production Deployments
  policyService.createPolicy({
    name: "Require Approval for Production Deployments",
    description: "Deployments targeting production microservices must be approved by senior engineer",
    actionPattern: "deploy_service_version",
    resourcePattern: "production:*",
    effect: "REQUIRE_APPROVAL",
    priority: 100,
  });

  // Policy 4: Explicit Deny for Table Dropping or Database Destruction
  policyService.createPolicy({
    name: "Strict Deny: Database Destruction",
    description: "Strictly forbids any agent from executing table drop or destructive commands",
    actionPattern: "drop_customer_table",
    resourcePattern: "*",
    effect: "DENY",
    priority: 999, // Highest priority
  });

  // 3. Create a sample Pending Approval for the Admin Dashboard
  const sampleApproval = approvalService.requestApproval({
    agentId: agentB.agent.id,
    action: "send_wire_transfer",
    resource: "accounts:external_vendor",
    parameters: {
      recipient: "CloudInfrastructure-Hosting-Ltd",
      amount: 450.0,
      invoiceNumber: "INV-2026-9912",
      justification: "Monthly compute cluster renewal",
    },
    estimatedCostUsd: 450.0,
    ttlSeconds: 600, // 10 minutes
  });

  console.log("✅ Database seeded successfully!");
  console.log(`- Support Assistant Agent ID: ${agentA.agent.id} (Key Configured & Hashed)`);
  console.log(`- FinOps Settlement Agent ID: ${agentB.agent.id} (Key Configured & Hashed)`);
  console.log(`- Sample Pending Approval ID: ${sampleApproval.id}`);

  return {
    agents: [agentA, agentB, agentC, agentD],
    sampleApproval,
  };
}

// Allow direct CLI execution
if (import.meta.url === `file://${process.argv[1]}`) {
  seedDatabase();
}
