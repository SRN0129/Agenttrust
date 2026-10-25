import React, { useState, useEffect } from "react";
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Clock,
  Key,
  Users,
  FileText,
  Sliders,
  Play,
  Copy,
  Check,
  RefreshCw,
  Lock,
  Unlock,
  Terminal,
  Activity,
  Layers,
  ArrowRight,
  ExternalLink,
  Flame,
  HelpCircle,
  Award,
  Zap,
  GitBranch,
  Radio,
  FileCheck2,
  AlertOctagon,
  Download,
} from "lucide-react";

interface Agent {
  id: string;
  name: string;
  description: string;
  operatorEmail: string;
  framework: string;
  status: "ACTIVE" | "SUSPENDED" | "REVOKED";
  apiKeyPrefix: string;
  allowedCapabilities: string[];
  rateLimitRpm: number;
  spendLimitUsd: number;
  currentSpendUsd: number;
  createdAt: number;
  updatedAt: number;
  revokedAt?: number;
  revocationReason?: string;
  parentAgentId?: string;
}

interface Policy {
  id: string;
  name: string;
  description: string;
  agent_id: string | null;
  action_pattern: string;
  resource_pattern: string;
  effect: "ALLOW" | "DENY" | "REQUIRE_APPROVAL";
  max_cost_usd: number;
  priority: number;
  created_at: number;
}

interface Approval {
  id: string;
  agentId: string;
  action: string;
  resource: string;
  parameters: Record<string, any>;
  estimatedCostUsd: number;
  status: "PENDING" | "APPROVED" | "REJECTED" | "EXPIRED" | "CONSUMED";
  executionNonce?: string;
  requestedAt: number;
  expiresAt: number;
  timeRemainingSeconds?: number;
  decidedAt?: number;
  decidedBy?: string;
  decisionReason?: string;
}

interface AuditEvent {
  index: number;
  eventId: string;
  timestamp: number;
  agentId: string;
  eventType: string;
  action: string;
  resource: string;
  decision: string;
  payload: any;
  payloadHash: string;
  prevHash: string;
  entryHash: string;
}

interface IntegrityReport {
  valid: boolean;
  totalRecords: number;
  latestHash?: string;
  brokenAt?: number;
  reason?: string;
}

interface ComplianceReport {
  generatedAt: number;
  reportId: string;
  frameworks: {
    euAiAct: {
      status: string;
      article14HumanOversight: {
        totalHITLApprovals: number;
        approvedCount: number;
        rejectedCount: number;
        expiredCount: number;
        replayBlockedCount: number;
        complianceScore: number;
      };
      article12Traceability: {
        totalAuditEvents: number;
        cryptographicIntegrity: boolean;
        latestTipHash: string;
        notarizedCheckpointsCount: number;
        tamperResistanceScore: number;
      };
    };
    nistAiRmf: {
      status: string;
      governScore: number;
      mapScore: number;
      measureScore: number;
      manageScore: number;
      controlsImplemented: string[];
    };
    soc2Type2: {
      criteriaCC6AccessControl: string;
      criteriaCC6AuditTrails: string;
      criteriaCC7IncidentResponse: string;
    };
  };
  summary: string;
}

interface Checkpoint {
  id: string;
  sequence_number: number;
  total_records: number;
  tip_hash: string;
  timestamp: number;
  signature_hex: string;
  public_key_pem: string;
}

export default function App() {
  const [activeTab, setActiveTab] = useState<
    "agents" | "policies" | "approvals" | "audit" | "compliance" | "simulator" | "docs"
  >("agents");

  // System States
  const [agents, setAgents] = useState<Agent[]>([]);
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [pendingApprovals, setPendingApprovals] = useState<Approval[]>([]);
  const [allApprovals, setAllApprovals] = useState<Approval[]>([]);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [integrity, setIntegrity] = useState<IntegrityReport | null>(null);
  const [checkpoints, setCheckpoints] = useState<Checkpoint[]>([]);
  const [compliance, setCompliance] = useState<ComplianceReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Modals
  const [showRegisterModal, setShowRegisterModal] = useState(false);
  const [showDelegateModal, setShowDelegateModal] = useState(false);
  const [showPolicyModal, setShowPolicyModal] = useState(false);
  const [showKillswitchModal, setShowKillswitchModal] = useState(false);

  // Registration Form
  const [regForm, setRegForm] = useState({
    name: "",
    description: "",
    operatorEmail: "",
    framework: "LangChain",
    capabilities: "read_customer_notes, search_documentation",
    rateLimitRpm: 60,
    spendLimitUsd: 100,
  });

  // Delegation Form
  const [delegateForm, setDelegateForm] = useState({
    parentAgentId: "",
    name: "",
    description: "",
    framework: "CrewAI",
    capabilities: "read_customer_notes",
    rateLimitRpm: 20,
    spendLimitUsd: 25,
  });

  // Policy Form
  const [policyForm, setPolicyForm] = useState({
    name: "",
    description: "",
    actionPattern: "",
    resourcePattern: "*",
    effect: "REQUIRE_APPROVAL" as "ALLOW" | "DENY" | "REQUIRE_APPROVAL",
    maxCostUsd: 0,
    priority: 50,
  });

  // Killswitch Form
  const [killswitchReason, setKillswitchReason] = useState("Suspected autonomous credential exfiltration anomaly");
  const [killswitchEmail, setKillswitchEmail] = useState("ciso@enterprise.internal");
  const [killswitchResult, setKillswitchResult] = useState<any | null>(null);

  // Newly Minted Key
  const [createdApiKey, setCreatedApiKey] = useState<{ key: string; agentId: string; type: string } | null>(null);

  // Simulator State
  const [simulatorStepLogs, setSimulatorStepLogs] = useState<any[]>([]);
  const [simulatorRunning, setSimulatorRunning] = useState(false);

  // Fetch all core data
  const loadData = async () => {
    try {
      setLoading(true);
      const [resAgents, resPolicies, resPending, resAllApprovals, resAudit, resVerify, resCheckpoints, resComp] =
        await Promise.all([
          fetch("/api/v1/agents").then((r) => r.json()),
          fetch("/api/v1/policies").then((r) => r.json()),
          fetch("/api/v1/approvals/pending").then((r) => r.json()),
          fetch("/api/v1/approvals").then((r) => r.json()),
          fetch("/api/v1/audit?limit=100").then((r) => r.json()),
          fetch("/api/v1/audit/verify").then((r) => r.json()),
          fetch("/api/v1/notarize/checkpoints").then((r) => r.json()),
          fetch("/api/v1/compliance/report").then((r) => r.json()),
        ]);

      if (resAgents.success) setAgents(resAgents.agents);
      if (resPolicies.success) setPolicies(resPolicies.policies);
      if (resPending.success) setPendingApprovals(resPending.approvals);
      if (resAllApprovals.success) setAllApprovals(resAllApprovals.approvals);
      if (resAudit.success) setAuditEvents(resAudit.events);
      if (resVerify.success) setIntegrity(resVerify.integrity);
      if (resCheckpoints.success) setCheckpoints(resCheckpoints.checkpoints);
      if (resComp.success) setCompliance(resComp.report);
    } catch (err) {
      console.error("Error loading dashboard data:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(() => {
      loadData();
    }, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(id);
    setTimeout(() => setCopiedKey(null), 2500);
  };

  // Register Agent Handler
  const handleRegisterAgent = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const caps = regForm.capabilities
        .split(",")
        .map((c) => c.trim())
        .filter(Boolean);

      const res = await fetch("/api/v1/agents/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: regForm.name,
          description: regForm.description,
          operatorEmail: regForm.operatorEmail,
          framework: regForm.framework,
          allowedCapabilities: caps,
          rateLimitRpm: Number(regForm.rateLimitRpm),
          spendLimitUsd: Number(regForm.spendLimitUsd),
        }),
      });
      const data = await res.json();
      if (data.success) {
        setCreatedApiKey({ key: data.apiKey, agentId: data.agent.id, type: "Root Agent" });
        setShowRegisterModal(false);
        loadData();
      } else {
        alert("Registration failed: " + JSON.stringify(data.error));
      }
    } catch (err: any) {
      alert("Registration error: " + err.message);
    }
  };

  // Delegate Subagent Handler
  const handleDelegateSubagent = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const caps = delegateForm.capabilities
        .split(",")
        .map((c) => c.trim())
        .filter(Boolean);

      const res = await fetch("/api/v1/agents/delegate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          parentAgentId: delegateForm.parentAgentId,
          name: delegateForm.name,
          description: delegateForm.description,
          framework: delegateForm.framework,
          delegatedCapabilities: caps,
          allocatedSpendLimitUsd: Number(delegateForm.spendLimitUsd),
          allocatedRateLimitRpm: Number(delegateForm.rateLimitRpm),
        }),
      });
      const data = await res.json();
      if (data.success) {
        setCreatedApiKey({
          key: data.apiKey,
          agentId: data.childAgent.id,
          type: `Attenuated Subagent (Delegated by ${delegateForm.parentAgentId})`,
        });
        setShowDelegateModal(false);
        loadData();
      } else {
        alert("Subagent delegation rejected: " + data.error);
      }
    } catch (err: any) {
      alert("Error delegating subagent: " + err.message);
    }
  };

  // Trigger Notarization Checkpoint
  const handleCreateCheckpoint = async () => {
    try {
      const res = await fetch("/api/v1/notarize/checkpoint", { method: "POST" });
      const data = await res.json();
      if (data.success) {
        alert(`✅ Checkpoint #${data.checkpoint.sequenceNumber} Notarized!\nTip Hash: ${data.checkpoint.tipEntryHash}\nSignature: ${data.checkpoint.signatureHex.substring(0, 32)}...`);
        loadData();
      } else {
        alert("Notarization failed: " + data.error);
      }
    } catch (err: any) {
      alert("Error creating checkpoint: " + err.message);
    }
  };

  // Trigger Killswitch Handler
  const handleTriggerKillswitch = async () => {
    try {
      const res = await fetch("/api/v1/system/killswitch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          reason: killswitchReason,
          operatorEmail: killswitchEmail,
        }),
      });
      const data = await res.json();
      if (data.success) {
        setKillswitchResult(data.result);
        setShowKillswitchModal(false);
        loadData();
      } else {
        alert("Killswitch execution failed: " + data.error);
      }
    } catch (err: any) {
      alert("Error triggering killswitch: " + err.message);
    }
  };

  // Revoke Agent Handler
  const handleRevokeAgent = async (agentId: string) => {
    const reason = prompt("Enter security reason for permanent revocation:", "Revoked by administrative operator");
    if (!reason) return;
    try {
      const res = await fetch(`/api/v1/agents/${agentId}/revoke`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reason }),
      });
      const data = await res.json();
      if (data.success) {
        loadData();
      } else {
        alert("Revoke failed: " + data.error);
      }
    } catch (err: any) {
      alert("Error revoking agent: " + err.message);
    }
  };

  // Toggle Suspend / Active Status
  const handleToggleStatus = async (agent: Agent) => {
    const nextStatus = agent.status === "ACTIVE" ? "SUSPENDED" : "ACTIVE";
    try {
      const res = await fetch(`/api/v1/agents/${agent.id}/status`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: nextStatus }),
      });
      const data = await res.json();
      if (data.success) {
        loadData();
      } else {
        alert("Status update failed: " + data.error);
      }
    } catch (err: any) {
      alert("Error updating status: " + err.message);
    }
  };

  // Create Policy Handler
  const handleCreatePolicy = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await fetch("/api/v1/policies", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: policyForm.name,
          description: policyForm.description,
          actionPattern: policyForm.actionPattern,
          resourcePattern: policyForm.resourcePattern,
          effect: policyForm.effect,
          maxCostUsd: Number(policyForm.maxCostUsd),
          priority: Number(policyForm.priority),
        }),
      });
      const data = await res.json();
      if (data.success) {
        setShowPolicyModal(false);
        setPolicyForm({
          name: "",
          description: "",
          actionPattern: "",
          resourcePattern: "*",
          effect: "REQUIRE_APPROVAL",
          maxCostUsd: 0,
          priority: 50,
        });
        loadData();
      } else {
        alert("Policy creation failed: " + JSON.stringify(data.error));
      }
    } catch (err: any) {
      alert("Error creating policy: " + err.message);
    }
  };

  // Delete Policy Handler
  const handleDeletePolicy = async (id: string) => {
    if (!confirm("Are you sure you want to delete this policy?")) return;
    try {
      await fetch(`/api/v1/policies/${id}`, { method: "DELETE" });
      loadData();
    } catch (err: any) {
      alert("Error deleting policy: " + err.message);
    }
  };

  // Approval Decision Handler
  const handleDecideApproval = async (id: string, decision: "APPROVE" | "REJECT") => {
    const reason = prompt(
      `Provide reviewer justification to ${decision}:`,
      decision === "APPROVE" ? "Verified legitimate operational request." : "Out of scope or unverified vendor."
    );
    if (!reason) return;

    try {
      const res = await fetch(`/api/v1/approvals/${id}/decide`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          decision,
          reviewerEmail: "sec-admin@enterprise.internal",
          reason,
        }),
      });
      const data = await res.json();
      if (data.success) {
        loadData();
      } else {
        alert("Decision failed: " + data.error);
      }
    } catch (err: any) {
      alert("Error deciding approval: " + err.message);
    }
  };

  // Test Tamper Detection
  const handleTamperTest = async () => {
    if (auditEvents.length === 0) {
      alert("No audit events to tamper with. Run a simulation first!");
      return;
    }
    const targetRow = auditEvents[auditEvents.length - 1].index;
    if (
      !confirm(
        `[SECURITY DRILL] This will purposefully alter audit record #${targetRow} in the database to test cryptographic hash chain tamper detection. Proceed?`
      )
    )
      return;

    try {
      const res = await fetch("/api/v1/audit/tamper-test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          index: targetRow,
          maliciousAction: "malicious:tampered_action_unauthorized",
        }),
      });
      const data = await res.json();
      alert(`Tamper test executed: ${data.message}\nVerification Result: ${JSON.stringify(data.verificationResult)}`);
      loadData();
    } catch (err: any) {
      alert("Error during tamper test: " + err.message);
    }
  };

  // Simulator Scenario Runners
  const runSimulatorScenario = async (
    scenario: "allowed" | "denied" | "destructive" | "approval" | "subagent" | "blastradius"
  ) => {
    setSimulatorRunning(true);
    setSimulatorStepLogs([]);
    const logs: any[] = [];

    const addLog = (step: string, status: "pending" | "success" | "denied" | "warning", detail: string, data?: any) => {
      logs.push({ step, status, detail, data, time: new Date().toLocaleTimeString() });
      setSimulatorStepLogs([...logs]);
    };

    try {
      const activeAgent = agents.find((a) => a.status === "ACTIVE");
      if (!activeAgent) {
        addLog("Agent Check", "warning", "No ACTIVE agent found. Register or unsuspend an agent first.");
        setSimulatorRunning(false);
        return;
      }

      addLog("Agent Identity", "success", `Operating as '${activeAgent.name}' (${activeAgent.id}) [${activeAgent.framework}]`);

      if (scenario === "allowed") {
        addLog("1. Intent", "pending", "Agent attempts: 'read_customer_notes' on customer:101");
        const authzRes = await fetch("/api/v1/authorize", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            apiKey: `at_live_${activeAgent.apiKeyPrefix}`,
            action: "read_customer_notes",
            resource: "customer:101",
          }),
        });
        const authzData = await authzRes.json();
        addLog(
          "2. Pre-Flight Blast Radius",
          "success",
          `Blast Radius Score: ${authzData.blastRadius?.riskScore || "0.05"} (${authzData.blastRadius?.riskTier || "LOW"}). Reversibility: 100%.`
        );
        addLog("3. Policy Evaluation", authzData.allowed ? "success" : "denied", `Decision: ${authzData.decision} — ${authzData.reason}`);

        if (authzData.allowed) {
          addLog("4. Protected Tool Execution", "success", "Side-effect executed inside security boundary.", {
            customerId: "cust_101",
            notes: ["Pricing review requested", "VIP tier activated"],
          });
        }
      } else if (scenario === "blastradius") {
        addLog("1. Intent", "pending", "Agent requests cloud infrastructure deployment targeting 'production:billing_service'");
        const authzRes = await fetch("/api/v1/authorize", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            apiKey: `at_live_${activeAgent.apiKeyPrefix}`,
            action: "deploy_service_version",
            resource: "production:billing_service",
            parameters: { service: "billing-service", version: "v2.5.0" },
            estimatedCostUsd: 120,
          }),
        });
        const authzData = await authzRes.json();
        addLog(
          "2. Pre-Flight Blast Radius",
          "warning",
          `CRITICAL IMPACT: Risk Score ${authzData.blastRadius?.riskScore} (${authzData.blastRadius?.riskTier}). Sensitive target detected.`,
          authzData.blastRadius
        );
        addLog(
          "3. Dynamic Escalation",
          "warning",
          `AUTOMATIC ESCALATION: ${authzData.reason} Action held for human sign-off.`
        );
      } else if (scenario === "subagent") {
        addLog("1. Parent Delegation Intent", "pending", `Parent agent '${activeAgent.name}' attempts to mint subagent with unauthorized admin privileges.`);
        const delegateRes = await fetch("/api/v1/agents/delegate", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            parentAgentId: activeAgent.id,
            name: "Malicious-Privilege-Escalator",
            delegatedCapabilities: ["read_customer_notes", "admin:drop_database"], // Parent lacks this!
            allocatedSpendLimitUsd: 25,
            allocatedRateLimitRpm: 10,
          }),
        });
        const delegateData = await delegateRes.json();
        addLog(
          "2. Attenuation Boundary Check",
          "denied",
          `ATTENUATION DEFENSE TRIGGERED: ${delegateData.error}`
        );
        addLog(
          "3. Security Result",
          "success",
          "Privilege escalation prevented. Child subagents cannot exceed parent capability perimeter."
        );
      } else if (scenario === "denied") {
        addLog("1. Intent", "pending", "Agent attempts out-of-scope action: 'system:drop_kernel'");
        const authzRes = await fetch("/api/v1/authorize", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            apiKey: `at_live_${activeAgent.apiKeyPrefix}`,
            action: "system:drop_kernel",
            resource: "server:root",
          }),
        });
        const authzData = await authzRes.json();
        addLog("2. Policy Boundary", "denied", `STRICTLY DENIED: ${authzData.reason || "Outside assigned capabilities"}`);
        addLog("3. Mock Tool Protection", "success", "PROTECTED: Mock tool was NEVER invoked. Execution failed closed.");
      } else if (scenario === "destructive") {
        addLog("1. Intent", "pending", "Agent attempts destructive action: 'drop_customer_table' on 'database:customers'");
        const authzRes = await fetch("/api/v1/authorize", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            apiKey: `at_live_${activeAgent.apiKeyPrefix}`,
            action: "drop_customer_table",
            resource: "database:customers",
          }),
        });
        const authzData = await authzRes.json();
        addLog("2. Policy Evaluation", "denied", `BLOCKED BY RULE: ${authzData.reason || "Explicit DENY rule triggered"}`);
        addLog("3. Database Safety", "success", "Database destruction prevented. Block logged in immutable ledger.");
      } else if (scenario === "approval") {
        addLog("1. Intent", "pending", "Agent requests high-value financial wire transfer: $450 to Vendor LLC");
        addLog("2. Policy Engine", "warning", "POLICY REQUIREMENT: Action requires human operator sign-off before execution.");
        addLog("3. Approval Queued", "pending", "Approval ticket queued in 'Human Approvals' tab with 5-minute TTL. Go to 'Human Approvals' tab to approve it!");
      }
    } catch (err: any) {
      addLog("Simulation Error", "denied", err.message);
    } finally {
      setSimulatorRunning(false);
      loadData();
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
      {/* Top Header */}
      <header className="border-b border-slate-800 bg-slate-900/90 backdrop-blur sticky top-0 z-40 px-6 py-3.5 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-emerald-500/10 border border-emerald-500/30 rounded-xl text-emerald-400">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="text-lg font-bold tracking-tight text-white">AgentTrust</h1>
              <span className="text-xs bg-emerald-500/20 text-emerald-300 font-mono px-2 py-0.5 rounded-full border border-emerald-500/30">
                Enterprise Zero-Trust Plane
              </span>
            </div>
            <p className="text-xs text-slate-400">Autonomous Identity, Cascading Delegation, HITL Approvals & Verifiable Audit</p>
          </div>
        </div>

        {/* Global Badges & Controls */}
        <div className="flex items-center space-x-3 text-xs font-mono">
          {/* Integrity Badge */}
          <div
            className={`flex items-center space-x-2 px-3 py-1.5 rounded-lg border cursor-pointer transition ${
              integrity?.valid
                ? "bg-emerald-950/40 border-emerald-500/40 text-emerald-300 hover:bg-emerald-900/50"
                : "bg-rose-950/50 border-rose-500 text-rose-300 animate-pulse hover:bg-rose-900/50"
            }`}
            onClick={loadData}
            title="Click to re-verify cryptographic hash chain"
          >
            {integrity?.valid ? (
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
            ) : (
              <ShieldAlert className="w-4 h-4 text-rose-400" />
            )}
            <span>
              {integrity?.valid
                ? `Audit Chain Valid (${integrity.totalRecords} blocks)`
                : `TAMPER DETECTED: Block #${integrity?.brokenAt}`}
            </span>
          </div>

          {/* Pending Approvals */}
          <div
            onClick={() => setActiveTab("approvals")}
            className="flex items-center space-x-1.5 px-3 py-1.5 bg-amber-950/40 border border-amber-500/40 text-amber-300 rounded-lg cursor-pointer hover:bg-amber-900/40 transition"
          >
            <Clock className="w-3.5 h-3.5 text-amber-400" />
            <span>Pending: {pendingApprovals.length}</span>
          </div>

          {/* Emergency Killswitch Button */}
          <button
            onClick={() => setShowKillswitchModal(true)}
            className="flex items-center space-x-1.5 px-3 py-1.5 bg-rose-950/80 hover:bg-rose-900 border border-rose-600 text-rose-200 rounded-lg font-bold transition shadow-lg shadow-rose-950/50"
            title="Emergency Air-Gap Killswitch: Instantly revoke all agents"
          >
            <AlertOctagon className="w-3.5 h-3.5 text-rose-400 animate-pulse" />
            <span>AIR-GAP KILLSWITCH</span>
          </button>

          <button
            onClick={loadData}
            disabled={loading}
            className="p-1.5 text-slate-400 hover:text-white bg-slate-800 rounded-lg border border-slate-700 hover:border-slate-600 transition"
            title="Refresh All Data"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
          </button>
        </div>
      </header>

      {/* Primary Navigation Tabs */}
      <nav className="border-b border-slate-800 bg-slate-900/40 px-6 flex space-x-1 overflow-x-auto">
        {[
          { id: "agents", label: "Agent Registry & Delegation", icon: Users, count: agents.length },
          { id: "policies", label: "Policies & Blast Radius", icon: Sliders, count: policies.length },
          { id: "approvals", label: "Human Approvals (HITL)", icon: Clock, count: pendingApprovals.length },
          { id: "audit", label: "Cryptographic Audit Ledger", icon: FileText, count: auditEvents.length },
          { id: "compliance", label: "EU AI Act & Notarization", icon: Award, count: checkpoints.length },
          { id: "simulator", label: "Interactive Simulator", icon: Play },
          { id: "docs", label: "Threat Model & Docs", icon: HelpCircle },
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`flex items-center space-x-2 py-3 px-4 border-b-2 font-medium text-xs whitespace-nowrap transition ${
                isActive
                  ? "border-emerald-500 text-emerald-400 bg-emerald-500/5"
                  : "border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-700"
              }`}
            >
              <Icon className="w-4 h-4" />
              <span>{tab.label}</span>
              {tab.count !== undefined && (
                <span
                  className={`text-[10px] px-1.5 py-0.2 rounded-full font-mono ${
                    isActive ? "bg-emerald-500/20 text-emerald-300" : "bg-slate-800 text-slate-400"
                  }`}
                >
                  {tab.count}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Main Content Area */}
      <main className="flex-1 p-6 max-w-7xl w-full mx-auto space-y-6">
        {/* Notice Banner */}
        <div className="p-3.5 bg-slate-900/90 border border-slate-800 rounded-xl flex items-center justify-between text-xs text-slate-300">
          <div className="flex items-center space-x-2.5">
            <Lock className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>
              <strong>Zero-Trust Axiom:</strong> Registration establishes identity and boundary rules; it does{" "}
              <span className="text-amber-400 underline decoration-amber-500/40">not</span> confer innate trust.
              Cascading subagent delegation enforces strict capability attenuation.
            </span>
          </div>
          <button
            onClick={() => setActiveTab("simulator")}
            className="flex items-center space-x-1 text-emerald-400 hover:text-emerald-300 font-medium font-mono shrink-0"
          >
            <span>Run Multi-Agent Simulation</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* ========================================================================= */}
        {/* TAB 1: AGENT REGISTRY & DELEGATION */}
        {/* ========================================================================= */}
        {activeTab === "agents" && (
          <div className="space-y-6">
            {/* Top KPI Cards */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl">
                <div className="text-slate-400 text-xs uppercase tracking-wider font-semibold">Total Agents</div>
                <div className="text-2xl font-bold font-mono text-white mt-1">{agents.length}</div>
                <div className="text-[11px] text-slate-500 mt-1">Root orchestrators & delegated subagents</div>
              </div>
              <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl">
                <div className="text-slate-400 text-xs uppercase tracking-wider font-semibold">Active Agents</div>
                <div className="text-2xl font-bold font-mono text-emerald-400 mt-1">
                  {agents.filter((a) => a.status === "ACTIVE").length}
                </div>
                <div className="text-[11px] text-slate-500 mt-1">Operating inside verified scopes</div>
              </div>
              <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl">
                <div className="text-slate-400 text-xs uppercase tracking-wider font-semibold">Revoked Agents</div>
                <div className="text-2xl font-bold font-mono text-rose-400 mt-1">
                  {agents.filter((a) => a.status === "REVOKED").length}
                </div>
                <div className="text-[11px] text-slate-500 mt-1">Permanently revoked credentials</div>
              </div>
              <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl">
                <div className="text-slate-400 text-xs uppercase tracking-wider font-semibold">Notarized Checkpoints</div>
                <div className="text-2xl font-bold font-mono text-cyan-400 mt-1">{checkpoints.length}</div>
                <div className="text-[11px] text-slate-500 mt-1">Signed with ECDSA P-256 certificate</div>
              </div>
            </div>

            {/* Newly Created Key Alert Banner */}
            {createdApiKey && (
              <div className="p-4 bg-emerald-950/60 border border-emerald-500/60 rounded-xl space-y-2">
                <div className="flex items-center space-x-2 text-emerald-300 font-semibold text-sm">
                  <CheckCircle2 className="w-5 h-5" />
                  <span>Credential Generated: {createdApiKey.type}</span>
                </div>
                <p className="text-xs text-slate-300">
                  This raw secret is hashed with SHA-256 at rest and will{" "}
                  <strong className="text-white">never be shown again</strong>.
                </p>
                <div className="flex items-center space-x-2 bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                  <code className="text-xs font-mono text-emerald-400 flex-1 select-all break-all">
                    {createdApiKey.key}
                  </code>
                  <button
                    onClick={() => handleCopy(createdApiKey.key, "new-key")}
                    className="px-3 py-1 bg-emerald-600 hover:bg-emerald-500 text-white rounded text-xs flex items-center space-x-1 shrink-0 transition"
                  >
                    {copiedKey === "new-key" ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedKey === "new-key" ? "Copied" : "Copy Secret"}</span>
                  </button>
                </div>
              </div>
            )}

            {/* Table Header & Actions */}
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-base font-semibold text-white">Agent Directory & Delegation Hierarchy</h2>
                <p className="text-xs text-slate-400">
                  Manage root orchestrators and mint attenuated subagents with capability downscoping.
                </p>
              </div>
              <div className="flex items-center space-x-2">
                <button
                  onClick={() => setShowDelegateModal(true)}
                  className="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-cyan-300 font-medium text-xs rounded-lg flex items-center space-x-2 transition"
                >
                  <GitBranch className="w-4 h-4 text-cyan-400" />
                  <span>Delegate Subagent</span>
                </button>
                <button
                  onClick={() => setShowRegisterModal(true)}
                  className="px-3.5 py-2 bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-xs rounded-lg flex items-center space-x-2 transition shadow-lg shadow-emerald-900/20"
                >
                  <Users className="w-4 h-4" />
                  <span>Register Root Agent</span>
                </button>
              </div>
            </div>

            {/* Agents Table */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-950/60 border-b border-slate-800 text-slate-400 font-mono uppercase text-[10px]">
                    <tr>
                      <th className="py-3 px-4">Agent & Hierarchy</th>
                      <th className="py-3 px-4">Operator</th>
                      <th className="py-3 px-4">Framework</th>
                      <th className="py-3 px-4">Status</th>
                      <th className="py-3 px-4">Scoped Capabilities</th>
                      <th className="py-3 px-4">Rate & Spend Limits</th>
                      <th className="py-3 px-4 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800 text-slate-300">
                    {agents.map((agent) => (
                      <tr key={agent.id} className="hover:bg-slate-800/40 transition">
                        <td className="py-3 px-4">
                          <div className="flex items-center space-x-1.5">
                            <span className="font-semibold text-white text-sm">{agent.name}</span>
                            {agent.name.includes("Delegated") && (
                              <span className="text-[9px] bg-cyan-950 text-cyan-300 font-mono px-1.5 py-0.5 rounded border border-cyan-700">
                                Subagent
                              </span>
                            )}
                          </div>
                          <div className="font-mono text-[11px] text-slate-400 flex items-center space-x-1.5 mt-0.5">
                            <span>{agent.id}</span>
                            <span className="text-slate-600">|</span>
                            <span>Key: {agent.apiKeyPrefix}...</span>
                          </div>
                          {agent.description && (
                            <div className="text-[11px] text-slate-400 mt-1 italic">{agent.description}</div>
                          )}
                        </td>
                        <td className="py-3 px-4 font-mono text-slate-300">{agent.operatorEmail}</td>
                        <td className="py-3 px-4">
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300 border border-slate-700">
                            {agent.framework}
                          </span>
                        </td>
                        <td className="py-3 px-4">
                          <span
                            className={`px-2 py-0.5 rounded-full text-[10px] font-semibold font-mono border ${
                              agent.status === "ACTIVE"
                                ? "bg-emerald-950/60 text-emerald-300 border-emerald-500/40"
                                : agent.status === "SUSPENDED"
                                ? "bg-amber-950/60 text-amber-300 border-amber-500/40"
                                : "bg-rose-950/60 text-rose-300 border-rose-500/40"
                            }`}
                          >
                            {agent.status}
                          </span>
                          {agent.revocationReason && (
                            <div className="text-[10px] text-rose-400 mt-1 max-w-xs break-words">
                              {agent.revocationReason}
                            </div>
                          )}
                        </td>
                        <td className="py-3 px-4">
                          <div className="flex flex-wrap gap-1 max-w-xs">
                            {agent.allowedCapabilities.map((cap, i) => (
                              <span
                                key={i}
                                className="px-1.5 py-0.5 bg-slate-800 text-slate-300 rounded text-[10px] font-mono border border-slate-700"
                              >
                                {cap}
                              </span>
                            ))}
                          </div>
                        </td>
                        <td className="py-3 px-4 font-mono text-[11px]">
                          <div>Rate: {agent.rateLimitRpm} rpm</div>
                          <div className="mt-1">
                            Budget: ${agent.currentSpendUsd.toFixed(2)} / ${agent.spendLimitUsd.toFixed(2)}
                          </div>
                          <div className="w-24 bg-slate-800 h-1.5 rounded-full overflow-hidden mt-1">
                            <div
                              className="bg-emerald-500 h-full rounded-full"
                              style={{
                                width: `${Math.min(100, (agent.currentSpendUsd / (agent.spendLimitUsd || 1)) * 100)}%`,
                              }}
                            />
                          </div>
                        </td>
                        <td className="py-3 px-4 text-right space-x-1.5 whitespace-nowrap">
                          {agent.status !== "REVOKED" ? (
                            <>
                              <button
                                onClick={() => handleToggleStatus(agent)}
                                className={`px-2 py-1 rounded text-[11px] font-mono border transition ${
                                  agent.status === "ACTIVE"
                                    ? "bg-slate-800 border-slate-700 text-amber-300 hover:bg-slate-700"
                                    : "bg-emerald-950 border-emerald-700 text-emerald-300 hover:bg-emerald-900"
                                }`}
                              >
                                {agent.status === "ACTIVE" ? "Suspend" : "Activate"}
                              </button>
                              <button
                                onClick={() => handleRevokeAgent(agent.id)}
                                className="px-2 py-1 bg-rose-950/60 border border-rose-700 hover:bg-rose-900 text-rose-300 rounded text-[11px] font-mono transition"
                              >
                                Revoke
                              </button>
                            </>
                          ) : (
                            <span className="text-[10px] font-mono text-slate-500 italic">Revoked Permanently</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* TAB 2: POLICIES & BLAST RADIUS */}
        {/* ========================================================================= */}
        {activeTab === "policies" && (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-base font-semibold text-white">Authorization Policies & Blast Radius Guardrails</h2>
                <p className="text-xs text-slate-400">
                  Priority-ordered rules combined with pre-flight semantic blast radius analysis.
                </p>
              </div>
              <button
                onClick={() => setShowPolicyModal(true)}
                className="px-3.5 py-2 bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-xs rounded-lg flex items-center space-x-2 transition"
              >
                <Sliders className="w-4 h-4" />
                <span>Create Policy Rule</span>
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {policies.map((pol) => (
                <div
                  key={pol.id}
                  className="bg-slate-900 border border-slate-800 rounded-xl p-4.5 space-y-3 relative group hover:border-slate-700 transition"
                >
                  <div className="flex items-start justify-between">
                    <div>
                      <div className="flex items-center space-x-2">
                        <span className="font-semibold text-white text-sm">{pol.name}</span>
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                          Priority {pol.priority}
                        </span>
                      </div>
                      <p className="text-xs text-slate-400 mt-0.5">{pol.description || "No description provided."}</p>
                    </div>
                    <span
                      className={`px-2.5 py-1 rounded-full text-[10px] font-bold font-mono border ${
                        pol.effect === "ALLOW"
                          ? "bg-emerald-950/70 text-emerald-300 border-emerald-500/40"
                          : pol.effect === "DENY"
                          ? "bg-rose-950/70 text-rose-300 border-rose-500/40"
                          : "bg-amber-950/70 text-amber-300 border-amber-500/40"
                      }`}
                    >
                      {pol.effect}
                    </span>
                  </div>

                  <div className="bg-slate-950/80 p-3 rounded-lg border border-slate-800/80 font-mono text-xs space-y-1.5">
                    <div className="flex items-center justify-between">
                      <span className="text-slate-500">Action Pattern:</span>
                      <span className="text-emerald-400 font-bold">{pol.action_pattern}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-500">Resource Pattern:</span>
                      <span className="text-slate-300">{pol.resource_pattern}</span>
                    </div>
                    {pol.max_cost_usd > 0 && (
                      <div className="flex items-center justify-between">
                        <span className="text-slate-500">Max Auto-Approve Cost:</span>
                        <span className="text-amber-300">${pol.max_cost_usd.toFixed(2)}</span>
                      </div>
                    )}
                  </div>

                  <div className="flex items-center justify-between pt-1 text-[11px] text-slate-500">
                    <span>Target: {pol.agent_id ? `Agent ${pol.agent_id}` : "Global (All Agents)"}</span>
                    <button
                      onClick={() => handleDeletePolicy(pol.id)}
                      className="text-rose-400 hover:text-rose-300 text-xs font-mono transition"
                    >
                      Delete
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* TAB 3: HUMAN APPROVALS (HITL) */}
        {/* ========================================================================= */}
        {activeTab === "approvals" && (
          <div className="space-y-6">
            <div>
              <h2 className="text-base font-semibold text-white">Human-in-the-Loop Review & Decision Console</h2>
              <p className="text-xs text-slate-400">
                Actions with high semantic blast radius or critical policies require human review. Approved tickets
                carry single-use execution nonces with replay protection.
              </p>
            </div>

            {/* Pending Approvals */}
            <div className="space-y-3">
              <h3 className="text-xs font-mono uppercase tracking-wider text-amber-400 font-semibold flex items-center space-x-1.5">
                <Clock className="w-4 h-4" />
                <span>Pending Approvals Awaiting Decision ({pendingApprovals.length})</span>
              </h3>

              {pendingApprovals.length === 0 ? (
                <div className="p-8 text-center bg-slate-900 border border-slate-800 rounded-xl text-slate-400 text-xs">
                  No pending approval requests. Sensitive actions requested by agents will appear here with Slack/Teams alerts.
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {pendingApprovals.map((req) => (
                    <div
                      key={req.id}
                      className="bg-slate-900 border border-amber-500/30 rounded-xl p-5 space-y-4 shadow-lg shadow-amber-950/20"
                    >
                      <div className="flex items-start justify-between">
                        <div>
                          <div className="flex items-center space-x-2">
                            <span className="font-semibold text-white text-sm">{req.action}</span>
                            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-500/40">
                              PENDING
                            </span>
                          </div>
                          <div className="text-xs font-mono text-slate-400 mt-1">
                            Resource: <span className="text-slate-200">{req.resource}</span>
                          </div>
                          <div className="text-[11px] text-slate-500 mt-0.5">Agent: {req.agentId}</div>
                        </div>

                        <div className="text-right font-mono text-xs text-amber-300 bg-amber-950/60 px-2.5 py-1 rounded border border-amber-500/30">
                          Expires in: {req.timeRemainingSeconds}s
                        </div>
                      </div>

                      <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 text-xs font-mono">
                        <div className="text-slate-500 text-[10px] uppercase mb-1">Payload Parameters</div>
                        <pre className="text-slate-300 overflow-x-auto text-[11px]">
                          {JSON.stringify(req.parameters, null, 2)}
                        </pre>
                      </div>

                      {req.estimatedCostUsd > 0 && (
                        <div className="text-xs text-slate-300 font-mono">
                          Financial Impact:{" "}
                          <span className="text-amber-400 font-bold">${req.estimatedCostUsd.toFixed(2)}</span>
                        </div>
                      )}

                      <div className="flex items-center space-x-3 pt-2">
                        <button
                          onClick={() => handleDecideApproval(req.id, "APPROVE")}
                          className="flex-1 py-2 bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs rounded-lg transition shadow-md shadow-emerald-900/30 flex items-center justify-center space-x-1.5"
                        >
                          <CheckCircle2 className="w-4 h-4" />
                          <span>Approve & Issue Ticket</span>
                        </button>
                        <button
                          onClick={() => handleDecideApproval(req.id, "REJECT")}
                          className="flex-1 py-2 bg-rose-950 border border-rose-700 hover:bg-rose-900 text-rose-300 font-semibold text-xs rounded-lg transition flex items-center justify-center space-x-1.5"
                        >
                          <XCircle className="w-4 h-4" />
                          <span>Reject Request</span>
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Approval History */}
            <div className="space-y-3 pt-6 border-t border-slate-800">
              <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 font-semibold">
                Recent Approvals & Ticket Consumption Ledger
              </h3>
              <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-950/60 border-b border-slate-800 text-slate-400 font-mono uppercase text-[10px]">
                    <tr>
                      <th className="py-2.5 px-4">Approval ID</th>
                      <th className="py-2.5 px-4">Agent</th>
                      <th className="py-2.5 px-4">Action & Resource</th>
                      <th className="py-2.5 px-4">Status</th>
                      <th className="py-2.5 px-4">Decided By & Reason</th>
                      <th className="py-2.5 px-4">Ticket State</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800 text-slate-300 font-mono text-[11px]">
                    {allApprovals.map((appr) => (
                      <tr key={appr.id} className="hover:bg-slate-800/40">
                        <td className="py-2.5 px-4 text-slate-400">{appr.id}</td>
                        <td className="py-2.5 px-4">{appr.agentId}</td>
                        <td className="py-2.5 px-4 font-sans font-medium text-white">
                          {appr.action}
                          <div className="text-[10px] font-mono text-slate-400">{appr.resource}</div>
                        </td>
                        <td className="py-2.5 px-4">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                              appr.status === "APPROVED"
                                ? "bg-emerald-950 text-emerald-300 border-emerald-600"
                                : appr.status === "CONSUMED"
                                ? "bg-cyan-950 text-cyan-300 border-cyan-600"
                                : appr.status === "REJECTED"
                                ? "bg-rose-950 text-rose-300 border-rose-600"
                                : appr.status === "EXPIRED"
                                ? "bg-slate-800 text-slate-400 border-slate-700"
                                : "bg-amber-950 text-amber-300 border-amber-600"
                            }`}
                          >
                            {appr.status}
                          </span>
                        </td>
                        <td className="py-2.5 px-4 font-sans text-xs">
                          {appr.decidedBy ? (
                            <div>
                              <span className="font-mono text-[10px] text-slate-400">{appr.decidedBy}</span>
                              <div className="text-slate-300 italic">{appr.decisionReason}</div>
                            </div>
                          ) : (
                            <span className="text-slate-500">—</span>
                          )}
                        </td>
                        <td className="py-2.5 px-4">
                          {appr.status === "CONSUMED" ? (
                            <span className="text-cyan-400 flex items-center space-x-1">
                              <Check className="w-3.5 h-3.5" />
                              <span>Burned (Replay-Protected)</span>
                            </span>
                          ) : appr.status === "APPROVED" ? (
                            <span className="text-emerald-400">Active (Single-Use)</span>
                          ) : (
                            <span className="text-slate-500">—</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* TAB 4: VERIFIABLE AUDIT LEDGER */}
        {/* ========================================================================= */}
        {activeTab === "audit" && (
          <div className="space-y-6">
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <div
                    className={`p-2 rounded-xl border ${
                      integrity?.valid
                        ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-400"
                        : "bg-rose-500/10 border-rose-500/40 text-rose-400"
                    }`}
                  >
                    <ShieldCheck className="w-6 h-6" />
                  </div>
                  <div>
                    <h2 className="text-base font-semibold text-white flex items-center space-x-2">
                      <span>Cryptographic Hash-Linked Audit Ledger</span>
                      <span
                        className={`text-xs px-2.5 py-0.5 rounded-full font-mono font-bold border ${
                          integrity?.valid
                            ? "bg-emerald-950 text-emerald-300 border-emerald-500/40"
                            : "bg-rose-950 text-rose-300 border-rose-500"
                        }`}
                      >
                        {integrity?.valid ? "CHAIN_VERIFIED_INTACT" : "CHAIN_TAMPERED"}
                      </span>
                    </h2>
                    <p className="text-xs text-slate-400 mt-0.5">
                      Sequential SHA-256 backward hash chaining. Any retroactive modification breaks verification instantly.
                    </p>
                  </div>
                </div>

                <div className="flex items-center space-x-3">
                  <button
                    onClick={handleTamperTest}
                    className="px-3.5 py-2 bg-rose-950/70 hover:bg-rose-900 border border-rose-700/80 text-rose-300 text-xs font-mono font-medium rounded-lg flex items-center space-x-1.5 transition"
                    title="Purposefully alter a record in SQLite to prove tamper detection"
                  >
                    <Flame className="w-3.5 h-3.5 text-rose-400" />
                    <span>Run Tamper Drill</span>
                  </button>
                  <button
                    onClick={loadData}
                    className="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-white text-xs font-mono rounded-lg flex items-center space-x-1.5 transition"
                  >
                    <RefreshCw className="w-3.5 h-3.5" />
                    <span>Re-verify Chain</span>
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2 text-xs font-mono border-t border-slate-800/80">
                <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                  <span className="text-slate-500">Chain Tip SHA-256 Hash:</span>
                  <div className="text-emerald-400 truncate mt-0.5 select-all">{integrity?.latestHash || "N/A"}</div>
                </div>
                <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                  <span className="text-slate-500">Validated Sequential Blocks:</span>
                  <div className="text-white font-bold mt-0.5">
                    {integrity?.totalRecords} blocks without gaps or deletions
                  </div>
                </div>
              </div>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-950/60 border-b border-slate-800 text-slate-400 font-mono uppercase text-[10px]">
                    <tr>
                      <th className="py-2.5 px-3"># Index</th>
                      <th className="py-2.5 px-3">Time</th>
                      <th className="py-2.5 px-3">Event Type</th>
                      <th className="py-2.5 px-3">Agent</th>
                      <th className="py-2.5 px-3">Action & Resource</th>
                      <th className="py-2.5 px-3">Decision</th>
                      <th className="py-2.5 px-3">prev_hash ➔ entry_hash</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800 text-slate-300 font-mono text-[11px]">
                    {auditEvents.map((evt) => (
                      <tr key={evt.index} className="hover:bg-slate-800/40">
                        <td className="py-2.5 px-3 text-slate-400 font-bold">#{evt.index}</td>
                        <td className="py-2.5 px-3 text-slate-400 whitespace-nowrap">
                          {new Date(evt.timestamp).toLocaleTimeString()}
                        </td>
                        <td className="py-2.5 px-3">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                              evt.eventType === "REGISTRATION" || evt.eventType === "DELEGATION_MINT"
                                ? "bg-purple-950 text-purple-300 border-purple-700"
                                : evt.eventType === "REVOCATION" || evt.eventType === "KILLSWITCH_TRIGGERED"
                                ? "bg-rose-950 text-rose-300 border-rose-700 animate-pulse"
                                : evt.eventType === "REPLAY_ATTEMPT"
                                ? "bg-red-950 text-red-300 border-red-500 animate-pulse"
                                : evt.eventType === "TOOL_EXECUTION"
                                ? "bg-cyan-950 text-cyan-300 border-cyan-700"
                                : "bg-slate-800 text-slate-300 border-slate-700"
                            }`}
                          >
                            {evt.eventType}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-slate-400 truncate max-w-[120px]">{evt.agentId}</td>
                        <td className="py-2.5 px-3 font-sans">
                          <div className="font-semibold text-white text-xs">{evt.action}</div>
                          <div className="text-[10px] font-mono text-slate-400">{evt.resource}</div>
                        </td>
                        <td className="py-2.5 px-3">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                              evt.decision === "ALLOW" || evt.decision === "EXECUTED" || evt.decision === "APPROVED"
                                ? "bg-emerald-950 text-emerald-300 border-emerald-600"
                                : evt.decision === "DENY" || evt.decision === "BLOCKED" || evt.decision === "REVOKED"
                                ? "bg-rose-950 text-rose-300 border-rose-600"
                                : "bg-amber-950 text-amber-300 border-amber-600"
                            }`}
                          >
                            {evt.decision}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-[10px] space-y-0.5">
                          <div className="text-slate-500 truncate max-w-[180px]">
                            <span className="text-slate-600">prev:</span> {evt.prevHash.substring(0, 16)}...
                          </div>
                          <div className="text-emerald-400 truncate max-w-[180px]">
                            <span className="text-slate-600">hash:</span> {evt.entryHash.substring(0, 16)}...
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* TAB 5: COMPLIANCE & NOTARIZATION */}
        {/* ========================================================================= */}
        {activeTab === "compliance" && (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-base font-semibold text-white">EU AI Act & NIST AI RMF Compliance Audit Dashboard</h2>
                <p className="text-xs text-slate-400">
                  Continuous evaluation against EU AI Act Article 14 (Human Oversight), Article 12 (Traceability), and ECDSA P-256 Notarization.
                </p>
              </div>
              <button
                onClick={handleCreateCheckpoint}
                className="px-3.5 py-2 bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-xs rounded-lg flex items-center space-x-2 transition shadow-lg shadow-cyan-900/30"
              >
                <FileCheck2 className="w-4 h-4" />
                <span>Mint Notarized Checkpoint</span>
              </button>
            </div>

            {/* Compliance Scores Grid */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="bg-slate-900 border border-emerald-500/30 rounded-xl p-5 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono uppercase text-slate-400 font-semibold">EU AI Act (Art. 14)</span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-500/40">
                    {compliance?.frameworks.euAiAct.status || "COMPLIANT"}
                  </span>
                </div>
                <div className="text-2xl font-bold font-mono text-emerald-400">
                  {compliance?.frameworks.euAiAct.article14HumanOversight.complianceScore || 100}%
                </div>
                <p className="text-xs text-slate-300">Human Oversight & Replay Protection Verified.</p>
                <div className="text-[11px] font-mono text-slate-400 space-y-1 pt-1 border-t border-slate-800">
                  <div>Reviewed HITL Actions: {compliance?.frameworks.euAiAct.article14HumanOversight.totalHITLApprovals || 0}</div>
                  <div>Replay Attempts Blocked: {compliance?.frameworks.euAiAct.article14HumanOversight.replayBlockedCount || 0}</div>
                </div>
              </div>

              <div className="bg-slate-900 border border-emerald-500/30 rounded-xl p-5 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono uppercase text-slate-400 font-semibold">EU AI Act (Art. 12)</span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-500/40">
                    {compliance?.frameworks.euAiAct.status || "COMPLIANT"}
                  </span>
                </div>
                <div className="text-2xl font-bold font-mono text-emerald-400">
                  {compliance?.frameworks.euAiAct.article12Traceability.tamperResistanceScore || 100}%
                </div>
                <p className="text-xs text-slate-300">Continuous Append-Only Hash Chain Integrity.</p>
                <div className="text-[11px] font-mono text-slate-400 space-y-1 pt-1 border-t border-slate-800">
                  <div>Sequential Records: {compliance?.frameworks.euAiAct.article12Traceability.totalAuditEvents || 0}</div>
                  <div>Signed Checkpoints: {compliance?.frameworks.euAiAct.article12Traceability.notarizedCheckpointsCount || 0}</div>
                </div>
              </div>

              <div className="bg-slate-900 border border-emerald-500/30 rounded-xl p-5 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono uppercase text-slate-400 font-semibold">NIST AI RMF 1.0</span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-500/40">
                    GOVERN & MANAGE
                  </span>
                </div>
                <div className="text-2xl font-bold font-mono text-cyan-400">96.5%</div>
                <p className="text-xs text-slate-300">Pre-flight Blast Radius & Killswitch Active.</p>
                <div className="text-[11px] font-mono text-slate-400 space-y-1 pt-1 border-t border-slate-800">
                  <div>Govern Score: {compliance?.frameworks.nistAiRmf.governScore || 98}%</div>
                  <div>Manage Score: {compliance?.frameworks.nistAiRmf.manageScore || 96}%</div>
                </div>
              </div>
            </div>

            {/* Signed Checkpoints Ledger */}
            <div className="space-y-3 pt-2">
              <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 font-semibold flex items-center space-x-1.5">
                <FileCheck2 className="w-4 h-4 text-cyan-400" />
                <span>ECDSA P-256 Notarized Checkpoint Certificates ({checkpoints.length})</span>
              </h3>

              {checkpoints.length === 0 ? (
                <div className="p-8 text-center bg-slate-900 border border-slate-800 rounded-xl text-slate-400 text-xs">
                  No notarized checkpoints minted yet. Click "Mint Notarized Checkpoint" to sign the current ledger tip!
                </div>
              ) : (
                <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-slate-950/60 border-b border-slate-800 text-slate-400 font-mono uppercase text-[10px]">
                      <tr>
                        <th className="py-2.5 px-4">Seq #</th>
                        <th className="py-2.5 px-4">Checkpoint ID</th>
                        <th className="py-2.5 px-4">Timestamp</th>
                        <th className="py-2.5 px-4">Notarized Tip Hash</th>
                        <th className="py-2.5 px-4">Records Covered</th>
                        <th className="py-2.5 px-4">Signature Digest</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800 text-slate-300 font-mono text-[11px]">
                      {checkpoints.map((c) => (
                        <tr key={c.id} className="hover:bg-slate-800/40">
                          <td className="py-2.5 px-4 font-bold text-cyan-400">#{c.sequence_number}</td>
                          <td className="py-2.5 px-4 text-slate-300">{c.id}</td>
                          <td className="py-2.5 px-4 text-slate-400">{new Date(c.timestamp).toLocaleString()}</td>
                          <td className="py-2.5 px-4 text-emerald-400 truncate max-w-[150px]">{c.tip_hash}</td>
                          <td className="py-2.5 px-4 text-white font-bold">{c.total_records} blocks</td>
                          <td className="py-2.5 px-4 text-slate-400 truncate max-w-[180px]">
                            {c.signature_hex.substring(0, 24)}...
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* TAB 6: INTERACTIVE SIMULATOR */}
        {/* ========================================================================= */}
        {activeTab === "simulator" && (
          <div className="space-y-6">
            <div>
              <h2 className="text-base font-semibold text-white">Live Multi-Agent Security & Attack Simulator</h2>
              <p className="text-xs text-slate-400">
                Trigger autonomous agent workflows, cascading subagent delegation violations, high blast radius escalations, and emergency killswitch drills.
              </p>
            </div>

            {/* Scenario Buttons */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <button
                onClick={() => runSimulatorScenario("allowed")}
                disabled={simulatorRunning}
                className="p-4 bg-slate-900 border border-slate-800 hover:border-emerald-500/50 rounded-xl text-left transition space-y-2 group"
              >
                <div className="flex items-center space-x-2 text-emerald-400 font-semibold text-xs">
                  <CheckCircle2 className="w-4 h-4" />
                  <span>1. Low-Risk Query (Auto-Allow)</span>
                </div>
                <p className="text-[11px] text-slate-400">
                  Read-only CRM query. Evaluates blast radius (LOW), verifies capability, executes protected mock tool.
                </p>
              </button>

              <button
                onClick={() => runSimulatorScenario("blastradius")}
                disabled={simulatorRunning}
                className="p-4 bg-slate-900 border border-slate-800 hover:border-amber-500/50 rounded-xl text-left transition space-y-2 group"
              >
                <div className="flex items-center space-x-2 text-amber-400 font-semibold text-xs">
                  <AlertTriangle className="w-4 h-4" />
                  <span>2. Blast Radius Auto-Escalation</span>
                </div>
                <p className="text-[11px] text-slate-400">
                  Agent deploys production billing service. Semantic analyzer flags CRITICAL risk and forces Human Sign-off.
                </p>
              </button>

              <button
                onClick={() => runSimulatorScenario("subagent")}
                disabled={simulatorRunning}
                className="p-4 bg-slate-900 border border-slate-800 hover:border-purple-500/50 rounded-xl text-left transition space-y-2 group"
              >
                <div className="flex items-center space-x-2 text-purple-400 font-semibold text-xs">
                  <GitBranch className="w-4 h-4" />
                  <span>3. Subagent Attenuation Defense</span>
                </div>
                <p className="text-[11px] text-slate-400">
                  Parent attempts to delegate out-of-scope admin privilege to worker. Blocked by Attenuation Boundary Check.
                </p>
              </button>

              <button
                onClick={() => runSimulatorScenario("denied")}
                disabled={simulatorRunning}
                className="p-4 bg-slate-900 border border-slate-800 hover:border-rose-500/50 rounded-xl text-left transition space-y-2 group"
              >
                <div className="flex items-center space-x-2 text-rose-400 font-semibold text-xs">
                  <XCircle className="w-4 h-4" />
                  <span>4. Capability Boundary Violation</span>
                </div>
                <p className="text-[11px] text-slate-400">
                  Agent attempts action outside declared capabilities. Strictly denied; tool execution gateway is never reached.
                </p>
              </button>

              <button
                onClick={() => runSimulatorScenario("destructive")}
                disabled={simulatorRunning}
                className="p-4 bg-slate-900 border border-slate-800 hover:border-rose-500/50 rounded-xl text-left transition space-y-2 group"
              >
                <div className="flex items-center space-x-2 text-rose-400 font-semibold text-xs">
                  <ShieldAlert className="w-4 h-4" />
                  <span>5. Forbidden Destructive Action</span>
                </div>
                <p className="text-[11px] text-slate-400">
                  Agent attempts table drop. Strictly blocked by high-priority DENY rule. Tool is never touched.
                </p>
              </button>

              <button
                onClick={() => runSimulatorScenario("approval")}
                disabled={simulatorRunning}
                className="p-4 bg-slate-900 border border-slate-800 hover:border-amber-500/50 rounded-xl text-left transition space-y-2 group"
              >
                <div className="flex items-center space-x-2 text-amber-400 font-semibold text-xs">
                  <Clock className="w-4 h-4" />
                  <span>6. Sensitive Wire Transfer (HITL)</span>
                </div>
                <p className="text-[11px] text-slate-400">
                  High-value funds transfer ($450). Transitions to Human Approval with TTL and single-use execution ticket.
                </p>
              </button>
            </div>

            {/* Trace Pipeline */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-mono uppercase tracking-wider text-slate-300 font-semibold flex items-center space-x-2">
                  <Terminal className="w-4 h-4 text-emerald-400" />
                  <span>Security Gateway Execution Trace</span>
                </h3>
                {simulatorRunning && (
                  <span className="text-xs font-mono text-emerald-400 animate-pulse flex items-center space-x-1.5">
                    <Activity className="w-3.5 h-3.5" />
                    <span>Evaluating Gateway...</span>
                  </span>
                )}
              </div>

              {simulatorStepLogs.length === 0 ? (
                <div className="p-8 text-center text-slate-500 text-xs border border-dashed border-slate-800 rounded-lg">
                  Click any scenario above to observe real-time policy evaluation, blast radius checks, and tool boundary enforcement.
                </div>
              ) : (
                <div className="space-y-3 font-mono text-xs">
                  {simulatorStepLogs.map((log, i) => (
                    <div
                      key={i}
                      className={`p-3 rounded-lg border flex items-start space-x-3 ${
                        log.status === "success"
                          ? "bg-emerald-950/40 border-emerald-500/30 text-emerald-200"
                          : log.status === "denied"
                          ? "bg-rose-950/40 border-rose-500/30 text-rose-200"
                          : log.status === "warning"
                          ? "bg-amber-950/40 border-amber-500/30 text-amber-200"
                          : "bg-slate-950 border-slate-800 text-slate-300"
                      }`}
                    >
                      <div className="mt-0.5">
                        {log.status === "success" ? (
                          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                        ) : log.status === "denied" ? (
                          <XCircle className="w-4 h-4 text-rose-400" />
                        ) : (
                          <Clock className="w-4 h-4 text-amber-400" />
                        )}
                      </div>
                      <div className="flex-1 space-y-1">
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-white">{log.step}</span>
                          <span className="text-[10px] text-slate-500">{log.time}</span>
                        </div>
                        <p className="text-xs">{log.detail}</p>
                        {log.data && (
                          <pre className="bg-slate-950/90 p-2 rounded border border-slate-800 text-[11px] text-slate-300 overflow-x-auto mt-1">
                            {JSON.stringify(log.data, null, 2)}
                          </pre>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* TAB 7: THREAT MODEL & DOCS */}
        {/* ========================================================================= */}
        {activeTab === "docs" && (
          <div className="space-y-6 text-xs text-slate-300">
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
              <h2 className="text-base font-bold text-white flex items-center space-x-2">
                <Shield className="w-5 h-5 text-emerald-400" />
                <span>Enterprise Threat Model & Security Boundaries</span>
              </h2>
              <p className="text-slate-400 leading-relaxed">
                AgentTrust operates on zero-trust principles. Registering an agent assigns an identity and boundary
                enforcement rules; it does not confer innate trust.
              </p>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
                <div className="bg-slate-950 p-4 rounded-xl border border-emerald-500/30 space-y-2">
                  <div className="font-semibold text-emerald-400 text-sm flex items-center space-x-1.5">
                    <CheckCircle2 className="w-4 h-4" />
                    <span>Enterprise Security Guarantees</span>
                  </div>
                  <ul className="list-disc list-inside space-y-1 text-slate-300 text-[11px]">
                    <li>Deny-by-default authorization on every tool call</li>
                    <li>Cascading subagent delegation with strict capability attenuation</li>
                    <li>Pre-flight semantic blast radius & reversibility evaluation</li>
                    <li>Single-use execution nonces with atomic replay defense</li>
                    <li>ECDSA P-256 digital signature checkpoint notarization</li>
                    <li>Instant global air-gap killswitch (&lt; 15ms execution)</li>
                  </ul>
                </div>

                <div className="bg-slate-950 p-4 rounded-xl border border-rose-500/30 space-y-2">
                  <div className="font-semibold text-rose-400 text-sm flex items-center space-x-1.5">
                    <AlertTriangle className="w-4 h-4" />
                    <span>Explicit Boundaries (What MVP Does NOT Protect Against)</span>
                  </div>
                  <ul className="list-disc list-inside space-y-1 text-slate-300 text-[11px]">
                    <li>Direct root access disk tampering (addressed via remote ECDSA notarization)</li>
                    <li>Client-side bypass if agent makes raw HTTP calls without SDK/sidecar</li>
                    <li>Prompt injection inside LLM reasoning tokens (gateway guards tool boundary)</li>
                  </ul>
                </div>
              </div>
            </div>

            {/* SDK Code Snippet */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-3">
              <h3 className="text-sm font-semibold text-white">Client SDK Integration Example</h3>
              <p className="text-slate-400 text-xs">
                Integrate with any AI framework (LangChain, CrewAI, AutoGen, or custom tools):
              </p>
              <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 font-mono text-xs overflow-x-auto text-emerald-300">
                <pre>{`import { AgentTrustClient } from "@agenttrust/sdk";

const client = new AgentTrustClient({
  baseUrl: "http://localhost:4000",
  apiKey: process.env.AGENT_TRUST_API_KEY!,
});

// Guardrail protected tool invocation:
const result = await client.executeProtectedTool({
  toolName: "send_wire_transfer",
  action: "send_wire_transfer",
  resource: "accounts:vendor_invoice",
  parameters: { amount: 250, recipient: "Acme Corp" },
  autoPollApproval: true, // waits for human operator if approval required
});`}</pre>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* Modal: Register Root Agent */}
      {showRegisterModal && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-lg w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="font-bold text-white text-base">Register Root Orchestrator Agent</h3>
              <button onClick={() => setShowRegisterModal(false)} className="text-slate-400 hover:text-white transition">
                ✕
              </button>
            </div>

            <form onSubmit={handleRegisterAgent} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Agent Name *</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Master-Treasury-Orchestrator"
                  value={regForm.name}
                  onChange={(e) => setRegForm({ ...regForm, name: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-white focus:outline-none focus:border-emerald-500 font-sans"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Operator Email *</label>
                <input
                  type="email"
                  required
                  placeholder="e.g. sec-ops@enterprise.com"
                  value={regForm.operatorEmail}
                  onChange={(e) => setRegForm({ ...regForm, operatorEmail: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-white focus:outline-none focus:border-emerald-500 font-sans"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Framework</label>
                  <select
                    value={regForm.framework}
                    onChange={(e) => setRegForm({ ...regForm, framework: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-white focus:outline-none focus:border-emerald-500 font-sans"
                  >
                    <option value="LangChain">LangChain</option>
                    <option value="CrewAI">CrewAI</option>
                    <option value="AutoGen">AutoGen</option>
                    <option value="Custom">Custom Agent Runtime</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-400 mb-1">Rate Limit (rpm)</label>
                  <input
                    type="number"
                    value={regForm.rateLimitRpm}
                    onChange={(e) => setRegForm({ ...regForm, rateLimitRpm: Number(e.target.value) })}
                    className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-white focus:outline-none focus:border-emerald-500 font-mono"
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Spend Budget Ceiling ($ USD)</label>
                <input
                  type="number"
                  value={regForm.spendLimitUsd}
                  onChange={(e) => setRegForm({ ...regForm, spendLimitUsd: Number(e.target.value) })}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-white focus:outline-none focus:border-emerald-500 font-mono"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Allowed Capabilities (Comma-separated) *</label>
                <textarea
                  rows={2}
                  required
                  placeholder="read_customer_notes, search_documentation, send_wire_transfer"
                  value={regForm.capabilities}
                  onChange={(e) => setRegForm({ ...regForm, capabilities: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-white focus:outline-none focus:border-emerald-500 font-mono text-xs"
                />
              </div>

              <div className="flex items-center justify-end space-x-2 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowRegisterModal(false)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white font-semibold rounded text-xs transition"
                >
                  Register & Generate Key
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: Delegate Subagent */}
      {showDelegateModal && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-lg w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2">
                <GitBranch className="w-5 h-5 text-cyan-400" />
                <h3 className="font-bold text-white text-base">Delegate Attenuated Subagent</h3>
              </div>
              <button onClick={() => setShowDelegateModal(false)} className="text-slate-400 hover:text-white transition">
                ✕
              </button>
            </div>

            <form onSubmit={handleDelegateSubagent} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Parent Agent *</label>
                <select
                  required
                  value={delegateForm.parentAgentId}
                  onChange={(e) => setDelegateForm({ ...delegateForm, parentAgentId: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-white focus:outline-none focus:border-cyan-500 font-sans"
                >
                  <option value="">Select Parent Orchestrator</option>
                  {agents
                    .filter((a) => a.status === "ACTIVE")
                    .map((a) => (
                      <option key={a.id} value={a.id}>
                        {a.name} ({a.id}) - Remaining: ${(a.spendLimitUsd - a.currentSpendUsd).toFixed(2)}
                      </option>
                    ))}
                </select>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Subagent Name *</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Research-Worker-Bot"
                  value={delegateForm.name}
                  onChange={(e) => setDelegateForm({ ...delegateForm, name: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-white focus:outline-none focus:border-cyan-500 font-sans"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Subagent Rate Limit (rpm)</label>
                  <input
                    type="number"
                    value={delegateForm.rateLimitRpm}
                    onChange={(e) => setDelegateForm({ ...delegateForm, rateLimitRpm: Number(e.target.value) })}
                    className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-white focus:outline-none focus:border-cyan-500 font-mono"
                  />
                </div>

                <div>
                  <label className="block text-slate-400 mb-1">Subagent Budget ($ USD)</label>
                  <input
                    type="number"
                    value={delegateForm.spendLimitUsd}
                    onChange={(e) => setDelegateForm({ ...delegateForm, spendLimitUsd: Number(e.target.value) })}
                    className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-white focus:outline-none focus:border-cyan-500 font-mono"
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Delegated Capabilities (Must be subset of parent) *</label>
                <input
                  type="text"
                  required
                  placeholder="read_customer_notes, search_documentation"
                  value={delegateForm.capabilities}
                  onChange={(e) => setDelegateForm({ ...delegateForm, capabilities: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-white focus:outline-none focus:border-cyan-500 font-mono"
                />
                <p className="text-[10px] text-slate-500 mt-1">
                  Enforces strict capability attenuation. Attempting to grant out-of-scope permissions will fail.
                </p>
              </div>

              <div className="flex items-center justify-end space-x-2 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowDelegateModal(false)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white font-semibold rounded text-xs transition"
                >
                  Mint Attenuated Subagent
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: Create Policy */}
      {showPolicyModal && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-lg w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="font-bold text-white text-base">Create Policy Rule</h3>
              <button onClick={() => setShowPolicyModal(false)} className="text-slate-400 hover:text-white transition">
                ✕
              </button>
            </div>

            <form onSubmit={handleCreatePolicy} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Policy Name *</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Require Approval For Large Payments"
                  value={policyForm.name}
                  onChange={(e) => setPolicyForm({ ...policyForm, name: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-white focus:outline-none focus:border-emerald-500 font-sans"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Action Pattern *</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. send_wire_transfer or data:*"
                    value={policyForm.actionPattern}
                    onChange={(e) => setPolicyForm({ ...policyForm, actionPattern: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-white focus:outline-none focus:border-emerald-500 font-mono"
                  />
                </div>

                <div>
                  <label className="block text-slate-400 mb-1">Resource Pattern *</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. accounts:* or *"
                    value={policyForm.resourcePattern}
                    onChange={(e) => setPolicyForm({ ...policyForm, resourcePattern: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-white focus:outline-none focus:border-emerald-500 font-mono"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Policy Effect *</label>
                  <select
                    value={policyForm.effect}
                    onChange={(e) => setPolicyForm({ ...policyForm, effect: e.target.value as any })}
                    className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-white focus:outline-none focus:border-emerald-500 font-sans"
                  >
                    <option value="REQUIRE_APPROVAL">REQUIRE_APPROVAL (HITL)</option>
                    <option value="ALLOW">ALLOW</option>
                    <option value="DENY">DENY (Highest Priority)</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-400 mb-1">Priority (1-999)</label>
                  <input
                    type="number"
                    value={policyForm.priority}
                    onChange={(e) => setPolicyForm({ ...policyForm, priority: Number(e.target.value) })}
                    className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-white focus:outline-none focus:border-emerald-500 font-mono"
                  />
                </div>
              </div>

              <div className="flex items-center justify-end space-x-2 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowPolicyModal(false)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white font-semibold rounded text-xs transition"
                >
                  Save Policy
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: Emergency Killswitch */}
      {showKillswitchModal && (
        <div className="fixed inset-0 bg-rose-950/80 backdrop-blur-md z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border-2 border-rose-600 rounded-2xl max-w-lg w-full p-6 space-y-4 shadow-2xl shadow-rose-950/80">
            <div className="flex items-center space-x-3 text-rose-400 border-b border-slate-800 pb-3">
              <AlertOctagon className="w-7 h-7 shrink-0 animate-bounce" />
              <div>
                <h3 className="font-bold text-white text-base">EMERGENCY AIR-GAP GLOBAL KILLSWITCH</h3>
                <p className="text-xs text-rose-300">Irrevocable containment action</p>
              </div>
            </div>

            <div className="p-3 bg-rose-950/40 border border-rose-700/60 rounded-lg text-xs text-rose-200 space-y-1">
              <p className="font-bold">Execution Consequences:</p>
              <ul className="list-disc list-inside text-[11px] space-y-0.5">
                <li>Instantly permanently revokes credentials for all agents in &lt; 15ms.</li>
                <li>Burns and cancels all pending human execution tickets.</li>
                <li>Severs all autonomous tool execution pathways.</li>
                <li>Generates an immutable ECDSA-signed forensic audit checkpoint.</li>
              </ul>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-300 mb-1">Operator Email *</label>
                <input
                  type="email"
                  value={killswitchEmail}
                  onChange={(e) => setKillswitchEmail(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-white focus:outline-none focus:border-rose-500 font-mono"
                />
              </div>

              <div>
                <label className="block text-slate-300 mb-1">Incident Justification *</label>
                <textarea
                  rows={2}
                  value={killswitchReason}
                  onChange={(e) => setKillswitchReason(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-white focus:outline-none focus:border-rose-500 font-sans"
                />
              </div>
            </div>

            <div className="flex items-center justify-end space-x-2 pt-3 border-t border-slate-800">
              <button
                onClick={() => setShowKillswitchModal(false)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs transition"
              >
                Cancel
              </button>
              <button
                onClick={handleTriggerKillswitch}
                className="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white font-bold rounded text-xs transition shadow-lg shadow-rose-950"
              >
                EXECUTE EMERGENCY KILLSWITCH
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
