import Database from "better-sqlite3";
import crypto from "node:crypto";
import { generateApiKey, verifyApiKey } from "../crypto.js";
import { AuditLedgerService } from "./audit.js";

export interface RegisterAgentInput {
  name: string;
  description?: string;
  operatorEmail: string;
  framework?: string;
  allowedCapabilities: string[];
  rateLimitRpm?: number;
  spendLimitUsd?: number;
}

export interface AgentRow {
  id: string;
  name: string;
  description: string;
  operator_email: string;
  framework: string;
  status: "ACTIVE" | "SUSPENDED" | "REVOKED";
  api_key_hash: string;
  api_key_prefix: string;
  allowed_capabilities: string; // JSON string
  rate_limit_rpm: number;
  spend_limit_usd: number;
  current_spend_usd: number;
  created_at: number;
  updated_at: number;
  revoked_at: number | null;
  revocation_reason: string | null;
}

export class AgentRegistryService {
  constructor(
    private db: Database.Database,
    private auditService: AuditLedgerService
  ) {}

  registerAgent(input: RegisterAgentInput): { agent: AgentRow; apiKey: string } {
    const id = `ag_${crypto.randomBytes(8).toString("hex")}`;
    const now = Date.now();
    const { apiKey, prefix, hash } = generateApiKey();

    const capabilitiesJson = JSON.stringify(input.allowedCapabilities || []);

    this.db
      .prepare(`
        INSERT INTO agents (
          id, name, description, operator_email, framework,
          status, api_key_hash, api_key_prefix, allowed_capabilities,
          rate_limit_rpm, spend_limit_usd, current_spend_usd,
          created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, 'ACTIVE', ?, ?, ?, ?, ?, 0.0, ?, ?)
      `)
      .run(
        id,
        input.name,
        input.description || "",
        input.operatorEmail,
        input.framework || "Custom",
        hash,
        prefix,
        capabilitiesJson,
        input.rateLimitRpm ?? 60,
        input.spendLimitUsd ?? 50.0,
        now,
        now
      );

    const agent = this.getAgentById(id)!;

    // Record registration in audit ledger
    this.auditService.append({
      agentId: id,
      eventType: "REGISTRATION",
      action: "agent:register",
      resource: `agent:${id}`,
      decision: "ALLOW",
      payload: {
        agentId: id,
        name: agent.name,
        operatorEmail: agent.operator_email,
        framework: agent.framework,
        allowedCapabilities: input.allowedCapabilities,
        rateLimitRpm: agent.rate_limit_rpm,
        spendLimitUsd: agent.spend_limit_usd,
      },
    });

    return { agent, apiKey };
  }

  getAgentById(id: string): AgentRow | null {
    const row = this.db.prepare("SELECT * FROM agents WHERE id = ?").get(id) as AgentRow | undefined;
    return row || null;
  }

  listAgents(): AgentRow[] {
    return this.db.prepare("SELECT * FROM agents ORDER BY created_at DESC").all() as AgentRow[];
  }

  authenticate(apiKey: string): AgentRow | null {
    if (!apiKey || !apiKey.startsWith("at_live_")) {
      return null;
    }
    const prefix = apiKey.substring(0, 15);
    const candidates = this.db
      .prepare("SELECT * FROM agents WHERE api_key_prefix = ?")
      .all(prefix) as AgentRow[];

    for (const agent of candidates) {
      if (verifyApiKey(apiKey, agent.api_key_hash)) {
        return agent;
      }
    }
    return null;
  }

  revokeAgent(id: string, reason: string): AgentRow {
    const agent = this.getAgentById(id);
    if (!agent) {
      throw new Error(`Agent ${id} not found.`);
    }

    const now = Date.now();
    this.db
      .prepare(`
        UPDATE agents 
        SET status = 'REVOKED', revoked_at = ?, revocation_reason = ?, updated_at = ?
        WHERE id = ?
      `)
      .run(now, reason, now, id);

    this.auditService.append({
      agentId: id,
      eventType: "REVOCATION",
      action: "agent:revoke",
      resource: `agent:${id}`,
      decision: "REVOKED",
      payload: {
        agentId: id,
        previousStatus: agent.status,
        revocationReason: reason,
        revokedAt: now,
      },
    });

    return this.getAgentById(id)!;
  }

  updateStatus(id: string, status: "ACTIVE" | "SUSPENDED"): AgentRow {
    const agent = this.getAgentById(id);
    if (!agent) {
      throw new Error(`Agent ${id} not found.`);
    }
    if (agent.status === "REVOKED") {
      throw new Error("Cannot change status of a permanently revoked agent.");
    }

    const now = Date.now();
    this.db
      .prepare("UPDATE agents SET status = ?, updated_at = ? WHERE id = ?")
      .run(status, now, id);

    this.auditService.append({
      agentId: id,
      eventType: "STATUS_CHANGE",
      action: `agent:${status.toLowerCase()}`,
      resource: `agent:${id}`,
      decision: status,
      payload: { agentId: id, oldStatus: agent.status, newStatus: status },
    });

    return this.getAgentById(id)!;
  }

  recordSpend(agentId: string, amountUsd: number): void {
    if (amountUsd <= 0) return;
    this.db
      .prepare("UPDATE agents SET current_spend_usd = current_spend_usd + ?, updated_at = ? WHERE id = ?")
      .run(amountUsd, Date.now(), agentId);
  }
}
