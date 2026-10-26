import Database from "better-sqlite3";
import crypto from "node:crypto";
import { AgentRow } from "./registry.js";
import { ApprovalWorkflowService } from "./approval.js";
import { AuditLedgerService } from "./audit.js";

export interface PolicyRule {
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

export interface AuthorizationRequest {
  agent: AgentRow;
  action: string;
  resource: string;
  parameters?: Record<string, unknown>;
  estimatedCostUsd?: number;
}

export interface AuthorizationDecision {
  allowed: boolean;
  decision: "ALLOW" | "DENY" | "NEEDS_APPROVAL";
  reason: string;
  matchedPolicyId?: string;
  approvalRequired?: boolean;
  approvalId?: string;
  ticket?: string; // execution nonce if auto-allowed or already pre-authorized
}

export class PolicyEngineService {
  constructor(
    private db: Database.Database,
    private auditService: AuditLedgerService,
    private approvalService: ApprovalWorkflowService
  ) {}

  /**
   * Helper to match wildcard patterns (e.g. "finance:*" matches "finance:transfer", "*:read" matches "docs:read")
   */
  public matchPattern(pattern: string, value: string): boolean {
    if (pattern === "*" || pattern === value) return true;
    if (pattern.includes("*")) {
      const regexPattern = "^" + pattern.split("*").map(s => s.replace(/[-/\\^$*+?.()|[\]{}]/g, "\\$&")).join(".*") + "$";
      return new RegExp(regexPattern).test(value);
    }
    return false;
  }

  /**
   * Check sliding-minute rate limit for an agent.
   * Returns true if allowed, false if limit exceeded.
   */
  private checkRateLimit(agent: AgentRow): { allowed: boolean; currentCount: number } {
    const currentMinute = Math.floor(Date.now() / 60000);

    // Periodically prune stale window buckets (older than 60 minutes) to prevent table bloat
    if (Math.random() < 0.1) {
      try {
        this.db
          .prepare("DELETE FROM rate_limit_buckets WHERE window_minute < ?")
          .run(currentMinute - 60);
      } catch {
        // Non-blocking cleanup
      }
    }

    const row = this.db
      .prepare("SELECT request_count FROM rate_limit_buckets WHERE agent_id = ? AND window_minute = ?")
      .get(agent.id, currentMinute) as { request_count: number } | undefined;

    const count = row ? row.request_count : 0;

    if (count >= agent.rate_limit_rpm) {
      return { allowed: false, currentCount: count };
    }

    // Increment bucket count
    this.db
      .prepare(`
        INSERT INTO rate_limit_buckets (agent_id, window_minute, request_count)
        VALUES (?, ?, 1)
        ON CONFLICT(agent_id, window_minute) DO UPDATE SET request_count = request_count + 1
      `)
      .run(agent.id, currentMinute);

    return { allowed: true, currentCount: count + 1 };
  }

  /**
   * Add a new policy rule.
   */
  createPolicy(rule: {
    name: string;
    description?: string;
    agentId?: string | null;
    actionPattern: string;
    resourcePattern: string;
    effect: "ALLOW" | "DENY" | "REQUIRE_APPROVAL";
    maxCostUsd?: number;
    priority?: number;
  }): PolicyRule {
    const id = `pol_${crypto.randomBytes(8).toString("hex")}`;
    const now = Date.now();

    this.db
      .prepare(`
        INSERT INTO policies (
          id, name, description, agent_id, action_pattern,
          resource_pattern, effect, max_cost_usd, priority, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `)
      .run(
        id,
        rule.name,
        rule.description || "",
        rule.agentId || null,
        rule.actionPattern,
        rule.resourcePattern,
        rule.effect,
        rule.maxCostUsd || 0.0,
        rule.priority ?? 10,
        now
      );

    return this.getPolicyById(id)!;
  }

  getPolicyById(id: string): PolicyRule | null {
    return (this.db.prepare("SELECT * FROM policies WHERE id = ?").get(id) as PolicyRule) || null;
  }

  listPolicies(agentId?: string): PolicyRule[] {
    if (agentId) {
      return this.db
        .prepare("SELECT * FROM policies WHERE agent_id = ? OR agent_id IS NULL ORDER BY priority DESC, created_at DESC")
        .all(agentId) as PolicyRule[];
    }
    return this.db
      .prepare("SELECT * FROM policies ORDER BY priority DESC, created_at DESC")
      .all() as PolicyRule[];
  }

  deletePolicy(id: string): boolean {
    const res = this.db.prepare("DELETE FROM policies WHERE id = ?").run(id);
    return res.changes > 0;
  }

  /**
   * Core zero-trust authorization pipeline.
   * Evaluates agent status, capability boundaries, rate limits, spend limits, and policy rules.
   * Strictly fails closed (DENY) on any evaluation failure.
   */
  authorize(request: AuthorizationRequest): AuthorizationDecision {
    const { agent, action, resource, parameters = {}, estimatedCostUsd = 0 } = request;

    try {
      // 1. Agent Status Check
      if (agent.status === "REVOKED") {
        this.auditService.append({
          agentId: agent.id,
          eventType: "AUTHZ_REQUEST",
          action,
          resource,
          decision: "DENY",
          payload: { reason: "Agent is REVOKED", agentStatus: agent.status },
        });
        return {
          allowed: false,
          decision: "DENY",
          reason: `Agent credentials have been permanently revoked: ${agent.revocation_reason || "Revoked by operator"}`,
        };
      }

      if (agent.status === "SUSPENDED") {
        this.auditService.append({
          agentId: agent.id,
          eventType: "AUTHZ_REQUEST",
          action,
          resource,
          decision: "DENY",
          payload: { reason: "Agent is SUSPENDED" },
        });
        return {
          allowed: false,
          decision: "DENY",
          reason: "Agent is currently SUSPENDED by admin.",
        };
      }

      // 2. Capability Scoping Check
      let allowedCapabilities: string[] = [];
      try {
        allowedCapabilities = JSON.parse(agent.allowed_capabilities);
      } catch {
        allowedCapabilities = [];
      }

      const hasCapability = allowedCapabilities.some((cap) => this.matchPattern(cap, action));
      if (!hasCapability) {
        this.auditService.append({
          agentId: agent.id,
          eventType: "AUTHZ_REQUEST",
          action,
          resource,
          decision: "DENY",
          payload: {
            reason: "Capability scope boundary violation",
            allowedCapabilities,
            requestedAction: action,
          },
        });
        return {
          allowed: false,
          decision: "DENY",
          reason: `Action '${action}' is outside agent's assigned capabilities: [${allowedCapabilities.join(", ")}].`,
        };
      }

      // 3. Rate Limit Check
      const rateCheck = this.checkRateLimit(agent);
      if (!rateCheck.allowed) {
        this.auditService.append({
          agentId: agent.id,
          eventType: "AUTHZ_REQUEST",
          action,
          resource,
          decision: "DENY",
          payload: {
            reason: "Rate limit exceeded",
            rateLimitRpm: agent.rate_limit_rpm,
            currentMinuteCount: rateCheck.currentCount,
          },
        });
        return {
          allowed: false,
          decision: "DENY",
          reason: `Rate limit of ${agent.rate_limit_rpm} requests/min exceeded.`,
        };
      }

      // 4. Spend Limit Check
      if (estimatedCostUsd > 0) {
        const projectedSpend = agent.current_spend_usd + estimatedCostUsd;
        if (projectedSpend > agent.spend_limit_usd) {
          this.auditService.append({
            agentId: agent.id,
            eventType: "AUTHZ_REQUEST",
            action,
            resource,
            decision: "DENY",
            payload: {
              reason: "Spending limit exceeded",
              currentSpend: agent.current_spend_usd,
              estimatedCost: estimatedCostUsd,
              spendLimit: agent.spend_limit_usd,
            },
          });
          return {
            allowed: false,
            decision: "DENY",
            reason: `Estimated cost ($${estimatedCostUsd.toFixed(2)}) exceeds remaining budget ($${(agent.spend_limit_usd - agent.current_spend_usd).toFixed(2)} remaining of $${agent.spend_limit_usd.toFixed(2)} limit).`,
          };
        }
      }

      // 5. Evaluate Applicable Policies (Ordered by Priority DESC)
      const policies = this.db
        .prepare(`
          SELECT * FROM policies 
          WHERE (agent_id = ? OR agent_id IS NULL)
          ORDER BY priority DESC, created_at DESC
        `)
        .all(agent.id) as PolicyRule[];

      let matchedPolicy: PolicyRule | null = null;
      for (const policy of policies) {
        if (
          this.matchPattern(policy.action_pattern, action) &&
          this.matchPattern(policy.resource_pattern, resource)
        ) {
          matchedPolicy = policy;
          break; // First matching highest-priority policy wins
        }
      }

      // DENY BY DEFAULT: If no explicit policy matched, deny!
      if (!matchedPolicy) {
        this.auditService.append({
          agentId: agent.id,
          eventType: "AUTHZ_REQUEST",
          action,
          resource,
          decision: "DENY",
          payload: {
            reason: "Deny by default: No matching policy rule found",
          },
        });
        return {
          allowed: false,
          decision: "DENY",
          reason: "Deny by default: No policy explicitly authorized this action and resource combination.",
        };
      }

      // 6. Handle Matched Policy Effect
      if (matchedPolicy.effect === "DENY") {
        this.auditService.append({
          agentId: agent.id,
          eventType: "AUTHZ_REQUEST",
          action,
          resource,
          decision: "DENY",
          payload: {
            policyId: matchedPolicy.id,
            policyName: matchedPolicy.name,
            reason: "Explicit DENY rule",
          },
        });
        return {
          allowed: false,
          decision: "DENY",
          reason: `Explicitly denied by policy '${matchedPolicy.name}' (${matchedPolicy.id}).`,
          matchedPolicyId: matchedPolicy.id,
        };
      }

      if (matchedPolicy.effect === "REQUIRE_APPROVAL") {
        // Enforce human approval workflow
        const approval = this.approvalService.requestApproval({
          agentId: agent.id,
          action,
          resource,
          parameters,
          estimatedCostUsd,
        });

        return {
          allowed: false,
          decision: "NEEDS_APPROVAL",
          reason: `Action requires human operator sign-off per policy '${matchedPolicy.name}'.`,
          matchedPolicyId: matchedPolicy.id,
          approvalRequired: true,
          approvalId: approval.id,
        };
      }

      if (matchedPolicy.effect === "ALLOW") {
        // Check per-policy cost ceiling if defined
        if (matchedPolicy.max_cost_usd > 0 && estimatedCostUsd > matchedPolicy.max_cost_usd) {
          // Escalate to approval if cost exceeds max_cost_usd threshold
          const approval = this.approvalService.requestApproval({
            agentId: agent.id,
            action,
            resource,
            parameters,
            estimatedCostUsd,
          });

          return {
            allowed: false,
            decision: "NEEDS_APPROVAL",
            reason: `Action cost ($${estimatedCostUsd.toFixed(2)}) exceeds policy auto-approval limit ($${matchedPolicy.max_cost_usd.toFixed(2)}). Escalating to human reviewer.`,
            matchedPolicyId: matchedPolicy.id,
            approvalRequired: true,
            approvalId: approval.id,
          };
        }

        // Action is authorized!
        this.auditService.append({
          agentId: agent.id,
          eventType: "AUTHZ_REQUEST",
          action,
          resource,
          decision: "ALLOW",
          payload: {
            policyId: matchedPolicy.id,
            policyName: matchedPolicy.name,
            estimatedCostUsd,
          },
        });

        return {
          allowed: true,
          decision: "ALLOW",
          reason: `Authorized by policy '${matchedPolicy.name}'.`,
          matchedPolicyId: matchedPolicy.id,
        };
      }

      // Fallback deny
      return {
        allowed: false,
        decision: "DENY",
        reason: "Unknown policy effect. Denying by default.",
      };
    } catch (err: any) {
      // Fail closed on any exception
      this.auditService.append({
        agentId: agent.id,
        eventType: "ANOMALY",
        action,
        resource,
        decision: "DENY",
        payload: {
          error: err?.message || String(err),
          warning: "Policy engine encountered an unexpected error and failed closed.",
        },
      });

      return {
        allowed: false,
        decision: "DENY",
        reason: `Policy engine failed closed: ${err?.message || "Internal evaluation error"}`,
      };
    }
  }
}
