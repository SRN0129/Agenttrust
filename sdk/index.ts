/**
 * AgentTrust Client SDK & Universal 1-Line Interceptor
 * Interoperable security guardrail and authorization client for AI Agent runtimes.
 */

export interface AgentTrustConfig {
  baseUrl: string;
  apiKey: string;
}

export interface AuthorizeResult {
  success: boolean;
  allowed: boolean;
  decision: "ALLOW" | "DENY" | "NEEDS_APPROVAL";
  reason: string;
  approvalRequired?: boolean;
  approvalId?: string;
  matchedPolicyId?: string;
}

export interface ApprovalDetails {
  id: string;
  agentId: string;
  action: string;
  resource: string;
  parameters: Record<string, any>;
  status: "PENDING" | "APPROVED" | "REJECTED" | "EXPIRED" | "CONSUMED";
  executionNonce?: string;
  requestedAt: number;
  expiresAt: number;
  decidedAt?: number;
  decidedBy?: string;
}

export class PolicyDenialError extends Error {
  constructor(public reason: string, public decision: string) {
    super(`AgentTrust Policy Denial [${decision}]: ${reason}`);
    this.name = "PolicyDenialError";
  }
}

export class ApprovalRequiredError extends Error {
  constructor(public approvalId: string, public reason: string) {
    super(`Action requires human approval. Approval ID: ${approvalId}. Reason: ${reason}`);
    this.name = "ApprovalRequiredError";
  }
}

export class CircuitBreakerError extends Error {
  constructor(public reason: string) {
    super(`AgentTrust Circuit Breaker Tripped: ${reason}`);
    this.name = "CircuitBreakerError";
  }
}

export class AgentTrustClient {
  private baseUrl: string;
  private apiKey: string;

  constructor(config: AgentTrustConfig) {
    this.baseUrl = config.baseUrl.replace(/\/$/, "");
    this.apiKey = config.apiKey;
  }

  private async fetchApi<T>(path: string, options: RequestInit = {}): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      Authorization: `Bearer ${this.apiKey}`,
      ...(options.headers as Record<string, string>),
    };

    const res = await fetch(url, { ...options, headers });
    const data = await res.json();

    if (!res.ok) {
      const msg = data.error || `HTTP ${res.status}: ${res.statusText}`;
      throw new Error(msg);
    }

    return data as T;
  }

  /**
   * Request authorization for an action on a target resource.
   */
  async authorize(
    action: string,
    resource: string,
    parameters: Record<string, any> = {},
    estimatedCostUsd = 0
  ): Promise<AuthorizeResult> {
    return this.fetchApi<AuthorizeResult>("/api/v1/authorize", {
      method: "POST",
      body: JSON.stringify({
        action,
        resource,
        parameters,
        estimatedCostUsd,
      }),
    });
  }

  /**
   * Check status of a pending approval request.
   */
  async getApproval(approvalId: string): Promise<ApprovalDetails> {
    const res = await this.fetchApi<{ success: boolean; approval: ApprovalDetails }>(
      `/api/v1/approvals/${approvalId}`
    );
    return res.approval;
  }

  /**
   * Poll for human approval decision with timeout.
   */
  async waitForApproval(
    approvalId: string,
    pollIntervalMs = 2000,
    maxWaitMs = 60000
  ): Promise<ApprovalDetails> {
    const startTime = Date.now();

    while (Date.now() - startTime < maxWaitMs) {
      const approval = await this.getApproval(approvalId);
      if (approval.status === "APPROVED") {
        return approval;
      }
      if (approval.status === "REJECTED") {
        throw new PolicyDenialError("Human operator rejected the action request.", "REJECTED");
      }
      if (approval.status === "EXPIRED") {
        throw new PolicyDenialError("Approval request expired before review.", "EXPIRED");
      }

      await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));
    }

    throw new Error(`Timed out waiting for human approval after ${maxWaitMs / 1000}s`);
  }

  /**
   * Invoke a protected tool through the security gateway.
   * Fails closed if unauthorized or if execution ticket is invalid/replayed.
   */
  async executeProtectedTool<T = any>(params: {
    toolName: string;
    action: string;
    resource: string;
    parameters?: Record<string, any>;
    costUsd?: number;
    autoPollApproval?: boolean;
    pollTimeoutMs?: number;
  }): Promise<{ success: boolean; output: T; consumedTicket?: boolean }> {
    const {
      toolName,
      action,
      resource,
      parameters = {},
      costUsd = 0,
      autoPollApproval = false,
      pollTimeoutMs = 30000,
    } = params;

    // 1. Request server-side authorization
    const authz = await this.authorize(action, resource, parameters, costUsd);

    if (authz.decision === "DENY") {
      throw new PolicyDenialError(authz.reason, "DENY");
    }

    let approvalId: string | undefined = undefined;
    let executionNonce: string | undefined = undefined;

    if (authz.decision === "NEEDS_APPROVAL") {
      if (!autoPollApproval) {
        throw new ApprovalRequiredError(authz.approvalId!, authz.reason);
      }

      // Wait for human approval
      const decidedApproval = await this.waitForApproval(authz.approvalId!, 1500, pollTimeoutMs);
      approvalId = decidedApproval.id;
      executionNonce = decidedApproval.executionNonce;
    }

    // 2. Execute protected tool on gateway
    const result = await this.fetchApi<{
      success: boolean;
      output: T;
      consumedTicket?: boolean;
      costRecorded?: number;
    }>("/api/v1/tools/execute", {
      method: "POST",
      body: JSON.stringify({
        toolName,
        action,
        resource,
        parameters,
        approvalId,
        executionNonce,
        costUsd,
      }),
    });

    return result;
  }

  /**
   * Report custom tool execution outcome to verifiable audit ledger.
   */
  async reportOutcome(data: {
    action: string;
    resource: string;
    executionStatus: "SUCCESS" | "FAILED";
    outputSummary: string;
    details?: Record<string, any>;
  }): Promise<{ success: boolean; auditIndex: number; entryHash: string }> {
    return this.fetchApi<{ success: boolean; auditIndex: number; entryHash: string }>(
      "/api/v1/audit/outcome",
      {
        method: "POST",
        body: JSON.stringify(data),
      }
    );
  }

  /**
   * Check for Goal Hijack & Semantic Drift.
   */
  async checkDrift(data: {
    systemGoal: string;
    action: string;
    resource: string;
    parameters: Record<string, any>;
  }) {
    return this.fetchApi<any>("/api/v1/governance/drift-check", {
      method: "POST",
      body: JSON.stringify(data),
    });
  }

  /**
   * Execute Chaos Monkey Adversarial Red-Team suite.
   */
  async runChaosMonkey() {
    return this.fetchApi<any>("/api/v1/chaos/audit", {
      method: "POST",
    });
  }

  /**
   * Fetch zero-knowledge verifiable Merkle attestation receipt for an audit entry.
   */
  async getAttestationReceipt(entryId: number) {
    return this.fetchApi<any>(`/api/v1/audit/attestation/${entryId}`);
  }
}

/**
 * Universal 1-Line Drop-in Agent Wrapper
 * Injects zero-trust security, blast radius scoring, goal drift detection,
 * and cryptographic audit trails into any agent runtime in a single line.
 */
export interface WrapAgentOptions {
  client: AgentTrustClient;
  systemGoal?: string;
  autoPollApproval?: boolean;
  pollTimeoutMs?: number;
  onApprovalRequired?: (approvalId: string, action: string, resource: string) => void;
}

export function wrapAgent<T extends Record<string, any>>(agent: T, options: WrapAgentOptions): T {
  const { client, systemGoal = "Autonomous agent execution", autoPollApproval = false, pollTimeoutMs = 30000 } = options;

  return new Proxy(agent, {
    get(target, prop, receiver) {
      const orig = Reflect.get(target, prop, receiver);

      // Wrap function/tool calls
      if (typeof orig === "function") {
        return async function (...args: any[]) {
          const action = String(prop);
          const parameters = args.length === 1 && typeof args[0] === "object" ? args[0] : { args };
          const resource = parameters.resource || parameters.url || parameters.table || `tool:${action}`;
          const estimatedCostUsd = Number(parameters.estimatedCostUsd || parameters.costUsd || 0);

          // 1. Pre-flight Goal Drift check
          if (systemGoal) {
            try {
              const drift = await client.checkDrift({
                systemGoal,
                action,
                resource,
                parameters,
              });

              if (drift && drift.divergenceScore >= 0.85) {
                throw new PolicyDenialError(drift.reason, "DENY_GOAL_DRIFT");
              }
            } catch (err: any) {
              if (err instanceof PolicyDenialError) throw err;
              // Pass-through if endpoint not available
            }
          }

          // 2. Server-side Zero-Trust Authorization
          const authz = await client.authorize(action, resource, parameters, estimatedCostUsd);

          if (authz.decision === "DENY") {
            throw new PolicyDenialError(authz.reason, "DENY");
          }

          if (authz.decision === "NEEDS_APPROVAL") {
            if (options.onApprovalRequired) {
              options.onApprovalRequired(authz.approvalId!, action, resource);
            }

            if (!autoPollApproval) {
              throw new ApprovalRequiredError(authz.approvalId!, authz.reason);
            }

            await client.waitForApproval(authz.approvalId!, 1500, pollTimeoutMs);
          }

          // 3. Execute underlying tool
          let result: any;
          let executionStatus: "SUCCESS" | "FAILED" = "SUCCESS";

          try {
            result = await (orig as Function).apply(target, args);
            return result;
          } catch (err: any) {
            executionStatus = "FAILED";
            throw err;
          } finally {
            // 4. Record verifiable audit outcome
            try {
              await client.reportOutcome({
                action,
                resource,
                executionStatus,
                outputSummary: executionStatus === "SUCCESS" ? "Executed tool successfully" : "Tool threw runtime exception",
                details: { parameters },
              });
            } catch {
              // Non-blocking outcome recording
            }
          }
        };
      }

      return orig;
    },
  });
}
