/**
 * AgentTrust Client SDK
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
}
