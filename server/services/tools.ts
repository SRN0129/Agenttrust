import Database from "better-sqlite3";
import { AgentRow, AgentRegistryService } from "./registry.js";
import { ApprovalWorkflowService } from "./approval.js";
import { AuditLedgerService } from "./audit.js";
import { PolicyEngineService } from "./policy.js";
import { IsolatedSandboxRunner } from "./sandbox.js";

export interface ExecuteToolInput {
  agent: AgentRow;
  toolName: string;
  action: string;
  resource: string;
  parameters: Record<string, unknown>;
  approvalId?: string;
  executionNonce?: string;
  costUsd?: number;
}

export interface ToolExecutionResult {
  success: boolean;
  toolName: string;
  output?: any;
  error?: string;
  consumedTicket?: boolean;
  costRecorded?: number;
}

export class ProtectedToolService {
  constructor(
    private db: Database.Database,
    private registryService: AgentRegistryService,
    private approvalService: ApprovalWorkflowService,
    private auditService: AuditLedgerService,
    private policyService: PolicyEngineService
  ) {}

  /**
   * Protected Mock Tools Map.
   * None of these will execute unless server-side authorization is fully satisfied.
   */
  private mockImplementations: Record<
    string,
    (params: Record<string, unknown>) => { result: any; summary: string }
  > = {
    // 1. Low-risk read-only tool
    read_customer_notes: (params) => {
      const customerId = params.customerId || "cust_101";
      return {
        summary: `Retrieved notes for customer ${customerId}`,
        result: {
          customerId,
          notes: [
            { id: "note_1", note: "Customer requested pricing consultation.", created: "2026-10-15" },
            { id: "note_2", note: "VIP tier upgrade requested.", created: "2026-10-20" },
          ],
        },
      };
    },

    // 2. Medium-risk web lookup
    search_documentation: (params) => {
      const query = params.query || "Agent security specs";
      return {
        summary: `Searched documentation for query: '${query}'`,
        result: {
          matches: [
            { title: "Zero Trust Architecture for AI", score: 0.98 },
            { title: "Scoped Delegation and HITL Approvals", score: 0.94 },
          ],
        },
      };
    },

    // 3. High-risk finance wire transfer
    send_wire_transfer: (params) => {
      const amount = Number(params.amount) || 0;
      const recipient = params.recipient || "Vendor Inc";
      return {
        summary: `Simulated wire transfer of $${amount.toFixed(2)} to ${recipient}`,
        result: {
          transactionId: `tx_wire_${Math.floor(Math.random() * 899999 + 100000)}`,
          amount,
          recipient,
          status: "SUCCESS_SIMULATED",
          clearedAt: new Date().toISOString(),
        },
      };
    },

    // 4. Critical database drop/truncate
    drop_customer_table: (params) => {
      return {
        summary: "SIMULATED DESTRUCTION: Table customer_records dropped",
        result: {
          table: params.table || "customer_records",
          dropped: true,
          notice: "This is a mock simulated tool execution.",
        },
      };
    },

    // 5. Cloud deployment tool
    deploy_service_version: (params) => {
      const service = params.service || "payment-gateway";
      const version = params.version || "v2.4.0";
      return {
        summary: `Deployed ${service} to production at version ${version}`,
        result: {
          service,
          version,
          deploymentId: `dep_${Math.floor(Math.random() * 899999 + 100000)}`,
          environment: "production",
        },
      };
    },
  };

  /**
   * Execute protected tool inside isolated defense sandbox.
   * Requires either:
   * - A pre-approved, unconsumed execution ticket (for sensitive approval-required actions)
   * - Or verification that the tool is registered and authorized.
   */
  async execute(input: ExecuteToolInput): Promise<ToolExecutionResult> {
    const { agent, toolName, action, resource, parameters, approvalId, executionNonce, costUsd = 0 } = input;

    // Check if tool exists
    const toolFn = this.mockImplementations[toolName];
    if (!toolFn) {
      return {
        success: false,
        toolName,
        error: `Protected tool '${toolName}' not found in registry.`,
      };
    }

    let ticketConsumed = false;

    // If an approvalId was provided, consume the single-use ticket
    if (approvalId || executionNonce) {
      if (!approvalId || !executionNonce) {
        return {
          success: false,
          toolName,
          error: "Both approvalId and executionNonce must be provided for ticketed execution.",
        };
      }

      const consumeRes = this.approvalService.consumeTicket(
        approvalId,
        executionNonce,
        action,
        resource
      );

      if (!consumeRes.success) {
        return {
          success: false,
          toolName,
          error: consumeRes.error || "Failed to consume execution ticket.",
        };
      }

      ticketConsumed = true;
    } else {
      // No ticket provided: evaluate policy engine directly on the server
      const authz = this.policyService.authorize({
        agent,
        action,
        resource,
        parameters,
        estimatedCostUsd: costUsd,
      });

      if (!authz.allowed) {
        return {
          success: false,
          toolName,
          error: `Execution blocked by server policy: [${authz.decision}] ${authz.reason}`,
        };
      }
    }

    // Now execute inside the defensive Isolated Sandbox
    const sandboxOutcome = await IsolatedSandboxRunner.executeSafely(
      toolName,
      toolFn,
      parameters,
      { timeoutMs: 3000 }
    );

    if (!sandboxOutcome.success) {
      this.auditService.append({
        agentId: agent.id,
        eventType: "TOOL_EXECUTION",
        action,
        resource,
        decision: "FAILED",
        payload: {
          toolName,
          error: sandboxOutcome.error,
          sandboxed: true,
        },
      });

      return {
        success: false,
        toolName,
        error: sandboxOutcome.error,
      };
    }

    // Record spend if applicable
    if (costUsd > 0) {
      this.registryService.recordSpend(agent.id, costUsd);
    }

    // Record execution in verifiable audit ledger
    this.auditService.append({
      agentId: agent.id,
      eventType: "TOOL_EXECUTION",
      action,
      resource,
      decision: "EXECUTED",
      payload: {
        toolName,
        parameters,
        ticketConsumed,
        approvalId: approvalId || null,
        costUsd,
        sandboxed: true,
        executionTimeMs: sandboxOutcome.executionTimeMs,
      },
    });

    return {
      success: true,
      toolName,
      output: sandboxOutcome.output,
      consumedTicket: ticketConsumed,
      costRecorded: costUsd,
    };
  }
}
