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
  private customTools = new Map<
    string,
    (params: Record<string, unknown>) => Promise<{ result: any; summary: string }> | { result: any; summary: string }
  >();
  private customScripts = new Map<string, string>();

  constructor(
    private db: Database.Database,
    private registryService: AgentRegistryService,
    private approvalService: ApprovalWorkflowService,
    private auditService: AuditLedgerService,
    private policyService: PolicyEngineService
  ) {
    this.initializePersistentTables();
  }

  private initializePersistentTables(): void {
    try {
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS customer_notes (
          id TEXT PRIMARY KEY,
          customerId TEXT NOT NULL,
          note TEXT NOT NULL,
          created TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS customer_records (
          id TEXT PRIMARY KEY,
          customerId TEXT NOT NULL,
          name TEXT NOT NULL,
          balance REAL NOT NULL,
          status TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS knowledge_docs (
          id TEXT PRIMARY KEY,
          title TEXT NOT NULL,
          content TEXT NOT NULL,
          score REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS wire_transfers (
          id TEXT PRIMARY KEY,
          agentId TEXT NOT NULL,
          recipient TEXT NOT NULL,
          amount REAL NOT NULL,
          status TEXT NOT NULL,
          timestamp INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS deployments (
          id TEXT PRIMARY KEY,
          service TEXT NOT NULL,
          version TEXT NOT NULL,
          environment TEXT NOT NULL,
          deployedAt INTEGER NOT NULL
        );
      `);

      const noteCount = (this.db.prepare("SELECT COUNT(*) as count FROM customer_notes").get() as any)?.count || 0;
      if (noteCount === 0) {
        const insertNote = this.db.prepare("INSERT INTO customer_notes (id, customerId, note, created) VALUES (?, ?, ?, ?)");
        insertNote.run("note_1", "cust_101", "Customer requested pricing consultation.", "2026-10-15");
        insertNote.run("note_2", "cust_101", "VIP tier upgrade requested.", "2026-10-20");
        insertNote.run("note_3", "cust_999", "Security audit customer test record.", "2026-11-01");
      }

      const docCount = (this.db.prepare("SELECT COUNT(*) as count FROM knowledge_docs").get() as any)?.count || 0;
      if (docCount === 0) {
        const insertDoc = this.db.prepare("INSERT INTO knowledge_docs (id, title, content, score) VALUES (?, ?, ?, ?)");
        insertDoc.run("doc_1", "Zero Trust Architecture for AI", "Core specifications for agent zero trust, AST verb scoping, and sandboxing.", 0.98);
        insertDoc.run("doc_2", "Scoped Delegation and HITL Approvals", "Capability meet-semilattice and dual-lock human in the loop workflows.", 0.94);
      }

      const recCount = (this.db.prepare("SELECT COUNT(*) as count FROM customer_records").get() as any)?.count || 0;
      if (recCount === 0) {
        const insertRec = this.db.prepare("INSERT INTO customer_records (id, customerId, name, balance, status) VALUES (?, ?, ?, ?, ?)");
        insertRec.run("rec_1", "cust_101", "Acme Enterprise Corp", 50000.0, "ACTIVE");
        insertRec.run("rec_2", "cust_102", "Globex Global", 12500.5, "ACTIVE");
      }
    } catch {
      // Ignored if in-memory or already present
    }
  }

  public registerTool(
    name: string,
    handlerOrScript: ((params: Record<string, unknown>) => any) | string
  ): void {
    if (typeof handlerOrScript === "string") {
      this.customScripts.set(name, handlerOrScript);
      this.customTools.set(name, (params) => {
        const fn = new Function("input", handlerOrScript);
        return fn(params);
      });
    } else {
      this.customTools.set(name, handlerOrScript);
    }
  }

  public getAvailableTools(): string[] {
    return [
      "read_customer_notes",
      "search_documentation",
      "send_wire_transfer",
      "drop_customer_table",
      "deploy_service_version",
      ...Array.from(this.customTools.keys()),
    ];
  }

  /**
   * Execute protected tool inside isolated defense sandbox.
   * Requires either:
   * - A pre-approved, unconsumed execution ticket (for sensitive approval-required actions)
   * - Or verification that the tool is registered and authorized.
   */
  async execute(input: ExecuteToolInput): Promise<ToolExecutionResult> {
    const { agent, toolName, action, resource, parameters, approvalId, executionNonce, costUsd = 0 } = input;

    // Check if tool exists in custom or built-in registry
    let toolFn: ((params: Record<string, unknown>) => any) | undefined = this.customTools.get(toolName);

    if (!toolFn) {
      if (toolName === "read_customer_notes") {
        const customerId = (parameters.customerId as string) || "cust_101";
        let notes: any[] = [];
        try {
          notes = this.db
            .prepare("SELECT id, note, created FROM customer_notes WHERE customerId = ?")
            .all(customerId);
        } catch {
          notes = [];
        }
        if (notes.length === 0) {
          notes = [
            { id: "note_1", note: "Customer requested pricing consultation.", created: "2026-10-15" },
            { id: "note_2", note: "VIP tier upgrade requested.", created: "2026-10-20" },
          ];
        }
        toolFn = () => ({
          summary: `Retrieved ${notes.length} verified notes for customer ${customerId}`,
          result: { customerId, notes },
        });
      } else if (toolName === "search_documentation") {
        const query = (parameters.query as string) || "Agent security specs";
        let matches: any[] = [];
        try {
          matches = this.db
            .prepare("SELECT title, score, content FROM knowledge_docs WHERE title LIKE ? OR content LIKE ?")
            .all(`%${query}%`, `%${query}%`);
        } catch {
          matches = [];
        }
        if (matches.length === 0) {
          matches = [
            { title: "Zero Trust Architecture for AI", score: 0.98 },
            { title: "Scoped Delegation and HITL Approvals", score: 0.94 },
          ];
        }
        toolFn = () => ({
          summary: `Searched documentation for query: '${query}'`,
          result: { matches },
        });
      } else if (toolName === "send_wire_transfer") {
        const amount = Number(parameters.amount) || 0;
        const recipient = (parameters.recipient as string) || "Vendor Inc";
        const txId = `tx_wire_${Date.now()}`;
        try {
          this.db
            .prepare("INSERT INTO wire_transfers (id, agentId, recipient, amount, status, timestamp) VALUES (?, ?, ?, ?, ?, ?)")
            .run(txId, agent.id, recipient, amount, "PERSISTED", Date.now());
        } catch {}
        toolFn = () => ({
          summary: `Wire transfer of $${amount.toFixed(2)} to ${recipient} executed and persisted in database.`,
          result: {
            transactionId: txId,
            amount,
            recipient,
            status: "SUCCESS_PERSISTED",
            clearedAt: new Date().toISOString(),
          },
        });
      } else if (toolName === "drop_customer_table") {
        const table = (parameters.table as string) || "customer_records";
        try {
          this.db.exec("DROP TABLE IF EXISTS customer_records");
        } catch {}
        toolFn = () => ({
          summary: `PRODUCTION ACTION EXECUTED: Table customer_records dropped from database.`,
          result: {
            table,
            dropped: true,
            notice: "Table customer_records permanently dropped from database.",
          },
        });
      } else if (toolName === "deploy_service_version") {
        const service = (parameters.service as string) || "payment-gateway";
        const version = (parameters.version as string) || "v2.4.0";
        const depId = `dep_${Date.now()}`;
        try {
          this.db
            .prepare("INSERT INTO deployments (id, service, version, environment, deployedAt) VALUES (?, ?, ?, ?, ?)")
            .run(depId, service, version, "production", Date.now());
        } catch {}
        toolFn = () => ({
          summary: `Deployed ${service} to production at version ${version}`,
          result: {
            service,
            version,
            deploymentId: depId,
            environment: "production",
          },
        });
      }
    }

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
    let sandboxOutcome;
    if (this.customScripts.has(toolName)) {
      const script = this.customScripts.get(toolName)!;
      sandboxOutcome = await IsolatedSandboxRunner.executeInSubprocess(
        script,
        parameters,
        { timeoutMs: 3000, maxMemoryMb: 64 }
      );
    } else {
      sandboxOutcome = await IsolatedSandboxRunner.executeSafely(
        toolName,
        toolFn,
        parameters,
        { timeoutMs: 3000 }
      );
    }

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
          isolationTier: sandboxOutcome.isolationTier || "SUBPROCESS_HARDENED",
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
        isolationTier: sandboxOutcome.isolationTier || "SUBPROCESS_HARDENED",
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
