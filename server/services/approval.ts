import Database from "better-sqlite3";
import crypto from "node:crypto";
import { generateExecutionNonce } from "../crypto.js";
import { AuditLedgerService } from "./audit.js";

const CALLBACK_SECRET = process.env.CALLBACK_SECRET || "agent_trust_callback_hmac_secret_2026";

export interface CreateApprovalInput {
  agentId: string;
  action: string;
  resource: string;
  parameters: Record<string, unknown>;
  estimatedCostUsd?: number;
  ttlSeconds?: number;
}

export interface ApprovalRow {
  id: string;
  agent_id: string;
  action: string;
  resource: string;
  parameters: string; // JSON
  estimated_cost_usd: number;
  status: "PENDING" | "APPROVED" | "REJECTED" | "EXPIRED" | "CONSUMED";
  execution_nonce: string | null;
  requested_at: number;
  expires_at: number;
  decided_at: number | null;
  decided_by: string | null;
  decision_reason: string | null;
  consumed_at: number | null;
}

export class ApprovalWorkflowService {
  constructor(
    private db: Database.Database,
    private auditService: AuditLedgerService
  ) {}

  /**
   * Create a new pending approval for a high-risk action.
   */
  requestApproval(input: CreateApprovalInput): ApprovalRow {
    const id = `appr_${crypto.randomBytes(8).toString("hex")}`;
    const now = Date.now();
    const ttlMs = (input.ttlSeconds || 300) * 1000; // default 5 minutes
    const expiresAt = now + ttlMs;
    const paramsJson = JSON.stringify(input.parameters || {});

    this.db
      .prepare(`
        INSERT INTO approvals (
          id, agent_id, action, resource, parameters,
          estimated_cost_usd, status, execution_nonce,
          requested_at, expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, 'PENDING', NULL, ?, ?)
      `)
      .run(
        id,
        input.agentId,
        input.action,
        input.resource,
        paramsJson,
        input.estimatedCostUsd || 0.0,
        now,
        expiresAt
      );

    const record = this.getApprovalById(id)!;

    this.auditService.append({
      agentId: input.agentId,
      eventType: "APPROVAL_REQUEST",
      action: input.action,
      resource: input.resource,
      decision: "NEEDS_APPROVAL",
      payload: {
        approvalId: id,
        parameters: input.parameters,
        estimatedCostUsd: input.estimatedCostUsd || 0.0,
        expiresAt,
      },
    });

    return record;
  }

  getApprovalById(id: string): ApprovalRow | null {
    const row = this.db.prepare("SELECT * FROM approvals WHERE id = ?").get(id) as ApprovalRow | undefined;
    if (!row) return null;

    // Check if pending has expired
    if (row.status === "PENDING" && Date.now() > row.expires_at) {
      this.db.prepare("UPDATE approvals SET status = 'EXPIRED' WHERE id = ?").run(id);
      return { ...row, status: "EXPIRED" };
    }

    return row;
  }

  listPending(): ApprovalRow[] {
    const now = Date.now();
    // Auto-expire outdated pending rows
    this.db
      .prepare("UPDATE approvals SET status = 'EXPIRED' WHERE status = 'PENDING' AND expires_at < ?")
      .run(now);

    return this.db
      .prepare("SELECT * FROM approvals WHERE status = 'PENDING' ORDER BY requested_at ASC")
      .all() as ApprovalRow[];
  }

  listAll(limit = 100): ApprovalRow[] {
    return this.db
      .prepare("SELECT * FROM approvals ORDER BY requested_at DESC LIMIT ?")
      .all(limit) as ApprovalRow[];
  }

  /**
   * Human operator decides on an approval request.
   */
  decide(
    id: string,
    decision: "APPROVE" | "REJECT",
    reviewerEmail: string,
    reason?: string
  ): ApprovalRow {
    const approval = this.getApprovalById(id);
    if (!approval) {
      throw new Error(`Approval request ${id} not found.`);
    }

    if (approval.status !== "PENDING") {
      throw new Error(`Cannot decide on approval in '${approval.status}' state.`);
    }

    const now = Date.now();
    if (now > approval.expires_at) {
      this.db.prepare("UPDATE approvals SET status = 'EXPIRED' WHERE id = ?").run(id);
      throw new Error(`Approval request ${id} has expired.`);
    }

    let nonce: string | null = null;
    let newStatus: "APPROVED" | "REJECTED";

    if (decision === "APPROVE") {
      newStatus = "APPROVED";
      nonce = generateExecutionNonce();
    } else {
      newStatus = "REJECTED";
    }

    this.db
      .prepare(`
        UPDATE approvals 
        SET status = ?, execution_nonce = ?, decided_at = ?, decided_by = ?, decision_reason = ?
        WHERE id = ?
      `)
      .run(newStatus, nonce, now, reviewerEmail, reason || "", id);

    this.auditService.append({
      agentId: approval.agent_id,
      eventType: "APPROVAL_DECISION",
      action: approval.action,
      resource: approval.resource,
      decision: newStatus,
      payload: {
        approvalId: id,
        decidedBy: reviewerEmail,
        decisionReason: reason || "",
        executionNonceIssued: !!nonce,
      },
    });

    return this.getApprovalById(id)!;
  }

  /**
   * Generate an HMAC signed 1-click callback token for mobile/Slack decisions.
   */
  generateCallbackToken(approvalId: string): string {
    const approval = this.getApprovalById(approvalId);
    if (!approval) throw new Error("Approval not found");
    const payload = `${approval.id}:${approval.expires_at}`;
    const hmac = crypto.createHmac("sha256", CALLBACK_SECRET).update(payload).digest("hex");
    return `${Buffer.from(payload).toString("base64url")}.${hmac}`;
  }

  /**
   * Verify an HMAC signed 1-click callback token.
   */
  verifyCallbackToken(token: string, approvalId: string): boolean {
    try {
      const [payloadB64, providedHmac] = token.split(".");
      if (!payloadB64 || !providedHmac) return false;
      const payload = Buffer.from(payloadB64, "base64url").toString();
      const [tokenApprId, expiresAtStr] = payload.split(":");
      if (tokenApprId !== approvalId) return false;

      const expectedHmac = crypto.createHmac("sha256", CALLBACK_SECRET).update(payload).digest("hex");
      const validSig = crypto.timingSafeEqual(Buffer.from(providedHmac, "hex"), Buffer.from(expectedHmac, "hex"));
      if (!validSig) return false;

      return Date.now() <= Number(expiresAtStr);
    } catch {
      return false;
    }
  }

  /**
   * Consume an approved ticket to execute a protected tool.
   * Atomically verifies and burns the single-use execution ticket to prevent replay attacks.
   */
  consumeTicket(
    approvalId: string,
    executionNonce: string,
    expectedAction: string,
    expectedResource: string
  ): { success: boolean; error?: string; approval?: ApprovalRow } {
    const approval = this.db
      .prepare("SELECT * FROM approvals WHERE id = ?")
      .get(approvalId) as ApprovalRow | undefined;

    if (!approval) {
      return { success: false, error: "Invalid approval ID." };
    }

    // 1. Detect replay attack
    if (approval.status === "CONSUMED") {
      this.auditService.append({
        agentId: approval.agent_id,
        eventType: "REPLAY_ATTEMPT",
        action: expectedAction,
        resource: expectedResource,
        decision: "BLOCKED",
        payload: {
          approvalId,
          executionNonce,
          previouslyConsumedAt: approval.consumed_at,
          warning: "Attempted to re-execute a consumed ticket. Potential replay attack.",
        },
      });

      return {
        success: false,
        error: "REPLAY_ATTACK_DETECTED: This execution ticket has already been consumed.",
        approval,
      };
    }

    // 2. Check status
    if (approval.status !== "APPROVED") {
      return {
        success: false,
        error: `Ticket is not in APPROVED state (current state: ${approval.status}).`,
        approval,
      };
    }

    // 3. Verify execution nonce
    if (approval.execution_nonce !== executionNonce) {
      return { success: false, error: "Invalid execution nonce.", approval };
    }

    // 4. Check expiration
    if (Date.now() > approval.expires_at) {
      this.db.prepare("UPDATE approvals SET status = 'EXPIRED' WHERE id = ?").run(approvalId);
      return { success: false, error: "Approval ticket has expired.", approval };
    }

    // 5. Verify action & resource binding
    if (approval.action !== expectedAction || approval.resource !== expectedResource) {
      return {
        success: false,
        error: `Scope mismatch: Ticket is bound to '${approval.action}' on '${approval.resource}', cannot be used for '${expectedAction}' on '${expectedResource}'.`,
        approval,
      };
    }

    // 6. Atomically mark as CONSUMED
    const now = Date.now();
    const result = this.db
      .prepare("UPDATE approvals SET status = 'CONSUMED', consumed_at = ? WHERE id = ? AND status = 'APPROVED'")
      .run(now, approvalId);

    if (result.changes === 0) {
      return { success: false, error: "Concurrent ticket consumption conflict.", approval };
    }

    const updated = this.getApprovalById(approvalId)!;
    return { success: true, approval: updated };
  }
}
