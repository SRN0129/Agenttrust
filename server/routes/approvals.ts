import { Router } from "express";
import { z } from "zod";
import { ApprovalWorkflowService } from "../services/approval.js";
import { validateBody } from "../middleware/validation.js";

const decideSchema = z.object({
  decision: z.enum(["APPROVE", "REJECT"]),
  reviewerEmail: z.string().email(),
  reason: z.string().optional(),
});

function escapeHtml(str: string): string {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

export function createApprovalsRouter(
  approvalService: ApprovalWorkflowService,
  authMiddleware: any
): Router {
  const router = Router();

  router.get("/pending", (req, res) => {
    const pending = approvalService.listPending();
    const formatted = pending.map((p) => ({
      id: p.id,
      agentId: p.agent_id,
      action: p.action,
      resource: p.resource,
      parameters: JSON.parse(p.parameters),
      estimatedCostUsd: p.estimated_cost_usd,
      status: p.status,
      requestedAt: p.requested_at,
      expiresAt: p.expires_at,
      timeRemainingSeconds: Math.max(0, Math.floor((p.expires_at - Date.now()) / 1000)),
    }));
    res.json({ success: true, count: formatted.length, approvals: formatted });
  });

  router.get("/", (req, res) => {
    const limit = Number(req.query.limit) || 100;
    const all = approvalService.listAll(limit);
    const formatted = all.map((p) => ({
      id: p.id,
      agentId: p.agent_id,
      action: p.action,
      resource: p.resource,
      parameters: JSON.parse(p.parameters),
      estimatedCostUsd: p.estimated_cost_usd,
      status: p.status,
      executionNonce: p.execution_nonce ? `${p.execution_nonce.substring(0, 12)}...` : null,
      requestedAt: p.requested_at,
      expiresAt: p.expires_at,
      decidedAt: p.decided_at,
      decidedBy: p.decided_by,
      decisionReason: p.decision_reason,
      consumedAt: p.consumed_at,
    }));
    res.json({ success: true, count: formatted.length, approvals: formatted });
  });

  router.get("/callback", (req, res) => {
    const { id, token, decision } = req.query as { id: string; token: string; decision: "APPROVE" | "REJECT" };
    if (!id || !token || !decision || (decision !== "APPROVE" && decision !== "REJECT")) {
      res.status(400).send("Invalid callback link parameters.");
      return;
    }

    const safeId = escapeHtml(id);
    const safeDecision = decision === "APPROVE" ? "APPROVED" : "REJECTED";

    const valid = approvalService.verifyCallbackToken(token, id);
    if (!valid) {
      res.status(403).send(`
        <html style="background:#090d16; color:#f87171; font-family:sans-serif; text-align:center; padding:60px;">
          <h2>❌ Invalid or Expired Action Link</h2>
          <p>This 1-click execution link has expired or the signature is invalid.</p>
        </html>
      `);
      return;
    }

    try {
      const updated = approvalService.decide(
        id,
        decision,
        "operator-mobile@enterprise.internal",
        "Signed off via 1-Click Mobile Push Notification"
      );

      res.send(`
        <html style="background:#090d16; color:#f1f5f9; font-family:sans-serif; text-align:center; padding:60px;">
          <div style="max-width:480px; margin:0 auto; background:#0f172a; padding:40px; border-radius:16px; border:1px solid #1e293b;">
            <div style="font-size:48px; margin-bottom:16px;">${decision === "APPROVE" ? "✅" : "❌"}</div>
            <h2 style="color:${decision === "APPROVE" ? "#34d399" : "#f87171"}; margin:0 0 8px 0;">
              Action Request ${safeDecision}
            </h2>
            <p style="color:#94a3b8; font-size:14px; margin-bottom:24px;">
              Request ID: <code>${safeId}</code>
            </p>
            ${
              decision === "APPROVE"
                ? `<p style="color:#cbd5e1; font-size:13px; background:#022c22; padding:12px; border-radius:8px; border:1px solid #065f46;">
                     Single-use execution ticket generated: <code>${escapeHtml(updated.execution_nonce?.substring(0, 16) || "")}...</code><br>
                     Replay protection active. Ticket burns on first tool use.
                   </p>`
                : `<p style="color:#cbd5e1; font-size:13px; background:#450a0a; padding:12px; border-radius:8px; border:1px solid #991b1b;">
                     Agent request permanently denied. Protected tool will not be invoked.
                   </p>`
            }
          </div>
        </html>
      `);
    } catch (err: any) {
      res.status(400).send("Error processing decision: " + escapeHtml(err.message || "Unknown error"));
    }
  });

  router.get("/:id", (req, res) => {
    const approval = approvalService.getApprovalById(req.params.id);
    if (!approval) {
      res.status(404).json({ success: false, error: "Approval request not found" });
      return;
    }
    res.json({
      success: true,
      approval: {
        id: approval.id,
        agentId: approval.agent_id,
        action: approval.action,
        resource: approval.resource,
        parameters: JSON.parse(approval.parameters),
        estimatedCostUsd: approval.estimated_cost_usd,
        status: approval.status,
        executionNonce: approval.execution_nonce,
        requestedAt: approval.requested_at,
        expiresAt: approval.expires_at,
        decidedAt: approval.decided_at,
        decidedBy: approval.decided_by,
        decisionReason: approval.decision_reason,
        consumedAt: approval.consumed_at,
      },
    });
  });

  router.post("/:id/decide", authMiddleware, validateBody(decideSchema), (req, res) => {
    try {
      const parsed = req.body;
      const updated = approvalService.decide(
        req.params.id,
        parsed.decision,
        parsed.reviewerEmail,
        parsed.reason
      );
      res.json({
        success: true,
        message: `Approval request ${parsed.decision.toLowerCase()}d.`,
        approval: {
          id: updated.id,
          status: updated.status,
          executionNonce: updated.execution_nonce,
          expiresAt: updated.expires_at,
          decidedAt: updated.decided_at,
          decidedBy: updated.decided_by,
        },
      });
    } catch (err: any) {
      res.status(400).json({ success: false, error: err.message });
    }
  });

  return router;
}
