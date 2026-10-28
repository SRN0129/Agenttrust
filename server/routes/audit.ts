import { Router } from "express";
import { z } from "zod";
import { AuditLedgerService } from "../services/audit.js";
import { AgentRow } from "../services/registry.js";
import { validateBody } from "../middleware/validation.js";

const tamperTestSchema = z.object({
  index: z.number().int().positive(),
  maliciousAction: z.string().optional(),
});

const outcomeSchema = z.object({
  action: z.string().min(1),
  resource: z.string().min(1),
  executionStatus: z.string(),
  outputSummary: z.string().optional(),
  details: z.record(z.string(), z.any()).optional(),
});

export function createAuditRouter(
  auditService: AuditLedgerService,
  authAgentMiddleware: any
): Router {
  const router = Router();

  router.get("/", (req, res) => {
    const limit = Math.min(200, Number(req.query.limit) || 50);
    const offset = Number(req.query.offset) || 0;
    const agentId = req.query.agentId as string | undefined;
    const eventType = req.query.eventType as string | undefined;
    const decision = req.query.decision as string | undefined;

    const { total, events } = auditService.listEvents({
      agentId,
      eventType,
      decision,
      limit,
      offset,
    });

    const parsedEvents = events.map((e) => ({
      index: e.index,
      eventId: e.event_id,
      timestamp: e.timestamp,
      agentId: e.agent_id,
      eventType: e.event_type,
      action: e.action,
      resource: e.resource,
      decision: e.decision,
      payload: JSON.parse(e.payload_json),
      payloadHash: e.payload_hash,
      prevHash: e.prev_hash,
      entryHash: e.entry_hash,
    }));

    res.json({
      success: true,
      total,
      limit,
      offset,
      events: parsedEvents,
    });
  });

  router.get("/verify", (req, res) => {
    const result = auditService.verifyIntegrity();
    res.json({
      success: true,
      integrity: result,
      tamperResistantStatus: result.valid ? "CHAIN_VERIFIED_INTACT" : "CHAIN_TAMPERED",
      verifiedAt: Date.now(),
      disclaimer: "Cryptographic hash chaining ensures detection of row modifications or deletions within the sequential ledger. It does not replace independent multi-party notarization.",
    });
  });

  router.post("/tamper-test", validateBody(tamperTestSchema), (req, res) => {
    const index = Number(req.body.index);
    const maliciousAction = req.body.maliciousAction || "malicious:tampered_action";
    auditService.tamperRecordForTesting(index, maliciousAction);
    const check = auditService.verifyIntegrity();
    res.json({
      success: true,
      message: `Directly altered row #${index} in SQLite DB to demonstrate tamper detection.`,
      verificationResult: check,
    });
  });

  router.post("/outcome", authAgentMiddleware, validateBody(outcomeSchema), (req, res) => {
    const agent = (req as any).agent as AgentRow;
    const { action, resource, executionStatus, outputSummary, details } = req.body;

    const entry = auditService.append({
      agentId: agent.id,
      eventType: "EXECUTION_OUTCOME",
      action,
      resource,
      decision: executionStatus === "SUCCESS" ? "EXECUTED" : "FAILED",
      payload: {
        executionStatus,
        outputSummary,
        details: details || {},
      },
    });

    res.json({
      success: true,
      auditIndex: entry.index,
      entryHash: entry.entry_hash,
    });
  });

  return router;
}
