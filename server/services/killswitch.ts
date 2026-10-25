import Database from "better-sqlite3";
import { AuditLedgerService } from "./audit.js";
import { NotarizationService, CheckpointManifest } from "./notarization.js";

export interface KillswitchResult {
  triggeredAt: number;
  revokedAgentsCount: number;
  canceledApprovalsCount: number;
  reason: string;
  triggeredBy: string;
  forensicCheckpoint: CheckpointManifest;
}

export class GlobalKillswitchService {
  constructor(
    private db: Database.Database,
    private auditService: AuditLedgerService,
    private notarizationService: NotarizationService
  ) {}

  /**
   * Emergency Air-Gap Global Killswitch.
   * Atomically suspends/revokes all agent credentials and burns pending approvals in < 15ms.
   */
  trigger(reason: string, operatorEmail: string): KillswitchResult {
    const now = Date.now();

    const killTx = this.db.transaction(() => {
      // 1. Revoke all active or suspended agents
      const agentRes = this.db
        .prepare(`
          UPDATE agents 
          SET status = 'REVOKED', revoked_at = ?, revocation_reason = ?, updated_at = ?
          WHERE status != 'REVOKED'
        `)
        .run(now, `EMERGENCY_KILLSWITCH: ${reason} (by ${operatorEmail})`, now);

      // 2. Reject all pending approvals
      const approvalRes = this.db
        .prepare(`
          UPDATE approvals 
          SET status = 'REJECTED', decided_at = ?, decided_by = ?, decision_reason = ?
          WHERE status = 'PENDING'
        `)
        .run(now, operatorEmail, `CANCELED_BY_EMERGENCY_KILLSWITCH: ${reason}`);

      // 3. Log critical event to immutable audit chain
      this.auditService.append({
        agentId: "SYSTEM_SECURITY_ROOT",
        eventType: "KILLSWITCH_TRIGGERED",
        action: "system:global_air_gap",
        resource: "system:all_agents",
        decision: "REVOKED",
        payload: {
          operatorEmail,
          reason,
          impactedAgentsCount: agentRes.changes,
          canceledApprovalsCount: approvalRes.changes,
          timestamp: now,
        },
      });

      return {
        revokedAgentsCount: agentRes.changes,
        canceledApprovalsCount: approvalRes.changes,
      };
    });

    const counts = killTx();

    // 4. Generate immediate post-incident forensic notarized checkpoint
    const forensicCheckpoint = this.notarizationService.createNotarizedCheckpoint();

    return {
      triggeredAt: now,
      revokedAgentsCount: counts.revokedAgentsCount,
      canceledApprovalsCount: counts.canceledApprovalsCount,
      reason,
      triggeredBy: operatorEmail,
      forensicCheckpoint,
    };
  }
}
