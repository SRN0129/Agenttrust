import Database from "better-sqlite3";
import { AuditLedgerService } from "./audit.js";

export interface DiagnosticsReport {
  timestamp: number;
  uptimeSeconds: number;
  memory: {
    rssMb: number;
    heapUsedMb: number;
    heapTotalMb: number;
  };
  database: {
    integrityOk: boolean;
    totalAuditRecords: number;
    chainIntegrityOk: boolean;
    pendingApprovalsCount: number;
    activeAgentsCount: number;
  };
  status: "OPTIMAL" | "DEGRADED" | "REQUIRES_ATTENTION";
  anomaliesDetected: string[];
}

export interface SelfHealActionReport {
  timestamp: number;
  actionsTaken: string[];
  recordsPruned: number;
  approvalsExpired: number;
  walCheckpointed: boolean;
  statusAfterHealing: "OPTIMAL" | "DEGRADED";
}

export class AutonomousSelfHealingService {
  private startTime = Date.now();

  constructor(
    private db: Database.Database,
    private auditService: AuditLedgerService
  ) {}

  /**
   * Run real-time diagnostic health assessment.
   */
  public diagnose(): DiagnosticsReport {
    const mem = process.memoryUsage();
    const anomalies: string[] = [];

    // 1. Memory check (Heap > 400MB is flagged)
    const heapUsedMb = Math.round((mem.heapUsed / 1024 / 1024) * 100) / 100;
    const rssMb = Math.round((mem.rss / 1024 / 1024) * 100) / 100;
    const heapTotalMb = Math.round((mem.heapTotal / 1024 / 1024) * 100) / 100;

    if (heapUsedMb > 400) {
      anomalies.push(`HIGH_MEMORY_PRESSURE: Heap usage at ${heapUsedMb} MB`);
    }

    // 2. Database Low-Level Integrity
    let integrityOk = true;
    try {
      const integrityRow = this.db.prepare("PRAGMA integrity_check").get() as { integrity_check?: string };
      integrityOk = integrityRow?.integrity_check === "ok";
    } catch {
      integrityOk = false;
      anomalies.push("DATABASE_INTEGRITY_CHECK_FAILED");
    }

    // 3. Cryptographic Hash Chain Integrity
    const chainVerification = this.auditService.verifyIntegrity();
    if (!chainVerification.valid) {
      anomalies.push(`AUDIT_CHAIN_CORRUPTION: Broken at #${chainVerification.brokenAt}: ${chainVerification.reason}`);
    }

    // 4. Pending Approvals & Active Agents Count
    const pendingCount = (
      this.db.prepare("SELECT COUNT(*) as count FROM approvals WHERE status = 'PENDING'").get() as { count: number }
    ).count;

    const activeAgentsCount = (
      this.db.prepare("SELECT COUNT(*) as count FROM agents WHERE status = 'ACTIVE'").get() as { count: number }
    ).count;

    const status = anomalies.length === 0 ? "OPTIMAL" : (chainVerification.valid ? "DEGRADED" : "REQUIRES_ATTENTION");

    return {
      timestamp: Date.now(),
      uptimeSeconds: Math.floor((Date.now() - this.startTime) / 1000),
      memory: { rssMb, heapUsedMb, heapTotalMb },
      database: {
        integrityOk,
        totalAuditRecords: chainVerification.totalRecords,
        chainIntegrityOk: chainVerification.valid,
        pendingApprovalsCount: pendingCount,
        activeAgentsCount,
      },
      status,
      anomaliesDetected: anomalies,
    };
  }

  /**
   * Automatically execute self-healing maintenance:
   * - Expire overdue approvals
   * - Prune obsolete rate-limit window buckets (> 60m old)
   * - Checkpoint SQLite WAL log to keep disk space lean
   */
  public executeSelfHealing(): SelfHealActionReport {
    const actionsTaken: string[] = [];
    const now = Date.now();
    const currentMinute = Math.floor(now / 60000);

    // 1. Auto-expire pending approvals past their TTL
    const expireRes = this.db
      .prepare("UPDATE approvals SET status = 'EXPIRED' WHERE status = 'PENDING' AND expires_at < ?")
      .run(now);

    const approvalsExpired = expireRes.changes;
    if (approvalsExpired > 0) {
      actionsTaken.push(`Auto-expired ${approvalsExpired} stale approvals past their TTL.`);
    }

    // 2. Prune old rate limit buckets (> 60m old)
    let recordsPruned = 0;
    try {
      const pruneRes = this.db
        .prepare("DELETE FROM rate_limit_buckets WHERE window_minute < ?")
        .run(currentMinute - 60);
      recordsPruned = pruneRes.changes;
      if (recordsPruned > 0) {
        actionsTaken.push(`Pruned ${recordsPruned} historical rate-limit window records.`);
      }
    } catch {
      // Table may not have old rows
    }

    // 3. SQLite WAL Checkpoint to compact database
    let walCheckpointed = false;
    try {
      this.db.pragma("wal_checkpoint(PASSIVE)");
      walCheckpointed = true;
      actionsTaken.push("Executed SQLite WAL passive checkpoint to compact journal size.");
    } catch {
      walCheckpointed = false;
    }

    const postDiagnosis = this.diagnose();

    return {
      timestamp: now,
      actionsTaken,
      recordsPruned,
      approvalsExpired,
      walCheckpointed,
      statusAfterHealing: postDiagnosis.status === "REQUIRES_ATTENTION" ? "DEGRADED" : "OPTIMAL",
    };
  }
}
