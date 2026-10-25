import Database from "better-sqlite3";
import { AuditLedgerService } from "./audit.js";

export interface MicroBudgetConfig {
  agentId: string;
  runId: string;
  maxSpendUsdPerRun: number;       // e.g. $5.00 limit for this specific mission
  maxVelocityRpm: number;          // e.g. 20 actions per minute
  maxSpendRateUsdPerMin: number;   // e.g. $2.00 per minute
}

export interface VelocityCheckResult {
  allowed: boolean;
  circuitTripped: boolean;
  totalRunSpendUsd: number;
  currentRpm: number;
  currentSpendRatePerMin: number;
  reason: string;
}

interface ActionTimestamp {
  timestamp: number;
  costUsd: number;
}

export class MicroBudgetService {
  private runs: Map<string, {
    config: MicroBudgetConfig;
    totalSpendUsd: number;
    actions: ActionTimestamp[];
    isTripped: boolean;
    tripReason?: string;
  }> = new Map();

  constructor(private db: Database.Database, private auditService?: AuditLedgerService) {}

  /**
   * Initialize a new bounded execution run with dedicated micro-budget and velocity caps.
   */
  public registerRun(config: MicroBudgetConfig) {
    this.runs.set(config.runId, {
      config,
      totalSpendUsd: 0,
      actions: [],
      isTripped: false,
    });
  }

  /**
   * Pre-check action before execution to ensure budget and velocity limits are not breached.
   */
  public checkAndRecord(runId: string, estimatedCostUsd: number = 0): VelocityCheckResult {
    const run = this.runs.get(runId);
    if (!run) {
      // Default permissive if no specific run isolation is active, but still track
      return {
        allowed: true,
        circuitTripped: false,
        totalRunSpendUsd: 0,
        currentRpm: 0,
        currentSpendRatePerMin: 0,
        reason: "No micro-budget constraints applied to this run.",
      };
    }

    if (run.isTripped) {
      return {
        allowed: false,
        circuitTripped: true,
        totalRunSpendUsd: run.totalSpendUsd,
        currentRpm: 0,
        currentSpendRatePerMin: 0,
        reason: `CIRCUIT_BREAKER_ACTIVE: Execution halted due to previous violation: ${run.tripReason}`,
      };
    }

    const now = Date.now();
    const oneMinuteAgo = now - 60000;

    // Prune actions older than 1 minute
    run.actions = run.actions.filter(a => a.timestamp >= oneMinuteAgo);

    const currentRpm = run.actions.length + 1; // including current attempt
    const currentSpendRatePerMin = run.actions.reduce((acc, a) => acc + a.costUsd, 0) + estimatedCostUsd;
    const projectedTotalSpend = run.totalSpendUsd + estimatedCostUsd;

    // Check 1: Exceeded total run allocation
    if (projectedTotalSpend > run.config.maxSpendUsdPerRun) {
      run.isTripped = true;
      run.tripReason = `RUN_BUDGET_EXCEEDED: Projected spend $${projectedTotalSpend.toFixed(2)} exceeds cap $${run.config.maxSpendUsdPerRun.toFixed(2)}`;
      
      this.auditService?.append({
        agentId: run.config.agentId,
        eventType: "CIRCUIT_BREAKER_TRIPPED",
        action: "CIRCUIT_BREAKER_TRIPPED",
        resource: `run:${runId}`,
        decision: "DENY",
        payload: { projectedTotalSpend, cap: run.config.maxSpendUsdPerRun, reason: run.tripReason },
      });

      return {
        allowed: false,
        circuitTripped: true,
        totalRunSpendUsd: run.totalSpendUsd,
        currentRpm,
        currentSpendRatePerMin,
        reason: run.tripReason,
      };
    }

    // Check 2: Action Velocity (RPM) Spike (Infinite loop protection)
    if (currentRpm > run.config.maxVelocityRpm) {
      run.isTripped = true;
      run.tripReason = `VELOCITY_SPIKE_DETECTED: Rate of ${currentRpm} RPM exceeds safe threshold of ${run.config.maxVelocityRpm} RPM`;

      this.auditService?.append({
        agentId: run.config.agentId,
        eventType: "CIRCUIT_BREAKER_TRIPPED",
        action: "CIRCUIT_BREAKER_TRIPPED",
        resource: `run:${runId}`,
        decision: "DENY",
        payload: { currentRpm, maxVelocityRpm: run.config.maxVelocityRpm, reason: run.tripReason },
      });

      return {
        allowed: false,
        circuitTripped: true,
        totalRunSpendUsd: run.totalSpendUsd,
        currentRpm,
        currentSpendRatePerMin,
        reason: run.tripReason,
      };
    }

    // Check 3: Spending Rate Velocity Spike ($/min)
    if (currentSpendRatePerMin > run.config.maxSpendRateUsdPerMin) {
      run.isTripped = true;
      run.tripReason = `SPEND_RATE_SPIKE_DETECTED: Spend rate $${currentSpendRatePerMin.toFixed(2)}/min exceeds limit $${run.config.maxSpendRateUsdPerMin.toFixed(2)}/min`;

      this.auditService?.append({
        agentId: run.config.agentId,
        eventType: "CIRCUIT_BREAKER_TRIPPED",
        action: "CIRCUIT_BREAKER_TRIPPED",
        resource: `run:${runId}`,
        decision: "DENY",
        payload: { currentSpendRatePerMin, maxRate: run.config.maxSpendRateUsdPerMin, reason: run.tripReason },
      });

      return {
        allowed: false,
        circuitTripped: true,
        totalRunSpendUsd: run.totalSpendUsd,
        currentRpm,
        currentSpendRatePerMin,
        reason: run.tripReason,
      };
    }

    // Record allowed action
    run.actions.push({ timestamp: now, costUsd: estimatedCostUsd });
    run.totalSpendUsd = projectedTotalSpend;

    return {
      allowed: true,
      circuitTripped: false,
      totalRunSpendUsd: run.totalSpendUsd,
      currentRpm,
      currentSpendRatePerMin,
      reason: "Within allocated micro-budget and safe velocity parameters.",
    };
  }

  /**
   * Reset a tripped circuit breaker after human review.
   */
  public resetCircuit(runId: string): boolean {
    const run = this.runs.get(runId);
    if (!run) return false;
    run.isTripped = false;
    run.tripReason = undefined;
    run.actions = [];
    return true;
  }

  public getRunStatus(runId: string) {
    const run = this.runs.get(runId);
    if (!run) return null;
    return {
      runId,
      agentId: run.config.agentId,
      totalSpendUsd: run.totalSpendUsd,
      maxSpendUsdPerRun: run.config.maxSpendUsdPerRun,
      isTripped: run.isTripped,
      tripReason: run.tripReason,
      activeWindowActions: run.actions.length,
    };
  }
}
