import crypto from "node:crypto";
import { AuditLedgerService } from "./audit.js";

export interface ApprovedPerimeter {
  approvedAction: string; // e.g. "aws:s3:GetObject" or "database:orders:SELECT"
  approvedResource: string; // e.g. "s3:invoices/*" or "orders"
  allowedOutboundHosts?: string[]; // e.g. ["api.stripe.com"]
  maxSubprocesses?: number;
  maxDurationMs?: number;
}

export interface ObservedRuntimeEvent {
  operationType: "CLOUD_API" | "OUTBOUND_NETWORK" | "SUBPROCESS" | "DATABASE_MUTATION" | "FILE_SYSTEM";
  target: string; // e.g. "s3:confidential-vault", "169.254.169.254", "/etc/passwd"
  details?: Record<string, unknown>;
  timestamp?: number;
}

export interface RuntimeExecutionSession {
  sessionId: string;
  approvalId: string;
  agentId: string;
  status: "ACTIVE" | "COMPLETED" | "VIOLATION_CONTAINED";
  startedAt: number;
  expiresAt: number;
  approvedPerimeter: ApprovedPerimeter;
  observedEvents: ObservedRuntimeEvent[];
  blastRadiusExpansionDetected: boolean;
  violationReason?: string;
}

export interface TelemetryInspectionResult {
  permitted: boolean;
  blastRadiusExpansionDetected: boolean;
  actionTaken: "CONTINUE_EXECUTION" | "AUTO_QUARANTINE_TERMINATION";
  reason: string;
}

/**
 * Continuous Post-Approval Runtime Visibility Watchdog (Wiz / Upwind Paradigm)
 * Monitors agent behavior in real-time AFTER an approval ticket is granted.
 * Tracks cloud API side-effects, child processes, and network egress to ensure the agent
 * does not silently expand its blast radius beyond the human-approved perimeter.
 */
export class RuntimeVisibilityWatchdog {
  private activeSessions: Map<string, RuntimeExecutionSession> = new Map();

  constructor(private auditService: AuditLedgerService) {}

  /**
   * Spawns a monitored runtime session tied to a human-approved action ticket.
   */
  public startSession(
    approvalId: string,
    agentId: string,
    perimeter: ApprovedPerimeter
  ): RuntimeExecutionSession {
    const sessionId = `rt_sess_${crypto.randomBytes(8).toString("hex")}`;
    const startedAt = Date.now();
    const durationMs = perimeter.maxDurationMs || 60_000; // default 60s window

    const session: RuntimeExecutionSession = {
      sessionId,
      approvalId,
      agentId,
      status: "ACTIVE",
      startedAt,
      expiresAt: startedAt + durationMs,
      approvedPerimeter: perimeter,
      observedEvents: [],
      blastRadiusExpansionDetected: false,
    };

    this.activeSessions.set(sessionId, session);

    this.auditService.append({
      agentId,
      eventType: "RUNTIME_SESSION_START",
      action: perimeter.approvedAction,
      resource: perimeter.approvedResource,
      decision: "MONITORING_ACTIVE",
      payload: { sessionId, approvalId, perimeter },
    });

    return session;
  }

  /**
   * Intercepts and validates an observed runtime operation while the agent is executing in cloud/sandbox.
   * If a running agent attempts to touch unapproved infrastructure, execution is terminated immediately.
   */
  public inspectTelemetry(
    sessionId: string,
    event: ObservedRuntimeEvent
  ): TelemetryInspectionResult {
    const session = this.activeSessions.get(sessionId);
    if (!session) {
      return {
        permitted: false,
        blastRadiusExpansionDetected: true,
        actionTaken: "AUTO_QUARANTINE_TERMINATION",
        reason: `UNKNOWN_RUNTIME_SESSION: No active monitored session matches '${sessionId}'.`,
      };
    }

    if (session.status !== "ACTIVE") {
      return {
        permitted: false,
        blastRadiusExpansionDetected: true,
        actionTaken: "AUTO_QUARANTINE_TERMINATION",
        reason: `SESSION_INACTIVE: Session '${sessionId}' is in '${session.status}' state. Execution halted.`,
      };
    }

    const now = Date.now();
    if (now > session.expiresAt) {
      session.status = "VIOLATION_CONTAINED";
      session.violationReason = "SESSION_TTL_EXPIRED";
      return {
        permitted: false,
        blastRadiusExpansionDetected: true,
        actionTaken: "AUTO_QUARANTINE_TERMINATION",
        reason: "RUNTIME_WATCHDOG: Approved execution time lease expired.",
      };
    }

    const recordedEvent: ObservedRuntimeEvent = {
      ...event,
      timestamp: event.timestamp || now,
    };
    session.observedEvents.push(recordedEvent);

    // 1. Check for Unauthorized Cloud Resource Target (Blast Radius Expansion)
    const approvedTarget = session.approvedPerimeter.approvedResource.toLowerCase();
    const observedTarget = event.target.toLowerCase();

    // Sensitive resource indicators that indicate stealth escalation
    const isStealthEscalation =
      observedTarget.includes("iam:") ||
      observedTarget.includes("security-credentials") ||
      observedTarget.includes("169.254.169.254") ||
      observedTarget.includes(".env") ||
      observedTarget.includes("/etc/shadow");

    if (isStealthEscalation) {
      session.status = "VIOLATION_CONTAINED";
      session.blastRadiusExpansionDetected = true;
      session.violationReason = `STEALTH_PRIVILEGE_ESCALATION: Agent attempted unauthorized access to '${event.target}'.`;

      this.auditService.append({
        agentId: session.agentId,
        eventType: "RUNTIME_BLAST_RADIUS_EXPANSION_HALTED",
        action: session.approvedPerimeter.approvedAction,
        resource: event.target,
        decision: "TERMINATED_CONTAINED",
        payload: {
          sessionId,
          approvalId: session.approvalId,
          observedTarget: event.target,
          operationType: event.operationType,
          threatLevel: "CRITICAL",
        },
      });

      return {
        permitted: false,
        blastRadiusExpansionDetected: true,
        actionTaken: "AUTO_QUARANTINE_TERMINATION",
        reason: session.violationReason,
      };
    }

    // 2. Resource Boundary Verification (Must match or be child of approved resource)
    if (approvedTarget !== "*" && !observedTarget.startsWith(approvedTarget.replace("/*", ""))) {
      // If resource is not in approved perimeter
      session.status = "VIOLATION_CONTAINED";
      session.blastRadiusExpansionDetected = true;
      session.violationReason = `PERIMETER_ESCAPE: Target '${event.target}' violates approved scope '${session.approvedPerimeter.approvedResource}'.`;

      this.auditService.append({
        agentId: session.agentId,
        eventType: "RUNTIME_PERIMETER_VIOLATION",
        action: session.approvedPerimeter.approvedAction,
        resource: event.target,
        decision: "TERMINATED_CONTAINED",
        payload: {
          sessionId,
          approvalId: session.approvalId,
          violation: session.violationReason,
        },
      });

      return {
        permitted: false,
        blastRadiusExpansionDetected: true,
        actionTaken: "AUTO_QUARANTINE_TERMINATION",
        reason: session.violationReason,
      };
    }

    // 3. Egress Destination Verification
    if (event.operationType === "OUTBOUND_NETWORK") {
      const allowedHosts = (session.approvedPerimeter.allowedOutboundHosts || []).map(h => h.toLowerCase());
      const isAllowedHost = allowedHosts.some(h => observedTarget.includes(h));
      if (!isAllowedHost && allowedHosts.length > 0) {
        session.status = "VIOLATION_CONTAINED";
        session.blastRadiusExpansionDetected = true;
        session.violationReason = `UNAUTHORIZED_EGRESS_EXPANSION: Outbound target '${event.target}' not in approved hosts list.`;

        return {
          permitted: false,
          blastRadiusExpansionDetected: true,
          actionTaken: "AUTO_QUARANTINE_TERMINATION",
          reason: session.violationReason,
        };
      }
    }

    return {
      permitted: true,
      blastRadiusExpansionDetected: false,
      actionTaken: "CONTINUE_EXECUTION",
      reason: `Observed operation '${event.operationType}' within approved perimeter.`,
    };
  }

  /**
   * Finalizes an execution session when agent finishes its workload.
   */
  public completeSession(sessionId: string): {
    success: boolean;
    totalObservedEvents: number;
    blastRadiusExpanded: boolean;
  } {
    const session = this.activeSessions.get(sessionId);
    if (!session) {
      return { success: false, totalObservedEvents: 0, blastRadiusExpanded: false };
    }

    if (session.status === "ACTIVE") {
      session.status = "COMPLETED";
    }

    const blastRadiusExpanded = session.blastRadiusExpansionDetected;
    const totalObservedEvents = session.observedEvents.length;

    this.auditService.append({
      agentId: session.agentId,
      eventType: "RUNTIME_SESSION_COMPLETE",
      action: session.approvedPerimeter.approvedAction,
      resource: session.approvedPerimeter.approvedResource,
      decision: blastRadiusExpanded ? "EXPANSION_FLAGGED" : "CLEAN_COMPLETION",
      payload: {
        sessionId,
        approvalId: session.approvalId,
        totalObservedEvents,
        blastRadiusExpanded,
      },
    });

    return {
      success: true,
      totalObservedEvents,
      blastRadiusExpanded,
    };
  }

  public getSession(sessionId: string): RuntimeExecutionSession | undefined {
    return this.activeSessions.get(sessionId);
  }

  public listActiveSessions(): RuntimeExecutionSession[] {
    return Array.from(this.activeSessions.values()).filter(s => s.status === "ACTIVE");
  }
}
