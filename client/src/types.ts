export interface Agent {
  id: string;
  name: string;
  description: string;
  operatorEmail: string;
  framework: string;
  status: "ACTIVE" | "SUSPENDED" | "REVOKED";
  apiKeyPrefix: string;
  allowedCapabilities: string[];
  rateLimitRpm: number;
  spendLimitUsd: number;
  currentSpendUsd: number;
  createdAt: number;
  updatedAt: number;
  revokedAt?: number;
  revocationReason?: string;
  parentAgentId?: string;
}

export interface Policy {
  id: string;
  name: string;
  description: string;
  agent_id: string | null;
  action_pattern: string;
  resource_pattern: string;
  effect: "ALLOW" | "DENY" | "REQUIRE_APPROVAL";
  max_cost_usd: number;
  priority: number;
  created_at: number;
}

export interface Approval {
  id: string;
  agentId: string;
  action: string;
  resource: string;
  parameters: Record<string, any>;
  estimatedCostUsd: number;
  status: "PENDING" | "APPROVED" | "REJECTED" | "EXPIRED" | "CONSUMED";
  executionNonce?: string;
  requestedAt: number;
  expiresAt: number;
  timeRemainingSeconds?: number;
  decidedAt?: number;
  decidedBy?: string;
  decisionReason?: string;
}

export interface AuditEvent {
  index: number;
  eventId: string;
  timestamp: number;
  agentId: string;
  eventType: string;
  action: string;
  resource: string;
  decision: string;
  payload: any;
  payloadHash: string;
  prevHash: string;
  entryHash: string;
}

export interface IntegrityReport {
  valid: boolean;
  totalRecords: number;
  latestHash?: string;
  brokenAt?: number;
  reason?: string;
}

export interface ComplianceReport {
  generatedAt: number;
  reportId: string;
  frameworks: {
    euAiAct: {
      status: string;
      article14HumanOversight: {
        totalHITLApprovals: number;
        approvedCount: number;
        rejectedCount: number;
        expiredCount: number;
        replayBlockedCount: number;
        complianceScore: number;
      };
      article12Traceability: {
        totalAuditEvents: number;
        cryptographicIntegrity: boolean;
        latestTipHash: string;
        notarizedCheckpointsCount: number;
        tamperResistanceScore: number;
      };
    };
    nistAiRmf: {
      governRiskStatus: string;
      mapRiskIdentified: number;
      measureValidationPassRate: number;
      manageMitigationActive: boolean;
    };
  };
}

export interface Checkpoint {
  checkpointId: string;
  index: number;
  merkleRoot: string;
  eventCount: number;
  timestamp: number;
  pqcSignature?: string;
  notarizedBy?: string;
}
