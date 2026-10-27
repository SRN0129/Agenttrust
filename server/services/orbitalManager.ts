import { OrbitalNotaryEngine, OrbitalAttestationReceipt, SatelliteNode } from "../../packages/orbital-notary/src/index.js";
import { SpaceKillSwitch, OrbitalKillDirective, KillSwitchStatus } from "../../packages/space-killswitch/src/index.js";
import { DopplerEphemerisEngine, SpaceTimeProofOfLocation, GroundCoordinate, SatelliteOrbitalState, DopplerObservation } from "../../packages/doppler-ephemeris/src/index.js";
import { QkdWitnessEngine, QkdLinkTelemetry, QuantumSessionKeyReceipt } from "../../packages/qkd-witness/src/index.js";
import { AuditLedgerService } from "./audit.js";

export interface OrbitalConfig {
  enabled: boolean;
  autoEnforceOnTier0Actions?: boolean;
  tier0SpendUsdThreshold?: number;
  defaultGroundStation?: GroundCoordinate;
}

export interface OrbitalAttestationOptions {
  agentId: string;
  action: string;
  resource: string;
  payload: Record<string, unknown>;
  groundLocation?: GroundCoordinate;
  requireQkdProtection?: boolean;
}

/**
 * AgentTrust Unified Orbital Manager
 * Coordinates the 4 frontier space-airgap defense modules:
 * 1. Orbital Space-Airgap Notary (LEO Space HSM)
 * 2. Space-Based Dead Man's Switch (Direct-to-Satellite Emergency Freeze)
 * 3. Relativistic Ephemeris & Doppler Proof-of-Space (Anti-Spoofing)
 * 4. Satellite Quantum Key Distribution (QKD) & Entanglement Witness (Q-Day Immunity)
 */
export class OrbitalManager {
  private config: OrbitalConfig;
  private auditService: AuditLedgerService;
  public readonly notary: OrbitalNotaryEngine;
  public readonly killSwitch: SpaceKillSwitch;
  public readonly doppler: DopplerEphemerisEngine;
  public readonly qkd: QkdWitnessEngine;

  constructor(auditService: AuditLedgerService, config?: Partial<OrbitalConfig>) {
    this.auditService = auditService;
    this.config = {
      enabled: config?.enabled ?? true,
      autoEnforceOnTier0Actions: config?.autoEnforceOnTier0Actions ?? true,
      tier0SpendUsdThreshold: config?.tier0SpendUsdThreshold ?? 5000,
      defaultGroundStation: config?.defaultGroundStation ?? { latitude: 37.7749, longitude: -122.4194 },
    };

    this.notary = new OrbitalNotaryEngine();
    this.killSwitch = new SpaceKillSwitch();
    this.doppler = new DopplerEphemerisEngine();
    this.qkd = new QkdWitnessEngine();

    // Hook space killswitch to audit ledger
    this.killSwitch.registerQuarantineCallback((agentId, reason) => {
      this.auditService.append({
        agentId: agentId || "GLOBAL_CLUSTER",
        eventType: "ORBITAL_KILL_DIRECTIVE_ENFORCED",
        action: "orbital:emergency:quarantine",
        resource: "agenttrust:runtime",
        decision: "TERMINATED_CONTAINED",
        payload: {
          reason,
          source: "SPACE_DIRECT_CARRIER_BROADCAST",
          timestamp: Date.now(),
        },
      });
    });
  }

  public isEnabled(): boolean {
    return this.config.enabled;
  }

  public setEnabled(enabled: boolean): void {
    this.config.enabled = enabled;
  }

  public getConfig(): OrbitalConfig {
    return { ...this.config };
  }

  public getConstellation(): SatelliteNode[] {
    return this.notary.getConstellation();
  }

  public getKillSwitchStatus(): KillSwitchStatus {
    return this.killSwitch.getStatus();
  }

  /**
   * Pre-execution authorization hook:
   * Checks if an agent is blocked by an active orbital kill-switch directive
   */
  public isAgentQuarantined(agentId: string): boolean {
    if (!this.config.enabled) return false;
    return this.killSwitch.isAgentBlocked(agentId);
  }

  /**
   * Evaluates whether an action qualifies as Tier-0 and requires an Orbital Attestation Receipt
   */
  public isTier0Action(action: string, estimatedCostUsd: number = 0): boolean {
    if (!this.config.enabled || !this.config.autoEnforceOnTier0Actions) {
      return false;
    }

    const highImpactVerbs = ["drop", "truncate", "terminate", "destroy", "wipe", "drain"];
    const actionLower = action.toLowerCase();
    const hasHighImpactVerb = highImpactVerbs.some(verb => actionLower.includes(verb));
    const exceedsSpendThreshold = estimatedCostUsd >= (this.config.tier0SpendUsdThreshold || 5000);

    return hasHighImpactVerb || exceedsSpendThreshold;
  }

  /**
   * Issues an Orbital Attestation Receipt from LEO constellation
   */
  public issueOrbitalAttestation(options: OrbitalAttestationOptions): OrbitalAttestationReceipt {
    const ground = options.groundLocation || this.config.defaultGroundStation;
    const receipt = this.notary.issueAttestation({
      agentId: options.agentId,
      action: options.action,
      resource: options.resource,
      payload: options.payload,
      groundLocation: ground,
    });

    // Anchor space receipt to cryptographic audit ledger
    this.auditService.append({
      agentId: options.agentId,
      eventType: "ORBITAL_NOTARY_ATTESTATION",
      action: options.action,
      resource: options.resource,
      decision: "ALLOW",
      payload: {
        receiptId: receipt.receiptId,
        satelliteId: receipt.satelliteId,
        noradId: receipt.telemetry.noradId,
        altitudeKm: receipt.telemetry.altitudeKm,
        relativisticGamma: receipt.telemetry.relativisticDilationGamma,
        merkleLeafHash: receipt.merkleLeafHash,
        pqcAlgorithm: receipt.pqcAlgorithm,
      },
    });

    return receipt;
  }

  /**
   * Verifies an Orbital Attestation Receipt
   */
  public verifyOrbitalAttestation(receipt: OrbitalAttestationReceipt): {
    valid: boolean;
    reason?: string;
    spaceAirgapConfirmed: boolean;
  } {
    return this.notary.verifyReceipt(receipt);
  }

  /**
   * Broadcasts an emergency orbital killswitch directive from space
   */
  public async broadcastOrbitalHalt(params: {
    scope: "GLOBAL_KILL" | "AGENT_SPECIFIC" | "CLUSTER_REGION";
    targetAgentId?: string;
    reason: string;
  }): Promise<{ accepted: boolean; reason: string }> {
    const directive = this.killSwitch.generateOrbitalBroadcast({
      scope: params.scope,
      targetAgentId: params.targetAgentId,
      reason: params.reason,
    });

    return await this.killSwitch.receiveSpaceBroadcast(directive);
  }

  /**
   * Verifies an agent's physical location using orbital RF Doppler S-curve
   */
  public verifyProofOfSpace(
    agentId: string,
    claimed: GroundCoordinate,
    sat: SatelliteOrbitalState,
    observation: DopplerObservation
  ): SpaceTimeProofOfLocation {
    const proof = this.doppler.verifyProofOfLocation(agentId, claimed, sat, observation);

    this.auditService.append({
      agentId,
      eventType: proof.verified ? "DOPPLER_PROOF_OF_SPACE_VERIFIED" : "DOPPLER_GEO_SPOOFING_REJECTED",
      action: "orbital:doppler:verify_position",
      resource: `geo:${claimed.latitude},${claimed.longitude}`,
      decision: proof.verified ? "ALLOW" : "DENY",
      payload: {
        proofId: proof.proofId,
        expectedDopplerShiftHz: proof.expectedDopplerShiftHz,
        observedDopplerShiftHz: proof.observedDopplerShiftHz,
        residualHz: proof.dopplerResidualHz,
        confidenceScore: proof.confidenceScore,
        rejectionReason: proof.rejectionReason,
      },
    });

    return proof;
  }

  /**
   * Evaluates Quantum Key Distribution (QKD) transmission and verifies Q-Day immunity
   */
  public evaluateQkdSecurity(agentId: string, simulatedEavesdropper: boolean = false): {
    telemetry: QkdLinkTelemetry;
    receipt: QuantumSessionKeyReceipt;
    safety: { permitted: boolean; reason: string; qDayImmunityActive: boolean };
  } {
    const telemetry = this.qkd.evaluateQkdTransmission({
      simulatedEavesdropperActive: simulatedEavesdropper,
    });

    const receipt = this.qkd.generateQuantumSessionReceipt(agentId, telemetry);
    const safety = this.qkd.evaluateQuantumSafety(receipt);

    this.auditService.append({
      agentId,
      eventType: safety.permitted ? "QKD_QUANTUM_ENTANGLEMENT_CONFIRMED" : "QKD_EAVESDROPPING_INTERCEPTED",
      action: "orbital:qkd:entanglement_witness",
      resource: telemetry.satelliteId,
      decision: safety.permitted ? "ALLOW" : "DENY",
      payload: {
        receiptId: receipt.receiptId,
        qberPercent: telemetry.quantumBitErrorRatePercent,
        chshParameterS: telemetry.chshParameterS,
        channelStatus: telemetry.channelStatus,
        qDayImmunityActive: safety.qDayImmunityActive,
        reason: safety.reason,
      },
    });

    return { telemetry, receipt, safety };
  }
}
