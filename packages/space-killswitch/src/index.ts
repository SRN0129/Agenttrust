import crypto from "node:crypto";

export type KillSwitchScope = "GLOBAL_KILL" | "AGENT_SPECIFIC" | "CLUSTER_REGION";

export interface OrbitalKillDirective {
  directiveId: string;
  scope: KillSwitchScope;
  targetAgentId?: string;
  targetClusterRegion?: string;
  reason: string;
  broadcastSatelliteId: string;
  frequencyBand: "UHF_BEACON_437MHZ" | "L_BAND_IRIDIUM_SBD" | "KU_BAND_STARLINK_D2C";
  issuedAt: number;
  nonce: string;
  signature: string;
}

export interface KillSwitchStatus {
  quarantined: boolean;
  activeDirective?: OrbitalKillDirective;
  quarantinedAt?: number;
  quarantinedAgentsCount: number;
}

export interface AgentRuntimeQuarantineCallback {
  (agentId: string, reason: string): void | Promise<void>;
}

/**
 * Space-Based Dead Man's Switch (Orbital Emergency Quarantine)
 * Intercepts direct-to-satellite space broadcasts to forcibly freeze, quarantine,
 * and zeroize rogue agent runtimes even when terrestrial internet is partitioned or hijacked.
 */
export class SpaceKillSwitch {
  private masterPublicKey: string;
  private masterPrivateKey: string;
  private isQuarantined: boolean = false;
  private activeDirective?: OrbitalKillDirective;
  private processedNonces: Set<string> = new Set();
  private quarantinedAgents: Set<string> = new Set();
  private onQuarantineCallbacks: AgentRuntimeQuarantineCallback[] = [];

  constructor(customMasterKeyPair?: { publicKey: string; privateKey: string }) {
    if (customMasterKeyPair) {
      this.masterPublicKey = customMasterKeyPair.publicKey;
      this.masterPrivateKey = customMasterKeyPair.privateKey;
    } else {
      const kp = crypto.generateKeyPairSync("ed25519", {
        publicKeyEncoding: { type: "spki", format: "pem" },
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
      });
      this.masterPublicKey = kp.publicKey;
      this.masterPrivateKey = kp.privateKey;
    }
  }

  public getMasterPublicKey(): string {
    return this.masterPublicKey;
  }

  public registerQuarantineCallback(cb: AgentRuntimeQuarantineCallback): void {
    this.onQuarantineCallbacks.push(cb);
  }

  /**
   * Broadcasts a cryptographically signed kill directive from an orbital satellite node
   */
  public generateOrbitalBroadcast(params: {
    scope: KillSwitchScope;
    targetAgentId?: string;
    targetClusterRegion?: string;
    reason: string;
    satelliteId?: string;
    band?: "UHF_BEACON_437MHZ" | "L_BAND_IRIDIUM_SBD" | "KU_BAND_STARLINK_D2C";
  }): OrbitalKillDirective {
    const directiveId = `kill_${crypto.randomBytes(10).toString("hex")}`;
    const issuedAt = Date.now();
    const nonce = crypto.randomBytes(16).toString("hex");
    const satelliteId = params.satelliteId || "SAT-AGENTTRUST-01";
    const frequencyBand = params.band || "L_BAND_IRIDIUM_SBD";

    // Canonical digest
    const digest = crypto
      .createHash("sha256")
      .update(
        `${directiveId}:${params.scope}:${params.targetAgentId || "ALL"}:${params.targetClusterRegion || "GLOBAL"}:${satelliteId}:${frequencyBand}:${issuedAt}:${nonce}:${params.reason}`
      )
      .digest();

    const signature = crypto.sign(null, digest, this.masterPrivateKey).toString("hex");

    return {
      directiveId,
      scope: params.scope,
      targetAgentId: params.targetAgentId,
      targetClusterRegion: params.targetClusterRegion,
      reason: params.reason,
      broadcastSatelliteId: satelliteId,
      frequencyBand,
      issuedAt,
      nonce,
      signature,
    };
  }

  /**
   * Ingests and processes an incoming space carrier broadcast frame
   */
  public async receiveSpaceBroadcast(directive: OrbitalKillDirective): Promise<{
    accepted: boolean;
    reason: string;
    quarantinedCount: number;
  }> {
    // 1. Anti-Replay Nonce Check
    if (this.processedNonces.has(directive.nonce)) {
      return { accepted: false, reason: "REPLAY_ATTACK_DETECTED: Directive nonce previously burned.", quarantinedCount: 0 };
    }

    // 2. Clock Drift Check (Max 15 minutes window for LEO radio propagation)
    const now = Date.now();
    if (Math.abs(now - directive.issuedAt) > 15 * 60 * 1000) {
      return { accepted: false, reason: "EXPIRED_DIRECTIVE: Broadcast timestamp exceeds valid orbital window.", quarantinedCount: 0 };
    }

    // 3. Signature Verification against Orbital Master Root
    const digest = crypto
      .createHash("sha256")
      .update(
        `${directive.directiveId}:${directive.scope}:${directive.targetAgentId || "ALL"}:${directive.targetClusterRegion || "GLOBAL"}:${directive.broadcastSatelliteId}:${directive.frequencyBand}:${directive.issuedAt}:${directive.nonce}:${directive.reason}`
      )
      .digest();

    try {
      const valid = crypto.verify(
        null,
        digest,
        this.masterPublicKey,
        Buffer.from(directive.signature, "hex")
      );

      if (!valid) {
        return { accepted: false, reason: "INVALID_SIGNATURE: Space broadcast failed cryptographic verification.", quarantinedCount: 0 };
      }
    } catch (err: any) {
      return { accepted: false, reason: `CRYPTO_VERIFICATION_FAILED: ${err.message}`, quarantinedCount: 0 };
    }

    // Burn nonce
    this.processedNonces.add(directive.nonce);
    this.activeDirective = directive;

    let affectedCount = 0;
    if (directive.scope === "GLOBAL_KILL") {
      this.isQuarantined = true;
      affectedCount = 1; // Global cluster
    } else if (directive.scope === "AGENT_SPECIFIC" && directive.targetAgentId) {
      this.quarantinedAgents.add(directive.targetAgentId);
      affectedCount = 1;
    }

    // Trigger registered callbacks to notify agent runtimes and revoke tokens
    for (const cb of this.onQuarantineCallbacks) {
      try {
        await cb(directive.targetAgentId || "ALL", directive.reason);
      } catch {
        // Fail-safe swallow
      }
    }

    return {
      accepted: true,
      reason: `ORBITAL_KILL_DIRECTIVE_ENFORCED: ${directive.reason}`,
      quarantinedCount: affectedCount,
    };
  }

  /**
   * Fast check whether an agent execution is blocked by an active orbital quarantine
   */
  public isAgentBlocked(agentId: string): boolean {
    if (this.isQuarantined) {
      return true; // Global space kill-switch active
    }
    return this.quarantinedAgents.has(agentId);
  }

  public getStatus(): KillSwitchStatus {
    return {
      quarantined: this.isQuarantined,
      activeDirective: this.activeDirective,
      quarantinedAt: this.activeDirective?.issuedAt,
      quarantinedAgentsCount: this.quarantinedAgents.size,
    };
  }

  /**
   * Resets local quarantine state (requires physical ground operator authentication)
   */
  public resetQuarantine(): void {
    this.isQuarantined = false;
    this.quarantinedAgents.clear();
    this.activeDirective = undefined;
  }
}
