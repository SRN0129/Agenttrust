import Database from "better-sqlite3";
import { AgentRow, AgentRegistryService } from "./registry.js";
import { AuditLedgerService } from "./audit.js";
import { CapabilitySemilattice } from "./capabilitySemilattice.js";
import { SpaceColonizationEngine, SwarmTaskInput, SynthesizedSwarmTopology } from "./spaceColonization.js";

export interface DelegateSubagentInput {
  parentAgentId: string;
  name: string;
  description?: string;
  framework?: string;
  delegatedCapabilities: string[];
  allocatedSpendLimitUsd: number;
  allocatedRateLimitRpm: number;
}

export class AgentDelegationService {
  constructor(
    private db: Database.Database,
    private registryService: AgentRegistryService,
    private auditService: AuditLedgerService
  ) {
    this.initializeTable();
  }

  private initializeTable() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS agent_delegations (
        parent_agent_id TEXT NOT NULL,
        child_agent_id TEXT PRIMARY KEY,
        delegated_at INTEGER NOT NULL,
        FOREIGN KEY(parent_agent_id) REFERENCES agents(id) ON DELETE CASCADE,
        FOREIGN KEY(child_agent_id) REFERENCES agents(id) ON DELETE CASCADE
      );
    `);
  }

  /**
   * Mint an attenuated subagent with strict capability and budget downscoping
   * verified by Bounded Meet-Semilattice algebra.
   */
  delegateSubagent(input: DelegateSubagentInput): { childAgent: AgentRow; apiKey: string; latticeProof?: string } {
    const parent = this.registryService.getAgentById(input.parentAgentId);
    if (!parent) {
      throw new Error(`Parent agent ${input.parentAgentId} not found.`);
    }

    if (parent.status !== "ACTIVE") {
      throw new Error(`Cannot delegate from non-active parent agent (status: ${parent.status}).`);
    }

    const parentCaps = JSON.parse(parent.allowed_capabilities) as string[];

    // 1. Strict Capability Attenuation via Bounded Meet-Semilattice Non-Amplification Theorem
    const semilatticeCheck = CapabilitySemilattice.verifyNonAmplification(parentCaps, input.delegatedCapabilities);
    if (!semilatticeCheck.valid) {
      const cap = semilatticeCheck.violations[0];
      throw new Error(
        `Attenuation Violation: Parent cannot delegate capability '${cap}' which it does not possess. Parent capabilities: [${parentCaps.join(", ")}].`
      );
    }

    // 2. Strict Budget Ceilings
    const parentRemaining = parent.spend_limit_usd - parent.current_spend_usd;
    if (input.allocatedSpendLimitUsd > parentRemaining) {
      throw new Error(
        `Attenuation Violation: Allocated spend limit ($${input.allocatedSpendLimitUsd.toFixed(2)}) exceeds parent's remaining budget ($${parentRemaining.toFixed(2)}).`
      );
    }

    // 3. Strict Rate Limit Ceilings
    if (input.allocatedRateLimitRpm > parent.rate_limit_rpm) {
      throw new Error(
        `Attenuation Violation: Allocated rate limit (${input.allocatedRateLimitRpm} rpm) exceeds parent's limit (${parent.rate_limit_rpm} rpm).`
      );
    }

    // Register child agent
    const { agent: childAgent, apiKey } = this.registryService.registerAgent({
      name: `${input.name} (Delegated by ${parent.name})`,
      description: input.description || `Subagent delegated by ${parent.id}`,
      operatorEmail: parent.operator_email,
      framework: input.framework || parent.framework,
      allowedCapabilities: input.delegatedCapabilities,
      rateLimitRpm: input.allocatedRateLimitRpm,
      spendLimitUsd: input.allocatedSpendLimitUsd,
    });

    const now = Date.now();
    this.db
      .prepare("INSERT INTO agent_delegations (parent_agent_id, child_agent_id, delegated_at) VALUES (?, ?, ?)")
      .run(parent.id, childAgent.id, now);

    this.auditService.append({
      agentId: childAgent.id,
      eventType: "DELEGATION_MINT",
      action: "agent:delegate_subagent",
      resource: `parent:${parent.id}`,
      decision: "ALLOW",
      payload: {
        parentAgentId: parent.id,
        childAgentId: childAgent.id,
        delegatedCapabilities: input.delegatedCapabilities,
        allocatedBudgetUsd: input.allocatedSpendLimitUsd,
        allocatedRateLimitRpm: input.allocatedRateLimitRpm,
        latticeProof: semilatticeCheck.latticeProof,
      },
    });

    return { childAgent, apiKey, latticeProof: semilatticeCheck.latticeProof };
  }

  /**
   * Synthesizes an optimal least-privilege subagent swarm hierarchy using
   * the Space Colonization Algorithm (SCA).
   */
  synthesizeSwarmTopology(parentAgentId: string, tasks: SwarmTaskInput[]): SynthesizedSwarmTopology {
    const parent = this.registryService.getAgentById(parentAgentId);
    if (!parent) {
      throw new Error(`Parent agent ${parentAgentId} not found.`);
    }

    const parentCaps = JSON.parse(parent.allowed_capabilities) as string[];
    return SpaceColonizationEngine.synthesizeSwarmTree(parent.id, parentCaps, tasks);
  }

  /**
   * Analyzes potential lateral attack paths from an agent's current permissions
   * towards high-value crown-jewel assets and identifies topological choke points.
   */
  analyzePerimeterRisk(
    agentId: string,
    crownJewels: { name: string; resourcePattern: string; valueScore: number }[],
    toolHops: { tool: string; requiredAccess: string; grantsAccess: string }[]
  ) {
    const agent = this.registryService.getAgentById(agentId);
    if (!agent) {
      throw new Error(`Agent ${agentId} not found.`);
    }

    const agentCaps = JSON.parse(agent.allowed_capabilities) as string[];
    return SpaceColonizationEngine.analyzeAttackPerimeter(agentCaps, crownJewels, toolHops);
  }

  /**
   * List subagents delegated by a specific parent
   */
  listSubagents(parentAgentId: string): AgentRow[] {
    return this.db
      .prepare(`
        SELECT a.* FROM agents a
        JOIN agent_delegations d ON a.id = d.child_agent_id
        WHERE d.parent_agent_id = ?
        ORDER BY d.delegated_at DESC
      `)
      .all(parentAgentId) as AgentRow[];
  }

  /**
   * Check if an agent is a subagent and get its parent
   */
  getParent(childAgentId: string): AgentRow | null {
    const row = this.db
      .prepare(`
        SELECT a.* FROM agents a
        JOIN agent_delegations d ON a.id = d.parent_agent_id
        WHERE d.child_agent_id = ?
      `)
      .get(childAgentId) as AgentRow | undefined;

    return row || null;
  }
}
