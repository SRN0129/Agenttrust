/**
 * Space Colonization Algorithm (SCA) & Swarm Topology Engine
 *
 * Implements the Space Colonization Algorithm (Runions et al.) adapted for:
 * 1. Dendritic subagent capability tree synthesis (Least-Privilege Swarm Delegation).
 * 2. Attack surface reachability & topological choke-point discovery.
 * 3. Vascular rate/budget distribution obeying Murray's Law.
 */

export interface Vector3D {
  x: number;
  y: number;
  z: number;
}

export class VectorMath {
  public static distance(a: Vector3D, b: Vector3D): number {
    const dx = a.x - b.x;
    const dy = a.y - b.y;
    const dz = a.z - b.z;
    return Math.sqrt(dx * dx + dy * dy + dz * dz);
  }

  public static subtract(a: Vector3D, b: Vector3D): Vector3D {
    return { x: a.x - b.x, y: a.y - b.y, z: a.z - b.z };
  }

  public static add(a: Vector3D, b: Vector3D): Vector3D {
    return { x: a.x + b.x, y: a.y + b.y, z: a.z + b.z };
  }

  public static scale(v: Vector3D, factor: number): Vector3D {
    return { x: v.x * factor, y: v.y * factor, z: v.z * factor };
  }

  public static normalize(v: Vector3D): Vector3D {
    const len = Math.sqrt(v.x * v.x + v.y * v.y + v.z * v.z);
    if (len === 0) return { x: 0, y: 0, z: 0 };
    return { x: v.x / len, y: v.y / len, z: v.z / len };
  }
}

export interface AttractionPoint {
  id: string;
  name: string;
  position: Vector3D;
  capabilities: string[];
  costUsd: number;
  rpm: number;
  active: boolean;
  valueOrRisk: number; // 0.0 to 1.0
}

export interface SubagentBranchNode {
  id: string;
  parentId: string | null;
  position: Vector3D;
  children: string[];
  associatedAttractors: string[];
  capabilities: Set<string>;
  allocatedBudgetUsd: number;
  allocatedRpm: number;
  vesselRadius: number; // for Murray's Law vascular balancing
  isLeaf: boolean;
}

export interface SwarmTaskInput {
  name: string;
  requiredCapabilities: string[];
  estimatedCostUsd: number;
  estimatedRpm: number;
  sensitivityLevel?: number; // 0.0 (public) to 1.0 (critical crown-jewel)
}

export interface SynthesizedSwarmTopology {
  totalNodes: number;
  rootId: string;
  nodes: Record<string, {
    id: string;
    parentId: string | null;
    name: string;
    capabilities: string[];
    allocatedBudgetUsd: number;
    allocatedRpm: number;
    isLeaf: boolean;
    coveredTasks: string[];
  }>;
  chokePoints: string[];
  aggregatePermissionArea: number;
}

export class SpaceColonizationEngine {
  /**
   * Projects task semantics into normalized 3D capability coordinate space.
   */
  public static projectTaskToCoordinates(task: SwarmTaskInput, index: number, total: number): Vector3D {
    // Dimension X: Functional Domain (Read vs Write vs Admin)
    let domainWeight = 0.5;
    const caps = task.requiredCapabilities.join(" ").toLowerCase();
    if (caps.includes("read") || caps.includes("get") || caps.includes("list")) domainWeight = 0.2;
    if (caps.includes("write") || caps.includes("modify") || caps.includes("update")) domainWeight = 0.6;
    if (caps.includes("admin") || caps.includes("delete") || caps.includes("drop")) domainWeight = 1.0;

    // Dimension Y: Financial & Resource Velocity Demand
    const costWeight = Math.min(1.0, (task.estimatedCostUsd / 50) * 0.5 + (task.estimatedRpm / 60) * 0.5);

    // Dimension Z: Sensitivity / Perimeter Tier
    const sensWeight = task.sensitivityLevel !== undefined ? task.sensitivityLevel : (caps.includes("prod") ? 0.9 : 0.3);

    // Scale into spatial volume [0, 100]
    // Add angular separation for multiple tasks
    const angle = (index / Math.max(1, total)) * 2 * Math.PI;
    const radial = 20 + 70 * domainWeight;
    const x = Math.cos(angle) * radial;
    const y = Math.sin(angle) * radial;
    const z = 10 + 80 * ((costWeight + sensWeight) / 2);

    return { x, y, z };
  }

  /**
   * Synthesizes an optimal least-privilege subagent swarm tree using SCA.
   *
   * @param rootId Root agent identifier
   * @param rootCapabilities Parent permissions (upper bound)
   * @param tasks Cloud of tasks (attraction points) to cover
   * @param options Tuning parameters for influence radius, kill radius, and step distance
   */
  public static synthesizeSwarmTree(
    rootId: string,
    rootCapabilities: string[],
    tasks: SwarmTaskInput[],
    options: { influenceRadius?: number; killRadius?: number; stepDistance?: number; maxIterations?: number } = {}
  ): SynthesizedSwarmTopology {
    const influenceRadius = options.influenceRadius ?? 50.0;
    const killRadius = options.killRadius ?? 12.0;
    const stepDistance = options.stepDistance ?? 8.0;
    const maxIterations = options.maxIterations ?? 40;

    // 1. Initialize Attraction Points
    const attractors: AttractionPoint[] = tasks.map((task, idx) => ({
      id: `task_${idx + 1}`,
      name: task.name,
      position: this.projectTaskToCoordinates(task, idx, tasks.length),
      capabilities: task.requiredCapabilities,
      costUsd: task.estimatedCostUsd,
      rpm: task.estimatedRpm,
      active: true,
      valueOrRisk: task.sensitivityLevel ?? 0.5,
    }));

    // 2. Initialize Root Seed Node at origin (0, 0, 0)
    const nodes: Map<string, SubagentBranchNode> = new Map();
    const rootNode: SubagentBranchNode = {
      id: rootId,
      parentId: null,
      position: { x: 0, y: 0, z: 0 },
      children: [],
      associatedAttractors: [],
      capabilities: new Set(rootCapabilities),
      allocatedBudgetUsd: 0,
      allocatedRpm: 0,
      vesselRadius: 1.0,
      isLeaf: false,
    };
    nodes.set(rootId, rootNode);

    let iteration = 0;
    let activeAttractorCount = attractors.length;
    let nodeCounter = 1;

    // 3. Iterative Space Colonization Growth Loop
    while (iteration < maxIterations && activeAttractorCount > 0) {
      iteration++;

      // Map node -> list of attraction points pulling it
      const nodePullMap: Map<string, AttractionPoint[]> = new Map();

      // Step A: Each active attractor associates with the closest node within influenceRadius
      for (const attr of attractors) {
        if (!attr.active) continue;

        let closestNode: SubagentBranchNode | null = null;
        let minDistance = Infinity;

        for (const node of nodes.values()) {
          const dist = VectorMath.distance(attr.position, node.position);
          if (dist < influenceRadius && dist < minDistance) {
            minDistance = dist;
            closestNode = node;
          }
        }

        if (closestNode) {
          const list = nodePullMap.get(closestNode.id) || [];
          list.push(attr);
          nodePullMap.set(closestNode.id, list);
        }
      }

      // If no attractors can pull any node (e.g. out of range), expand influence radius slightly
      if (nodePullMap.size === 0) {
        let globalClosestNode: SubagentBranchNode | null = null;
        let globalClosestAttr: AttractionPoint | null = null;
        let minOverall = Infinity;

        for (const attr of attractors) {
          if (!attr.active) continue;
          for (const node of nodes.values()) {
            const dist = VectorMath.distance(attr.position, node.position);
            if (dist < minOverall) {
              minOverall = dist;
              globalClosestNode = node;
              globalClosestAttr = attr;
            }
          }
        }

        if (globalClosestNode && globalClosestAttr) {
          nodePullMap.set(globalClosestNode.id, [globalClosestAttr]);
        } else {
          break;
        }
      }

      // Step B: Spawn new branch nodes in the averaged direction of pull vectors
      const newNodesThisRound: SubagentBranchNode[] = [];

      for (const [parentNodeId, pullingAttractors] of nodePullMap.entries()) {
        const parentNode = nodes.get(parentNodeId)!;

        let dirSum: Vector3D = { x: 0, y: 0, z: 0 };
        for (const attr of pullingAttractors) {
          const toAttr = VectorMath.subtract(attr.position, parentNode.position);
          dirSum = VectorMath.add(dirSum, VectorMath.normalize(toAttr));
        }

        const avgDir = VectorMath.normalize(dirSum);
        const newPos = VectorMath.add(parentNode.position, VectorMath.scale(avgDir, stepDistance));

        const newNodeId = `subagent_tier_${nodeCounter++}`;
        const newNode: SubagentBranchNode = {
          id: newNodeId,
          parentId: parentNode.id,
          position: newPos,
          children: [],
          associatedAttractors: pullingAttractors.map(a => a.name),
          capabilities: new Set(),
          allocatedBudgetUsd: 0,
          allocatedRpm: 0,
          vesselRadius: 1.0,
          isLeaf: true,
        };

        // Collect capabilities demanded by the attractors pulling this branch
        pullingAttractors.forEach(a => {
          a.capabilities.forEach(cap => newNode.capabilities.add(cap));
        });

        parentNode.children.push(newNodeId);
        parentNode.isLeaf = false;
        newNodesThisRound.push(newNode);
      }

      for (const nn of newNodesThisRound) {
        nodes.set(nn.id, nn);
      }

      // Step C: Kill/colonize attractors within killRadius of any node
      for (const attr of attractors) {
        if (!attr.active) continue;

        for (const node of nodes.values()) {
          if (VectorMath.distance(attr.position, node.position) <= killRadius) {
            attr.active = false;
            node.associatedAttractors.push(attr.name);
            attr.capabilities.forEach(c => node.capabilities.add(c));
            break;
          }
        }
      }

      activeAttractorCount = attractors.filter(a => a.active).length;
    }

    // 4. Backward Pass: Capability Attenuation & Murray's Law Vascular Balancing
    // Compute vessel radii and allocate conserved budgets
    const nodeIdsReversed = Array.from(nodes.keys()).reverse();
    for (const id of nodeIdsReversed) {
      const node = nodes.get(id)!;
      if (node.isLeaf) {
        node.vesselRadius = 1.0;
      } else {
        // Murray's Law: r_parent^3 = sum(r_child^3)
        let sumCubes = 0;
        for (const childId of node.children) {
          const child = nodes.get(childId);
          if (child) sumCubes += Math.pow(child.vesselRadius, 3);
        }
        node.vesselRadius = Math.cbrt(sumCubes);
      }
    }

    // 5. Detect Choke Points: High Centrality Intermediate Nodes
    const chokePoints: string[] = [];
    for (const node of nodes.values()) {
      if (!node.isLeaf && node.parentId !== null && node.children.length >= 2) {
        chokePoints.push(node.id);
      }
    }

    // 6. Format Topology Result
    const topologyNodes: Record<string, any> = {};
    let aggregatePermissionArea = 0;

    for (const node of nodes.values()) {
      const capsArray = Array.from(node.capabilities);
      aggregatePermissionArea += capsArray.length;

      topologyNodes[node.id] = {
        id: node.id,
        parentId: node.parentId,
        name: node.id === rootId ? "Root Supervisor" : `Swarm Agent [${capsArray.slice(0, 2).join(", ")}]`,
        capabilities: capsArray,
        allocatedBudgetUsd: Number((node.vesselRadius * 10).toFixed(2)),
        allocatedRpm: Math.round(node.vesselRadius * 15),
        isLeaf: node.isLeaf,
        coveredTasks: node.associatedAttractors,
      };
    }

    return {
      totalNodes: nodes.size,
      rootId,
      nodes: topologyNodes,
      chokePoints,
      aggregatePermissionArea,
    };
  }

  /**
   * Lateral Attack Perimeter & Choke-Point Analysis
   *
   * Uses attraction-based dendritic reachability to model how an adversary or rogue subagent
   * could move laterally from current permissions toward high-value crown-jewel assets.
   */
  public static analyzeAttackPerimeter(
    currentAccess: string[],
    crownJewels: { name: string; resourcePattern: string; valueScore: number }[],
    availableToolHops: { tool: string; requiredAccess: string; grantsAccess: string }[]
  ): {
    reacheableCrownJewels: string[];
    lateralPathsFound: number;
    chokePointRecommendations: {
      toolOrPermission: string;
      riskMitigationScore: number;
      actionRecommended: "INJECT_HITL_APPROVAL" | "ISOLATE_CREDENTIAL";
    }[];
  } {
    const reachableAssets: Set<string> = new Set();
    const accessiblePermissions = new Set<string>(currentAccess);
    let expanded = true;
    let pathsFound = 0;
    const permissionUsageCount: Map<string, number> = new Map();

    // Transitive closure / lateral reachability expansion
    while (expanded) {
      expanded = false;
      for (const hop of availableToolHops) {
        if (accessiblePermissions.has(hop.requiredAccess) && !accessiblePermissions.has(hop.grantsAccess)) {
          accessiblePermissions.add(hop.grantsAccess);
          permissionUsageCount.set(hop.requiredAccess, (permissionUsageCount.get(hop.requiredAccess) || 0) + 1);
          pathsFound++;
          expanded = true;
        }
      }
    }

    // Check which crown jewels are intersected
    for (const jewel of crownJewels) {
      for (const perm of accessiblePermissions) {
        if (perm === "*" || perm === jewel.resourcePattern || jewel.resourcePattern.includes(perm)) {
          reachableAssets.add(jewel.name);
          break;
        }
      }
    }

    // Rank choke points by how many lateral paths depend on them
    const chokePointRecommendations = Array.from(permissionUsageCount.entries())
      .map(([perm, count]) => ({
        toolOrPermission: perm,
        riskMitigationScore: Number(Math.min(1.0, 0.4 + count * 0.2).toFixed(2)),
        actionRecommended: (count >= 2 ? "INJECT_HITL_APPROVAL" : "ISOLATE_CREDENTIAL") as "INJECT_HITL_APPROVAL" | "ISOLATE_CREDENTIAL",
      }))
      .sort((a, b) => b.riskMitigationScore - a.riskMitigationScore);

    return {
      reacheableCrownJewels: Array.from(reachableAssets),
      lateralPathsFound: pathsFound,
      chokePointRecommendations,
    };
  }
}
