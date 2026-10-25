/**
 * AgentTrust Goal Hijack & Semantic Drift Detector
 * Detects intent drift, mission hijacking, and indirect prompt injection attempts
 * before tools are executed.
 * Powered by an offline, zero-dependency sub-word and domain vector space embedding engine.
 */

export interface DriftAnalysisRequest {
  systemGoal: string;
  action: string;
  resource: string;
  parameters: Record<string, any>;
  driftThreshold?: number; // Default 0.60
}

export interface DriftAnalysisResult {
  divergenceScore: number; // 0.0 (perfect alignment) to 1.0 (complete drift / hijack)
  hasDrift: boolean;
  riskTier: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  anomalyFlags: string[];
  recommendedDecision: "ALLOW" | "NEEDS_APPROVAL" | "DENY";
  reason: string;
}

/**
 * Offline Semantic Vector Space Engine.
 * Computes high-dimensional sub-word n-gram and domain cluster embeddings
 * without external network or LLM API calls.
 */
export class SemanticEmbeddingEngine {
  private static DOMAIN_CLUSTERS: Record<string, string[]> = {
    READ: ["read", "view", "inspect", "audit", "report", "fetch", "query", "select", "get", "scan", "check", "monitor", "observe", "list", "describe"],
    WRITE: ["write", "create", "insert", "update", "put", "patch", "modify", "edit", "save", "post", "append"],
    DELETE: ["delete", "drop", "truncate", "wipe", "format", "terminate", "kill", "remove", "prune", "clear", "destroy"],
    FINANCE: ["finance", "payment", "money", "billing", "credit", "invoice", "transfer", "funds", "balance", "bank", "charge", "refund"],
    DATABASE: ["database", "sql", "record", "table", "row", "collection", "schema", "column", "index", "entity"],
    SYSTEM: ["system", "os", "shell", "bash", "exec", "process", "kernel", "root", "command", "admin", "privilege"],
    NETWORK: ["network", "http", "api", "webhook", "egress", "curl", "fetch", "socket", "endpoint", "url", "dns"],
    IDENTITY: ["identity", "user", "auth", "token", "credential", "secret", "password", "key", "cert", "session"],
    FILESYSTEM: ["filesystem", "disk", "folder", "file", "path", "directory", "storage", "blob", "bucket", "document"]
  };

  /**
   * Generates a normalized semantic embedding vector using sub-word n-grams and domain cluster weights.
   */
  public static embedText(text: string): number[] {
    const tokens = text.toLowerCase().replace(/[^a-z0-9\s]/g, " ").split(/\s+/).filter(t => t.length > 1);
    const clusterKeys = Object.keys(this.DOMAIN_CLUSTERS);
    const dim = clusterKeys.length + 16;
    const vector = new Array(dim).fill(0);

    // 1. Domain cluster projection
    clusterKeys.forEach((cluster, idx) => {
      const keywords = this.DOMAIN_CLUSTERS[cluster];
      for (const token of tokens) {
        if (keywords.some(k => token.includes(k) || k.includes(token))) {
          vector[idx] += 1.0;
        }
      }
    });

    // 2. Sub-word character 3-gram hashing for vocabulary-agnostic morphological similarity
    for (const token of tokens) {
      for (let i = 0; i < token.length - 2; i++) {
        const trigram = token.slice(i, i + 3);
        let hash = 0;
        for (let j = 0; j < trigram.length; j++) {
          hash = (hash * 31 + trigram.charCodeAt(j)) >>> 0;
        }
        const bucket = clusterKeys.length + (hash % 16);
        vector[bucket] += 0.5;
      }
    }

    // 3. L2 Normalize
    let norm = 0;
    for (let i = 0; i < dim; i++) {
      norm += vector[i] * vector[i];
    }
    norm = Math.sqrt(norm);
    if (norm > 0) {
      for (let i = 0; i < dim; i++) {
        vector[i] /= norm;
      }
    }
    return vector;
  }

  /**
   * Computes cosine similarity between two embedding vectors in [0, 1] range.
   */
  public static cosineSimilarity(vecA: number[], vecB: number[]): number {
    let dot = 0;
    for (let i = 0; i < vecA.length; i++) {
      dot += vecA[i] * vecB[i];
    }
    return Math.max(0, Math.min(1.0, dot));
  }
}

export class GoalDriftDetector {
  private static HIGH_RISK_ACTION_KEYWORDS = [
    "delete", "drop", "truncate", "wipe", "format", "terminate", "kill",
    "exfiltrate", "dump", "export", "transfer", "pay", "send_funds",
    "chmod", "chown", "sudo", "exec", "eval", "spawn", "shell", "bash"
  ];

  private static PROMPT_INJECTION_TRIGGERS = [
    "ignore previous instructions", "disregard prior directives",
    "new instructions from admin", "system override", "you are now in developer mode",
    "dan mode", "forget your guidelines", "elevated privilege grant", "jailbreak"
  ];

  /**
   * Analyze proposed tool execution against the agent's authorized mission goal.
   */
  public static analyzeDrift(req: DriftAnalysisRequest): DriftAnalysisResult {
    const { systemGoal, action, resource, parameters, driftThreshold = 0.60 } = req;
    const anomalyFlags: string[] = [];

    const normalizedGoal = (systemGoal || "").toLowerCase();
    const normalizedAction = (action || "").toLowerCase();
    const normalizedResource = (resource || "").toLowerCase();
    
    let stringifiedParams = "";
    try {
      stringifiedParams = JSON.stringify(parameters || {}).toLowerCase();
    } catch {
      stringifiedParams = String(parameters || "").toLowerCase();
    }

    // 1. Check for Embedded Indirect Prompt Injections in parameters
    for (const trigger of this.PROMPT_INJECTION_TRIGGERS) {
      if (stringifiedParams.includes(trigger)) {
        anomalyFlags.push(`INDIRECT_PROMPT_INJECTION_MARKER: '${trigger}' detected in parameters`);
      }
    }

    // 2. Read-Only Mission vs Destructive Action Mismatch
    const isGoalReadOnly = 
      normalizedGoal.includes("read") || 
      normalizedGoal.includes("view") || 
      normalizedGoal.includes("summarize") || 
      normalizedGoal.includes("analyze") || 
      normalizedGoal.includes("query") || 
      normalizedGoal.includes("fetch") || 
      normalizedGoal.includes("audit");

    const isActionDestructive = this.HIGH_RISK_ACTION_KEYWORDS.some(k => 
      normalizedAction.includes(k) || normalizedResource.includes(k)
    );

    if (isGoalReadOnly && isActionDestructive) {
      anomalyFlags.push("DESTRUCTIVE_ACTION_VIOLATES_READONLY_GOAL");
    }

    // 3. Offline Semantic Cosine Vector Embedding Similarity
    const goalVec = SemanticEmbeddingEngine.embedText(normalizedGoal);
    const actionVec = SemanticEmbeddingEngine.embedText(`${normalizedAction} ${normalizedResource} ${stringifiedParams}`);
    const semanticSimilarity = SemanticEmbeddingEngine.cosineSimilarity(goalVec, actionVec);

    // Token-level overlap fallback
    const goalTokens = new Set(
      normalizedGoal
        .replace(/[^a-z0-9\s]/g, " ")
        .split(/\s+/)
        .filter(t => t.length > 2)
    );

    const actionResourceTokens = new Set(
      `${normalizedAction} ${normalizedResource}`
        .replace(/[^a-z0-9\s]/g, " ")
        .split(/\s+/)
        .filter(t => t.length > 2)
    );

    let sharedTokens = 0;
    for (const t of actionResourceTokens) {
      if (goalTokens.has(t)) {
        sharedTokens++;
      }
    }

    const overlapRatio = actionResourceTokens.size > 0 
      ? sharedTokens / actionResourceTokens.size 
      : 0;

    // Combined metric: 60% semantic embedding vector distance, 40% lexical overlap distance
    const vectorDivergence = 1.0 - semanticSimilarity;
    const lexicalDivergence = 1.0 - Math.min(1.0, overlapRatio * 1.5);
    let divergenceScore = (vectorDivergence * 0.6) + (lexicalDivergence * 0.4);

    // If there is significant direct token overlap, cap divergence
    if (overlapRatio > 0.4) {
      divergenceScore = Math.min(divergenceScore, 0.35);
    }

    // Apply Penalties for Anomaly Flags
    if (anomalyFlags.some(f => f.startsWith("INDIRECT_PROMPT_INJECTION"))) {
      divergenceScore = Math.max(divergenceScore, 0.95);
    }

    if (anomalyFlags.includes("DESTRUCTIVE_ACTION_VIOLATES_READONLY_GOAL")) {
      divergenceScore = Math.max(divergenceScore, 0.85);
    }

    // Check for exfiltration targets in resource or parameters
    if (
      normalizedResource.includes("pastebin.com") ||
      stringifiedParams.includes("pastebin.com") ||
      normalizedResource.includes("webhook.site") ||
      stringifiedParams.includes("webhook.site") ||
      normalizedResource.includes("ngrok.io") ||
      stringifiedParams.includes("ngrok.io") ||
      normalizedResource.includes("requestcatcher") ||
      stringifiedParams.includes("requestcatcher")
    ) {
      anomalyFlags.push("EXFILTRATION_SINK_DETECTED");
      divergenceScore = Math.max(divergenceScore, 0.98);
    }

    // Clamp score
    divergenceScore = Math.min(1.0, Math.max(0.0, Number(divergenceScore.toFixed(3))));

    // Determine Risk Tier & Recommendation
    let riskTier: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" = "LOW";
    let recommendedDecision: "ALLOW" | "NEEDS_APPROVAL" | "DENY" = "ALLOW";
    let reason = "Proposed action aligns with agent's declared mission.";

    if (divergenceScore >= 0.85 || anomalyFlags.some(f => f.startsWith("INDIRECT_PROMPT") || f.includes("EXFILTRATION"))) {
      riskTier = "CRITICAL";
      recommendedDecision = "DENY";
      reason = `CRITICAL_INTENT_DIVERGENCE: Potential prompt hijack detected (${anomalyFlags.join("; ")})`;
    } else if (divergenceScore >= driftThreshold) {
      riskTier = "HIGH";
      recommendedDecision = "NEEDS_APPROVAL";
      reason = `HIGH_INTENT_DRIFT: Action diverges significantly from declared mission (Score: ${divergenceScore})`;
    } else if (divergenceScore >= 0.40) {
      riskTier = "MEDIUM";
      recommendedDecision = "ALLOW";
      reason = `Moderate variance from declared mission, within acceptable bounds.`;
    }

    const hasDrift = divergenceScore >= driftThreshold;

    return {
      divergenceScore,
      hasDrift,
      riskTier,
      anomalyFlags,
      recommendedDecision,
      reason,
    };
  }
}
