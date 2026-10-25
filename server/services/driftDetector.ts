/**
 * AgentTrust Goal Hijack & Semantic Drift Detector
 * Detects intent drift, mission hijacking, and indirect prompt injection attempts
 * before tools are executed.
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

    // 3. Keyword / Concept Overlap & Domain Divergence
    // Tokenize goal and tool context
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

    // Baseline divergence is 1 - overlap
    let divergenceScore = 1.0 - Math.min(1.0, overlapRatio * 1.5);

    // Apply Penalties for Anomaly Flags
    if (anomalyFlags.some(f => f.startsWith("INDIRECT_PROMPT_INJECTION"))) {
      divergenceScore = Math.max(divergenceScore, 0.95);
    }

    if (anomalyFlags.includes("DESTRUCTIVE_ACTION_VIOLATES_READONLY_GOAL")) {
      divergenceScore = Math.max(divergenceScore, 0.85);
    }

    // Check for exfiltration targets (e.g. pastebin, webhook, temp external ips)
    if (
      stringifiedParams.includes("pastebin.com") ||
      stringifiedParams.includes("webhook.site") ||
      stringifiedParams.includes("ngrok.io") ||
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
