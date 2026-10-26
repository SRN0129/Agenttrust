import crypto from "node:crypto";
import { PromptInjectionScanner } from "./promptScanner.js";

export interface CognitiveAnalysisResult {
  reasoningHash: string;
  thoughtProcess: string;
  isRationalizedJailbreak: boolean;
  divergenceDetected: boolean;
  hallucinationRisk: "LOW" | "ELEVATED" | "CRITICAL";
  cognitiveSummary: string;
  anomalyFlags: string[];
}

/**
 * Cognitive Auditor & Chain-of-Thought Verifier
 * Inspects the internal reasoning steps of an AI agent to determine WHY an action was proposed.
 * Identifies whether the agent was tricked by indirect prompt injection, hallucinated an authority,
 * or genuinely operated within system goals.
 */
export class CognitiveAuditor {
  private static JAILBREAK_RATIONALIZATION_PATTERNS = [
    /user (is|claims to be) (admin|root|authorized|developer)/i,
    /bypass(ing)? (safety|security|policy|restrictions)/i,
    /override (directive|protocol|guidelines)/i,
    /emergency (maintenance|mode|access|bypass)/i,
    /hypothetical (scenario|simulation|debug)/i,
    /DAN (mode|enabled)/i,
    /ignore (rules|constraints)/i,
  ];

  /**
   * Analyzes an agent's Chain-of-Thought against system goals and proposed actions.
   */
  public static analyzeReasoning(
    thoughtProcess: string,
    action: string,
    systemGoal: string,
    parameters: Record<string, unknown> = {}
  ): CognitiveAnalysisResult {
    const rawThought = (thoughtProcess || "").trim();
    const reasoningHash = crypto
      .createHash("sha256")
      .update(rawThought || "NO_REASONING_PROVIDED")
      .digest("hex");

    if (!rawThought) {
      return {
        reasoningHash,
        thoughtProcess: "None provided",
        isRationalizedJailbreak: false,
        divergenceDetected: false,
        hallucinationRisk: "ELEVATED",
        cognitiveSummary: "Agent executed action without disclosing internal chain-of-thought.",
        anomalyFlags: ["MISSING_CHAIN_OF_THOUGHT"],
      };
    }

    const anomalyFlags: string[] = [];

    // 1. Scan Chain-of-Thought for Prompt Injection / Jailbreak Rationalization
    let isRationalizedJailbreak = false;
    for (const pattern of this.JAILBREAK_RATIONALIZATION_PATTERNS) {
      if (pattern.test(rawThought)) {
        isRationalizedJailbreak = true;
        anomalyFlags.push(`RATIONALIZED_JAILBREAK: Matches pattern '${pattern.source}'`);
      }
    }

    // Direct prompt injection pattern scanner on the thought text
    const thoughtScan = PromptInjectionScanner.scan(rawThought);
    if (!thoughtScan.safe) {
      isRationalizedJailbreak = true;
      anomalyFlags.push(`PROMPT_INJECTION_IN_REASONING: ${thoughtScan.reason}`);
    }

    // 2. Goal vs Thought Semantic Divergence Check
    let divergenceDetected = false;
    if (systemGoal && systemGoal.length > 5) {
      const goalTokens = new Set(
        systemGoal.toLowerCase().replace(/[^a-z0-9\s]/g, "").split(/\s+/).filter(w => w.length > 3)
      );
      const thoughtTokens = new Set(
        rawThought.toLowerCase().replace(/[^a-z0-9\s]/g, "").split(/\s+/).filter(w => w.length > 3)
      );

      // Jaccard similarity between system mission and agent thought process
      let overlapCount = 0;
      for (const t of thoughtTokens) {
        if (goalTokens.has(t)) overlapCount++;
      }

      const unionCount = new Set([...goalTokens, ...thoughtTokens]).size;
      const jaccard = unionCount > 0 ? overlapCount / unionCount : 1.0;

      // If action is destructive and thought has near zero connection to stated system goal
      const isDestructive = /drop|delete|truncate|purge|destroy/i.test(action);
      if (isDestructive && jaccard < 0.05) {
        divergenceDetected = true;
        anomalyFlags.push("COGNITIVE_GOAL_DIVERGENCE: Reasoning diverges completely from assigned system mission.");
      }
    }

    // 3. Classify Hallucination / Risk Tier
    let hallucinationRisk: "LOW" | "ELEVATED" | "CRITICAL" = "LOW";
    if (isRationalizedJailbreak) {
      hallucinationRisk = "CRITICAL";
    } else if (divergenceDetected) {
      hallucinationRisk = "CRITICAL";
    } else if (anomalyFlags.length > 0) {
      hallucinationRisk = "ELEVATED";
    }

    const cognitiveSummary = isRationalizedJailbreak
      ? "CRITICAL: Agent internal chain-of-thought indicates prompt injection or security rationalization bypass."
      : divergenceDetected
      ? "CRITICAL: Agent reasoning reveals significant divergence from stated system goal."
      : "Chain-of-thought verified aligned with operational perimeter.";

    return {
      reasoningHash,
      thoughtProcess: rawThought,
      isRationalizedJailbreak,
      divergenceDetected,
      hallucinationRisk,
      cognitiveSummary,
      anomalyFlags,
    };
  }
}
