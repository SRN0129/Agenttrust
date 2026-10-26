export interface BlastRadiusAssessment {
  riskScore: number; // 0.0 to 1.0
  riskTier: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  reversibilityFactor: number;
  financialImpactFactor: number;
  sensitivityFactor: number;
  escalationRequired: boolean;
  reasons: string[];
}

export class BlastRadiusAnalyzer {
  /**
   * Pre-flight semantic risk evaluation before policy execution.
   */
  static analyze(
    action: string,
    resource: string,
    parameters: Record<string, unknown> = {},
    estimatedCostUsd = 0
  ): BlastRadiusAssessment {
    const reasons: string[] = [];
    const lowerAction = action.toLowerCase();
    const lowerResource = resource.toLowerCase();

    // 1. Reversibility Factor (0.0 to 1.0)
    let reversibilityFactor = 0.1;
    if (lowerAction.includes("read") || lowerAction.includes("get") || lowerAction.includes("search") || lowerAction.includes("list")) {
      reversibilityFactor = 0.05;
      reasons.push("Idempotent read-only action (low operational risk).");
    } else if (lowerAction.includes("draft") || lowerAction.includes("stage") || lowerAction.includes("simulate")) {
      reversibilityFactor = 0.2;
      reasons.push("Staging action without irreversible external side-effects.");
    } else if (lowerAction.includes("update") || lowerAction.includes("modify") || lowerAction.includes("patch")) {
      reversibilityFactor = 0.55;
      reasons.push("State modification action with potential rollback overhead.");
    } else if (lowerAction.includes("wire") || lowerAction.includes("transfer") || lowerAction.includes("payout") || lowerAction.includes("deploy")) {
      reversibilityFactor = 0.85;
      reasons.push("High-impact external side-effect (difficult to reverse).");
    } else if (lowerAction.includes("drop") || lowerAction.includes("delete") || lowerAction.includes("truncate") || lowerAction.includes("destroy") || lowerAction.includes("purge")) {
      reversibilityFactor = 1.0;
      reasons.push("Permanent destructive action (irreversible data loss).");
    }

    // 2. Financial Impact Factor (0.0 to 1.0)
    let financialImpactFactor = 0.0;
    if (estimatedCostUsd > 0) {
      if (estimatedCostUsd < 50) {
        financialImpactFactor = 0.2;
      } else if (estimatedCostUsd < 250) {
        financialImpactFactor = 0.5;
        reasons.push(`Moderate financial exposure ($${estimatedCostUsd.toFixed(2)}).`);
      } else if (estimatedCostUsd < 1000) {
        financialImpactFactor = 0.8;
        reasons.push(`Substantial financial expenditure ($${estimatedCostUsd.toFixed(2)}).`);
      } else {
        financialImpactFactor = 1.0;
        reasons.push(`Critical financial expenditure exceeding threshold ($${estimatedCostUsd.toFixed(2)}).`);
      }
    }

    // 3. Sensitivity & Target Perimeter Factor (0.0 to 1.0)
    let sensitivityFactor = 0.1;
    const sensitiveKeywords = ["prod", "production", "master", "root", "auth", "secret", "pci", "vault", "customer_records"];
    const matchedSensitive = sensitiveKeywords.filter(k => lowerResource.includes(k) || lowerAction.includes(k));

    if (matchedSensitive.length > 0) {
      sensitivityFactor = Math.min(1.0, 0.4 + matchedSensitive.length * 0.3);
      reasons.push(`Target resource matches sensitive perimeter keywords: [${matchedSensitive.join(", ")}].`);
    }

    // Composite Weighted Risk Formula
    let compositeScore = Number(
      (0.45 * reversibilityFactor + 0.35 * financialImpactFactor + 0.20 * sensitivityFactor).toFixed(2)
    );

    // Destructive action on sensitive/production assets is automatically critical
    if (reversibilityFactor >= 0.9 && sensitivityFactor >= 0.7) {
      compositeScore = Math.max(0.9, compositeScore);
      reasons.push("CRITICAL COMBINATION: Irreversible destruction targeting sensitive production assets.");
    }

    let riskTier: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
    let escalationRequired = false;

    if (compositeScore >= 0.85) {
      riskTier = "CRITICAL";
      escalationRequired = true;
    } else if (compositeScore >= 0.65) {
      riskTier = "HIGH";
      escalationRequired = true;
    } else if (compositeScore >= 0.35) {
      riskTier = "MEDIUM";
    } else {
      riskTier = "LOW";
    }

    return {
      riskScore: compositeScore,
      riskTier,
      reversibilityFactor,
      financialImpactFactor,
      sensitivityFactor,
      escalationRequired,
      reasons,
    };
  }
}
