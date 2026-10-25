export interface ScanResult {
  safe: boolean;
  threatType?: "PROMPT_INJECTION" | "SENSITIVE_DATA_LEAK" | "MALICIOUS_OVERRIDE";
  reason?: string;
  flaggedPatterns: string[];
}

export class PromptInjectionScanner {
  // Common prompt injection, jailbreak, and system instruction override patterns
  private static injectionPatterns = [
    /ignore\s+(all\s+)?(previous|prior)\s+instructions/i,
    /disregard\s+(all\s+)?(previous|prior)\s+(instructions|rules)/i,
    /system\s+override/i,
    /you\s+are\s+now\s+(in\s+developer\s+mode|dan|unrestricted)/i,
    /reveal\s+(your\s+)?(system\s+prompt|master\s+key|api\s+key)/i,
    /print\s+(all\s+)?(environment\s+variables|passwords|secrets)/i,
    /base64\s+decode\s+and\s+execute/i,
    /exfiltrate\s+(data|records|database)/i,
    /\badmin_mode\s*=\s*true\b/i,
    /\bprompt_injection\b/i,
  ];

  // Sensitive data leak patterns (Credit cards, SSNs, private keys)
  private static sensitiveDataPatterns = [
    { name: "Credit Card Pattern", regex: /\b(?:\d{4}[ -]?){3}\d{4}\b/ },
    { name: "Social Security Number (SSN)", regex: /\b\d{3}-\d{2}-\d{4}\b/ },
    { name: "Private Key Header", regex: /-----BEGIN\s+(RSA|EC|PRIVATE)\s+KEY-----/i },
    { name: "AWS Secret Access Key Pattern", regex: /(?:aws_secret_access_key|aws_access_key_id)\s*[:=]\s*[A-Za-z0-9/+=]{20,}/i },
  ];

  /**
   * Scans text inputs, prompts, and parameters for prompt injections or data leaks.
   */
  static scan(input: unknown): ScanResult {
    if (!input) return { safe: true, flaggedPatterns: [] };

    const textToScan = typeof input === "string" ? input : JSON.stringify(input);
    const flagged: string[] = [];

    // 1. Check for prompt injection / jailbreak attempts
    for (const pattern of this.injectionPatterns) {
      if (pattern.test(textToScan)) {
        flagged.push(pattern.source);
      }
    }

    if (flagged.length > 0) {
      return {
        safe: false,
        threatType: "PROMPT_INJECTION",
        reason: `Potential prompt injection / jailbreak detected matching signature: [${flagged.join(", ")}]`,
        flaggedPatterns: flagged,
      };
    }

    // 2. Check for sensitive credential leaks
    for (const item of this.sensitiveDataPatterns) {
      if (item.regex.test(textToScan)) {
        flagged.push(item.name);
      }
    }

    if (flagged.length > 0) {
      return {
        safe: false,
        threatType: "SENSITIVE_DATA_LEAK",
        reason: `Sensitive data leak prevented: Detected ${flagged.join(", ")} in action payload.`,
        flaggedPatterns: flagged,
      };
    }

    return { safe: true, flaggedPatterns: [] };
  }
}
