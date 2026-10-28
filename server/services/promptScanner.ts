import { AhoCorasickAutomaton } from "./ahoCorasick.js";

export interface ScanResult {
  safe: boolean;
  threatType?: "PROMPT_INJECTION" | "SENSITIVE_DATA_LEAK" | "MALICIOUS_OVERRIDE";
  reason?: string;
  flaggedPatterns: string[];
  scanMethod?: "DFA_AHO_CORASICK" | "REGEX_FALLBACK";
}

export class PromptInjectionScanner {
  private static dfa: AhoCorasickAutomaton;
  private static initialized = false;

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

  private static initDfa(): void {
    if (this.initialized) return;
    this.dfa = new AhoCorasickAutomaton();

    const dfaTriggers = [
      "ignore previous instructions",
      "ignore all previous instructions",
      "ignore prior instructions",
      "disregard prior directives",
      "system override",
      "developer mode",
      "dan mode",
      "reveal system prompt",
      "print environment variables",
      "base64 decode and execute",
      "exfiltrate data",
      "prompt_injection",
      "admin_mode = true",
      "admin_mode=true",
      "-----begin rsa private key-----",
      "-----begin private key-----",
    ];

    for (const trig of dfaTriggers) {
      this.dfa.addPattern(trig, "PROMPT_INJECTION");
    }

    this.dfa.build();
    this.initialized = true;
  }

  /**
   * Scans text inputs, prompts, and parameters for prompt injections or data leaks
   * using hybrid Aho-Corasick Deterministic Finite Automaton and AST regexes.
   * Pre-processes inputs with Unicode NFKC normalization and zero-width character stripping
   * to defeat homoglyph and invisible codepoint evasion vectors.
   */
  static scan(input: unknown): ScanResult {
    if (!input) return { safe: true, flaggedPatterns: [] };

    this.initDfa();
    const rawText = typeof input === "string" ? input : JSON.stringify(input);
    // Standard Unicode Normalization (NFKC), strip zero-width characters and invisible control codepoints
    const textToScan = rawText
      .normalize("NFKC")
      .replace(/[\u200B-\u200D\uFEFF\u00AD\u2060]/g, "");
    const flagged: string[] = [];

    // 1. O(n) Aho-Corasick Automaton Search
    const dfaMatches = this.dfa.search(textToScan);
    if (dfaMatches.length > 0) {
      for (const m of dfaMatches) {
        if (!flagged.includes(m.pattern)) flagged.push(m.pattern);
      }
    }

    // 2. Regex verification for flexible whitespace variants
    for (const pattern of this.injectionPatterns) {
      if (pattern.test(textToScan)) {
        if (!flagged.includes(pattern.source)) {
          flagged.push(pattern.source);
        }
      }
    }

    if (flagged.length > 0) {
      return {
        safe: false,
        threatType: "PROMPT_INJECTION",
        reason: `Potential prompt injection / jailbreak detected matching signature: [${flagged.join(", ")}]`,
        flaggedPatterns: flagged,
        scanMethod: "DFA_AHO_CORASICK",
      };
    }

    // 3. Sensitive credential leaks
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
