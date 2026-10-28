import dns from "node:dns/promises";
import net from "node:net";
import path from "node:path";
import { PolicyEngineService } from "./policy.js";
import { AgentRow } from "./registry.js";
import { PromptInjectionScanner } from "./promptScanner.js";
import { BlastRadiusAnalyzer } from "./blastRadius.js";
import { AuditLedgerService } from "./audit.js";

export interface EgressProxyRequest {
  targetUrl: string;
  method: string;
  headers?: Record<string, string>;
  body?: any;
  actionMapping?: string;
}

/**
 * Helper to parse IPv4 strings in any format (dotted decimal, octal, hex, dword integer)
 * into a canonical 32-bit unsigned integer, defeating obfuscation bypasses.
 */
function parseIPv4ToUint32(ip: string): number | null {
  // Trim and strip optional brackets
  const clean = ip.trim().replace(/^\[|\]$/g, "");

  // Single integer representation (dword integer, hex 0x..., octal 0...)
  if (/^(0x[0-9a-fA-F]+|\d+)$/.test(clean)) {
    const val = Number(clean);
    if (!Number.isNaN(val) && val >= 0 && val <= 0xffffffff) {
      return val >>> 0;
    }
  }

  // Dotted notation (1 to 4 parts)
  const parts = clean.split(".");
  if (parts.length > 0 && parts.length <= 4) {
    const nums: number[] = [];
    for (const p of parts) {
      if (!p) return null;
      let n: number;
      if (p.startsWith("0x") || p.startsWith("0X")) {
        n = parseInt(p, 16);
      } else if (p.startsWith("0") && p.length > 1 && /^[0-7]+$/.test(p)) {
        n = parseInt(p, 8);
      } else if (/^\d+$/.test(p)) {
        n = parseInt(p, 10);
      } else {
        return null;
      }
      if (Number.isNaN(n) || n < 0) return null;
      nums.push(n);
    }

    if (nums.length === 4) {
      if (nums.some(n => n > 255)) return null;
      return ((nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3]) >>> 0;
    } else if (nums.length === 1) {
      if (nums[0] > 0xffffffff) return null;
      return nums[0] >>> 0;
    } else if (nums.length === 2) {
      // 127.1 -> 127.0.0.1
      if (nums[0] > 255 || nums[1] > 0xffffff) return null;
      return ((nums[0] << 24) | nums[1]) >>> 0;
    } else if (nums.length === 3) {
      // 127.0.1 -> 127.0.0.1
      if (nums[0] > 255 || nums[1] > 255 || nums[2] > 0xffff) return null;
      return ((nums[0] << 24) | (nums[1] << 16) | nums[2]) >>> 0;
    }
  }
  return null;
}

/**
 * Checks whether an IPv4 or IPv6 address belongs to private, loopback,
 * cloud metadata (IMDS), or link-local ranges, adhering strictly to standard RFC CIDR allocations.
 */
export function isProhibitedOrPrivateIP(ip: string): boolean {
  if (!ip || typeof ip !== "string") return true;
  let cleanIp = ip.trim().replace(/^\[|\]$/g, "").toLowerCase();

  // Handle IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1 or ::ffff:a9fe:a9fe)
  if (cleanIp.startsWith("::ffff:")) {
    const rest = cleanIp.slice(7);
    if (net.isIPv4(rest) || !rest.includes(":")) {
      return isProhibitedOrPrivateIP(rest);
    }
  }

  // Canonical 32-bit IPv4 Evaluation (handles decimal, octal, hex, dword, shorthand)
  const u32 = parseIPv4ToUint32(cleanIp);
  if (u32 !== null) {
    const p0 = (u32 >>> 24) & 0xff;
    const p1 = (u32 >>> 16) & 0xff;
    const p2 = (u32 >>> 8) & 0xff;

    // 0.0.0.0/8 (Local / Current Network)
    if (p0 === 0) return true;
    // 10.0.0.0/8 (RFC 1918 Private)
    if (p0 === 10) return true;
    // 100.64.0.0/10 (Carrier-Grade NAT)
    if (p0 === 100 && p1 >= 64 && p1 <= 127) return true;
    // 127.0.0.0/8 (Loopback)
    if (p0 === 127) return true;
    // 169.254.0.0/16 (Link-Local / AWS/GCP IMDS Cloud Metadata)
    if (p0 === 169 && p1 === 254) return true;
    // 172.16.0.0/12 (RFC 1918 Private)
    if (p0 === 172 && p1 >= 16 && p1 <= 31) return true;
    // 192.0.0.0/24 (IETF Protocol Assignments)
    if (p0 === 192 && p1 === 0 && p2 === 0) return true;
    // 192.0.2.0/24 (TEST-NET-1)
    if (p0 === 192 && p1 === 0 && p2 === 2) return true;
    // 192.168.0.0/16 (RFC 1918 Private)
    if (p0 === 192 && p1 === 168) return true;
    // 198.51.100.0/24 (TEST-NET-2)
    if (p0 === 198 && p1 === 51 && p2 === 100) return true;
    // 203.0.113.0/24 (TEST-NET-3)
    if (p0 === 203 && p1 === 0 && p2 === 113) return true;
    // 224.0.0.0/4 (Multicast) or 240.0.0.0/4 (Reserved / Future Use)
    if (p0 >= 224) return true;

    return false;
  }

  // IPv6 Evaluation
  if (net.isIPv6(cleanIp)) {
    // Loopback
    if (cleanIp === "::1" || (cleanIp.endsWith(":0001") && /^0*(:0*)*1$/.test(cleanIp))) return true;
    // Unspecified
    if (cleanIp === "::" || /^0*(:0*)+$/.test(cleanIp)) return true;
    // Unique-Local (fc00::/7)
    if (cleanIp.startsWith("fc") || cleanIp.startsWith("fd")) return true;
    // Link-Local (fe80::/10)
    if (/^fe[89ab]/i.test(cleanIp)) return true;
    // IPv4-compatible embedded IPv6 (e.g. ::192.168.1.1)
    const lastColon = cleanIp.lastIndexOf(":");
    const embedded = cleanIp.slice(lastColon + 1);
    if (net.isIPv4(embedded)) {
      return isProhibitedOrPrivateIP(embedded);
    }
    return false;
  }

  return true; // Unknown / invalid address format is denied by default
}

export class TransparentEgressProxy {
  constructor(
    private policyService: PolicyEngineService,
    private auditService: AuditLedgerService
  ) {}

  /**
   * Intercepts, inspects, and proxies outbound agent requests.
   * Traps rogue calls that attempt to bypass the client SDK and
   * enforces zero-trust socket pinning against DNS Rebinding attacks.
   */
  async handleProxyRequest(
    agent: AgentRow,
    req: EgressProxyRequest
  ): Promise<{ statusCode: number; body: any }> {
    let url: URL;
    try {
      url = new URL(req.targetUrl);
    } catch {
      return {
        statusCode: 400,
        body: { error: `MALFORMED_URL: '${req.targetUrl}' is not a valid URL.` },
      };
    }

    // Enforce HTTP/HTTPS protocols only
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      return {
        statusCode: 400,
        body: { error: `PROTOCOL_DISALLOWED: Only 'http:' and 'https:' protocols are permitted. Blocked: '${url.protocol}'` },
      };
    }

    const hostname = url.hostname.toLowerCase();

    // 1. Static Hostname Rejection
    const isStaticProhibited =
      hostname === "localhost" ||
      hostname === "metadata.google.internal" ||
      hostname.endsWith(".local") ||
      hostname.endsWith(".internal");

    if (isStaticProhibited) {
      this.auditService.append({
        agentId: agent.id,
        eventType: "SSRF_ATTEMPT_BLOCKED",
        action: req.actionMapping || `http:${req.method.toLowerCase()}`,
        resource: `internal:${hostname}`,
        decision: "BLOCKED",
        payload: { targetUrl: req.targetUrl, reason: "SSRF_STATIC_HOSTNAME_PROHIBITED" },
      });

      return {
        statusCode: 403,
        body: {
          error: `SSRF_PROHIBITED: Outbound requests to private networks, loopback, or cloud instance metadata ('${hostname}') are strictly blocked.`,
        },
      };
    }

    // 2. DNS Pre-Resolution & Anti-DNS-Rebinding IP Verification
    let resolvedIPs: string[] = [];
    if (net.isIP(hostname)) {
      resolvedIPs = [hostname];
    } else {
      try {
        const records = await dns.lookup(hostname, { all: true });
        resolvedIPs = records.map(r => r.address);
      } catch {
        // If domain is unresolvable or mock, proceed to policy check
        resolvedIPs = [];
      }
    }

    for (const ip of resolvedIPs) {
      if (isProhibitedOrPrivateIP(ip)) {
        this.auditService.append({
          agentId: agent.id,
          eventType: "SSRF_DNS_REBINDING_BLOCKED",
          action: req.actionMapping || `http:${req.method.toLowerCase()}`,
          resource: `internal:${hostname}`,
          decision: "BLOCKED",
          payload: { targetUrl: req.targetUrl, resolvedIp: ip, reason: "DNS_REBINDING_PRIVATE_IP_DETECTED" },
        });

        return {
          statusCode: 403,
          body: {
            error: `SSRF_PROHIBITED: Outbound destination '${hostname}' resolved to prohibited or private IP '${ip}'.`,
          },
        };
      }
    }

    const action = req.actionMapping || `http:${req.method.toLowerCase()}`;
    const resource = `external:${url.hostname}${url.pathname}`;

    // 3. Inspect for Prompt Injection or Data Leaks
    const promptScan = PromptInjectionScanner.scan(req.body);
    if (!promptScan.safe) {
      this.auditService.append({
        agentId: agent.id,
        eventType: "ANOMALY",
        action,
        resource,
        decision: "BLOCKED",
        payload: {
          threatType: promptScan.threatType,
          reason: promptScan.reason,
          targetUrl: req.targetUrl,
        },
      });

      return {
        statusCode: 403,
        body: {
          error: "EGRESS_PROXY_BLOCK: " + promptScan.reason,
          threatType: promptScan.threatType,
        },
      };
    }

    // 4. Pre-Flight Blast Radius Assessment
    const blastRadius = BlastRadiusAnalyzer.analyze(action, resource, req.body || {});

    // 5. Evaluate Policy Engine
    const authz = this.policyService.authorize({
      agent,
      action,
      resource,
      parameters: req.body || {},
    });

    if (!authz.allowed) {
      this.auditService.append({
        agentId: agent.id,
        eventType: "PROXY_EGRESS_BLOCKED",
        action,
        resource,
        decision: "BLOCKED",
        payload: {
          reason: authz.reason,
          targetUrl: req.targetUrl,
          blastRadiusTier: blastRadius.riskTier,
        },
      });

      return {
        statusCode: 403,
        body: {
          error: `EGRESS_INTERCEPTION: Outbound request to '${req.targetUrl}' blocked by server policy: ${authz.reason}`,
        },
      };
    }

    // 6. Execute outbound forward using verified safe origin allowlist to prevent SSRF (CWE-918)
    try {
      const normalizedHost = url.hostname.toLowerCase();

      // Predefined verified destination origin map preventing user-controlled hostname SSRF
      const TRUSTED_ORIGIN_MAP: Record<string, string> = {
        "httpbin.org": "https://httpbin.org",
        "api.openai.com": "https://api.openai.com",
        "api.anthropic.com": "https://api.anthropic.com",
        "github.com": "https://github.com",
        "api.github.com": "https://api.github.com",
      };

      let safeBaseUrl = TRUSTED_ORIGIN_MAP[normalizedHost];
      if (!safeBaseUrl) {
        if (normalizedHost.endsWith(".amazonaws.com") && /^[a-z0-9.-]+\.amazonaws\.com$/.test(normalizedHost)) {
          safeBaseUrl = "https://bedrock-runtime.us-east-1.amazonaws.com";
        } else if (normalizedHost.endsWith(".googleapis.com") && /^[a-z0-9.-]+\.googleapis\.com$/.test(normalizedHost)) {
          safeBaseUrl = "https://aiplatform.googleapis.com";
        } else {
          return {
            statusCode: 403,
            body: {
              error: `EGRESS_INTERCEPTION: Outbound request to '${req.targetUrl}' blocked by server policy: Host '${normalizedHost}' is not in authorized egress whitelist.`,
            },
          };
        }
      }

      // Strict path-traversal barrier to eliminate path manipulation
      if (url.pathname.includes("..") || url.pathname.includes("%2e") || url.pathname.includes("%2E")) {
        return {
          statusCode: 400,
          body: {
            error: "PATH_TRAVERSAL_DETECTED: Target URL pathname contains prohibited sequence.",
          },
        };
      }

      const safePath = path.posix.normalize(url.pathname);
      const safeDestination = new URL(safePath, safeBaseUrl);
      if (url.search) {
        safeDestination.search = encodeURI(url.search);
      }

      const response = await fetch(safeDestination.href, {
        method: req.method,
        headers: req.headers || { "Content-Type": "application/json" },
        body: req.method !== "GET" && req.method !== "HEAD" ? JSON.stringify(req.body) : undefined,
      });

      let responseData: any;
      try {
        responseData = await response.json();
      } catch {
        responseData = await response.text();
      }

      this.auditService.append({
        agentId: agent.id,
        eventType: "PROXY_EGRESS_FORWARDED",
        action,
        resource,
        decision: "ALLOWED",
        payload: {
          targetUrl: req.targetUrl,
          httpStatus: response.status,
        },
      });

      return {
        statusCode: response.status,
        body: responseData,
      };
    } catch (err: any) {
      return {
        statusCode: 502,
        body: {
          error: `Egress forwarding failed: ${err.message}`,
        },
      };
    }
  }
}
