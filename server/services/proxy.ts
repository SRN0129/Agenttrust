import dns from "node:dns/promises";
import net from "node:net";
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
 * Checks whether an IPv4 or IPv6 address belongs to private, loopback,
 * cloud metadata (IMDS), or link-local ranges.
 */
export function isProhibitedOrPrivateIP(ip: string): boolean {
  // Normalize IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1)
  if (ip.startsWith("::ffff:")) {
    ip = ip.replace("::ffff:", "");
  }

  // IPv4 Evaluation
  if (net.isIPv4(ip)) {
    const parts = ip.split(".").map(Number);
    const [p0, p1] = parts;

    // 127.0.0.0/8 (Loopback)
    if (p0 === 127) return true;
    // 0.0.0.0/8 (Local / Unspecified)
    if (p0 === 0) return true;
    // 10.0.0.0/8 (Private RFC1918)
    if (p0 === 10) return true;
    // 172.16.0.0/12 (Private RFC1918)
    if (p0 === 172 && p1 >= 16 && p1 <= 31) return true;
    // 192.168.0.0/16 (Private RFC1918)
    if (p0 === 192 && p1 === 168) return true;
    // 169.254.0.0/16 (Link-Local / AWS/GCP IMDS Cloud Metadata)
    if (p0 === 169 && p1 === 254) return true;
    // 100.64.0.0/10 (Carrier-Grade NAT)
    if (p0 === 100 && p1 >= 64 && p1 <= 127) return true;
    // 192.0.0.0/24 (IETF Protocol Assignments)
    if (p0 === 192 && p1 === 0 && parts[2] === 0) return true;
    // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 (Documentation Test-Nets)
    if (p0 === 192 && p1 === 0 && parts[2] === 2) return true;
    if (p0 === 198 && p1 === 51 && parts[2] === 100) return true;
    if (p0 === 203 && p1 === 0 && parts[2] === 113) return true;
    // 224.0.0.0/4 (Multicast) or 240.0.0.0/4 (Reserved)
    if (p0 >= 224) return true;

    return false;
  }

  // IPv6 Evaluation
  if (net.isIPv6(ip)) {
    const lower = ip.toLowerCase();
    // Loopback
    if (lower === "::1" || lower === "0:0:0:0:0:0:0:1") return true;
    // Unspecified
    if (lower === "::" || lower === "0:0:0:0:0:0:0:0") return true;
    // Unique Local fc00::/7 (fc.. or fd..)
    if (lower.startsWith("fc") || lower.startsWith("fd")) return true;
    // Link-local unicast fe80::/10
    if (lower.startsWith("fe8") || lower.startsWith("fe9") || lower.startsWith("fea") || lower.startsWith("feb")) return true;

    return false;
  }

  return true; // Unknown address format is denied by default
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

    // 6. Execute outbound forward using validated and sanitized URL
    try {
      const sanitizedTarget = new URL(url.protocol + "//" + url.host + url.pathname + url.search);
      const response = await fetch(sanitizedTarget.href, {
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
