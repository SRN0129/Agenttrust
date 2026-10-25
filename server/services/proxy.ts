import { Request, Response } from "express";
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

export class TransparentEgressProxy {
  constructor(
    private policyService: PolicyEngineService,
    private auditService: AuditLedgerService
  ) {}

  /**
   * Intercepts, inspects, and proxies outbound agent requests.
   * Traps rogue calls that attempt to bypass the client SDK.
   */
  async handleProxyRequest(
    agent: AgentRow,
    req: EgressProxyRequest
  ): Promise<{ statusCode: number; body: any }> {
    const url = new URL(req.targetUrl);
    const action = req.actionMapping || `http:${req.method.toLowerCase()}`;
    const resource = `external:${url.hostname}${url.pathname}`;

    // 1. Inspect for Prompt Injection or Data Leaks
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

    // 2. Pre-Flight Blast Radius Assessment
    const blastRadius = BlastRadiusAnalyzer.analyze(action, resource, req.body || {});

    // 3. Evaluate Policy Engine
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

    // 4. If Allowed, execute outbound HTTP forward
    try {
      const response = await fetch(req.targetUrl, {
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
