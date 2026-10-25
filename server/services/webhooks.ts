import { ApprovalRow } from "./approval.js";
import { BlastRadiusAssessment } from "./blastRadius.js";

export interface WebhookConfig {
  url?: string;
  enabled: boolean;
  channelName?: string;
}

export class WebhookNotificationService {
  private config: WebhookConfig;

  constructor() {
    this.config = {
      url: process.env.SLACK_WEBHOOK_URL || "",
      enabled: Boolean(process.env.SLACK_WEBHOOK_URL),
      channelName: "#agent-security-approvals",
    };
  }

  setConfig(config: WebhookConfig) {
    this.config = config;
  }

  getConfig(): WebhookConfig {
    return this.config;
  }

  /**
   * Format and dispatch Slack/Teams compatible approval request notification.
   */
  async notifyApprovalRequest(
    approval: ApprovalRow,
    agentName: string,
    blastRadius?: BlastRadiusAssessment,
    callbackToken?: string,
    baseUrl = "http://localhost:4000"
  ): Promise<any> {
    const approveUrl = callbackToken
      ? `${baseUrl}/api/v1/approvals/callback?id=${approval.id}&token=${callbackToken}&decision=APPROVE`
      : "";
    const rejectUrl = callbackToken
      ? `${baseUrl}/api/v1/approvals/callback?id=${approval.id}&token=${callbackToken}&decision=REJECT`
      : "";

    const payload = {
      text: `🚨 [AgentTrust] Approval Required: Agent '${agentName}' requesting '${approval.action}'`,
      approveUrl,
      rejectUrl,
      blocks: [
        {
          type: "header",
          text: {
            type: "plain_text",
            text: "🛡️ AgentTrust: 1-Click Human Decision Required",
          },
        },
        {
          type: "section",
          fields: [
            { type: "mrkdwn", text: `*Agent:*\n${agentName} (\`${approval.agent_id}\`)` },
            { type: "mrkdwn", text: `*Target Action:*\n\`${approval.action}\`` },
            { type: "mrkdwn", text: `*Target Resource:*\n\`${approval.resource}\`` },
            {
              type: "mrkdwn",
              text: `*Risk Tier:*\n${
                blastRadius ? `*${blastRadius.riskTier}* (Score: ${blastRadius.riskScore})` : "MEDIUM"
              }`,
            },
          ],
        },
        {
          type: "section",
          text: {
            type: "mrkdwn",
            text: `*Parameters:*\n\`\`\`${approval.parameters}\`\`\``,
          },
        },
        {
          type: "actions",
          elements: [
            {
              type: "button",
              text: { type: "plain_text", text: "✅ Approve from Phone" },
              style: "primary",
              url: approveUrl,
            },
            {
              type: "button",
              text: { type: "plain_text", text: "❌ Reject Action" },
              style: "danger",
              url: rejectUrl,
            },
          ],
        },
        {
          type: "context",
          elements: [
            {
              type: "mrkdwn",
              text: `⏱️ Single-use execution ticket will expire at ${new Date(approval.expires_at).toISOString()}. Replay protection enforced.`,
            },
          ],
        },
      ],
    };

    if (this.config.enabled && this.config.url) {
      try {
        await fetch(this.config.url, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
      } catch (err) {
        console.warn("Webhook dispatch failed:", err);
      }
    }

    return payload;
  }
}
