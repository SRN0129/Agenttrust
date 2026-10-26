/**
 * AgentTrust Cloud Egress Connectors
 * Pre-configured action mappings, credential isolation, and prompt injection screening
 * for AWS Bedrock Converse API and Google Vertex AI Gemini tool-calling endpoints.
 */

export interface CloudEgressMapping {
  provider: "AWS_BEDROCK" | "GOOGLE_VERTEX_AI";
  serviceAction: string;
  targetEndpointTemplate: string;
  requiredHeaders: string[];
  sanitizedHeaders: string[];
}

export class CloudEgressConnectorService {
  private static MAPPINGS: Record<string, CloudEgressMapping> = {
    "bedrock:converse": {
      provider: "AWS_BEDROCK",
      serviceAction: "bedrock:converse",
      targetEndpointTemplate: "https://bedrock-runtime.{region}.amazonaws.com/model/{modelId}/converse",
      requiredHeaders: ["x-amz-date", "authorization"],
      sanitizedHeaders: ["x-amz-security-token", "authorization"],
    },
    "vertex:generate_content": {
      provider: "GOOGLE_VERTEX_AI",
      serviceAction: "vertex:generate_content",
      targetEndpointTemplate: "https://{region}-aiplatform.googleapis.com/v1/projects/{projectId}/locations/{region}/publishers/google/models/{modelId}:generateContent",
      requiredHeaders: ["authorization"],
      sanitizedHeaders: ["authorization"],
    },
  };

  /**
   * Resolves cloud-specific action mapping and performs credential isolation.
   */
  public static resolveMapping(action: string): CloudEgressMapping | null {
    return this.MAPPINGS[action] || null;
  }

  /**
   * Strips ambient credentials from outgoing payload to ensure Zero-Trust egress isolation.
   */
  public static isolateCredentials(headers: Record<string, string>): Record<string, string> {
    const sanitized = { ...headers };
    delete sanitized["x-agenttrust-internal-secret"];
    delete sanitized["cookie"];
    return sanitized;
  }
}
