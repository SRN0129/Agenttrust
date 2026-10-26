/**
 * Action-Specific Scoping Engine
 * Enforces granular, verb-level access control on resources rather than binary Allow/Deny.
 * Ensures agents granted read/query access (e.g. SELECT) cannot perform mutative or destructive
 * operations (e.g. UPDATE, DELETE, DROP, TRUNCATE) on the exact same resource.
 */

export type ActionVerb =
  | "SELECT"
  | "INSERT"
  | "UPDATE"
  | "DELETE"
  | "DROP"
  | "ALTER"
  | "TRUNCATE"
  | "GET"
  | "POST"
  | "PUT"
  | "PATCH"
  | "EXECUTE"
  | "ADMIN";

export interface ScopedAction {
  domain: string; // e.g. "database", "cloud", "api", "filesystem"
  target: string; // e.g. "production.orders", "s3:invoices", "/var/log"
  verb: ActionVerb | string; // e.g. "SELECT", "DROP", "GET", "DELETE"
  isDestructive: boolean; // DROP, TRUNCATE, DELETE, RM
  isMutative: boolean; // INSERT, UPDATE, PUT, POST
  canonicalAction: string; // e.g. "database:production.orders:SELECT"
}

export interface ScopeEvaluationResult {
  allowed: boolean;
  effectiveScope: string;
  verb: string;
  isDestructive: boolean;
  reason: string;
}

export class ActionScoper {
  private static DESTRUCTIVE_VERBS = new Set([
    "DROP",
    "TRUNCATE",
    "DELETE",
    "PURGE",
    "DESTROY",
    "TERMINATE",
    "REVOKE",
  ]);

  private static MUTATIVE_VERBS = new Set([
    "INSERT",
    "UPDATE",
    "ALTER",
    "POST",
    "PUT",
    "PATCH",
    "CREATE",
    "WRITE",
  ]);

  /**
   * Parses raw SQL query string to extract the primary operational verb and target table.
   */
  public static extractSqlDetails(query: string): {
    verb: ActionVerb | string;
    targetTable?: string;
    isDestructive: boolean;
    isMutative: boolean;
  } {
    if (!query || typeof query !== "string") {
      return { verb: "UNKNOWN", isDestructive: false, isMutative: false };
    }

    const clean = query.trim().replace(/\/\*[\s\S]*?\*\/|--.*$/gm, "").trim();
    const tokens = clean.split(/\s+/);
    const verb = tokens[0]?.toUpperCase() || "UNKNOWN";

    let targetTable: string | undefined;

    if (verb === "SELECT") {
      const fromIdx = tokens.findIndex(t => t.toUpperCase() === "FROM");
      if (fromIdx !== -1 && tokens[fromIdx + 1]) {
        targetTable = tokens[fromIdx + 1].replace(/[;,`"'\[\]]/g, "");
      }
    } else if (verb === "INSERT") {
      const intoIdx = tokens.findIndex(t => t.toUpperCase() === "INTO");
      if (intoIdx !== -1 && tokens[intoIdx + 1]) {
        targetTable = tokens[intoIdx + 1].replace(/[;,`"'\[\]]/g, "");
      }
    } else if (verb === "UPDATE") {
      if (tokens[1]) {
        targetTable = tokens[1].replace(/[;,`"'\[\]]/g, "");
      }
    } else if (verb === "DELETE") {
      const fromIdx = tokens.findIndex(t => t.toUpperCase() === "FROM");
      if (fromIdx !== -1 && tokens[fromIdx + 1]) {
        targetTable = tokens[fromIdx + 1].replace(/[;,`"'\[\]]/g, "");
      }
    } else if (verb === "DROP" || verb === "TRUNCATE" || verb === "ALTER") {
      const tableIdx = tokens.findIndex(t => t.toUpperCase() === "TABLE");
      if (tableIdx !== -1 && tokens[tableIdx + 1]) {
        targetTable = tokens[tableIdx + 1].replace(/[;,`"'\[\]]/g, "");
      } else if (tokens[1]) {
        targetTable = tokens[1].replace(/[;,`"'\[\]]/g, "");
      }
    }

    const isDestructive = this.DESTRUCTIVE_VERBS.has(verb);
    const isMutative = this.MUTATIVE_VERBS.has(verb);

    return { verb, targetTable, isDestructive, isMutative };
  }

  /**
   * Deconstructs action name, resource, and parameters into a standardized ScopedAction object.
   */
  public static resolveScopedAction(
    action: string,
    resource: string,
    parameters: Record<string, unknown> = {}
  ): ScopedAction {
    let domain = "general";
    let target = resource;
    let verb: ActionVerb | string = "EXECUTE";

    // 1. Database / SQL queries
    if (
      action.startsWith("database:") ||
      action.startsWith("sql:") ||
      parameters.query ||
      parameters.sql
    ) {
      domain = "database";
      const queryStr = String(parameters.query || parameters.sql || "");
      const sqlInfo = this.extractSqlDetails(queryStr);
      verb = sqlInfo.verb;
      if (sqlInfo.targetTable) {
        target = resource === "*" || !resource ? sqlInfo.targetTable : `${resource}.${sqlInfo.targetTable}`;
      }
    }
    // 2. HTTP / REST API tools
    else if (action.startsWith("http:") || action.startsWith("rest:") || parameters.method) {
      domain = "api";
      const method = String(parameters.method || action.split(":")[1] || "GET").toUpperCase();
      verb = method as ActionVerb;
    }
    // 3. Cloud Provider SDKs (AWS, GCP, Azure)
    else if (action.includes(":")) {
      const parts = action.split(":");
      domain = parts[0];
      verb = parts[parts.length - 1].toUpperCase();
      target = resource;
    }

    const isDestructive = this.DESTRUCTIVE_VERBS.has(String(verb).toUpperCase());
    const isMutative = this.MUTATIVE_VERBS.has(String(verb).toUpperCase());
    const canonicalAction = `${domain}:${target}:${verb}`;

    return {
      domain,
      target,
      verb,
      isDestructive,
      isMutative,
      canonicalAction,
    };
  }

  /**
   * Evaluates if a scoped action matches fine-grained capability grants.
   * Prevents destructive or mutative verbs from matching read-only scopes.
   */
  public static evaluateScope(
    scoped: ScopedAction,
    allowedCapabilities: string[]
  ): ScopeEvaluationResult {
    const requestedCanonical = scoped.canonicalAction.toLowerCase();
    const requestedTarget = scoped.target.toLowerCase();
    const requestedVerb = String(scoped.verb).toLowerCase();

    for (const grant of allowedCapabilities) {
      const normGrant = grant.toLowerCase();

      // Exact match e.g. "database:orders:select"
      if (normGrant === requestedCanonical) {
        return {
          allowed: true,
          effectiveScope: grant,
          verb: String(scoped.verb),
          isDestructive: scoped.isDestructive,
          reason: `Action granted by exact action-specific scope '${grant}'.`,
        };
      }

      // Verb-level pattern match e.g. "database:orders:*" or "database:*:select"
      const grantParts = normGrant.split(":");
      if (grantParts.length === 3) {
        const [gDomain, gTarget, gVerb] = grantParts;
        const domainMatch = gDomain === "*" || gDomain === scoped.domain.toLowerCase();
        const targetMatch = gTarget === "*" || gTarget === requestedTarget || requestedTarget.endsWith(`.${gTarget}`);
        const verbMatch = gVerb === "*" || gVerb === requestedVerb;

        // If grant specifies a read-only verb like "select" or "get", reject destructive verbs
        if (domainMatch && targetMatch) {
          if (verbMatch) {
            return {
              allowed: true,
              effectiveScope: grant,
              verb: String(scoped.verb),
              isDestructive: scoped.isDestructive,
              reason: `Action granted by scoped policy '${grant}'.`,
            };
          } else {
            return {
              allowed: false,
              effectiveScope: grant,
              verb: String(scoped.verb),
              isDestructive: scoped.isDestructive,
              reason: `SCOPE_VIOLATION: Verb '${scoped.verb}' is strictly prohibited. Scope '${grant}' only authorizes '${gVerb.toUpperCase()}'.`,
            };
          }
        }
      }

      // Legacy two-part grant e.g. "database:read" vs "database:write"
      if (normGrant === `${scoped.domain}:read` && (requestedVerb === "select" || requestedVerb === "get")) {
        return {
          allowed: true,
          effectiveScope: grant,
          verb: String(scoped.verb),
          isDestructive: scoped.isDestructive,
          reason: `Read verb '${scoped.verb}' granted by general '${grant}' scope.`,
        };
      }
    }

    return {
      allowed: false,
      effectiveScope: "NONE",
      verb: String(scoped.verb),
      isDestructive: scoped.isDestructive,
      reason: `ACTION_SCOPE_DENIED: No scoped permission grants '${scoped.canonicalAction}'. Destructive: ${scoped.isDestructive}.`,
    };
  }
}
