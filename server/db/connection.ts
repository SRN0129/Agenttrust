import Database from "better-sqlite3";
import { DatabaseSync } from "node:sqlite";
import path from "node:path";
import fs from "node:fs";

let dbInstance: any = null;

/**
 * Creates a zero-external-dependency SQLite instance using Node 22+ built-in node:sqlite.
 * Eliminates C++ node-gyp binaries, Python toolchain dependencies, and native binary supply chain vulnerabilities.
 */
export function createBuiltinSqliteDatabase(customPath?: string): any {
  const dbPath = customPath || process.env.DATABASE_PATH || path.resolve(process.cwd(), "data", "agent_trust.db");
  const dir = path.dirname(dbPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  const db = new DatabaseSync(dbPath) as any;
  db.pragma = (cmd: string) => db.exec(`PRAGMA ${cmd};`);
  db.transaction = (fn: (...args: any[]) => any) => {
    return (...args: any[]) => {
      db.exec("BEGIN");
      try {
        const res = fn(...args);
        db.exec("COMMIT");
        return res;
      } catch (err) {
        db.exec("ROLLBACK");
        throw err;
      }
    };
  };

  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  db.pragma("synchronous = NORMAL");

  initializeSchema(db);
  return db;
}

export function getDatabase(customPath?: string): any {
  if (dbInstance && !customPath) {
    return dbInstance;
  }

  if (process.env.USE_BUILTIN_SQLITE === "true") {
    const db = createBuiltinSqliteDatabase(customPath);
    if (!customPath) {
      dbInstance = db;
    }
    return db;
  }

  const dbPath = customPath || process.env.DATABASE_PATH || path.resolve(process.cwd(), "data", "agent_trust.db");
  const dir = path.dirname(dbPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  const db = new Database(dbPath);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  db.pragma("synchronous = NORMAL");

  initializeSchema(db);

  if (!customPath) {
    dbInstance = db;
  }
  return db;
}

export function closeDatabase(): void {
  if (dbInstance) {
    dbInstance.close();
    dbInstance = null;
  }
}

export function initializeSchema(db: Database.Database): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS agents (
      id TEXT PRIMARY KEY,
      tenant_id TEXT DEFAULT 'default',
      name TEXT NOT NULL,
      description TEXT DEFAULT '',
      operator_email TEXT NOT NULL,
      framework TEXT DEFAULT 'Custom',
      status TEXT NOT NULL CHECK(status IN ('ACTIVE', 'SUSPENDED', 'REVOKED')),
      api_key_hash TEXT NOT NULL,
      api_key_prefix TEXT NOT NULL,
      allowed_capabilities TEXT NOT NULL, -- JSON array
      rate_limit_rpm INTEGER DEFAULT 60,
      spend_limit_usd REAL DEFAULT 50.0,
      current_spend_usd REAL DEFAULT 0.0,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL,
      revoked_at INTEGER,
      revocation_reason TEXT
    );

    CREATE TABLE IF NOT EXISTS policies (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT DEFAULT '',
      agent_id TEXT, -- NULL applies to all agents
      action_pattern TEXT NOT NULL, -- e.g. "finance:*", "data:read"
      resource_pattern TEXT NOT NULL, -- e.g. "accounts:*", "*"
      effect TEXT NOT NULL CHECK(effect IN ('ALLOW', 'DENY', 'REQUIRE_APPROVAL')),
      max_cost_usd REAL DEFAULT 0.0,
      priority INTEGER DEFAULT 10,
      created_at INTEGER NOT NULL,
      FOREIGN KEY(agent_id) REFERENCES agents(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS approvals (
      id TEXT PRIMARY KEY,
      agent_id TEXT NOT NULL,
      action TEXT NOT NULL,
      resource TEXT NOT NULL,
      parameters TEXT NOT NULL, -- JSON
      estimated_cost_usd REAL DEFAULT 0.0,
      status TEXT NOT NULL CHECK(status IN ('PENDING', 'APPROVED', 'REJECTED', 'EXPIRED', 'CONSUMED')),
      execution_nonce TEXT UNIQUE,
      requested_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      decided_at INTEGER,
      decided_by TEXT,
      decision_reason TEXT,
      consumed_at INTEGER,
      FOREIGN KEY(agent_id) REFERENCES agents(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS rate_limit_buckets (
      agent_id TEXT NOT NULL,
      window_minute INTEGER NOT NULL,
      request_count INTEGER NOT NULL DEFAULT 1,
      PRIMARY KEY (agent_id, window_minute),
      FOREIGN KEY(agent_id) REFERENCES agents(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS audit_ledger (
      "index" INTEGER PRIMARY KEY AUTOINCREMENT,
      event_id TEXT UNIQUE NOT NULL,
      timestamp INTEGER NOT NULL,
      agent_id TEXT NOT NULL,
      event_type TEXT NOT NULL,
      action TEXT NOT NULL,
      resource TEXT NOT NULL,
      decision TEXT NOT NULL,
      payload_json TEXT NOT NULL,
      payload_hash TEXT NOT NULL,
      prev_hash TEXT NOT NULL,
      entry_hash TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_ledger(agent_id);
    CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_ledger(timestamp);
    CREATE INDEX IF NOT EXISTS idx_approvals_agent_status ON approvals(agent_id, status);
  `);
}
