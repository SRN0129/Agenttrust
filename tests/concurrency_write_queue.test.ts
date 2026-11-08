import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { getDatabase, closeDatabase, SerializedWriteQueue } from "../server/db/connection.js";
import fs from "node:fs";
import path from "node:path";

describe("Enterprise Concurrency & Serialized Write Queue", () => {
  const testDbPath = path.resolve(process.cwd(), "data", "test_concurrency.db");

  beforeEach(() => {
    if (fs.existsSync(testDbPath)) {
      try { fs.unlinkSync(testDbPath); } catch (_) {}
    }
    const db = getDatabase(testDbPath);
    db.exec(`
      CREATE TABLE IF NOT EXISTS concurrency_counters (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        worker_id INTEGER NOT NULL,
        val INTEGER NOT NULL,
        timestamp INTEGER NOT NULL
      );
    `);
  });

  afterEach(() => {
    closeDatabase();
    if (fs.existsSync(testDbPath)) {
      try { fs.unlinkSync(testDbPath); } catch (_) {}
    }
  });

  it("should process 50 simultaneous parallel write transactions with zero SQLITE_BUSY errors", async () => {
    const db = getDatabase(testDbPath);
    const PARALLEL_WORKERS = 50;

    const tasks = Array.from({ length: PARALLEL_WORKERS }, (_, i) => {
      return SerializedWriteQueue.enqueue(() => {
        const stmt = db.prepare("INSERT INTO concurrency_counters (worker_id, val, timestamp) VALUES (?, ?, ?)");
        stmt.run(i, i * 10, Date.now());
        return i;
      });
    });

    const results = await Promise.all(tasks);
    expect(results).toHaveLength(PARALLEL_WORKERS);

    const countRow = db.prepare("SELECT COUNT(*) as total FROM concurrency_counters").get() as { total: number };
    expect(countRow.total).toBe(PARALLEL_WORKERS);
  });
});
