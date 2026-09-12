import { DatabaseSync } from "node:sqlite";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
const sqlite = new DatabaseSync(":memory:");
let batchHook: ((sql: string) => Promise<void>) | undefined;
export function setBatchHook(hook?: (sql: string) => Promise<void>) { batchHook = hook; }
for (const file of readdirSync("drizzle").filter(f => f.endsWith(".sql")).sort()) sqlite.exec(readFileSync(join("drizzle", file), "utf8"));
class Statement {
  values: any[] = [];
  constructor(public sql: string) {}
  bind(...values: any[]) { this.values = values; return this; }
  async run() { const result = sqlite.prepare(this.sql).run(...this.values); return { meta: { changes: Number(result.changes) } }; }
  async first() { return sqlite.prepare(this.sql).get(...this.values) ?? null; }
  async all() { return { results: sqlite.prepare(this.sql).all(...this.values) }; }
}
export function getDatabase(): any { return {
  prepare: (sql: string) => new Statement(sql),
  batch: async (statements: Statement[]) => {
    sqlite.exec("BEGIN");
    try { const result = []; for (const statement of statements) { result.push(await statement.run()); await batchHook?.(statement.sql); } sqlite.exec("COMMIT"); return result; }
    catch (error) { sqlite.exec("ROLLBACK"); throw error; }
  },
}; }
export function resetDatabase() { for (const table of ["watchtower_snapshots", "watchtower_scans", "watchtower_sources", "watchtower_announcements", "watchtower_control"]) sqlite.exec(`DELETE FROM ${table}`); }
