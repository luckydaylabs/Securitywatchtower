import { index, integer, sqliteTable, text } from "drizzle-orm/sqlite-core";

export const watchtowerSnapshots = sqliteTable(
  "watchtower_snapshots",
  {
    id: text("id").primaryKey(),
    checkedAt: text("checked_at").notNull(),
    trigger: text("trigger").notNull(),
    findingCount: integer("finding_count").notNull().default(0),
    criticalCount: integer("critical_count").notNull().default(0),
    platformCount: integer("platform_count").notNull().default(0),
    findingsJson: text("findings_json").notNull(),
    message: text("message").notNull(),
    createdAt: text("created_at").notNull(),
  },
  (table) => ({
    checkedAtIndex: index("idx_watchtower_snapshots_checked_at").on(table.checkedAt),
  }),
);
