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
    trustJson: text("trust_json"),
    message: text("message").notNull(),
    createdAt: text("created_at").notNull(),
  },
  (table) => ({
    checkedAtIndex: index("idx_watchtower_snapshots_checked_at").on(table.checkedAt),
  }),
);

export const watchtowerScans = sqliteTable("watchtower_scans", {
  id: text("id").primaryKey(),
  status: text("status").notNull(),
  stage: text("stage").notNull(),
  startedAt: text("started_at").notNull(),
  updatedAt: text("updated_at").notNull(),
  stateJson: text("state_json").notNull(),
  error: text("error"),
}, (table) => ({ statusIndex: index("idx_watchtower_scans_status").on(table.status) }));

export const watchtowerSources = sqliteTable("watchtower_sources", {
  id: text("id").primaryKey(),
  documentsJson: text("documents_json"),
  etag: text("etag"),
  lastModified: text("last_modified"),
  checkedAt: text("checked_at"),
  succeededAt: text("succeeded_at"),
  status: text("status").notNull(),
  error: text("error"),
});

export const watchtowerAnnouncements = sqliteTable("watchtower_announcements", {
  versionId: text("version_id").primaryKey(),
  advisoryId: text("advisory_id").notNull(),
  sourceId: text("source_id").notNull(),
  contentHash: text("content_hash").notNull(),
  sourceDate: text("source_date").notNull(),
  firstSeenAt: text("first_seen_at").notNull(),
  evidenceJson: text("evidence_json").notNull(),
  reviewStatus: text("review_status").notNull(),
  findingJson: text("finding_json"),
  scanId: text("scan_id"),
}, (table) => ({
  pendingIndex: index("idx_watchtower_announcements_review").on(table.reviewStatus, table.sourceDate),
  advisoryIndex: index("idx_watchtower_announcements_advisory").on(table.advisoryId, table.sourceDate),
}));

export const watchtowerControl = sqliteTable("watchtower_control", {
  id: text("id").primaryKey(),
  activeScan: text("active_scan"),
  leaseOwner: text("lease_owner"),
  leaseUntil: integer("lease_until").notNull().default(0),
});
