import { getDatabase } from "../db";
import { MONITOR_SOURCES } from "./source-config";
import { collectSource, fingerprint, readEvidence, type Announcement, type SourceCheckpoint } from "./source-monitor";
import { hasNimbleKey, readResearch, researchInput, startResearch, validateResearch, type ResearchRun, type ResearchStage } from "./nimble-research";
import type { CheckTrigger, Finding, NimbleTrust, SnapshotHistory } from "./watchtower";

type Candidate = Announcement & { versionId: string };
type SourceOutcome = { id: string; status: string; count: number; error?: string };
type ScanState = { trigger: CheckTrigger; until: string; candidates: Candidate[]; sources: SourceOutcome[];
  run?: ResearchRun; submission?: ResearchStage; investigator?: unknown; verifier?: unknown;
  investigated?: Finding[]; trust?: NimbleTrust; nextPollAt?: number };
type ScanRow = { id: string; status: string; stage: string; started_at: string; updated_at: string; state_json: string; error: string | null; lease?: string };
type SnapshotRow = { id: string; checked_at: string; trigger: CheckTrigger; finding_count: number; critical_count: number;
  platform_count: number; findings_json: string; trust_json: string | null; message: string };
const now = () => new Date().toISOString();
class LeaseLost extends Error {}
function assertLease(owner: string): D1PreparedStatement {
  // SQLite integer overflow aborts the entire D1 batch if ownership expires mid-transition.
  return getDatabase().prepare("SELECT CASE WHEN EXISTS(SELECT 1 FROM watchtower_control WHERE id='main' AND lease_owner=? AND lease_until>CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)) THEN 1 ELSE abs(-9223372036854775808) END AS lease_valid").bind(owner);
}
function write(owner: string | undefined, sql: string): D1PreparedStatement {
  if (!owner || !/^[a-f0-9-]{36}$/.test(owner)) throw new LeaseLost("The check is being continued by another request.");
  // All writes below use simple VALUES lists or UPDATE ... WHERE statements. The ownership test
  // executes in the same SQLite statement as the mutation, fencing expired request handlers.
  const guard = `EXISTS(SELECT 1 FROM watchtower_control WHERE id='main' AND lease_owner='${owner}' AND lease_until>CAST((julianday('now')-2440587.5)*86400000 AS INTEGER))`;
  const fenced = sql.startsWith("INSERT") ? sql.replace(/VALUES\(([^()]*)\)/, `SELECT $1 WHERE ${guard}`) : `${sql} AND ${guard}`;
  return getDatabase().prepare(fenced);
}
const historyRow = (row: SnapshotRow): SnapshotHistory => ({ id: row.id, checkedAt: row.checked_at, trigger: row.trigger,
  findingCount: row.finding_count, criticalCount: row.critical_count, platformCount: row.platform_count });

async function claim(): Promise<string | null> {
  const db = getDatabase();
  await db.prepare("INSERT INTO watchtower_control(id,lease_until) VALUES('main',0) ON CONFLICT(id) DO NOTHING").run();
  const owner = crypto.randomUUID();
  const result = await db.prepare("UPDATE watchtower_control SET lease_owner=?,lease_until=? WHERE id='main' AND lease_until<?")
    .bind(owner, Date.now() + 180000, Date.now()).run();
  return result.meta.changes ? owner : null;
}
async function release(owner: string) {
  await getDatabase().prepare("UPDATE watchtower_control SET lease_owner=NULL,lease_until=0 WHERE id='main' AND lease_owner=?").bind(owner).run();
}
async function activeScan(): Promise<ScanRow | null> {
  return getDatabase().prepare("SELECT s.* FROM watchtower_scans s JOIN watchtower_control c ON c.active_scan=s.id WHERE c.id='main'").first<ScanRow>();
}
async function save(scan: ScanRow, state: ScanState, stage = scan.stage, status = "running", error: string | null = null) {
  const result = await write(scan.lease, "UPDATE watchtower_scans SET state_json=?,stage=?,status=?,error=?,updated_at=? WHERE id=?")
    .bind(JSON.stringify(state), stage, status, error, now(), scan.id).run();
  if (!result.meta.changes) throw new LeaseLost("The check is being continued by another request.");
  scan.state_json = JSON.stringify(state); scan.stage = stage; scan.status = status; scan.error = error;
}

export async function startScan(trigger: CheckTrigger) {
  if (!hasNimbleKey()) throw new Error("Nimble monitoring is not configured.");
  const owner = await claim();
  if (!owner) return dashboardFeed();
  try {
    const existing = await activeScan();
    if (existing) {
      existing.lease = owner;
      // Resume durable work; do not create another paid research run.
      if (existing.status === "blocked") await save(existing, JSON.parse(existing.state_json));
      return scanResponse(existing);
    }
    const timestamp = now();
    const scan: ScanRow = { id: crypto.randomUUID(), stage: "monitor", status: "running", started_at: timestamp,
      updated_at: timestamp, error: null, state_json: JSON.stringify({ trigger, until: timestamp, candidates: [], sources: [] } satisfies ScanState) };
    const db = getDatabase();
    await db.batch([
      write(owner, "INSERT INTO watchtower_scans(id,status,stage,started_at,updated_at,state_json) VALUES(?,?,?,?,?,?)")
        .bind(scan.id, scan.status, scan.stage, timestamp, timestamp, scan.state_json),
      write(owner, "UPDATE watchtower_control SET active_scan=? WHERE id='main'").bind(scan.id),
      assertLease(owner),
    ]);
    return scanResponse(scan);
  } finally { await release(owner); }
}

async function collect(scan: ScanRow, state: ScanState) {
  const db = getDatabase();
  // Process sources separately and persist each outcome so a later source failure cannot discard captured evidence.
  for (const source of MONITOR_SOURCES) {
    if (state.sources.some(s => s.id === source.id)) continue;
    const checkpoint = await db.prepare("SELECT * FROM watchtower_sources WHERE id=?").bind(source.id).first<SourceCheckpoint>() ?? {};
    const since = new Date(checkpoint.succeeded_at ? Date.parse(checkpoint.succeeded_at) - 6 * 3600000 : Date.parse(state.until) - 72 * 3600000).toISOString();
    try {
      const fetchedThrough = now();
      const result = await collectSource(source, checkpoint, since, fetchedThrough);
      for (const item of result.items) {
        const hash = await fingerprint(JSON.stringify({ title: item.title, url: item.url, date: item.sourceDate, evidence: item.evidence }));
        const versionId = `${item.id}:${hash}`;
        await write(scan.lease, "INSERT INTO watchtower_announcements(version_id,advisory_id,source_id,content_hash,source_date,first_seen_at,evidence_json,review_status) VALUES(?,?,?,?,?,?,?,'pending') ON CONFLICT(version_id) DO NOTHING")
          .bind(versionId, item.id, item.sourceId, hash, item.sourceDate, now(), JSON.stringify(item)).run();
      }
      const status = result.warning ? "partial" : "checked";
      await write(scan.lease, "INSERT INTO watchtower_sources(id,etag,last_modified,checked_at,succeeded_at,status,error,documents_json) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET etag=excluded.etag,last_modified=excluded.last_modified,checked_at=excluded.checked_at,succeeded_at=excluded.succeeded_at,status=excluded.status,error=excluded.error,documents_json=excluded.documents_json")
        .bind(source.id, result.warning && source.id !== "msrc" ? null : result.etag, result.warning && source.id !== "msrc" ? null : result.lastModified, now(), result.warning && source.id !== "msrc" ? checkpoint.succeeded_at ?? null : fetchedThrough, status, result.warning ?? null, result.documentsJson ?? null).run();
      state.sources.push({ id: source.id, status, count: result.items.length, ...(result.warning ? { error: result.warning } : {}) });
    } catch (error) {
      const message = error instanceof Error ? error.message : "Source could not be checked.";
      await write(scan.lease, "INSERT INTO watchtower_sources(id,checked_at,status,error) VALUES(?,?,'error',?) ON CONFLICT(id) DO UPDATE SET checked_at=excluded.checked_at,status='error',error=excluded.error")
        .bind(source.id, now(), message).run();
      state.sources.push({ id: source.id, status: "error", count: 0, error: message });
    }
    await save(scan, state);
    // One source per request keeps worker execution bounded and allows refresh recovery.
    if (state.sources.length < MONITOR_SOURCES.length) return;
  }
  const rows = await db.prepare("SELECT a.version_id,a.evidence_json FROM watchtower_announcements a WHERE a.review_status='pending' AND NOT EXISTS (SELECT 1 FROM watchtower_announcements newer WHERE newer.advisory_id=a.advisory_id AND (newer.source_date>a.source_date OR (newer.source_date=a.source_date AND (newer.first_seen_at>a.first_seen_at OR (newer.first_seen_at=a.first_seen_at AND newer.version_id>a.version_id))))) ORDER BY a.source_date DESC LIMIT 3")
    .all<{ version_id: string; evidence_json: string }>();
  state.candidates = rows.results.map(row => ({ ...JSON.parse(row.evidence_json), versionId: row.version_id }));
  await save(scan, state, state.candidates.length ? "investigator" : "orchestrator");
}

async function currentFindings(): Promise<Finding[]> {
  const db = getDatabase();
  const rows = await db.prepare("SELECT advisory_id,finding_json FROM watchtower_announcements WHERE review_status='accepted' ORDER BY source_date DESC,first_seen_at DESC").all<{ advisory_id: string; finding_json: string }>();
  const findings = new Map<string, Finding>();
  for (const row of rows.results) if (!findings.has(row.advisory_id)) findings.set(row.advisory_id, JSON.parse(row.finding_json));
  // Retain previously published snapshots when migrating from the original pipeline.
  const previous = await db.prepare("SELECT findings_json FROM watchtower_snapshots ORDER BY checked_at DESC LIMIT 1").first<{ findings_json: string }>();
  for (const finding of previous ? JSON.parse(previous.findings_json) as Finding[] : []) if (!findings.has(finding.id)) findings.set(finding.id, finding);
  return [...findings.values()].sort((a, b) => b.detectedAt.localeCompare(a.detectedAt));
}
async function publish(scan: ScanRow, state: ScanState, verified: Finding[]) {
  const db = getDatabase();
  const accepted = new Map(verified.map(f => [f.id, f]));
  if (verified.some(f => !state.investigated?.some(i => i.id === f.id))) throw new Error("Verifier added an announcement that was not investigated.");
  if (state.candidates.length) await db.batch([...state.candidates.map(item => write(scan.lease, "UPDATE watchtower_announcements SET review_status=?,finding_json=?,scan_id=? WHERE version_id=?")
    .bind(accepted.has(item.id) ? "accepted" : "rejected", accepted.has(item.id) ? JSON.stringify(accepted.get(item.id)) : null, scan.id, item.versionId)), assertLease(scan.lease!)]);
  const findings = await currentFindings();
  const incomplete = state.sources.filter(s => s.status !== "checked").length;
  const message = `${verified.length} announcements verified in this check. ${findings.length} retained in history.${incomplete ? ` ${incomplete} sources have incomplete coverage; see Sources.` : ""}`;
  const timestamp = now();
  const result = await db.batch([
    write(scan.lease, "INSERT INTO watchtower_snapshots(id,checked_at,trigger,finding_count,critical_count,platform_count,findings_json,trust_json,message,created_at) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING")
      .bind(`scan:${scan.id}`, timestamp, state.trigger, findings.length, findings.filter(f => f.severity === "critical").length,
        new Set(findings.map(f => f.platform)).size, JSON.stringify(findings), state.trust ? JSON.stringify(state.trust) : null, message, timestamp),
    write(scan.lease, "UPDATE watchtower_scans SET status='completed',stage='orchestrator',state_json=?,updated_at=?,error=NULL WHERE id=?").bind(JSON.stringify(state), timestamp, scan.id),
    write(scan.lease, "UPDATE watchtower_control SET active_scan=NULL WHERE id='main' AND active_scan=?").bind(scan.id),
    assertLease(scan.lease!),
  ]);
  if (!result[1].meta.changes) throw new LeaseLost("Another request is continuing this check.");
  scan.status = "completed";
}

export async function advanceScan(scanId?: string) {
  const db = getDatabase();
  const scan = scanId ? await db.prepare("SELECT * FROM watchtower_scans WHERE id=?").bind(scanId).first<ScanRow>() : await activeScan();
  if (!scan || scan.status === "completed") return savedFeed();
  if (scan.status !== "running") return scanResponse(scan);
  const owner = await claim();
  if (!owner) return scanResponse(scan);
  try {
    const fresh = await db.prepare("SELECT * FROM watchtower_scans WHERE id=?").bind(scan.id).first<ScanRow>();
    if (!fresh || fresh.status !== "running") return dashboardFeed();
    Object.assign(scan, fresh);
    scan.lease = owner;
    const state: ScanState = JSON.parse(scan.state_json);
    try {
      if (scan.stage === "monitor") await collect(scan, state);
      else if (scan.stage === "orchestrator") await publish(scan, state, state.verifier ? validateResearch(state.verifier, state.candidates) : []);
      else {
        if (scan.stage !== "investigator" && scan.stage !== "verifier") throw new Error("Saved scan has an unsupported stage.");
        const stage: ResearchStage = scan.stage;
        if (state[stage]) {
          const findings = validateResearch(state[stage], state.candidates);
          if (stage === "investigator") {
            state.investigated = findings; delete state.run; delete state.submission; delete state.nextPollAt;
            await save(scan, state, findings.length ? "verifier" : "orchestrator");
          } else await publish(scan, state, findings);
        } else if (state.run) {
          if (!state.nextPollAt || state.nextPollAt <= Date.now()) {
            const result = await readResearch(state.run);
            state.nextPollAt = Date.now() + 15000;
            if (result.status === "completed") { state[stage] = result.payload; if (result.trust) state.trust = result.trust; }
            // Commit raw provider output before validating or publishing; recovery never needs to repeat research.
            await save(scan, state);
          }
        } else {
          if (state.submission) throw new Error("A previous Nimble submission has an uncertain result. No duplicate was started; its identifiers require reconciliation.");
          if (stage === "investigator") for (const item of state.candidates) {
            try { item.evidence = `${item.evidence}\n${await readEvidence(item)}`.slice(0, 5000); } catch { /* Captured official feed evidence is retained; the investigator also reads the exact advisory URL. */ }
          }
          const candidates = stage === "verifier" ? state.candidates.filter(c => state.investigated?.some(f => f.id === c.id)) : state.candidates;
          researchInput(scan.id, stage, candidates, stage === "verifier" ? state.investigated : undefined);
          state.submission = stage;
          await save(scan, state);
          state.run = await startResearch(scan.id, stage, candidates, stage === "verifier" ? state.investigated : undefined);
          delete state.submission; state.nextPollAt = Date.now() + 15000;
          await save(scan, state);
        }
      }
    } catch (error) {
      if (error instanceof LeaseLost) return dashboardFeed();
      if (error && typeof error === "object" && "submissionRejected" in error) delete state.submission;
      const retryable = state.run && !state[scan.stage as ResearchStage] && (error instanceof TypeError || error instanceof DOMException || (error && typeof error === "object" && "retryable" in error));
      if (retryable) state.nextPollAt = Date.now() + 30000;
      await save(scan, state, scan.stage, retryable ? "running" : "blocked", error instanceof Error ? error.message : "The saved check needs attention.");
    }
    return String(scan.status) === "completed" ? savedFeed() : scanResponse(scan);
  } finally { await release(owner); }
}

async function savedFeed(snapshotId?: string) {
  const db = getDatabase();
  const row = snapshotId ? await db.prepare("SELECT * FROM watchtower_snapshots WHERE id=?").bind(snapshotId).first<SnapshotRow>()
    : await db.prepare("SELECT * FROM watchtower_snapshots ORDER BY checked_at DESC LIMIT 1").first<SnapshotRow>();
  const history = await db.prepare("SELECT id,checked_at,trigger,finding_count,critical_count,platform_count FROM watchtower_snapshots ORDER BY checked_at DESC LIMIT 100").all<SnapshotRow>();
  const sources = await db.prepare("SELECT id,status,error,checked_at,succeeded_at FROM watchtower_sources").all();
  const pending = await db.prepare("SELECT COUNT(*) AS count FROM watchtower_announcements WHERE review_status='pending'").first<{ count: number }>();
  return { mode: row ? "live" : "idle", status: "completed", findings: row ? JSON.parse(row.findings_json) as Finding[] : [],
    checkedAt: row?.checked_at ?? null, snapshotId: row?.id ?? null, history: history.results.map(historyRow),
    trust: row?.trust_json ? JSON.parse(row.trust_json) as NimbleTrust : undefined, sourceStatuses: sources.results,
    pendingCount: pending?.count ?? 0, message: row?.message ?? "No completed checks yet." };
}
async function scanResponse(scan: ScanRow) {
  const state: ScanState = JSON.parse(scan.state_json);
  const feed = await savedFeed();
  return { ...feed, mode: scan.status === "blocked" ? "fallback" : "pending", status: scan.status === "blocked" ? "failed" : "running",
    scanId: scan.id, runId: scan.id, agentId: "watchtower", stage: scan.stage, startedAt: scan.started_at, trigger: state.trigger,
    message: scan.error ?? "Check in progress. Previously saved announcements remain available.", resumable: true };
}
export async function dashboardFeed(snapshotId?: string) {
  if (snapshotId) return savedFeed(snapshotId);
  const active = await activeScan();
  return active ? scanResponse(active) : savedFeed();
}
