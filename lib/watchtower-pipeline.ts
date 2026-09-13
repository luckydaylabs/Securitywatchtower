/**
 * Durable check coordinator. A request advances saved work rather than running the
 * entire check in memory: collect sources → investigate → verify → publish.
 * The database is authoritative, so page reloads and multiple viewers share one scan.
 * Provider calls may cost money; preserve submission markers and raw responses when
 * changing transitions so an interrupted request cannot silently repeat a paid run.
 */
import { getDatabase } from "../db";
import { MONITOR_SOURCES } from "./source-config";
import { ANNOUNCEMENTS_PER_PLATFORM, collectSource, fingerprint, readEvidence, type Announcement, type SourceCheckpoint } from "./source-monitor";
import { hasNimbleKey, readResearch, researchInput, startResearch, validateResearch, type ResearchRun, type ResearchStage } from "./nimble-research";
import type { CheckTrigger, Finding, NimbleTrust, SnapshotHistory, PlatformReport } from "./watchtower";

import { platformJobs, nextPlatformJobs, researchBatches, RESEARCH_PLATFORMS, type Candidate, type ResearchJob } from "./platform-research";
type SourceOutcome = { id: string; status: string; count: number; error?: string };
type ScanState = { trigger: CheckTrigger; until: string; candidates: Candidate[]; sources: SourceOutcome[];
  run?: ResearchRun; submission?: ResearchStage; investigator?: unknown; verifier?: unknown;
  investigated?: Finding[]; trust?: NimbleTrust; nextPollAt?: number; jobs?: ResearchJob[]; runsStarted?: number };
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
  findingCount: row.finding_count, criticalCount: row.critical_count, platformCount: row.platform_count, outcome: /partial|incomplete coverage/i.test(row.message ?? "") ? "partial" : "completed" });

async function claim(): Promise<string | null> {
  // Only one request may advance shared state at a time. Expiry permits recovery
  // after a crashed request; fenced writes prevent that old request writing later.
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
      if (existing.status === "blocked") {
        const state: ScanState = JSON.parse(existing.state_json);
        // Older edge builds rejected redirect:"error" before dispatch; this specific failure cannot have created a provider run.
        if (!state.run && existing.error?.startsWith("Invalid redirect value, must be one of")) delete state.submission;
        await save(existing, state);
      }
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

// Owner-authorized, single-use maintenance operation. Keep the receipt across resets.
export async function resetMonitoringOnce() {
  const owner = await claim();
  if (!owner) throw new Error("A check is being processed; reset refused.");
  const db = getDatabase(), receipt = "reset-2026-09-12-fresh-start";
  try {
    if (await db.prepare("SELECT id FROM watchtower_control WHERE id=?").bind(receipt).first()) return { reset: false, alreadyReset: true };
    if (await activeScan()) throw new Error("An active check exists; reset refused.");
    const tables = ["watchtower_announcements", "watchtower_snapshots", "watchtower_sources", "watchtower_scans"];
    await db.batch([
      assertLease(owner),
      ...tables.map(table => db.prepare(`DELETE FROM ${table}`)),
      db.prepare("UPDATE watchtower_control SET active_scan=NULL WHERE id='main'"),
      db.prepare("INSERT INTO watchtower_control(id,lease_until) VALUES(?,0)").bind(receipt),
      assertLease(owner),
    ]);
    return { reset: true, alreadyReset: false };
  } finally { await release(owner); }
}

async function collect(scan: ScanRow, state: ScanState) {
  const db = getDatabase();
  // Process sources separately and persist each outcome so a later source failure cannot discard captured evidence.
  for (const source of MONITOR_SOURCES) {
    if (state.sources.some(s => s.id === source.id)) continue;
    const checkpoint = await db.prepare("SELECT * FROM watchtower_sources WHERE id=?").bind(source.id).first<SourceCheckpoint>() ?? {};
    try {
      const fetchedThrough = now();
      const result = await collectSource(source, checkpoint, fetchedThrough);
      for (const item of result.items) {
        const firstSeen = await db.prepare("SELECT MIN(first_seen_at) AS first_seen_at FROM watchtower_announcements WHERE advisory_id=?")
          .bind(item.id).first<{ first_seen_at: string | null }>();
        item.firstDiscoveredAt = firstSeen?.first_seen_at ?? now();
        const hash = await fingerprint(JSON.stringify({ title: item.title, url: item.url, date: item.sourceDate, evidence: item.evidence }));
        const versionId = `${item.id}:${hash}`;
        // Date metadata is enriched in place; it does not invalidate prior research.
        await write(scan.lease, "INSERT INTO watchtower_announcements(version_id,advisory_id,source_id,content_hash,source_date,first_seen_at,evidence_json,review_status) VALUES(?,?,?,?,?,?,?,'pending') ON CONFLICT(version_id) DO UPDATE SET evidence_json=excluded.evidence_json")
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
  state.candidates = await pendingLatestAnnouncements();
  state.jobs = platformJobs(state.candidates);
  state.runsStarted = 0;
  await save(scan, state, state.candidates.length ? "investigator" : "orchestrator");
}

async function pendingLatestAnnouncements(): Promise<Candidate[]> {
  // Rank all records before filtering their review status. Otherwise a no-change
  // check would refill each platform with five older, unreviewed announcements.
  const rows = await getDatabase().prepare(`WITH versions AS (
    SELECT *, ROW_NUMBER() OVER (PARTITION BY advisory_id ORDER BY first_seen_at DESC, version_id DESC) AS version_rank
    FROM watchtower_announcements
    WHERE source_id NOT IN ('anthropic','openai')
      OR advisory_id LIKE 'anthropic:article:%' OR advisory_id LIKE 'openai:article:%'
  ), ranked AS (
    SELECT *, ROW_NUMBER() OVER (PARTITION BY json_extract(evidence_json,'$.platform') ORDER BY source_date DESC, advisory_id ASC) AS platform_rank
    FROM versions WHERE version_rank=1
  ) SELECT version_id,evidence_json FROM ranked
    WHERE platform_rank<=? AND review_status='pending' ORDER BY source_date DESC,advisory_id ASC`)
    .bind(ANNOUNCEMENTS_PER_PLATFORM).all<{ version_id: string; evidence_json: string }>();
  return rows.results.map(row => ({ ...JSON.parse(row.evidence_json), versionId: row.version_id }));
}

async function advancePlatformResearch(scan: ScanRow, state: ScanState) {
  const jobs = state.jobs!;
  // Interpret only already-saved responses. Raw provider results survive parser failures.
  for (const job of [...jobs]) {
    if (!job.payload || job.status === "done" || job.status === "delegated" || job.status === "blocked") continue;
    try {
      const findings = validateResearch(job.payload, job.candidates);
      if (job.stage === "verifier") {
        if (findings.some(f => !job.investigated?.some(i => i.id === f.id))) throw new Error("Verifier returned an uninvestigated announcement.");
        job.verified = findings; job.status = "done";
      } else {
        job.investigated = findings;
        job.rejectedIds = job.candidates.filter(c => !findings.some(f => f.id === c.id)).map(c => c.id);
        if (!findings.length) { job.verified = []; job.status = "done"; continue; }
        const candidates = job.candidates.filter(c => findings.some(f => f.id === c.id));
        const batches = researchBatches(candidates, "verifier", findings);
        if (batches.length > 1) {
          job.status = "delegated";
          jobs.push(...batches.map((rows, index) => ({ id: `${job.id}-verify-${index}`, platform: job.platform,
            candidates: rows, stage: "verifier" as const, status: "ready" as const,
            investigated: findings.filter(f => rows.some(c => c.id === f.id)) })));
        } else {
          job.stage = "verifier"; job.status = "ready";
          delete job.run; delete job.payload; delete job.nextPollAt;
        }
      }
    } catch (error) { job.status = "blocked"; job.error = error instanceof Error ? error.message : "Saved result needs review."; }
  }
  await save(scan, state);
  await publishCompletedJobs(scan, state);
  const selected = nextPlatformJobs(jobs);
  const submit: ResearchJob[] = [];
  for (const job of [...selected].sort((a, b) => Number(b.stage === "verifier") - Number(a.stage === "verifier"))) {
    if (job.status !== "ready") continue;
    if (job.submission) { job.status = "blocked"; job.error = "Submission outcome is uncertain; no duplicate was started."; continue; }
    const candidates = job.stage === "verifier" ? job.candidates.filter(c => job.investigated?.some(f => f.id === c.id)) : job.candidates;
    researchInput(`${scan.id}:${job.id}`, job.stage, candidates, job.stage === "verifier" ? job.investigated : undefined);
    job.submission = true; state.runsStarted = (state.runsStarted ?? 0) + 1; submit.push(job);
  }
  if (submit.length) {
    // Persist intent for every request before dispatching concurrently. A lost response
    // requires reconciliation, not a second billable submission after refresh.
    await save(scan, state);
    await Promise.all(submit.map(async job => {
      try {
        const candidates = job.stage === "verifier" ? job.candidates.filter(c => job.investigated?.some(f => f.id === c.id)) : job.candidates;
        job.run = await startResearch(`${scan.id}:${job.id}`, job.stage, candidates, job.stage === "verifier" ? job.investigated : undefined, job.platform);
        delete job.submission; job.status = "running"; job.nextPollAt = Date.now() + 15000;
      } catch (error) {
        if (error && typeof error === "object" && "submissionRejected" in error) delete job.submission;
        job.status = "blocked"; job.error = error instanceof Error ? error.message : "Research could not start.";
      }
    }));
    await save(scan, state);
    return;
  }
  const polling = selected.filter(j => j.status === "running" && j.run && !j.payload && (j.nextPollAt ?? 0) <= Date.now());
  if (polling.length) {
    await Promise.all(polling.map(async job => {
      try {
        const result = await readResearch(job.run!);
        job.nextPollAt = Date.now() + 15000;
        if (result.status === "completed") {
          job.payload = result.payload; job.trust = result.trust;
          (job.outputs ??= []).push({ stage: job.stage, run: job.run!, payload: result.payload, trust: result.trust });
        }
      } catch (error) {
        const retryable = error instanceof TypeError || error instanceof DOMException || (error && typeof error === "object" && "retryable" in error);
        job.nextPollAt = Date.now() + 30000;
        if (!retryable) { job.status = "blocked"; job.error = error instanceof Error ? error.message : "Research needs review."; }
      }
    }));
    await save(scan, state);
    return;
  }
  if (jobs.some(j => j.status === "running")) return;
  if (jobs.some(j => j.submission)) {
    await save(scan, state, scan.stage, "blocked", "A platform submission has an uncertain outcome. Saved identifiers must be reconciled before another check; no duplicate was started.");
    return;
  }
  const completed = jobs.filter(j => j.status === "done");
  const verified = completed.flatMap(j => j.verified ?? []);
  state.investigated = jobs.flatMap(j => j.investigated ?? []);
  const handled = new Set(jobs.flatMap(j => [...(j.rejectedIds ?? []), ...(j.status === "done" ? j.candidates.map(c => c.id) : [])]));
  // Unfinished evidence remains pending, never silently rejected or removed.
  state.candidates = state.candidates.filter(c => handled.has(c.id));
  const traces = completed.filter(j => j.stage === "verifier" && j.trust);
  state.trust = { reasoning: "Evidence from completed platform verification runs; claim paths are scoped by research job.",
    sources: Array.from(new Map(traces.flatMap(j => j.trust!.sources).map(s => [s.url, s])).values()),
    claims: traces.flatMap(j => j.trust!.claims.map(c => ({ ...c, researchJob: j.id, platform: j.platform }))) };
  await publish(scan, state, verified);
}

// Commit each verified batch independently, before waiting on other platforms.
// Findings and the publication marker share a transaction, making retries safe.
async function publishCompletedJobs(scan: ScanRow, state: ScanState) {
  const completed = state.jobs!.filter(job => job.status === "done" && !job.published);
  if (!completed.length) return;
  const nextState = { ...state, jobs: state.jobs!.map(job => completed.includes(job) ? { ...job, published: true } : job) };
  const statements: D1PreparedStatement[] = [];
  for (const job of completed) {
    const accepted = new Map((job.verified ?? []).map(f => [f.id, f]));
    if ([...accepted.keys()].some(id => !job.investigated?.some(f => f.id === id) || !job.candidates.some(c => c.id === id))) {
      throw new Error("Cannot publish an uninvestigated announcement.");
    }
    for (const item of job.candidates) statements.push(write(scan.lease,
      "UPDATE watchtower_announcements SET review_status=?,finding_json=?,scan_id=? WHERE version_id=?")
      .bind(accepted.has(item.id) ? "accepted" : "rejected", accepted.has(item.id) ? JSON.stringify(accepted.get(item.id)) : null, scan.id, item.versionId));
  }
  statements.push(write(scan.lease, "UPDATE watchtower_scans SET state_json=?,updated_at=? WHERE id=?")
    .bind(JSON.stringify(nextState), now(), scan.id), assertLease(scan.lease!));
  await getDatabase().batch(statements);
  for (const job of completed) job.published = true;
  scan.state_json = JSON.stringify(state);
}

async function currentFindings(): Promise<Finding[]> {
  const db = getDatabase();
  const rows = await db.prepare("SELECT advisory_id,finding_json FROM watchtower_announcements WHERE review_status='accepted' ORDER BY source_date DESC,first_seen_at DESC").all<{ advisory_id: string; finding_json: string }>();
  const findings = new Map<string, Finding>();
  for (const row of rows.results) if (!findings.has(row.advisory_id)) findings.set(row.advisory_id, JSON.parse(row.finding_json));
  // Retain previously published snapshots when migrating from the original pipeline.
  const previous = await db.prepare("SELECT findings_json FROM watchtower_snapshots ORDER BY checked_at DESC LIMIT 1").first<{ findings_json: string }>();
  for (const finding of previous ? JSON.parse(previous.findings_json) as Finding[] : []) if (!findings.has(finding.id)) findings.set(finding.id, finding);
  return hydrateFindingDates([...findings.values()].sort((a, b) => b.detectedAt.localeCompare(a.detectedAt)));
}

async function hydrateFindingDates(findings: Finding[]): Promise<Finding[]> {
  if (!findings.length) return findings;
  const db = getDatabase();
  const rows = await db.prepare("SELECT advisory_id,source_date,evidence_json,first_seen_at,review_status FROM watchtower_announcements ORDER BY first_seen_at ASC,version_id ASC")
    .all<{ advisory_id: string; source_date: string; evidence_json: string; first_seen_at: string; review_status: string }>();
  const firstSeen = new Map<string, string>();
  const dates = new Map<string, Announcement>();
  for (const row of rows.results) {
    if (!firstSeen.has(row.advisory_id)) firstSeen.set(row.advisory_id, row.first_seen_at);
    if (row.review_status === "accepted") dates.set(`${row.advisory_id}:${row.source_date}`, JSON.parse(row.evidence_json));
  }
  return findings.map(finding => {
    const captured = dates.get(`${finding.id}:${finding.detectedAt}`);
    return { ...finding, publishedAt: finding.publishedAt ?? captured?.publishedAt,
      updatedAt: finding.updatedAt ?? captured?.updatedAt,
      firstDiscoveredAt: firstSeen.get(finding.id) ?? finding.firstDiscoveredAt };
  });
}
async function publish(scan: ScanRow, state: ScanState, verified: Finding[]) {
  const db = getDatabase();
  const accepted = new Map(verified.map(f => [f.id, f]));
  if (verified.some(f => !state.investigated?.some(i => i.id === f.id))) throw new Error("Verifier added an announcement that was not investigated.");
  if (state.candidates.length) await db.batch([...state.candidates.map(item => write(scan.lease, "UPDATE watchtower_announcements SET review_status=?,finding_json=?,scan_id=? WHERE version_id=?")
    .bind(accepted.has(item.id) ? "accepted" : "rejected", accepted.has(item.id) ? JSON.stringify(accepted.get(item.id)) : null, scan.id, item.versionId)), assertLease(scan.lease!)]);
  const findings = await currentFindings();
  const incomplete = state.sources.filter(s => s.status !== "checked").length;
  const unfinished = state.jobs?.filter(j => j.status === "ready" || j.status === "blocked") ?? [];
  const message = `${verified.length} announcements verified in this check. ${findings.length} retained in history.${incomplete ? ` ${incomplete} sources have incomplete coverage; see Check details.` : ""}${unfinished.length ? " Research is partial; additional announcements remain pending because research could not finish." : ""}`;
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
  // Each call performs bounded work. The browser or an external scheduler must
  // call again; this function does not create a background timer or scheduler.
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
      else if (state.jobs?.length) await advancePlatformResearch(scan, state);
      else if (scan.stage === "orchestrator") await publish(scan, state, state.verifier ? validateResearch(state.verifier, state.candidates) : []);
      else {
        // Compatibility path for scans saved before per-platform jobs existed.
        // Keep it until those persisted scans no longer need to be resumed.
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
  const history = await db.prepare("SELECT id,checked_at,trigger,finding_count,critical_count,platform_count,message FROM watchtower_snapshots ORDER BY checked_at DESC LIMIT 100").all<SnapshotRow>();
  const sources = await db.prepare("SELECT id,status,error,checked_at,succeeded_at FROM watchtower_sources").all();
  const savedScan = row?.id.startsWith("scan:") ? await db.prepare("SELECT state_json FROM watchtower_scans WHERE id=?").bind(row.id.slice(5)).first<{ state_json: string }>() : null;
  const state: ScanState | undefined = savedScan ? JSON.parse(savedScan.state_json) : undefined;
  const pending = await pendingLatestAnnouncements();
  const partial = state ? state.sources.some(s => s.status !== "checked") || Boolean(state.jobs?.some(j => ["blocked", "ready", "running"].includes(j.status))) : /partial|incomplete coverage/i.test(row?.message ?? "");
  return { mode: row ? partial ? "partial" : "live" : "idle", status: partial ? "partial" : "completed", findings: row ? await hydrateFindingDates(JSON.parse(row.findings_json) as Finding[]) : [],
    checkedAt: row?.checked_at ?? null, snapshotId: row?.id ?? null, history: history.results.map(historyRow),
    trust: row?.trust_json ? JSON.parse(row.trust_json) as NimbleTrust : undefined, sourceStatuses: sources.results,
    platformReports: state ? platformReports(state, false) : [], runsStarted: state?.runsStarted ?? 0,
    pendingCount: pending.length, message: row?.message ?? "No completed checks yet." };
}
function platformReports(state: ScanState, running: boolean): PlatformReport[] {
  const sourceIds = { macos: ["apple"], windows: ["msrc"], linux: ["ubuntu"], ai: ["anthropic", "openai"] };
  return RESEARCH_PLATFORMS.map(platform => {
    const sources = state.sources.filter(s => sourceIds[platform].includes(s.id));
    const jobs = state.jobs?.filter(j => j.platform === platform) ?? [];
    const pending = jobs.some(j => j.status === "ready" || j.status === "running" || j.status === "blocked");
    const sourcePartial = sources.length !== sourceIds[platform].length || sources.some(s => s.status !== "checked");
    const verified = jobs.flatMap(j => j.verified ?? []).length;
    const failure = jobs.find(j => j.error)?.error;
    const status = failure ? "partial" : running && (pending || sources.length !== sourceIds[platform].length) ? "running" : sourcePartial || pending ? "partial" : verified ? "checked" : "no_changes";
    return { platform, status, verified, message: status === "running" ? "Check in progress" : status === "partial"
      ? failure ?? (pending ? "Additional announcements await research" : "Source coverage is incomplete")
      : verified ? `${verified} announcements verified in this check` : "No new supported announcements in the checked sources" };
  });
}
async function scanResponse(scan: ScanRow) {
  const state: ScanState = JSON.parse(scan.state_json);
  const feed = await savedFeed();
  const findings = await currentFindings();
  const completed = state.jobs?.filter(j => j.published && j.stage === "verifier" && j.trust) ?? [];
  const trust = completed.length ? {
    reasoning: "Evidence from platform verification runs published so far; other platforms may still be running.",
    sources: Array.from(new Map(completed.flatMap(j => j.trust!.sources).map(s => [s.url, s])).values()),
    claims: completed.flatMap(j => j.trust!.claims.map(c => ({ ...c, researchJob: j.id, platform: j.platform }))),
  } : feed.trust;
  return { ...feed, mode: scan.status === "blocked" ? "fallback" : "pending", status: scan.status === "blocked" ? "failed" : "running",
    findings, trust,
    scanId: scan.id, runId: scan.id, agentId: "watchtower", stage: scan.stage, startedAt: scan.started_at, trigger: state.trigger,
    platformReports: platformReports(state, scan.status === "running"), runsStarted: state.runsStarted ?? 0,
    message: scan.error ?? "Check in progress. Verified announcements are saved and displayed as each platform finishes.", resumable: true };
}
export async function dashboardFeed(snapshotId?: string) {
  if (snapshotId) return savedFeed(snapshotId);
  const active = await activeScan();
  return active ? scanResponse(active) : savedFeed();
}
