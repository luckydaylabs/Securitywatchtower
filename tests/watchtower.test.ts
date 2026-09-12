import test from "node:test";
import assert from "node:assert/strict";
import { MONITOR_SOURCES } from "../lib/source-config";
import { parseSource, parseMicrosoftDocument, collectSource, type Announcement } from "../lib/source-monitor";
import { researchInput, researchSchema, validateResearch, readResearch } from "../lib/nimble-research";
import { startScan, advanceScan, dashboardFeed } from "../lib/watchtower-pipeline";
import { getDatabase, resetDatabase, setBatchHook } from "./d1-fixture";
import { platformJobs, researchBatches } from "../lib/platform-research";

const since = "2026-09-09T00:00:00.000Z", until = "2026-09-12T23:59:59.000Z";
const source = (id: string) => MONITOR_SOURCES.find(s => s.id === id)!;
const item: Announcement = { id: "ubuntu:USN-1234-1", sourceId: "ubuntu", source: "Ubuntu Security Notices", title: "Test advisory", url: "https://ubuntu.com/security/notices/USN-1234-1", sourceDate: "2026-09-11T00:00:00.000Z", platform: "linux", evidence: "Test fixture only." };
const finding = { id: item.id, source: item.source, sourceUrl: item.url, platform: "linux", detectedAt: item.sourceDate, severity: "high", title: "Test advisory", summary: "Fixture summary", whatHappened: "Fixture evidence", whyItMatters: "Fixture impact", nextStep: "Install the vendor update", signalType: "Security update", scope: "Ubuntu", evidenceNote: "Fixture source note" };
const originalFetch = globalThis.fetch;
process.env.NIMBLE_API_KEY = "test-placeholder-not-a-real-key";

test("RSS object GUIDs remain distinct; old notices are excluded", () => {
  const body = `<rss><channel>${[1, 2].map(n => `<item><guid isPermaLink="false">USN-${n}</guid><title>Notice ${n}</title><link>https://ubuntu.com/security/notices/USN-${n}</link><pubDate>Fri, 11 Sep 2026 00:00:00 GMT</pubDate></item>`).join("")}<item><title>Old</title><link>https://ubuntu.com/security/notices/old</link><pubDate>2020-01-01</pubDate></item></channel></rss>`;
  assert.deepEqual(parseSource(source("ubuntu"), body, since, until).map(i => i.id), ["ubuntu:USN-1", "ubuntu:USN-2"]);
});
test("Microsoft dates and platform come from individual advisories, not the monthly revision", () => {
  const body = JSON.stringify({ ProductTree: { FullProductName: [{ ProductID: "1", Value: "Windows 11" }, { ProductID: "2", Value: "Office" }] }, Vulnerability: [
    { CVE: "CVE-2026-1234", Title: { Value: "Windows issue" }, ProductStatuses: [{ ProductID: ["1"] }], RevisionHistory: [{ Date: "2026-09-11", Description: { Value: "Security update" } }] },
    { CVE: "CVE-2020-1234", ProductStatuses: [{ ProductID: ["1"] }], RevisionHistory: [{ Date: "2020-01-01" }, { Date: "2026-09-11", Description: { Value: "Acknowledgement updated" } }] },
    { CVE: "CVE-2026-9999", ProductStatuses: [{ ProductID: ["2"] }], RevisionHistory: [{ Date: "2026-09-11" }] },
  ] });
  assert.deepEqual(parseMicrosoftDocument(body, since, until).map(i => i.id), ["msrc:CVE-2026-1234"]);
});
test("Public compliance updates and unrelated AI-discovered vulnerabilities are excluded", () => {
  assert.equal(parseSource(source("anthropic"), JSON.stringify([{ revealed: true, ant_id: "a1", project: "GraphicsMagick", bug_class: "overflow", revealed_at: "2026-09-11" }]), since, until).length, 0);
  const data = { props: { pageProps: { orgInfo: { topics: [{ subject: "SOC2 report", updates: [{ id: "a", createdAt: "2026-09-11", message: "Compliance report" }] }] } } } };
  assert.equal(parseSource(source("openai"), `<script id="__NEXT_DATA__">${JSON.stringify(data)}</script>`, since, until).length, 0);
});
test("Research guards cardinality and preserves captured source identity", () => {
  assert.doesNotMatch(JSON.stringify(researchSchema), /"(?:maxItems|minItems|maxLength|minLength)":/);
  assert.throws(() => researchInput("scan", "investigator", [item, item, item, item]));
  const many = Array.from({ length: 7 }, (_, n) => ({ ...item, id: `ubuntu:USN-${n}`, url: `https://ubuntu.com/security/notices/USN-${n}` }));
  assert.doesNotThrow(() => researchInput("scan", "investigator", many));
  assert.equal(validateResearch({ findings: many.map(i => ({ ...finding, id: i.id, sourceUrl: i.url })) }, many).length, 7);
  assert.equal(researchBatches(many, "investigator").flat().length, 7);
  assert.throws(() => researchInput("scan", "investigator", [{ ...item, url: "https://attacker.invalid" }]));
  assert.throws(() => validateResearch({ findings: [finding, finding] }, [item]));
  assert.equal(validateResearch({ output: { type: "json", content: { findings: [{ ...finding, platform: "ai" }] } } }, [item])[0].platform, "linux");
  assert.equal(validateResearch({ findings: [{ ...finding, id: "USN-1234-1" }] }, [item])[0].id, item.id);
  assert.throws(() => validateResearch({ findings: [{ ...finding, id: "unrelated", sourceUrl: "https://ubuntu.com/security/notices/unrelated" }] }, [item]), /unknown announcement/);
});

test("Current Microsoft documents precede recently edited historical releases", async () => {
  const document = (id: string) => ({ ...item, id: `msrc:${id}`, sourceId: "msrc", url: `https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/${id}`, windowStart: since, windowEnd: until });
  const urls: string[] = [];
  globalThis.fetch = async (url: any) => { urls.push(String(url)); return String(url).endsWith("updates") ? new Response(null, { status: 304 }) : Response.json({ Vulnerability: [], ProductTree: {} }); };
  try {
    const result = await collectSource(source("msrc"), { etag: "v1", documents_json: JSON.stringify({ done: [], pending: [document("2016-Jul"), document("2026-Sep")] }) }, since, until);
    assert.match(urls[1], /2026-Sep$/);
    assert.equal(JSON.parse(result.documentsJson!).pending[0].id, "msrc:2016-Jul");
  } finally { globalThis.fetch = originalFetch; }
});

test("Four platform lanes dispatch concurrently, verify every record, and persist after refresh", async () => {
  resetDatabase();
  const candidates = [
    ...Array.from({ length: 7 }, (_, n) => ({ ...item, id: `ubuntu:USN-${n}`, url: `https://ubuntu.com/security/notices/USN-${n}`, versionId: `linux-${n}` })),
    ...(["macos", "windows", "ai"] as const).map(platform => ({ ...item, platform, id: `${platform}:fixture`, versionId: platform })),
  ];
  const db = getDatabase(), scan: any = await startScan("manual");
  for (const c of candidates) await db.prepare("INSERT INTO watchtower_announcements(version_id,advisory_id,source_id,content_hash,source_date,first_seen_at,evidence_json,review_status) VALUES(?,?,?,?,?,?,?,?)")
    .bind(c.versionId, c.id, c.sourceId, c.versionId, c.sourceDate, until, JSON.stringify(c), "pending").run();
  await db.prepare("UPDATE watchtower_scans SET stage='investigator',state_json=? WHERE id=?").bind(JSON.stringify({ trigger: "manual", until, candidates, sources: MONITOR_SOURCES.map(s => ({ id: s.id, status: "checked", count: 1 })), jobs: platformJobs(candidates), runsStarted: 0 }), scan.runId).run();
  const outputs = new Map<string, unknown>(); let posts = 0, inFlight = 0, peak = 0;
  const originalNow = Date.now; let tick = originalNow(); Date.now = () => tick;
  globalThis.fetch = async (url: any, init?: any) => {
    if (init?.method === "POST") {
      const body = JSON.parse(init.body); const id = `run-${++posts}`;
      inFlight++; peak = Math.max(peak, inFlight);
      await new Promise(resolve => setTimeout(resolve, 5)); inFlight--;
      const evidence = JSON.parse(body.input.split("EVIDENCE:\n")[1].split("\nPROPOSED RECORDS:")[0]);
      outputs.set(id, { findings: evidence.map((c: any) => ({ ...finding, id: c.id, sourceUrl: c.url, platform: c.platform })) });
      return Response.json({ id, web_search_agent_id: body.agent_name });
    }
    if (String(url).endsWith("/result")) return Response.json(outputs.get(String(url).split("/").at(-2)!));
    return Response.json({ status: "completed" });
  };
  try {
    let result: any;
    for (let n = 0; n < 40; n++) { tick += 20000; result = await advanceScan(scan.runId); if (result.status === "completed") break; }
    assert.equal(result.status, "completed");
    assert.equal(result.findings.length, 10); assert.equal(posts, 8); assert.equal(peak, 4);
    assert.equal(result.platformReports.length, 4);
    assert.equal((await dashboardFeed()).findings.length, 10);
    assert.equal((await advanceScan(scan.runId)).history.length, 1); assert.equal(posts, 8);
    const state = JSON.parse((await db.prepare("SELECT state_json FROM watchtower_scans WHERE id=?").bind(scan.runId).first()).state_json);
    assert.equal(state.jobs.flatMap((j: any) => j.outputs ?? []).length, 8);
  } finally { globalThis.fetch = originalFetch; Date.now = originalNow; }
});
test("Document queue drains on 304 without fetching the index again", async () => {
  const document = { ...item, id: "msrc:2026-Sep", sourceId: "msrc", url: "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Sep", windowStart: since, windowEnd: until };
  globalThis.fetch = async (url: any) => String(url).endsWith("updates") ? new Response(null, { status: 304 }) : Response.json({ Vulnerability: [], ProductTree: {} });
  try {
    const result = await collectSource(source("msrc"), { etag: "v1", documents_json: JSON.stringify({ done: [], pending: [document] }) }, since, until);
    assert.equal(JSON.parse(result.documentsJson!).pending.length, 0);
    assert.equal(JSON.parse(result.documentsJson!).done.length, 1);
  } finally { globalThis.fetch = originalFetch; }
});
test("Result 409 stays pending; unknown provider status is explicit", async () => {
  globalThis.fetch = async (url: any) => String(url).endsWith("result") ? new Response(null, { status: 409 }) : Response.json({ status: "completed" });
  const run = { stage: "investigator" as const, agentId: "agent", runId: "run" };
  try {
    assert.deepEqual(await readResearch(run), { status: "pending" });
    globalThis.fetch = async () => Response.json({ status: "unexpected" });
    await assert.rejects(() => readResearch(run), /unsupported status/);
  } finally { globalThis.fetch = originalFetch; }
});
test("Durable scan resumes, publishes idempotently, and no-change checks retain history", async () => {
  resetDatabase();
  const first: any = await startScan("manual");
  assert.equal(first.status, "running");
  assert.equal((await startScan("manual") as any).runId, first.runId);
  assert.equal((await dashboardFeed() as any).runId, first.runId);
  const db = getDatabase();
  const candidate = { ...item, versionId: "version-test" };
  await db.prepare("INSERT INTO watchtower_announcements(version_id,advisory_id,source_id,content_hash,source_date,first_seen_at,evidence_json,review_status) VALUES(?,?,?,?,?,?,?,?)")
    .bind(candidate.versionId, item.id, item.sourceId, "hash", item.sourceDate, new Date().toISOString(), JSON.stringify(item), "pending").run();
  await db.prepare("UPDATE watchtower_scans SET stage='verifier',state_json=? WHERE id=?").bind(JSON.stringify({ trigger: "manual", until, candidates: [candidate], sources: [], investigated: [finding], verifier: { findings: [finding] } }), first.runId).run();
  assert.equal((await advanceScan(first.runId)).findings.length, 1);
  assert.equal((await advanceScan(first.runId)).history.length, 1);
  const second: any = await startScan("manual");
  await db.prepare("UPDATE watchtower_scans SET stage='orchestrator' WHERE id=?").bind(second.runId).run();
  const completed = await advanceScan(second.runId);
  assert.equal(completed.findings.length, 1);
  assert.equal(completed.history.length, 2);
  assert.equal((await dashboardFeed()).findings.length, 1);
});
test("Expiry during scan creation rolls back the whole transition", async () => {
  resetDatabase();
  const db = getDatabase();
  setBatchHook(async sql => { if (sql.startsWith("INSERT INTO watchtower_scans")) await db.prepare("UPDATE watchtower_control SET lease_until=0 WHERE id='main'").run(); });
  try {
    await assert.rejects(() => startScan("manual"), /overflow/);
    assert.equal((await db.prepare("SELECT COUNT(*) AS n FROM watchtower_scans").first()).n, 0);
    assert.equal((await db.prepare("SELECT active_scan FROM watchtower_control").first()).active_scan, null);
  } finally { setBatchHook(); }
});
test("Expiry during publication cannot leave a completed active scan", async () => {
  resetDatabase();
  const db = getDatabase();
  const scan: any = await startScan("manual");
  await db.prepare("UPDATE watchtower_scans SET stage='orchestrator' WHERE id=?").bind(scan.runId).run();
  setBatchHook(async sql => { if (sql.startsWith("UPDATE watchtower_scans SET status='completed'")) await db.prepare("UPDATE watchtower_control SET lease_until=0 WHERE id='main'").run(); });
  try {
    const result = await advanceScan(scan.runId);
    assert.equal(result.status, "failed");
    assert.equal((await db.prepare("SELECT COUNT(*) AS n FROM watchtower_snapshots").first()).n, 0);
    assert.equal((await db.prepare("SELECT status FROM watchtower_scans WHERE id=?").bind(scan.runId).first()).status, "blocked");
  } finally { setBatchHook(); }
});
