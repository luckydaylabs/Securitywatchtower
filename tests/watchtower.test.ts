import test from "node:test";
import assert from "node:assert/strict";
import { MONITOR_SOURCES } from "../lib/source-config";
import { parseSource, parseMicrosoftDocument, collectSource, latestPerPlatform, fingerprint, type Announcement } from "../lib/source-monitor";
import { researchInput, researchSchema, validateResearch, readResearch, startResearch } from "../lib/nimble-research";
import { startScan, advanceScan, dashboardFeed, resetMonitoringOnce } from "../lib/watchtower-pipeline";
import { getDatabase, resetDatabase, setBatchHook } from "./d1-fixture";
import { platformJobs, researchBatches } from "../lib/platform-research";
import { sourceTimestamp, formatSourceTimestamp } from "../lib/announcement-dates";

const since = "2026-09-09T00:00:00.000Z", until = "2026-09-12T23:59:59.000Z";
const source = (id: string) => MONITOR_SOURCES.find(s => s.id === id)!;
const item: Announcement = { id: "ubuntu:USN-1234-1", sourceId: "ubuntu", source: "Ubuntu Security Notices", title: "Test advisory", url: "https://ubuntu.com/security/notices/USN-1234-1", sourceDate: "2026-09-11T00:00:00.000Z", platform: "linux", evidence: "Test fixture only." };
const finding = { id: item.id, source: item.source, sourceUrl: item.url, platform: "linux", detectedAt: item.sourceDate, severity: "high", title: "Test advisory", summary: "Fixture summary", whatHappened: "Fixture evidence", whyItMatters: "Fixture impact", nextStep: "Install the vendor update", signalType: "Security update", scope: "Ubuntu", evidenceNote: "Fixture source note" };
const originalFetch = globalThis.fetch;
test("One-time reset refuses active checks and cannot erase subsequent data", async () => {
  resetDatabase();
  const db = getDatabase();
  await startScan("manual");
  await assert.rejects(resetMonitoringOnce(), /active check/);
  assert.equal((await db.prepare("SELECT COUNT(*) AS n FROM watchtower_scans").first()).n, 1);
  await db.prepare("UPDATE watchtower_control SET active_scan=NULL WHERE id='main'").run();
  assert.equal((await resetMonitoringOnce()).reset, true);
  assert.equal((await db.prepare("SELECT COUNT(*) AS n FROM watchtower_scans").first()).n, 0);
  await startScan("manual");
  assert.equal((await resetMonitoringOnce()).alreadyReset, true);
  assert.equal((await db.prepare("SELECT COUNT(*) AS n FROM watchtower_scans").first()).n, 1);
});
process.env.NIMBLE_API_KEY = "test-placeholder-not-a-real-key";

test("Verified platform findings publish while another runs, survive reload and failures, and finalize once", async () => {
  resetDatabase();
  const db = getDatabase();
  const scan: any = await startScan("manual");
  const candidate = { ...item, versionId: "progressive-linux" };
  await db.prepare("INSERT INTO watchtower_announcements(version_id,advisory_id,source_id,content_hash,source_date,first_seen_at,evidence_json,review_status) VALUES(?,?,?,?,?,?,?,?)")
    .bind(candidate.versionId, item.id, item.sourceId, "hash", item.sourceDate, since, JSON.stringify(item), "pending").run();
  const state = { trigger: "manual", until, candidates: [candidate], sources: MONITOR_SOURCES.map(s => ({ id: s.id, status: "checked", count: 1 })), runsStarted: 8, jobs: [
    { id: "linux", platform: "linux", stage: "verifier", status: "running", candidates: [candidate], investigated: [finding], payload: { findings: [finding] } },
    { id: "windows", platform: "windows", stage: "investigator", status: "running", candidates: [], nextPollAt: Date.now() + 100000 },
    { id: "macos", platform: "macos", stage: "verifier", status: "blocked", candidates: [], error: "Invalid severity" },
  ] };
  await db.prepare("UPDATE watchtower_scans SET stage='investigator',state_json=? WHERE id=?").bind(JSON.stringify(state), scan.runId).run();
  const partial: any = await advanceScan(scan.runId);
  assert.equal(partial.status, "running");
  assert.equal(partial.findings.length, 1);
  assert.equal(partial.platformReports.find((p: any) => p.platform === "macos").status, "partial");
  assert.equal(partial.platformReports.find((p: any) => p.platform === "linux").status, "checked");
  assert.equal((await dashboardFeed()).findings.length, 1);
  assert.equal((await advanceScan(scan.runId)).findings.length, 1);
  const saved = JSON.parse((await db.prepare("SELECT state_json FROM watchtower_scans WHERE id=?").bind(scan.runId).first()).state_json);
  assert.equal(saved.jobs[0].published, true);
  saved.jobs[1].status = "blocked";
  await db.prepare("UPDATE watchtower_scans SET state_json=? WHERE id=?").bind(JSON.stringify(saved), scan.runId).run();
  const finished = await advanceScan(scan.runId);
  assert.equal(finished.status, "partial");
  assert.equal(finished.history[0].outcome, "partial");
  assert.equal((await dashboardFeed()).mode, "partial");
  assert.equal(finished.findings.length, 1);
  assert.equal(finished.history.length, 1);
  assert.equal((await advanceScan(scan.runId)).history.length, 1);
});

test("Both research stages receive the unknown severity contract without paid runs", async () => {
  globalThis.fetch = async (_url, init) => {
    const body = JSON.parse(String(init?.body));
    assert.deepEqual(body.output_schema, researchSchema);
    assert.match(body.input, /use unknown/i);
    assert.match(body.skill, /unknown/);
    return Response.json({ id: "test-run", agent_id: "test-agent" });
  };
  try {
    await startResearch("test", "investigator", [item], undefined, "linux");
    await startResearch("test", "verifier", [item], validateResearch({ findings: [finding] }, [item]), "linux");
  } finally { globalThis.fetch = originalFetch; }
  for (const severity of [null, undefined, "", "unknown", " Unknown "]) {
    assert.equal(validateResearch({ findings: [{ ...finding, severity }] }, [item])[0].severity, "unknown");
  }
  assert.throws(() => validateResearch({ findings: [{ ...finding, severity: "invalid" }] }, [item]), /severity/);
});

test("Apple investigator and verifier must read full release pages without a supplied-CVE restriction", async () => {
  const apple = { ...item, sourceId: "apple", platform: "macos" as const, id: "apple:123456", url: "https://support.apple.com/en-us/123456" };
  let calls = 0;
  globalThis.fetch = async (_url, init) => {
    calls++;
    const body = JSON.parse(String(init?.body));
    assert.match(body.sources.prioritize, /read the full page/);
    assert.match(body.sources.prioritize, /one comprehensive, concise record per supplied release ID/);
    assert.match(body.sources.prioritize, /verifier must independently read/);
    assert.doesNotMatch(body.sources.prioritize, /check supplied CVEs/i);
    return Response.json({ id: "test-run", agent_id: "test-agent" });
  };
  try {
    await startResearch("apple-test", "investigator", [apple], undefined, "macos");
    await startResearch("apple-test", "verifier", [apple], undefined, "macos");
    assert.equal(calls, 2);
  } finally { globalThis.fetch = originalFetch; }
});

test("Windows verification retains valid structured severity evidence and official document URL", () => {
  const windows = { ...item, id: "msrc:CVE-2026-1234", sourceId: "msrc", platform: "windows" as const,
    url: "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-1234",
    evidenceUrl: "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Sep",
    evidence: JSON.stringify({ cve: "CVE-2026-1234", threats: [{ type: 3, description: "Important" }], products: Array(20).fill("Windows 11") }) };
  const prompt = researchInput("windows", "verifier", [windows]);
  const packet = JSON.parse(prompt.split("EVIDENCE:\n")[1]);
  assert.equal(packet[0].officialDocumentUrl, windows.evidenceUrl);
  assert.equal(JSON.parse(packet[0].capturedEvidence).threats[0].description, "Important");
});

test("Source timestamps preserve date-only precision, real midnight, offsets, and unknown timezones", () => {
  assert.equal(formatSourceTimestamp(sourceTimestamp("6 August 2026")), "Aug 6, 2026 (time not provided)");
  assert.equal(formatSourceTimestamp(sourceTimestamp("2026-08-06T00:00:00Z")), "Aug 6, 2026, 00:00:00 UTC");
  assert.equal(formatSourceTimestamp(sourceTimestamp("2026-08-06T09:15+07:00")), "Aug 6, 2026, 02:15 UTC");
  assert.equal(formatSourceTimestamp(sourceTimestamp("2026-08-06T09:15")), "2026-08-06T09:15 (timezone not specified)");
  assert.equal(sourceTimestamp("not a date"), undefined);
});

test("Source parsers distinguish publication from updates without manufacturing absent fields", () => {
  const ubuntu = parseSource(source("ubuntu"), `<feed><entry><id>USN-1</id><title>Update</title><link href="${item.url}"/><published>2026-08-01T12:30:00Z</published><updated>2026-09-11T14:15:00Z</updated></entry></feed>`, until)[0];
  assert.equal(ubuntu.publishedAt?.value, "2026-08-01T12:30:00.000Z");
  assert.equal(ubuntu.updatedAt?.value, "2026-09-11T14:15:00.000Z");
  const apple = parseSource(source("apple"), '<table><tr><td><a href="/en-us/123456">macOS Tahoe</a></td><td>6 August 2026</td></tr></table>', until)[0];
  assert.equal(apple.publishedAt?.precision, "date");
  assert.equal(apple.updatedAt, undefined);
  const verified = validateResearch({ findings: [{ ...finding, id: ubuntu.id, publishedAt: { value: "invented" } }] }, [ubuntu])[0];
  assert.deepEqual(verified.publishedAt, ubuntu.publishedAt);
});

test("Microsoft publication requires an initial revision, separate from subsequent meaningful updates", () => {
  const base = { ProductTree: { FullProductName: [{ ProductID: "1", Value: "Windows 11" }] }, Vulnerability: [{ CVE: "CVE-2026-1234", ProductStatuses: [{ ProductID: ["1"] }], RevisionHistory: [
    { Number: "1.0", Date: "2026-08-01T12:00:00Z", Description: { Value: "Information published." } },
    { Number: "2.0", Date: "2026-09-11", Description: { Value: "Affected products updated" } },
  ] }] };
  const parsed = parseMicrosoftDocument(JSON.stringify(base), until)[0];
  assert.equal(parsed.publishedAt?.value, "2026-08-01T12:00:00.000Z");
  assert.equal(parsed.updatedAt?.precision, "date");
  base.Vulnerability[0].RevisionHistory.shift();
  const partial = parseMicrosoftDocument(JSON.stringify(base), until)[0];
  assert.equal(partial.publishedAt, undefined);
  assert.equal(partial.updatedAt?.value, "2026-09-11");
});

test("Metadata refresh preserves discovery, accepted research, and snapshot history without paid runs", async () => {
  resetDatabase();
  const db = getDatabase();
  const body = `<feed><entry><id>USN-1234-1</id><title>Test advisory</title><link href="${item.url}"/><published>2026-08-01</published><updated>2026-09-11T00:00:00Z</updated><summary>Test fixture only.</summary></entry></feed>`;
  const parsed = parseSource(source("ubuntu"), body, until)[0];
  const hash = await fingerprint(JSON.stringify({ title: parsed.title, url: parsed.url, date: parsed.sourceDate, evidence: parsed.evidence }));
  await db.prepare("INSERT INTO watchtower_announcements(version_id,advisory_id,source_id,content_hash,source_date,first_seen_at,evidence_json,review_status,finding_json) VALUES(?,?,?,?,?,?,?,?,?)")
    .bind(`${parsed.id}:${hash}`, parsed.id, parsed.sourceId, hash, parsed.sourceDate, since,
      JSON.stringify({ ...parsed, publishedAt: undefined, updatedAt: undefined }), "accepted", JSON.stringify(finding)).run();
  globalThis.fetch = async (_url: any, init?: any) => {
    assert.notEqual(init?.method, "POST", "Metadata enrichment must not submit research");
    return new Response(body);
  };
  try {
    for (let n = 0; n < 2; n++) {
      const scan: any = await startScan("manual");
      await db.prepare("UPDATE watchtower_scans SET state_json=? WHERE id=?").bind(JSON.stringify({ trigger: "manual", until, candidates: [],
        sources: MONITOR_SOURCES.filter(s => s.id !== "ubuntu").map(s => ({ id: s.id, status: "checked", count: 0 })) }), scan.runId).run();
      await advanceScan(scan.runId);
      const result = await advanceScan(scan.runId);
      assert.equal(result.status, "completed");
      assert.equal(result.findings.length, 1);
      assert.equal(result.findings[0].publishedAt?.value, "2026-08-01");
      assert.equal(result.findings[0].firstDiscoveredAt, since);
      assert.equal(result.history.length, n + 1);
      assert.equal(result.pendingCount, 0);
    }
    const refreshed = await dashboardFeed();
    assert.equal(refreshed.findings[0].updatedAt?.value, "2026-09-11T00:00:00.000Z");
    assert.equal((await db.prepare("SELECT COUNT(*) AS count FROM watchtower_announcements").first()).count, 1);
  } finally { globalThis.fetch = originalFetch; }
});

test("RSS object GUIDs remain distinct; older notices stay eligible without a date cutoff", () => {
  const body = `<rss><channel>${[1, 2].map(n => `<item><guid isPermaLink="false">USN-${n}</guid><title>Notice ${n}</title><link>https://ubuntu.com/security/notices/USN-${n}</link><pubDate>Fri, 11 Sep 2026 00:00:00 GMT</pubDate></item>`).join("")}<item><title>Old</title><link>https://ubuntu.com/security/notices/old</link><pubDate>2020-01-01</pubDate></item></channel></rss>`;
  assert.deepEqual(parseSource(source("ubuntu"), body, until).map(i => i.id), ["ubuntu:USN-1", "ubuntu:USN-2", "ubuntu:old"]);
});
test("Microsoft dates and platform come from individual advisories, not the monthly revision", () => {
  const body = JSON.stringify({ ProductTree: { FullProductName: [{ ProductID: "1", Value: "Windows 11" }, { ProductID: "2", Value: "Office" }] }, Vulnerability: [
    { CVE: "CVE-2026-1234", Title: { Value: "Windows issue" }, ProductStatuses: [{ ProductID: ["1"] }], RevisionHistory: [{ Date: "2026-09-11", Description: { Value: "Security update" } }] },
    { CVE: "CVE-2020-1234", ProductStatuses: [{ ProductID: ["1"] }], RevisionHistory: [{ Date: "2020-01-01" }, { Date: "2026-09-11", Description: { Value: "Acknowledgement updated" } }] },
    { CVE: "CVE-2026-9999", ProductStatuses: [{ ProductID: ["2"] }], RevisionHistory: [{ Date: "2026-09-11" }] },
  ] });
  const items = parseMicrosoftDocument(body, until);
  assert.deepEqual(items.map(i => i.id), ["msrc:CVE-2026-1234", "msrc:CVE-2020-1234"]);
  assert.equal(items[1].sourceDate, "2020-01-01T00:00:00.000Z");
});
test("Public compliance updates and unrelated AI-discovered vulnerabilities are excluded", () => {
  assert.equal(parseSource(source("anthropic"), JSON.stringify([{ revealed: true, ant_id: "a1", project: "GraphicsMagick", bug_class: "overflow", revealed_at: "2026-09-11" }]), until).length, 0);
  const data = { props: { pageProps: { orgInfo: { topics: [{ subject: "SOC2 report", updates: [{ id: "a", createdAt: "2026-09-11", message: "Compliance report" }] }] } } } };
  assert.equal(parseSource(source("openai"), `<script id="__NEXT_DATA__">${JSON.stringify(data)}</script>`, until).length, 0);
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

test("CSAF discovery selects five Windows advisories and reuses unchanged documents", async () => {
  const urls: string[] = [];
  globalThis.fetch = async (url: any) => {
    urls.push(String(url));
    return String(url).endsWith("changes.csv")
      ? new Response(Array.from({ length: 8 }, (_, n) => `"2026/msrc_cve-2026-${1000 + n}.json","2026-09-0${n + 1}T07:00:00Z"`).join("\n"))
      : Response.json({ document: { csaf_version: "2.0", tracking: { initial_release_date: "2026-09-01T07:00:00Z", revision_history: [{ date: `2026-09-0${Number(String(url).match(/100(\d)/)![1]) + 1}T07:00:00Z`, summary: "Security update" }] } },
        product_tree: { branches: [{ product: { product_id: "1", name: "Windows 11" } }] },
        vulnerabilities: [{ cve: String(url).match(/cve-2026-\d+/i)![0].toUpperCase(), product_status: { known_affected: ["1"] } }] });
  };
  try {
    const result = await collectSource(source("msrc"), { etag: "v1", documents_json: JSON.stringify({ done: [], pending: [] }) }, until);
    assert.match(urls[0], /csaf\/advisories\/changes.csv$/);
    assert.equal(urls.length, 6);
    assert.equal(result.items.length, 5);
    assert.equal(result.items[0].id, "msrc:CVE-2026-1007");
    assert.equal(result.items[0].publishedAt?.value, "2026-09-01T07:00:00.000Z");
    await collectSource(source("msrc"), { documents_json: result.documentsJson }, until);
    assert.equal(urls.length, 7);
  } finally { globalThis.fetch = originalFetch; }
});

test("Four five-announcement platform lanes dispatch concurrently and persist all twenty records", async () => {
  resetDatabase();
  const candidates = (["macos", "windows", "linux", "ai"] as const).flatMap(platform =>
    Array.from({ length: 5 }, (_, n) => ({ ...item, platform, id: `${platform}:fixture-${n}`, url: `${item.url}-${platform}-${n}`, versionId: `${platform}-${n}` })));
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
    assert.equal(result.findings.length, 20); assert.equal(posts, 8); assert.equal(peak, 4);
    assert.equal(result.platformReports.length, 4);
    assert.equal((await dashboardFeed()).findings.length, 20);
    assert.equal((await advanceScan(scan.runId)).history.length, 1); assert.equal(posts, 8);
    const state = JSON.parse((await db.prepare("SELECT state_json FROM watchtower_scans WHERE id=?").bind(scan.runId).first()).state_json);
    assert.equal(state.jobs.flatMap((j: any) => j.outputs ?? []).length, 8);
  } finally { globalThis.fetch = originalFetch; Date.now = originalNow; }
});
test("Latest-five cache retains selected announcements on 304", async () => {
  globalThis.fetch = async (_url: any, init?: any) => {
    assert.equal(init.headers["If-None-Match"], "v1");
    return new Response(null, { status: 304 });
  };
  try {
    const result = await collectSource(source("ubuntu"), { etag: "v1", documents_json: JSON.stringify({ policy: "latest-five-dates-v2", items: [item] }) }, until);
    assert.deepEqual(result.items, [item]);
    assert.equal(result.unchanged, true);
  } finally { globalThis.fetch = originalFetch; }
});

test("Apple ignores old checkpoints and selects five August announcements without an age filter", async () => {
  globalThis.fetch = async (_url: any, init?: any) => {
    assert.equal(init.headers["If-None-Match"], undefined);
    assert.equal(init.headers["If-Modified-Since"], undefined);
    return new Response(`<table>${[1, 3, 2, 4, 6, 5].map(n => `<tr><td><a href="/en-us/10010${n}">macOS Tahoe ${n}</a></td><td>${n} August 2026</td></tr>`).join("")}</table>`);
  };
  try {
    const result = await collectSource(source("apple"), { etag: "old", last_modified: until, succeeded_at: until }, until);
    assert.deepEqual(result.items.map(i => i.title), [6, 5, 4, 3, 2].map(n => `macOS Tahoe ${n}`));
    assert.equal(result.warning, undefined);
    assert.match(researchInput("august", "investigator", result.items), /no date cutoff/);
    assert.match(researchInput("august", "verifier", result.items), /no date cutoff/);
  } finally { globalThis.fetch = originalFetch; }
});

test("Latest-five selection merges both AI sources and keeps other platforms independent", () => {
  const items = (["macos", "windows", "linux", "ai"] as const).flatMap(platform => Array.from({ length: 7 }, (_, n) => ({
    ...item, id: `${platform}:${n}`, platform, sourceId: platform === "ai" ? n % 2 ? "openai" : "anthropic" : item.sourceId,
    sourceDate: `2026-08-0${n + 1}T00:00:00.000Z`,
  })));
  const selected = latestPerPlatform([...items, items[0]]);
  assert.equal(selected.length, 20);
  for (const platform of ["macos", "windows", "linux", "ai"]) {
    assert.deepEqual(selected.filter(i => i.platform === platform).map(i => i.id), [6, 5, 4, 3, 2].map(n => `${platform}:${n}`));
  }
});

test("Saved latest-five records prevent backfilling older pending records; changed versions remain eligible", async () => {
  resetDatabase();
  const db = getDatabase();
  for (const platform of ["macos", "windows", "linux", "ai"] as const) for (let n = 1; n <= 7; n++) {
    const candidate = { ...item, id: `${platform}:${n}`, platform, sourceDate: `2026-08-0${n}T00:00:00.000Z` };
    await db.prepare("INSERT INTO watchtower_announcements(version_id,advisory_id,source_id,content_hash,source_date,first_seen_at,evidence_json,review_status) VALUES(?,?,?,?,?,?,?,?)")
      .bind(candidate.id, candidate.id, candidate.sourceId, candidate.id, candidate.sourceDate, since, JSON.stringify(candidate), n >= 3 ? "accepted" : "pending").run();
  }
  assert.equal((await dashboardFeed()).pendingCount, 0);
  const changed = { ...item, id: "macos:7", platform: "macos", sourceDate: "2026-08-07T00:00:00.000Z", evidence: "Revised affected versions" };
  await db.prepare("INSERT INTO watchtower_announcements(version_id,advisory_id,source_id,content_hash,source_date,first_seen_at,evidence_json,review_status) VALUES(?,?,?,?,?,?,?,?)")
    .bind("macos:7:changed", changed.id, changed.sourceId, "new-hash", changed.sourceDate, until, JSON.stringify(changed), "pending").run();
  assert.equal((await dashboardFeed()).pendingCount, 1);
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
