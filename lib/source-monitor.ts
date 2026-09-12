import { XMLParser } from "fast-xml-parser";
import { approvedSourceUrl, type MonitorSource } from "./source-config";
import type { Finding } from "./watchtower";
import { sourceTimestamp, type AnnouncementDates } from "./announcement-dates";

export type Announcement = AnnouncementDates & {
  id: string; sourceId: string; source: string; url: string; title: string;
  sourceDate: string; platform: Finding["platform"]; evidence: string;
};
export type SourceCheckpoint = { etag?: string | null; last_modified?: string | null; succeeded_at?: string | null; documents_json?: string | null };
export type SourceResult = { items: Announcement[]; etag: string | null; lastModified: string | null; unchanged: boolean; warning?: string; documentsJson?: string };

export const ANNOUNCEMENTS_PER_PLATFORM = 5;
export function latestPerPlatform<T extends Announcement>(items: T[]): T[] {
  const counts = new Map<string, number>(), seen = new Set<string>();
  return [...items].sort((a, b) => b.sourceDate.localeCompare(a.sourceDate) || a.id.localeCompare(b.id)).filter(item => {
    if (seen.has(item.id)) return false;
    seen.add(item.id);
    const count = counts.get(item.platform) ?? 0;
    if (count >= ANNOUNCEMENTS_PER_PLATFORM) return false;
    counts.set(item.platform, count + 1);
    return true;
  });
}

const parser = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: "@", processEntities: true });
const list = <T>(value: T | T[] | undefined): T[] => value == null ? [] : Array.isArray(value) ? value : [value];
export function plainText(value: string): string {
  return value.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, " ").replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ").replace(/&nbsp;|&#160;/g, " ").replace(/&amp;/g, "&")
    .replace(/&quot;/g, '"').replace(/&#39;|&apos;/g, "'").replace(/\s+/g, " ").trim();
}
function date(value: unknown): string | null {
  const timestamp = sourceTimestamp(value);
  const parsed = timestamp ? Date.parse(timestamp.value) : NaN;
  return Number.isFinite(parsed) ? new Date(parsed).toISOString() : null;
}
export async function fingerprint(value: string): Promise<string> {
  const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(bytes), x => x.toString(16).padStart(2, "0")).join("");
}
export async function fetchSource(url: string, headers: Record<string, string> = {}): Promise<Response> {
  if (!approvedSourceUrl(url)) throw new Error("Source address is outside the approved catalog.");
  for (let i = 0; i < 4; i++) {
    const response = await fetch(url, { headers: { Accept: "application/json, application/atom+xml, text/html", ...headers }, redirect: "manual", signal: AbortSignal.timeout(12000) });
    if (response.status >= 300 && response.status < 400 && response.status !== 304) {
      const next = new URL(response.headers.get("location") || "", url).href;
      if (!approvedSourceUrl(next)) throw new Error("Source redirected outside its approved domains.");
      url = next;
      continue;
    }
    return response;
  }
  throw new Error("Source exceeded the redirect limit.");
}
async function boundedText(response: Response, limit = 4_000_000): Promise<string> {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > limit) { await reader.cancel(); throw new Error("Source response is too large for a bounded check."); }
    chunks.push(value);
  }
  const merged = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { merged.set(chunk, offset); offset += chunk.length; }
  return new TextDecoder().decode(merged);
}

export function parseSource(source: MonitorSource, body: string, until: string): Announcement[] {
  const items: Announcement[] = [];
  const add = (id: string, title: string, url: string, timestamp: unknown, evidence: string, platform: Finding["platform"], published?: unknown, updated?: unknown) => {
    const sourceDate = date(timestamp);
    if (!sourceDate || sourceDate > until || !approvedSourceUrl(url)) return;
    items.push({ id: `${source.id}:${id}`.slice(0, 160), sourceId: source.id, source: source.name,
      title: plainText(title).slice(0, 240), url, sourceDate, platform, evidence: plainText(evidence).slice(0, 4000),
      publishedAt: sourceTimestamp(published), updatedAt: sourceTimestamp(updated) });
  };
  if (source.id === "ubuntu") {
    const xml = parser.parse(body);
    const entries = list<Record<string, any>>(xml.feed?.entry ?? xml.rss?.channel?.item);
    if (!entries.length) throw new Error("Announcement feed did not contain recognizable entries.");
    for (const entry of entries) {
      const link = list<any>(entry.link).find(x => typeof x === "string" || x["@rel"] === "alternate" || !x["@rel"]);
      const url = typeof link === "string" ? link : link?.["@href"];
      if (!url) continue;
      const text = (v: any) => typeof v === "string" ? v : v?.["#text"] ?? "";
      add(String(text(entry.id) || text(entry.guid) || url).split("/").filter(Boolean).pop()!, text(entry.title), url,
        entry.updated ?? entry.published ?? entry.pubDate, text(entry.content ?? entry.summary ?? entry.description), "linux", entry.published ?? entry.pubDate, entry.updated);
    }
  } else if (source.id === "msrc") {
    const data = JSON.parse(body);
    if (!Array.isArray(data.value)) throw new Error("Microsoft update index has an unexpected format.");
    for (const item of data.value) {
      add(String(item.ID), String(item.DocumentTitle ?? item.Alias ?? item.ID),
        item.CvrfUrl ?? `https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/${encodeURIComponent(item.ID)}`,
        item.CurrentReleaseDate ?? item.InitialReleaseDate, JSON.stringify(item), "windows", item.InitialReleaseDate, item.CurrentReleaseDate);
    }
  } else if (source.id === "apple") {
    const rows = body.match(/<tr\b[^>]*>[\s\S]*?<\/tr>/gi) ?? [];
    if (!rows.length) throw new Error("Apple release table could not be read.");
    for (const row of rows) {
      if (!/macOS|Safari/i.test(plainText(row))) continue;
      const stamp = plainText(row).match(/\b\d{1,2}\s+[A-Za-z]{3,9}\s+20\d{2}\b|\b[A-Za-z]{3,9}\s+\d{1,2},?\s+20\d{2}\b/)?.[0];
      const anchor = row.match(/<a\b[^>]*href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/i);
      if (!anchor) continue;
      const url = new URL(anchor[1], source.url).href;
      add(url.split("/").pop()!, anchor[2], url, stamp, row, "macos", stamp);
    }
  } else if (source.id === "anthropic") {
    const records = JSON.parse(body);
    if (!Array.isArray(records)) throw new Error("Disclosure ledger has an unexpected format.");
    for (const record of records) {
      if (!record.revealed || !record.ant_id || record.withdrawn || record.superseded_by || record.merged_into) continue;
      // AI-assisted discovery in unrelated software is not an AI-platform vulnerability.
      if (!/claude|anthropic|prompt.?injection|model context protocol|\bmcp\b/i.test(`${record.project} ${record.bug_class}`)) continue;
      add(record.ant_id, `${record.project}: ${record.bug_class}`, `https://red.anthropic.com/2026/cvd/findings/${encodeURIComponent(record.ant_id)}.html`,
        record.revealed_at, JSON.stringify(record), "ai", record.revealed_at);
    }
  } else if (source.id === "openai") {
    const json = body.match(/<script[^>]*id=["']__NEXT_DATA__["'][^>]*>([\s\S]*?)<\/script>/i)?.[1];
    if (!json) throw new Error("Public disclosure page format could not be read.");
    const topics = JSON.parse(json).props?.pageProps?.orgInfo?.topics;
    if (!Array.isArray(topics)) throw new Error("Public disclosure listing has an unexpected format.");
    for (const topic of topics) {
      if (topic.hidden) continue;
      for (const update of list<any>(topic.updates)) {
        const text = `${topic.subject} ${plainText(update.message ?? "")}`;
        if (!/CVE-\d{4}-\d+|security incident|vulnerabilit|prompt.?injection/i.test(text)) continue;
        add(String(update.id), topic.subject, source.url, update.updatedAt ?? update.createdAt, text, "ai", update.createdAt, update.updatedAt);
      }
    }
  }
  return Array.from(new Map(items.map(item => [item.id, item])).values());
}

export async function collectSource(source: MonitorSource, checkpoint: SourceCheckpoint, until: string): Promise<SourceResult> {
  // Old checkpoints contain only a date window, not the full latest-five selection.
  // Ignore their validators once so older announcements are actually retrieved.
  const stored = checkpoint.documents_json ? JSON.parse(checkpoint.documents_json) : null;
  const cached = stored?.policy === "latest-five-dates-v2" && Array.isArray(stored.items) ? stored : null;
  const headers: Record<string, string> = {};
  if (cached && checkpoint.etag) headers["If-None-Match"] = checkpoint.etag;
  if (cached && checkpoint.last_modified) headers["If-Modified-Since"] = checkpoint.last_modified;
  const response = await fetchSource(source.url, headers);
  if (response.status === 304 && cached) return { items: cached.items, etag: checkpoint.etag ?? null, lastModified: checkpoint.last_modified ?? null, unchanged: true, warning: cached.warning, documentsJson: checkpoint.documents_json! };
  if (!response.ok) throw new Error(`Source returned HTTP ${response.status}.`);
  const body = await boundedText(response);
  const capturedUntil = new Date(Math.max(Date.parse(until), Date.now())).toISOString();
  let items = parseSource(source, body, capturedUntil);
  let warning: string | undefined;
  if (source.id === "msrc") {
    // Read the newest release documents first, not recently edited archive documents.
    const documents = items.sort((a, b) => {
      const release = (item: Announcement) => Date.parse(item.id.replace(/^msrc:/, "1-")) || 0;
      return release(b) - release(a) || b.sourceDate.localeCompare(a.sourceDate);
    });
    items = [];
    // Stop once five Windows advisories are available. This is a request bound,
    // not an age cutoff; a quiet month can fall back to an older release.
    for (const document of documents.slice(0, 5)) {
      const detail = await fetchSource(document.url);
      if (!detail.ok) throw new Error(`Microsoft advisory document returned HTTP ${detail.status}.`);
      items = latestPerPlatform([...items, ...parseMicrosoftDocument(await boundedText(detail, 25_000_000), capturedUntil)]);
      if (items.length >= ANNOUNCEMENTS_PER_PLATFORM) break;
    }
    if (items.length < ANNOUNCEMENTS_PER_PLATFORM && documents.length > 5) warning = "Fewer than five Windows announcements were found in the five newest release documents; older documents were not checked.";
  }
  items = latestPerPlatform(items);
  const documentsJson = JSON.stringify({ policy: "latest-five-dates-v2", items, warning });
  return { items, etag: response.headers.get("etag"), lastModified: response.headers.get("last-modified"), unchanged: false, warning, documentsJson };
}

export function parseMicrosoftDocument(body: string, until: string): Announcement[] {
  const data = JSON.parse(body);
  if (!Array.isArray(data.Vulnerability)) throw new Error("Microsoft advisory document has an unexpected format.");
  const windows = new Map(list<any>(data.ProductTree?.FullProductName).filter(x => /Windows/i.test(x.Value)).map(x => [String(x.ProductID), String(x.Value)]));
  const output: Announcement[] = [];
  for (const v of data.Vulnerability) {
    const products = list<any>(v.ProductStatuses).flatMap(s => list<any>(s.ProductID)).map(String).filter(id => windows.has(id));
    if (!products.length || !/^CVE-\d{4}-\d+$/.test(v.CVE)) continue;
    const revisions = list<any>(v.RevisionHistory).filter(r => !/acknowledg|credit|typo/i.test(r.Description?.Value ?? ""));
    const sourceDate = revisions.map(r => date(r.Date)).filter((x): x is string => Boolean(x)).sort().at(-1);
    if (!sourceDate || sourceDate > until) continue;
    const evidence = JSON.stringify({ cve: v.CVE, title: v.Title?.Value, products: products.slice(0, 12).map(id => windows.get(id)),
      revisions: revisions.slice(-3), notes: list<any>(v.Notes).slice(0, 3), threats: list<any>(v.Threats).slice(0, 4), remediations: list<any>(v.Remediations).slice(0, 3) });
    const ordered = list<any>(v.RevisionHistory).filter(r => date(r.Date)).sort((a, b) => date(a.Date)!.localeCompare(date(b.Date)!));
    const latest = [...revisions].filter(r => date(r.Date)).sort((a, b) => date(a.Date)!.localeCompare(date(b.Date)!)).at(-1);
    const initial = /initial|first publish|original release|information published/i.test(ordered[0]?.Description?.Value ?? "") || String(ordered[0]?.Number) === "1.0";
    output.push({ id: `msrc:${v.CVE}`, sourceId: "msrc", source: "Microsoft Windows advisories", title: v.Title?.Value ?? v.CVE,
      url: `https://msrc.microsoft.com/update-guide/vulnerability/${v.CVE}`, sourceDate, platform: "windows", evidence: evidence.slice(0, 4000),
      // Only an explicitly initial revision establishes publication; the earliest
      // retained revision alone is not proof of the original publication date.
      publishedAt: initial ? sourceTimestamp(ordered[0].Date) : undefined,
      updatedAt: latest && (!initial || latest !== ordered[0]) ? sourceTimestamp(latest.Date) : undefined });
  }
  return output;
}

export async function readEvidence(item: Announcement): Promise<string> {
  if (item.sourceId === "msrc") return item.evidence;
  const response = await fetchSource(item.url);
  if (!response.ok) throw new Error(`Advisory returned HTTP ${response.status}.`);
  const body = await boundedText(response, 8_000_000);
  const relevant = body.match(/<main\b[^>]*>([\s\S]*?)<\/main>/i)?.[1] ?? body.match(/<article\b[^>]*>([\s\S]*?)<\/article>/i)?.[1] ?? body;
  return plainText(relevant).slice(0, 5000);
}
