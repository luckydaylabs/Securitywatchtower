import { XMLParser } from "fast-xml-parser";
import { approvedSourceUrl, type MonitorSource } from "./source-config";
import type { Finding } from "./watchtower";
import { sourceTimestamp, type AnnouncementDates } from "./announcement-dates";

export type Announcement = AnnouncementDates & {
  id: string; sourceId: string; source: string; url: string; title: string;
  sourceDate: string; platform: Finding["platform"]; evidence: string; evidenceUrl?: string;
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
    // Only dated article cards, never navigation links or the disclosure ledger.
    const html = body.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, "");
    const anchors = html.match(/<a\b[^>]*href=["'][^"']+["'][^>]*>[\s\S]*?<\/a>/gi) ?? [];
    let datedCards = 0;
    for (const anchor of anchors) {
      const time = anchor.match(/<time\b([^>]*)>([\s\S]*?)<\/time>/i);
      if (!time) continue;
      datedCards++;
      const href = anchor.match(/href=["']([^"']+)["']/i)?.[1];
      if (!href) continue;
      let url: URL;
      try { url = new URL(href, source.url); } catch { continue; }
      if (!["www.anthropic.com", "anthropic.com"].includes(url.hostname)) continue;
      url.hostname = "www.anthropic.com"; url.search = ""; url.hash = "";
      const heading = anchor.match(/<h[2-6]\b[^>]*>([\s\S]*?)<\/h[2-6]>/i)?.[1]
        ?? anchor.match(/<span\b[^>]*class=["'][^"']*__title[^"']*["'][^>]*>([\s\S]*?)<\/span>/i)?.[1];
      const title = plainText(heading ?? "");
      if (!title || !isSecurityArticle(title, plainText(anchor))) continue;
      const stamp = time[1].match(/datetime=["']([^"']+)["']/i)?.[1] ?? plainText(time[2]);
      add(`article:${url.pathname.replace(/\/$/, "")}`, title, url.href.replace(/\/$/, ""), stamp, title + " " + (anchor.match(/<p\b[^>]*>([\s\S]*?)<\/p>/i)?.[1] ?? ""), "ai", stamp);
    }
    if (!datedCards) throw new Error("Anthropic page did not contain readable dated article cards; coverage could not be verified.");
  } else if (source.id === "openai") {
    const entries = list<any>(parser.parse(body).rss?.channel?.item);
    if (!entries.length) throw new Error("OpenAI public news feed did not contain readable articles.");
    for (const entry of entries) {
      const title = String(entry.title ?? ""), description = String(entry.description ?? "");
      if (!isSecurityArticle(title, description)) continue;
      let url: URL;
      try { url = new URL(String(entry.link)); } catch { continue; }
      if (!["openai.com", "www.openai.com"].includes(url.hostname)) continue;
      url.hostname = "openai.com"; url.search = ""; url.hash = "";
      add(`article:${url.pathname.replace(/\/$/, "")}`, title, url.href.replace(/\/$/, ""), entry.updated ?? entry.pubDate,
        `${title} ${description}`, "ai", entry.pubDate, entry.updated);
    }
  }
  return Array.from(new Map(items.map(item => [item.id, item])).values());
}

export function isSecurityArticle(title: string, description: string): boolean {
  // A passing mention of security in a customer story or company update is not a finding.
  if (/\bgrant|\bboard|\bnational security\b|\$\d|expand\w*.*(?:access|partnership)/i.test(title)
    && !/incident|vulnerabilit|prompt.?injection|misuse/i.test(title)) return false;
  const direct = /incident|vulnerabilit|prompt.?injection|jailbreak|cyber|threat|malicious|misuse|espionage|sandbox|breach|security|defender/i;
  const context = /incident|vulnerabilit|prompt.?injection|jailbreak|cyber|malicious|unauthorized|sandbox|breach/i;
  return direct.test(title) || (/research|safety|safeguard|alignment/i.test(title) && context.test(description));
}

export async function collectSource(source: MonitorSource, checkpoint: SourceCheckpoint, until: string): Promise<SourceResult> {
  if (source.id === "msrc") return collectMicrosoftCsaf(checkpoint, until);
  if (source.id === "anthropic") {
    const results = await Promise.allSettled([source.url, ...source.additionalPages.map(page => page.url)].map(async url => {
      const response = await fetchSource(url);
      if (!response.ok) throw new Error(`${url} returned HTTP ${response.status}.`);
      return parseSource(source, await boundedText(response), until);
    }));
    const items = latestPerPlatform(results.flatMap(result => result.status === "fulfilled" ? result.value : []));
    const failures = results.filter(result => result.status === "rejected");
    if (failures.length === results.length) throw new Error("Anthropic News and Threat Intelligence could not be read.");
    const warning = failures.length ? "One Anthropic listing could not be read; coverage is incomplete." : undefined;
    // Fetch both small listings every check; deduplicated article fingerprints prevent paid re-research.
    return { items, etag: null, lastModified: null, unchanged: false, warning,
      documentsJson: JSON.stringify({ policy: "public-ai-articles-v1", items, warning }) };
  }
  // Old checkpoints contain only a date window, not the full latest-five selection.
  // Ignore their validators once so older announcements are actually retrieved.
  const stored = checkpoint.documents_json ? JSON.parse(checkpoint.documents_json) : null;
  const policy = source.id === "openai" ? "public-ai-articles-v1" : "latest-five-dates-v2";
  const cached = stored?.policy === policy && Array.isArray(stored.items) ? stored : null;
  const headers: Record<string, string> = {};
  if (cached && checkpoint.etag) headers["If-None-Match"] = checkpoint.etag;
  if (cached && checkpoint.last_modified) headers["If-Modified-Since"] = checkpoint.last_modified;
  const response = await fetchSource("feedUrl" in source ? source.feedUrl : source.url, headers);
  if (response.status === 304 && cached) return { items: cached.items, etag: checkpoint.etag ?? null, lastModified: checkpoint.last_modified ?? null, unchanged: true, warning: cached.warning, documentsJson: checkpoint.documents_json! };
  if (!response.ok) throw new Error(`Source returned HTTP ${response.status}.`);
  const body = await boundedText(response);
  const capturedUntil = new Date(Math.max(Date.parse(until), Date.now())).toISOString();
  let items = parseSource(source, body, capturedUntil);
  let warning: string | undefined;
  items = latestPerPlatform(items);
  const documentsJson = JSON.stringify({ policy, items, warning });
  return { items, etag: response.headers.get("etag"), lastModified: response.headers.get("last-modified"), unchanged: false, warning, documentsJson };
}

export function parseCsafIndex(body: string): { url: string; changedAt: string }[] {
  const entries = body.trim().split(/\r?\n/).map(line => {
    const match = line.match(/^"(\d{4}\/msrc_cve-\d{4}-\d+\.json)","([^"]+)"$/i);
    const changedAt = match && date(match[2]);
    return match && changedAt ? { url: `https://msrc.microsoft.com/csaf/advisories/${match[1]}`, changedAt } : null;
  }).filter((entry): entry is { url: string; changedAt: string } => Boolean(entry));
  if (!entries.length) throw new Error("Microsoft CSAF change index could not be read.");
  return [...new Map(entries.map(entry => [entry.url, entry])).values()]
    .sort((a, b) => b.changedAt.localeCompare(a.changedAt) || a.url.localeCompare(b.url));
}

export function parseMicrosoftCsaf(body: string, url: string, until: string): Announcement[] {
  const data = JSON.parse(body), tracking = data.document?.tracking;
  if (data.document?.csaf_version !== "2.0" || !tracking || !Array.isArray(data.vulnerabilities)) throw new Error("Microsoft CSAF advisory has an unexpected format.");
  const products = new Map<string, string>();
  const visit = (branches: any[]) => { for (const branch of branches) {
    if (branch.product?.product_id && branch.product?.name) products.set(branch.product.product_id, branch.product.name);
    visit(list(branch.branches));
  } };
  visit(list(data.product_tree?.branches));
  for (const product of list<any>(data.product_tree?.full_product_names)) products.set(product.product_id, product.name);
  const published = date(tracking.initial_release_date);
  const revised = list<any>(tracking.revision_history).filter(r => !/acknowledg|credit|typo/i.test(r.summary ?? ""))
    .map(r => date(r.date)).filter((value): value is string => Boolean(value)).sort().at(-1);
  const sourceDate = revised ?? published;
  if (!sourceDate || sourceDate > until) return [];
  return data.vulnerabilities.flatMap((v: any) => {
    const affected = list<string>(v.product_status?.known_affected).map(id => products.get(id)).filter((name): name is string => Boolean(name && /Windows/i.test(name)));
    if (!affected.length || !/^CVE-\d{4}-\d+$/.test(v.cve)) return [];
    const evidence = JSON.stringify({ cve: v.cve, vendorSeverity: data.document.aggregate_severity?.text ?? null,
      scores: list<any>(v.scores).slice(0, 2).map(s => s.cvss_v4 ?? s.cvss_v3 ?? s.cvss_v2),
      products: affected.slice(0, 8), productsTruncated: affected.length > 8,
      notes: list<any>(v.notes).filter(n => n.category !== "legal_disclaimer").slice(0, 2).map(n => plainText(n.text ?? "").slice(0, 250)),
      remediations: list<any>(v.remediations).slice(0, 2).map(r => ({ details: plainText(r.details ?? "").slice(0, 200), url: r.url })) });
    return [{ id: `msrc:${v.cve}`, sourceId: "msrc", source: "Microsoft CSAF advisories", title: v.title ?? data.document.title ?? v.cve,
      url, evidenceUrl: url, sourceDate, platform: "windows" as const, evidence,
      publishedAt: sourceTimestamp(tracking.initial_release_date), updatedAt: revised && revised !== published ? sourceTimestamp(revised) : undefined }];
  });
}

async function collectMicrosoftCsaf(checkpoint: SourceCheckpoint, until: string): Promise<SourceResult> {
  const policy = "latest-five-msrc-csaf-v1";
  const stored = checkpoint.documents_json ? JSON.parse(checkpoint.documents_json) : null;
  const cached = stored?.policy === policy ? stored : null;
  const headers: Record<string, string> = {};
  if (cached && checkpoint.etag) headers["If-None-Match"] = checkpoint.etag;
  if (cached && checkpoint.last_modified) headers["If-Modified-Since"] = checkpoint.last_modified;
  const response = await fetchSource("https://msrc.microsoft.com/csaf/advisories/changes.csv", headers);
  if (response.status === 304 && cached) return { items: cached.items, unchanged: true, etag: checkpoint.etag ?? null, lastModified: checkpoint.last_modified ?? null, warning: cached.warning, documentsJson: checkpoint.documents_json! };
  if (!response.ok) throw new Error(`Microsoft CSAF index returned HTTP ${response.status}.`);
  const entries = parseCsafIndex(await boundedText(response));
  let items: Announcement[] = [], offset = 0;
  const capturedUntil = new Date(Math.max(Date.parse(until), Date.now())).toISOString();
  // Reuse unchanged document versions without downloading or researching them again.
  const documents: Record<string, { changedAt: string; items: Announcement[] }> = {};
  for (; offset < Math.min(entries.length, 100); offset += 5) {
    // Remaining documents cannot be newer; equal timestamps are interchangeable.
    if (items.length >= 5 && entries[offset].changedAt <= items[4].sourceDate) break;
    const batch = entries.slice(offset, offset + 5);
    const results = await Promise.all(batch.map(async entry => {
      const previous = cached?.documents?.[entry.url];
      if (previous?.changedAt === entry.changedAt) { documents[entry.url] = previous; return previous.items as Announcement[]; }
      const detail = await fetchSource(entry.url);
      if (!detail.ok) throw new Error(`Microsoft CSAF advisory returned HTTP ${detail.status}.`);
      const parsed = parseMicrosoftCsaf(await boundedText(detail, 2_000_000), entry.url, capturedUntil);
      documents[entry.url] = { changedAt: entry.changedAt, items: parsed };
      return parsed;
    }));
    items = latestPerPlatform([...items, ...results.flat()]);
  }
  const warning = offset < entries.length && (items.length < 5 || entries[offset].changedAt > items[4].sourceDate)
    ? "Microsoft CSAF discovery reached its 100-document safety bound; the latest-five selection may be incomplete." : undefined;
  return { items, unchanged: false, warning, etag: response.headers.get("etag"), lastModified: response.headers.get("last-modified"),
    documentsJson: JSON.stringify({ policy, items, documents, warning }) };
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
    const evidence = JSON.stringify({ cve: v.CVE,
      threats: list<any>(v.Threats).slice(0, 4).map(t => ({ type: t.Type, description: plainText(t.Description?.Value ?? "").slice(0, 180) })),
      products: products.slice(0, 12).map(id => windows.get(id)),
      productsTruncated: products.length > 12,
      notes: list<any>(v.Notes).slice(0, 2).map(n => plainText(n.Value ?? "").slice(0, 350)),
      remediations: list<any>(v.Remediations).slice(0, 2).map(r => ({ description: plainText(r.Description?.Value ?? "").slice(0, 180), url: String(r.URL ?? "").slice(0, 300) })) });
    const ordered = list<any>(v.RevisionHistory).filter(r => date(r.Date)).sort((a, b) => date(a.Date)!.localeCompare(date(b.Date)!));
    const latest = [...revisions].filter(r => date(r.Date)).sort((a, b) => date(a.Date)!.localeCompare(date(b.Date)!)).at(-1);
    const initial = /initial|first publish|original release|information published/i.test(ordered[0]?.Description?.Value ?? "") || String(ordered[0]?.Number) === "1.0";
    output.push({ id: `msrc:${v.CVE}`, sourceId: "msrc", source: "Microsoft Windows advisories", title: v.Title?.Value ?? v.CVE,
      url: `https://msrc.microsoft.com/update-guide/vulnerability/${v.CVE}`, sourceDate, platform: "windows", evidence,
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
