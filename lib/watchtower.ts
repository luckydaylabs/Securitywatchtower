export type PlatformKey = "all" | "macos" | "windows" | "linux" | "ai";
export type Severity = "critical" | "high" | "medium" | "low";
export type CheckTrigger = "manual" | "automatic";

export type SnapshotHistory = {
  id: string;
  checkedAt: string;
  trigger: CheckTrigger;
  findingCount: number;
  criticalCount: number;
  platformCount: number;
};

export type NimbleTrustSource = {
  title: string;
  url: string;
  type?: string;
  source_category?: string;
};

export type NimbleTrust = {
  confidence?: string;
  reasoning?: string;
  sources: NimbleTrustSource[];
  claims: Array<Record<string, unknown>>;
};

export type Finding = {
  id: string;
  platform: Exclude<PlatformKey, "all">;
  severity: Severity;
  title: string;
  summary: string;
  whatHappened: string;
  whyItMatters: string;
  nextStep: string;
  source: string;
  sourceUrl: string;
  detectedAt: string;
  signalType: string;
  scope: string;
  evidenceNote: string;
};

export const PLATFORM_META: Record<Exclude<PlatformKey, "all">, {
  label: string;
  logos: string[];
}> = {
  macos: { label: "macOS", logos: ["/brand-logos/apple.svg"] },
  windows: { label: "Windows", logos: ["/brand-logos/microsoft.svg"] },
  linux: { label: "Linux", logos: ["/brand-logos/linux.svg"] },
  ai: { label: "AI prompt safety", logos: ["/brand-logos/openai.svg", "/brand-logos/anthropic.svg"] },
};

export const SOURCE_CATALOG = [
  { name: "Microsoft MSRC CVRF updates", url: "https://api.msrc.microsoft.com/cvrf/v3.0/updates" },
  { name: "Debian security tracker", url: "https://security-tracker.debian.org/tracker/data/json" },
  { name: "Ubuntu Security Notices", url: "https://ubuntu.com/security/notices/atom.xml" },
  { name: "Red Hat CSAF advisories", url: "https://security.access.redhat.com/data/csaf/v2/advisories/" },
  { name: "SUSE CSAF advisories", url: "https://ftp.suse.com/pub/projects/security/csaf/" },
  { name: "Alpine SecDB release JSON", url: "https://secdb.alpinelinux.org/v3.23/main.json" },
  { name: "Apple security releases", url: "https://support.apple.com/en-us/100100" },
  { name: "Linux kernel CVE announcements", url: "https://lists.openwall.net/linux-cve-announce/" },
  { name: "Fedora security updates RSS", url: "https://bodhi.fedoraproject.org/rss/updates/" },
  { name: "OpenAI security disclosures", url: "https://openai.com/policies/coordinated-vulnerability-disclosure-policy/" },
  { name: "Anthropic vulnerability ledger", url: "https://red.anthropic.com/2026/cvd/" },
  { name: "Google AI security disclosures", url: "https://bughunters.google.com/blog/announcing-googles-new-ai-vulnerability-reward-program" },
  { name: "CISA KEV JSON feed", url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" },
  { name: "OWASP prompt injection guidance", url: "https://genai.owasp.org/llmrisk/llm01-prompt-injection/" },
];
