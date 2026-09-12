export const MONITOR_SOURCES = [
  { id: "msrc", name: "Microsoft CSAF advisories", url: "https://msrc.microsoft.com/csaf", domains: ["api.msrc.microsoft.com", "msrc.microsoft.com"] },
  { id: "ubuntu", name: "Ubuntu Security Notices", url: "https://ubuntu.com/security/notices/atom.xml", domains: ["ubuntu.com"] },
  { id: "apple", name: "Apple security releases", url: "https://support.apple.com/en-us/100100", domains: ["support.apple.com"] },
  { id: "anthropic", name: "Anthropic disclosure ledger", url: "https://red.anthropic.com/2026/cvd/data/ledger.json", domains: ["red.anthropic.com", "anthropic.com"] },
  { id: "openai", name: "OpenAI public disclosures", url: "https://trust.openai.com/", domains: ["trust.openai.com", "openai.com"] },
] as const;

export type MonitorSource = typeof MONITOR_SOURCES[number];
export function approvedSourceUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "https:" && !url.username && !url.password && !url.port
      && MONITOR_SOURCES.some(source => source.domains.some(domain => url.hostname === domain));
  } catch { return false; }
}
