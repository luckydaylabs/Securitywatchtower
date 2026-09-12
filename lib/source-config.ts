export const MONITOR_SOURCES = [
  { id: "msrc", name: "Microsoft CSAF advisories", url: "https://msrc.microsoft.com/csaf", domains: ["api.msrc.microsoft.com", "msrc.microsoft.com"] },
  { id: "ubuntu", name: "Ubuntu Security Notices", url: "https://ubuntu.com/security/notices/atom.xml", domains: ["ubuntu.com"] },
  { id: "apple", name: "Apple security releases", url: "https://support.apple.com/en-us/100100", domains: ["support.apple.com"] },
  { id: "anthropic", name: "Anthropic News", url: "https://www.anthropic.com/news", domains: ["www.anthropic.com", "anthropic.com", "red.anthropic.com", "www-cdn.anthropic.com"], additionalPages: [{ name: "Anthropic Threat Intelligence", url: "https://www.anthropic.com/threat-intelligence" }] },
  { id: "openai", name: "OpenAI news & security research", url: "https://openai.com/news/", feedUrl: "https://openai.com/news/rss.xml", domains: ["openai.com", "www.openai.com", "cdn.openai.com"] },
] as const;

export type MonitorSource = typeof MONITOR_SOURCES[number];
export function approvedSourceUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "https:" && !url.username && !url.password && !url.port
      && MONITOR_SOURCES.some(source => source.domains.some(domain => url.hostname === domain));
  } catch { return false; }
}
