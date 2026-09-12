export type PlatformKey = "all" | "macos" | "windows" | "linux" | "ai";
export type Severity = "critical" | "high" | "medium" | "low";

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
  { name: "Apple security releases", url: "https://support.apple.com/en-us/100100" },
  { name: "Microsoft MSRC", url: "https://msrc.microsoft.com/update-guide" },
  { name: "Ubuntu notices", url: "https://ubuntu.com/security/notices" },
  { name: "Red Hat advisories", url: "https://access.redhat.com/security/security-updates" },
  { name: "OWASP prompt injection", url: "https://genai.owasp.org/llmrisk/llm01-prompt-injection/" },
];
