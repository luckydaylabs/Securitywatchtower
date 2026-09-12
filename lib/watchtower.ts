import { MONITOR_SOURCES } from "./source-config";
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
  ai: { label: "AI security", logos: ["/brand-logos/openai.svg", "/brand-logos/anthropic.svg"] },
};

export const SOURCE_CATALOG = MONITOR_SOURCES;
