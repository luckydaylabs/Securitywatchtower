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

export const DEMO_FINDINGS: Finding[] = [
  {
    id: "linux-demo-01",
    platform: "linux",
    severity: "critical",
    title: "A public advisory affects a common system component",
    summary: "A Linux security notice describes a flaw that may let an attacker run code with higher privileges.",
    whatHappened: "A vendor advisory was published for a system component used by Linux installations.",
    whyItMatters: "If the affected version is installed, a local or remote attacker may be able to move beyond the access they started with.",
    nextStep: "Confirm the installed version, apply the vendor update, and review whether the component is exposed or running with elevated permissions.",
    source: "Ubuntu Security Notices",
    sourceUrl: "https://ubuntu.com/security/notices",
    detectedAt: "2026-09-11T13:36:00.000Z",
    signalType: "Vendor vulnerability announcement",
    scope: "Linux packages and system services",
    evidenceNote: "Illustrative finding from the dashboard demo feed",
  },
  {
    id: "ai-demo-01",
    platform: "ai",
    severity: "high",
    title: "A page tried to make the assistant ignore its instructions",
    summary: "Untrusted content included directions to reveal hidden instructions and change the assistant’s task.",
    whatHappened: "A prompt-injection pattern was found in content an AI agent could read while completing a request.",
    whyItMatters: "The content could redirect an agent, expose private context, or trigger an action the user did not request.",
    nextStep: "Keep retrieved content separate from system instructions and require confirmation before any tool action or data release.",
    source: "OWASP GenAI Security Project",
    sourceUrl: "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
    detectedAt: "2026-09-11T14:02:00.000Z",
    signalType: "Prompt-injection pattern",
    scope: "AI agents reading external webpages",
    evidenceNote: "Illustrative finding; live monitoring requires a configured Nimble agent",
  },
  {
    id: "macos-demo-01",
    platform: "macos",
    severity: "high",
    title: "An app tried to access protected files",
    summary: "An application requested access to folders macOS normally keeps behind a privacy prompt.",
    whatHappened: "A security signal identified an application reaching toward protected user data locations.",
    whyItMatters: "Unexpected access can expose documents, browser data, or other private information if the request is approved.",
    nextStep: "Check the application’s publisher and purpose. Deny access unless the request is expected and necessary.",
    source: "Apple Platform Security",
    sourceUrl: "https://support.apple.com/guide/security/welcome/web",
    detectedAt: "2026-09-11T14:28:00.000Z",
    signalType: "Privacy and access signal",
    scope: "macOS protected data locations",
    evidenceNote: "Illustrative finding from the dashboard demo feed",
  },
  {
    id: "windows-demo-01",
    platform: "windows",
    severity: "medium",
    title: "A startup task can run code when a user signs in",
    summary: "A persistence signal was found in a startup location that launches programs during sign-in.",
    whatHappened: "A program was registered to run automatically when a user starts a Windows session.",
    whyItMatters: "Startup persistence is common for legitimate software, but it is also used to survive restarts after an intrusion.",
    nextStep: "Confirm the file path and publisher, remove entries that are not needed, and review recent account activity.",
    source: "Microsoft Security Response Center",
    sourceUrl: "https://msrc.microsoft.com/update-guide",
    detectedAt: "2026-09-11T15:04:00.000Z",
    signalType: "Persistence signal",
    scope: "Windows sign-in startup tasks",
    evidenceNote: "Illustrative finding from the dashboard demo feed",
  },
];
