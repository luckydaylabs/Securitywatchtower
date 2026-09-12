"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import Image from "next/image";
import {
  Activity,
  ArrowUpRight,
  CheckCircle2,
  ChevronDown,
  CircleAlert,
  Clock3,
  ExternalLink,
  LayoutDashboard,
  Layers3,
  Radar,
  Radio,
  ScanLine,
  RefreshCw,
  ShieldCheck,
  TriangleAlert,
} from "lucide-react";
import {
  PLATFORM_META,
  SOURCE_CATALOG,
  type CheckTrigger,
  type Finding,
  type NimbleTrust,
  type PlatformKey,
  type Severity,
  type SnapshotHistory,
} from "@/lib/watchtower";
import { VulnerabilityTicker } from "@/components/vulnerability-ticker";
import { ThreatAnalytics } from "@/components/threat-analytics";

type FeedMode = "idle" | "live" | "fallback" | "pending";
type PipelineStage = "monitor" | "investigator" | "verifier" | "orchestrator";

type RunReference = {
  stage: PipelineStage;
  agentId: string;
  runId: string;
};

type PipelineBaseline = {
  since: string;
  findings: Array<{
    id: string;
    platform: Exclude<PlatformKey, "all">;
    severity: Severity;
    title: string;
    summary: string;
    sourceUrl: string;
    detectedAt: string;
  }>;
};

type PipelineContext = Partial<Record<PipelineStage, RunReference>> & {
  trigger?: CheckTrigger;
  baseline?: PipelineBaseline;
};

type FeedResponse = {
  agentId?: string;
  checkedAt?: string;
  findings?: Finding[];
  history?: SnapshotHistory[];
  message?: string;
  mode?: FeedMode;
  selectedSnapshot?: SnapshotHistory;
  trust?: NimbleTrust;
  stage?: PipelineStage;
  context?: PipelineContext;
  pipelineStages?: PipelineStage[];
  runId?: string;
  startedAt?: string;
  trigger?: CheckTrigger;
  sourceStatuses?: Array<{ id: string; status: string; error?: string }>;
  pendingCount?: number;
  status?: "running" | "completed" | "failed";
};

type ActiveRun = RunReference & { context: PipelineContext; startedAt: number };
type HistoryStatus = "loading" | "ready" | "empty" | "error";

const pipelineStages: PipelineStage[] = ["monitor", "investigator", "verifier", "orchestrator"];
const HOURLY_MONITORING_STORAGE_KEY = "watchtower.hourly-monitoring";
const LAST_AUTOMATIC_CHECK_STORAGE_KEY = "watchtower.last-automatic-check";
const HOURLY_MONITORING_INTERVAL_MS = 60 * 60 * 1000;
const PIPELINE_INITIAL_POLL_DELAY_MS = 2_000;
const PIPELINE_POLL_INTERVAL_MS = 15_000;

const severityLabels: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
};

const severityDescriptions: Record<Severity, string> = {
  critical: "Act now",
  high: "Review today",
  medium: "Review soon",
  low: "Monitor",
};

const platformOrder: Exclude<PlatformKey, "all">[] = [
  "macos",
  "windows",
  "linux",
  "ai",
];

function formatCheckedAt(value?: string) {
  if (!value) return "Not checked yet";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;

  const seconds = Math.max(0, Math.round((Date.now() - parsed.getTime()) / 1000));
  if (seconds < 60) return "Just now";
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} hr ago`;
  return parsed.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

function findingTime(value: string) {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  const minutes = Math.max(1, Math.round((Date.now() - parsed.getTime()) / 60000));
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} hr ago`;
  return parsed.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

function historyTime(value: string) {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function trustClaimPath(claim: Record<string, unknown>, index: number) {
  for (const key of ["path", "json_path", "jsonPath"]) {
    if (typeof claim[key] === "string" && claim[key].trim()) return claim[key].trim();
  }
  return `Claim ${index + 1}`;
}

function trustClaimConfidence(claim: Record<string, unknown>) {
  return typeof claim.confidence === "string" && claim.confidence.trim() ? claim.confidence.trim() : null;
}

function trustClaimExcerpt(claim: Record<string, unknown>) {
  const candidates: unknown[] = [];
  if (typeof claim.excerpt === "string") candidates.push(claim.excerpt);
  if (typeof claim.text === "string") candidates.push(claim.text);
  if (Array.isArray(claim.excerpts)) candidates.push(...claim.excerpts);

  for (const candidate of candidates) {
    if (typeof candidate === "string" && candidate.trim()) return candidate.trim();
    if (!isRecord(candidate)) continue;
    for (const key of ["excerpt", "text", "content"]) {
      if (typeof candidate[key] === "string" && candidate[key].trim()) return candidate[key].trim();
    }
  }
  return null;
}

export default function Home() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [history, setHistory] = useState<SnapshotHistory[]>([]);
  const [selectedSnapshotId, setSelectedSnapshotId] = useState<string>();
  const [historyStatus, setHistoryStatus] = useState<HistoryStatus>("loading");
  const [mode, setMode] = useState<FeedMode>("idle");
  const [lastChecked, setLastChecked] = useState<string>();
  const [trust, setTrust] = useState<NimbleTrust>();
  const [sourceStatuses, setSourceStatuses] = useState<NonNullable<FeedResponse["sourceStatuses"]>>([]);
  const [pendingCount, setPendingCount] = useState(0);
  const [activeRun, setActiveRun] = useState<ActiveRun | null>(null);
  const [hourlyMonitoringEnabled, setHourlyMonitoringEnabled] = useState<boolean | null>(null);
  const [checkTrigger, setCheckTrigger] = useState<CheckTrigger>("automatic");
  const [selectedPlatform, setSelectedPlatform] = useState<PlatformKey>("all");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [technicalId, setTechnicalId] = useState<string | null>(null);
  const [reviewedIds, setReviewedIds] = useState<Set<string>>(new Set());
  const [isRefreshing, setIsRefreshing] = useState(false);
  const isRefreshingRef = useRef(false);
  const [error, setError] = useState<string>();
  const [historyError, setHistoryError] = useState<string>();
  const [announcement, setAnnouncement] = useState("Preparing the monitoring check.");

  const loadFindings = useCallback(async (trigger: CheckTrigger = "manual") => {
    if (isRefreshingRef.current) return;

    isRefreshingRef.current = true;
    setCheckTrigger(trigger);
    setIsRefreshing(true);
    setError(undefined);
    setMode("pending");

    try {
      const response = await fetch("/api/findings", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ trigger }),
        cache: "no-store",
      });
      const payload = (await response.json()) as FeedResponse;
      if (Array.isArray(payload.findings)) setFindings(payload.findings);
      if (payload.history) { setHistory(payload.history); setHistoryStatus(payload.history.length ? "ready" : "empty"); setHistoryError(undefined); }
      if (payload.sourceStatuses) setSourceStatuses(payload.sourceStatuses);
      if (typeof payload.pendingCount === "number") setPendingCount(payload.pendingCount);

      if (!response.ok) {
        throw new Error(payload.message ?? "The latest findings could not be loaded.");
      }

      if (payload.mode === "live") {
        if (Array.isArray(payload.findings)) setFindings(payload.findings);
        setTrust(payload.trust);
        if (Array.isArray(payload.history)) {
          setHistory(payload.history);
          setHistoryStatus(payload.history.length ? "ready" : "empty");
          setHistoryError(undefined);
        }
        if (payload.selectedSnapshot?.id) setSelectedSnapshotId(payload.selectedSnapshot.id);
        setReviewedIds(new Set());
        setExpandedId(null);
        setTechnicalId(null);
        setMode("live");
        if (payload.checkedAt) setLastChecked(payload.checkedAt);
        setAnnouncement(payload.message ?? "Findings refreshed.");
        isRefreshingRef.current = false;
        setIsRefreshing(false);
        return;
      }

      if (!payload.runId || !payload.agentId || !payload.stage) {
        throw new Error("Nimble returned an incomplete monitoring run.");
      }

      setActiveRun({
        stage: payload.stage,
        runId: payload.runId,
        agentId: payload.agentId,
        startedAt: payload.startedAt ? Date.parse(payload.startedAt) : Date.now(),
        context: payload.context ?? {
          monitor: { stage: "monitor", runId: payload.runId, agentId: payload.agentId },
        },
      });
      setAnnouncement(payload.message ?? "Nimble research is running.");
    } catch (loadError) {
      setMode("fallback");
      setError(loadError instanceof Error ? loadError.message : "The latest findings could not be loaded.");
      setAnnouncement("The security check could not be completed. No new findings were loaded.");
      isRefreshingRef.current = false;
      setIsRefreshing(false);
    }
  }, []);

  const loadSavedSnapshot = useCallback(async (snapshotId?: string) => {
    setHistoryStatus("loading");
    setHistoryError(undefined);
    setError(undefined);

    try {
      const endpoint = snapshotId
        ? `/api/findings?snapshotId=${encodeURIComponent(snapshotId)}`
        : "/api/findings";
      const response = await fetch(endpoint, { cache: "no-store" });
      const payload = (await response.json()) as FeedResponse;

      if (Array.isArray(payload.history)) {
        setHistory(payload.history);
        setHistoryStatus(payload.history.length ? "ready" : "empty");
      }
      if (Array.isArray(payload.findings)) setFindings(payload.findings);
      setTrust(payload.trust);
      if (payload.checkedAt) setLastChecked(payload.checkedAt);
      if (payload.sourceStatuses) setSourceStatuses(payload.sourceStatuses);
      if (typeof payload.pendingCount === "number") setPendingCount(payload.pendingCount);
      if (!response.ok) throw new Error(payload.message ?? "Saved check history could not be loaded.");
      if (payload.status === "running" && payload.runId && payload.agentId && payload.stage) {
        setMode("pending");
        setCheckTrigger(payload.trigger ?? "manual");
        isRefreshingRef.current = true;
        setIsRefreshing(true);
        setActiveRun({ runId: payload.runId, agentId: payload.agentId, stage: payload.stage,
          startedAt: payload.startedAt ? Date.parse(payload.startedAt) : Date.now(), context: {} });
        return;
      }
      if (payload.mode === "live") {
        setMode("live");
        if (payload.checkedAt) setLastChecked(payload.checkedAt);
        setSelectedSnapshotId(payload.selectedSnapshot?.id ?? snapshotId ?? payload.history?.[0]?.id);
        setSelectedPlatform("all");
        setReviewedIds(new Set());
        setExpandedId(null);
        setTechnicalId(null);
      } else {
        setMode(payload.mode ?? "idle");
        setSelectedSnapshotId(undefined);
      }
    } catch (loadError) {
      setHistoryStatus("error");
      setMode("fallback");
      setHistoryError(loadError instanceof Error ? loadError.message : "Saved check history could not be loaded.");
    }
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void loadSavedSnapshot();
    }, 0);
    return () => window.clearTimeout(timer);
  }, [loadSavedSnapshot]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      try {
        const storedPreference = window.localStorage.getItem(HOURLY_MONITORING_STORAGE_KEY);
        setHourlyMonitoringEnabled(storedPreference === "true");
      } catch {
        setHourlyMonitoringEnabled(false);
      }
    }, 0);
    return () => window.clearTimeout(timer);
  }, []);

  useEffect(() => {
    if (hourlyMonitoringEnabled !== true) return;

    let cancelled = false;
    let timer: number | undefined;

    const runOnSchedule = async () => {
      if (cancelled) return;
      try {
        window.localStorage.setItem(LAST_AUTOMATIC_CHECK_STORAGE_KEY, String(Date.now()));
      } catch {
        // The timer still runs for this tab when browser storage is unavailable.
      }
      await loadFindings("automatic");
      if (cancelled) return;
      timer = window.setTimeout(() => void runOnSchedule(), HOURLY_MONITORING_INTERVAL_MS);
    };

    let delay = 0;
    try {
      const lastAutomaticCheck = Number(window.localStorage.getItem(LAST_AUTOMATIC_CHECK_STORAGE_KEY));
      if (Number.isFinite(lastAutomaticCheck) && lastAutomaticCheck > 0) {
        delay = Math.max(0, HOURLY_MONITORING_INTERVAL_MS - (Date.now() - lastAutomaticCheck));
      }
    } catch {
      delay = 0;
    }
    timer = window.setTimeout(() => void runOnSchedule(), delay);

    return () => {
      cancelled = true;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [hourlyMonitoringEnabled, loadFindings]);

  useEffect(() => {
    if (!activeRun) return;
    const run = activeRun;

    let cancelled = false;
    let timer: number | undefined;

    async function pollRun() {
      try {
        const response = await fetch("/api/findings", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ scanId: run.runId }),
          cache: "no-store",
        });
        const payload = (await response.json()) as FeedResponse;

        if (cancelled) return;
        if (payload.sourceStatuses) setSourceStatuses(payload.sourceStatuses);
        if (typeof payload.pendingCount === "number") setPendingCount(payload.pendingCount);

        if (response.status === 202 || payload.status === "running" || payload.mode === "pending") {
          setAnnouncement(payload.message ?? "Nimble research is still running.");
          if (payload.runId && payload.agentId && payload.stage) {
            const nextContext = payload.context ?? run.context;
            const changed = payload.runId !== run.runId || payload.agentId !== run.agentId || payload.stage !== run.stage;
            if (changed) {
              setActiveRun({
                stage: payload.stage,
                runId: payload.runId,
                agentId: payload.agentId,
                startedAt: run.startedAt,
                context: nextContext,
              });
              return;
            }
          }
          timer = window.setTimeout(() => void pollRun(), PIPELINE_POLL_INTERVAL_MS);
          return;
        }

        if (!response.ok) {
          if (payload.status === "failed") {
            setActiveRun(null);
            isRefreshingRef.current = false;
            setIsRefreshing(false);
            setMode("fallback");
            setError(payload.message ?? "The saved check needs attention.");
            return;
          }
          throw new Error("Connection interrupted. The saved check will be resumed.");
        }

        if (Array.isArray(payload.findings)) setFindings(payload.findings);
        setTrust(payload.trust);
        if (Array.isArray(payload.history)) {
          setHistory(payload.history);
          setHistoryStatus(payload.history.length ? "ready" : "empty");
          setHistoryError(undefined);
        }
        if (payload.selectedSnapshot?.id) setSelectedSnapshotId(payload.selectedSnapshot.id);
        setReviewedIds(new Set());
        setExpandedId(null);
        setTechnicalId(null);
        setMode(payload.mode ?? "live");
        if (payload.checkedAt) setLastChecked(payload.checkedAt);
        setAnnouncement(payload.message ?? "Findings refreshed.");
        setActiveRun(null);
        isRefreshingRef.current = false;
        setIsRefreshing(false);
      } catch (pollError) {
        if (cancelled) return;
        setAnnouncement(pollError instanceof Error ? pollError.message : "Reconnecting to the saved check.");
        timer = window.setTimeout(() => void pollRun(), PIPELINE_POLL_INTERVAL_MS);
      }
    }

    timer = window.setTimeout(() => void pollRun(), PIPELINE_INITIAL_POLL_DELAY_MS);
    return () => {
      cancelled = true;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [activeRun]);

  const visibleFindings = useMemo(() => {
    const scoped = selectedPlatform === "all"
      ? findings
      : findings.filter((finding) => finding.platform === selectedPlatform);
    return scoped.filter((finding) => !reviewedIds.has(finding.id));
  }, [findings, reviewedIds, selectedPlatform]);

  const openCount = findings.filter((finding) => !reviewedIds.has(finding.id)).length;
  const scopeFindings = selectedPlatform === "all" ? findings : findings.filter(finding => finding.platform === selectedPlatform);
  const reviewedCount = findings.length - openCount;
  const platformsRepresented = new Set(findings.map(finding => finding.platform)).size;
  const criticalCount = findings.filter(
    (finding) => finding.severity === "critical" && !reviewedIds.has(finding.id),
  ).length;

  function countFor(platform: Exclude<PlatformKey, "all">) {
    return findings.filter(
      (finding) => finding.platform === platform && !reviewedIds.has(finding.id),
    ).length;
  }

  function markReviewed(id: string) {
    setReviewedIds((current) => new Set([...current, id]));
    setExpandedId(null);
    setTechnicalId(null);
    setAnnouncement("Finding marked as reviewed.");
  }

  function focusFinding(id: string) {
    setSelectedPlatform("all");
    setExpandedId(id);
    setTechnicalId(null);
    window.setTimeout(() => {
      const card = document.getElementById(`finding-${id}`);
      card?.querySelector<HTMLButtonElement>(".finding-trigger")?.focus({ preventScroll: true });
      card?.scrollIntoView({
        behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth",
        block: "center",
      });
    }, 0);
  }

  function toggleHourlyMonitoring() {
    if (hourlyMonitoringEnabled === null) return;

    const nextValue = !hourlyMonitoringEnabled;
    setHourlyMonitoringEnabled(nextValue);
    try {
      window.localStorage.setItem(HOURLY_MONITORING_STORAGE_KEY, String(nextValue));
    } catch {
      // The setting still applies for this tab when browser storage is unavailable.
    }
    setAnnouncement(
      nextValue
        ? "Hourly monitoring is on. Checks run while this dashboard is open."
        : "Hourly monitoring is off. Manual checks remain available.",
    );
  }

  const progressValue = isRefreshing
    ? activeRun
      ? Math.min(92, 17 + pipelineStages.indexOf(activeRun.stage) * 25)
      : 7
    : 0;
  const monitoringStatus = isRefreshing
    ? `${checkTrigger === "manual" ? "Manual" : "Hourly"} check in progress`
    : hourlyMonitoringEnabled === false
      ? "Manual monitoring"
      : hourlyMonitoringEnabled === true
        ? "Hourly monitoring"
        : "Loading monitoring settings";

  return (
    <main className="watchtower-shell">
      <aside className="command-rail" aria-label="Dashboard navigation">
        <a className="rail-brand" href="#overview" aria-label="Watchtower overview"><Radar size={28} /></a>
        <nav>
          <a href="#overview" aria-label="Overview" title="Overview"><LayoutDashboard size={21} /></a>
          <a href="#findings-title" aria-label="Security Announcements" title="Security Announcements"><ShieldCheck size={21} /></a>
          <a href="#sources" aria-label="Sources" title="Sources"><Radio size={21} /></a>
        </nav>
        <span className="rail-monogram" title="Nimble">N</span>
      </aside>
      <header className="topbar">
        <div className="topbar-inner">
          <div className="brand-lockup">
            <div className="brand-mark" aria-hidden="true">
              <Radar size={20} strokeWidth={2.2} />
            </div>
            <div className="brand-copy">
              <p className="brand-name">WATCHTOWER<span className="brand-slash">/</span><span className="brand-section">Security operations</span></p>
              <span className="brand-scope"><ScanLine size={13} aria-hidden="true" />macOS · Windows · Linux · AI</span>
            </div>
          </div>

          <div className="topbar-status" aria-label="Monitoring status">
            <span className="status-dot" aria-hidden="true" />
            <span>{monitoringStatus}</span>
            <span className="topbar-divider" aria-hidden="true" />
            <span>Last checked {formatCheckedAt(lastChecked)}</span>
          </div>

          <div className="monitoring-controls">
            <div className="monitoring-toggle">
              <span className="monitoring-toggle-copy">
                <span className="monitoring-toggle-label">Hourly checks</span>
                <span className="monitoring-toggle-state">{hourlyMonitoringEnabled === null ? "Loading" : hourlyMonitoringEnabled ? "On · while open" : "Off · manual"}</span>
              </span>
              <button
                className={`monitoring-switch ${hourlyMonitoringEnabled ? "monitoring-switch-on" : ""}`}
                type="button"
                role="switch"
                aria-checked={hourlyMonitoringEnabled === true}
                aria-label="Toggle hourly monitoring"
                disabled={hourlyMonitoringEnabled === null}
                onClick={toggleHourlyMonitoring}
              >
                <span aria-hidden="true" />
              </button>
            </div>

            <button
              className={`refresh-button ${isRefreshing ? "refresh-button-checking" : ""}`}
              type="button"
              onClick={() => void loadFindings("manual")}
              disabled={isRefreshing}
              aria-label={isRefreshing ? `${checkTrigger === "manual" ? "Manual" : "Hourly"} check in progress` : "Run a manual security check"}
            >
              <span className="refresh-button-copy">
                <RefreshCw size={16} className={isRefreshing ? "spin" : ""} aria-hidden="true" />
                <span>{isRefreshing ? `${checkTrigger === "manual" ? "Manual" : "Hourly"} check` : hourlyMonitoringEnabled === false ? "Run manual check" : "Run check"}</span>
              </span>
              {isRefreshing ? (
                <span
                  className="refresh-progress"
                  role="progressbar"
                  aria-label="Security check progress"
                  aria-valuemin={0}
                  aria-valuemax={100}
                  aria-valuenow={progressValue}
                  aria-valuetext={`${progressValue}% estimated progress`}
                >
                  <span className="refresh-progress-fill" style={{ width: `${progressValue}%` }} />
                </span>
              ) : null}
            </button>
          </div>
        </div>
      </header>

      <div className="page-wrap" id="overview">
        <VulnerabilityTicker
          findings={findings.filter((finding) => !reviewedIds.has(finding.id))}
          mode={mode}
          onSelectFinding={focusFinding}
        />

        <section className="metrics-grid" aria-label="Current feed overview">
          <div className="metric-card"><div className="metric-heading"><span>Open findings</span><ShieldCheck size={17}/></div><div className="metric-value-row"><strong>{String(openCount).padStart(2, "0")}</strong><div className="metric-mini-bars" aria-hidden="true">{platformOrder.map(platform => <i key={platform} style={{ height: `${5 + countFor(platform) / Math.max(1, openCount) * 38}px` }}/>)}</div></div><div className="metric-caption">Across all platforms<span>{findings.length} in current feed</span></div></div>
          <div className="metric-card metric-critical"><div className="metric-heading"><span>Critical alerts</span><TriangleAlert size={17}/></div><div className="metric-value-row"><strong>{String(criticalCount).padStart(2, "0")}</strong><span className="critical-marker" aria-hidden="true"><CircleAlert size={30} strokeWidth={1.25}/></span></div><div className="metric-caption">{criticalCount ? "Priority review required" : "No critical findings open"}<span className="critical-tag">P1</span></div></div>
          <div className="metric-card"><div className="metric-heading"><span>Platforms represented</span><Layers3 size={17}/></div><div className="metric-value-row"><strong>{String(platformsRepresented).padStart(2, "0")}<small>/04</small></strong><div className="metric-platform-dots" aria-hidden="true">{platformOrder.map(platform => <i key={platform} className={findings.some(f => f.platform === platform) ? 'represented' : ''}/>)}</div></div><div className="metric-caption">OS & AI security<span>Current feed</span></div></div>
          <div className="metric-card"><div className="metric-heading"><span>Reviewed</span><CheckCircle2 size={17}/></div><div className="metric-value-row"><strong>{String(reviewedCount).padStart(2, "0")}</strong><span className="review-fraction">of {findings.length}</span></div><div className="metric-caption">This session{reviewedCount > 0 ? <button type="button" onClick={() => { setReviewedIds(new Set()); setAnnouncement("Reviewed findings restored to the queue."); }}>Reset reviews</button> : <span>Ready for triage</span>}</div></div>
        </section>

        <div className="analytics-context"><span>Security Announcements History</span><span>{selectedPlatform === "all" ? "All platforms" : PLATFORM_META[selectedPlatform].label} · {mode === "live" ? "Latest results" : mode === "pending" ? "Awaiting results" : "No completed data"}</span></div>
        <ThreatAnalytics findings={scopeFindings} checkedAt={lastChecked}/>

        <div className="queue-context"><span>Platforms Monitored</span><button type="button" onClick={() => setSelectedPlatform("all")} aria-pressed={selectedPlatform === "all"}>All platforms <ArrowUpRight size={13}/></button></div>

        <section className="platform-grid" aria-label="Monitoring scopes">
          {platformOrder.map((platform) => {
            const metadata = PLATFORM_META[platform];
            const count = countFor(platform);
            const isSelected = selectedPlatform === platform;
            return (
              <button
                key={platform}
                className={`platform-card ${isSelected ? "platform-card-selected" : ""}`}
                type="button"
                aria-pressed={isSelected}
                onClick={() => setSelectedPlatform(isSelected ? "all" : platform)}
              >
                <div
                  className={`platform-icon platform-icon-${platform} ${metadata.logos.length > 1 ? "platform-icon-multiple" : ""}`}
                  aria-hidden="true"
                >
                  {metadata.logos.map((logo) => (
                    <Image key={logo} className="platform-logo" src={logo} alt="" width={22} height={22} />
                  ))}
                </div>
                <div className="platform-card-body">
                  <div className="platform-card-heading">
                    <span>{metadata.label}</span>
                    <ArrowUpRight size={15} aria-hidden="true" />
                  </div>
                  <p><strong>{String(count).padStart(2, "0")}</strong><span>{count === 1 ? "open finding" : "open findings"}</span></p>
                </div>
              </button>
            );
          })}
        </section>

        <div className="operations-grid">
        <section className="findings-section" aria-labelledby="findings-title">
          <div className="section-heading">
            <div>
              <h2 id="findings-title">Security Announcements <span className="queue-count">{visibleFindings.length}</span></h2>
            </div>
            {selectedPlatform !== "all" ? (
              <button className="clear-filter" type="button" onClick={() => setSelectedPlatform("all")}>
                Showing {PLATFORM_META[selectedPlatform].label} <span>×</span>
              </button>
            ) : null}
          </div>

          {error ? (
            <div className="error-state" role="alert">
              <CircleAlert size={18} aria-hidden="true" />
              <div>
                <strong>We couldn’t load the latest findings.</strong>
                <p>{error}</p>
              </div>
              <button type="button" onClick={() => void loadFindings("manual")}>Try again</button>
            </div>
          ) : null}

          <div className="sr-only" aria-live="polite" aria-atomic="true">{announcement}</div>

          {visibleFindings.length ? (
            <div className="finding-list">
              {visibleFindings.map((finding) => {
                const expanded = expandedId === finding.id;
                const technicalOpen = technicalId === finding.id;
                const platform = PLATFORM_META[finding.platform];
                return (
                  <article id={`finding-${finding.id}`} key={finding.id} className={`finding-card ${expanded ? "finding-card-expanded" : ""}`}>
                    <button
                      className="finding-trigger"
                      type="button"
                      aria-expanded={expanded}
                      onClick={() => setExpandedId(expanded ? null : finding.id)}
                    >
                      <span className={`severity-bar severity-${finding.severity}`} aria-hidden="true" />
                      <span className="finding-content">
                        <span className="finding-meta">
                          <span className={`severity-chip severity-chip-${finding.severity}`}>
                            {severityLabels[finding.severity]}
                          </span>
                          <span className="severity-helper">{severityDescriptions[finding.severity]}</span>
                          <span className="meta-separator" aria-hidden="true">·</span>
                          <span>{platform.label}</span>
                          <span className="meta-separator" aria-hidden="true">·</span>
                          <span>{findingTime(finding.detectedAt)}</span>
                        </span>
                        <span className="finding-title">{finding.title}</span>
                        <span className="finding-systems">
                          <span className="finding-systems-label">Affected Systems</span>
                          <span className="finding-systems-value">{finding.scope?.trim() || "Not specified in the source"}</span>
                        </span>
                        <span className="finding-summary">{finding.summary}</span>
                      </span>
                      <ChevronDown className={`chevron ${expanded ? "chevron-open" : ""}`} size={19} aria-hidden="true" />
                    </button>

                    {expanded ? (
                      <div className="finding-details">
                        <div className="detail-grid">
                          <div className="detail-block">
                            <span className="detail-label">What happened</span>
                            <p>{finding.whatHappened}</p>
                          </div>
                          <div className="detail-block">
                            <span className="detail-label">Why it matters</span>
                            <p>{finding.whyItMatters}</p>
                          </div>
                          <div className="detail-block detail-block-wide">
                            <span className="detail-label">Recommended next step</span>
                            <p>{finding.nextStep}</p>
                          </div>
                        </div>

                        <div className="evidence-row">
                          <div className="evidence-source">
                            <span className="evidence-icon" aria-hidden="true"><Clock3 size={14} /></span>
                            <span>
                              <span className="detail-label">Source</span>
                              <a href={finding.sourceUrl} target="_blank" rel="noopener noreferrer">
                                {finding.source} <ExternalLink size={12} aria-hidden="true" />
                              </a>
                            </span>
                          </div>
                          <span className="evidence-time">Detected {findingTime(finding.detectedAt)}</span>
                        </div>

                        <div className="technical-disclosure">
                          <button
                            type="button"
                            className="technical-toggle"
                            aria-expanded={technicalOpen}
                            onClick={() => setTechnicalId(technicalOpen ? null : finding.id)}
                          >
                            <span>{technicalOpen ? "Hide technical evidence" : "Show technical evidence"}</span>
                            <ChevronDown size={15} className={technicalOpen ? "chevron-open" : ""} aria-hidden="true" />
                          </button>
                          {technicalOpen ? (
                            <div className="technical-panel">
                              <div><span>Signal type</span><strong>{finding.signalType}</strong></div>
                              <div><span>Observed scope</span><strong>{finding.scope}</strong></div>
                              <div><span>Evidence note</span><strong>{finding.evidenceNote}</strong></div>
                            </div>
                          ) : null}
                        </div>

                        <div className="detail-actions">
                          <button type="button" className="review-button" onClick={() => markReviewed(finding.id)}>
                            <CheckCircle2 size={15} aria-hidden="true" />
                            Reviewed this session
                          </button>
                          <span className="detail-disclaimer">Review the source before taking action.</span>
                        </div>
                      </div>
                    ) : null}
                  </article>
                );
              })}
            </div>
          ) : (
            <div className="empty-state">
              <div className="empty-icon" aria-hidden="true"><CheckCircle2 size={22} /></div>
              <strong>{selectedPlatform === "all" ? "No active findings." : "No findings match this environment."}</strong>
              <p>
                {selectedPlatform === "all"
                  ? mode === "pending"
                    ? "The security check is still running. Results will appear when it completes."
                    : mode === "fallback"
                      ? "No current results are available. Resolve the monitoring configuration and run the check again."
                      : reviewedCount > 0
                        ? "All findings in the current snapshot have been reviewed. Run a manual check for current results."
                        : "Run a manual check to collect current results from the configured public sources."
                  : "Try the full view to see findings from every monitored scope."}
              </p>
              {selectedPlatform !== "all" ? (
                <button type="button" onClick={() => setSelectedPlatform("all")}>Show all environments</button>
              ) : null}
            </div>
          )}
        </section>

        <aside className="sources-panel" id="sources" aria-labelledby="sources-title">
          <div className="sources-heading"><Radio size={17}/><h2 id="sources-title">Source catalog</h2><span>{SOURCE_CATALOG.length}</span></div>
          <p className="sources-description">Authoritative advisories used by the research agent.</p>
          <div className="source-cards">{SOURCE_CATALOG.map((source, index) => <a key={source.name} href={source.url} target="_blank" rel="noopener noreferrer"><span className="source-number">0{index + 1}</span><span>{source.name}</span><ExternalLink size={13}/></a>)}</div>
          {pendingCount > 0 && <p className="source-note">{pendingCount} new or changed announcements awaiting review. Each check reviews up to three.</p>}
          {sourceStatuses.filter(source => source.status !== "checked").map(source => <p className="source-note" key={source.id}>{SOURCE_CATALOG.find(item => item.id === source.id)?.name}: {source.error ?? "Coverage is incomplete."}</p>)}
          {trust ? (
            <section className="trust-panel" aria-labelledby="trust-title">
              <div className="trust-heading">
                <div><ShieldCheck size={15} aria-hidden="true" /><h3 id="trust-title">Evidence trace</h3></div>
                <span>{trust.confidence ?? "Recorded"}</span>
              </div>
              <p className="trust-summary">{trust.claims.length} claim checks · {trust.sources.length} cited sources</p>
              {trust.reasoning ? <p className="trust-reasoning">{trust.reasoning}</p> : null}
              <details className="trust-details">
                <summary>View citation trace</summary>
                {trust.sources.length ? (
                  <div className="trust-source-list">
                    {trust.sources.map((source) => (
                      <a key={`${source.url}-${source.title}`} href={source.url} target="_blank" rel="noopener noreferrer">
                        <span>{source.title}</span>
                        <ExternalLink size={12} aria-hidden="true" />
                      </a>
                    ))}
                  </div>
                ) : null}
                {trust.claims.length ? (
                  <div className="trust-claim-list">
                    {trust.claims.slice(0, 8).map((claim, index) => {
                      const excerpt = trustClaimExcerpt(claim);
                      const confidence = trustClaimConfidence(claim);
                      return (
                        <div key={`${trustClaimPath(claim, index)}-${index}`} className="trust-claim">
                          <div><strong>{trustClaimPath(claim, index)}</strong>{confidence ? <span>{confidence}</span> : null}</div>
                          {excerpt ? <p>{excerpt}</p> : null}
                        </div>
                      );
                    })}
                  </div>
                ) : null}
              </details>
            </section>
          ) : null}
          <div className="research-state"><div><Activity size={15}/><span>Research status</span><span className={`research-status ${isRefreshing ? 'research-running' : ''}`}>{isRefreshing ? 'Running' : mode === 'fallback' ? 'Unavailable' : mode === 'pending' ? 'Queued' : mode === 'live' ? 'Complete' : 'Standby'}</span></div><p>{isRefreshing ? 'Nimble is checking public advisories.' : mode === 'fallback' ? 'Nimble is unavailable. Check the runtime configuration and retry.' : mode === 'live' ? 'The latest completed check supplied this snapshot.' : 'Run a check to collect current public advisories.'}</p><div className="research-progress" aria-hidden="true"><span className={isRefreshing ? 'progress-scanning' : ''}/></div><small>Run mode <strong>{hourlyMonitoringEnabled === true ? 'Hourly' : 'Manual'}</strong></small></div>
        </aside>
        </div>

        <section className="history-panel" aria-labelledby="history-title">
          <div className="section-heading history-heading">
            <div>
              <p className="section-kicker">Audit trail</p>
              <h2 id="history-title">Check history <span className="queue-count">{history.length}</span></h2>
            </div>
            {selectedSnapshotId && history[0]?.id !== selectedSnapshotId ? (
              <button type="button" className="history-latest-button" onClick={() => void loadSavedSnapshot()} disabled={isRefreshing}>
                Return to latest
              </button>
            ) : (
              <span className="history-caption">Saved snapshots · newest first</span>
            )}
          </div>

          {historyStatus === "loading" ? (
            <div className="history-empty" role="status">
              <Clock3 size={18} aria-hidden="true" />
              <div><strong>Loading saved checks…</strong><p>Retrieving the shared audit trail.</p></div>
            </div>
          ) : historyStatus === "error" ? (
            <div className="history-error" role="alert">
              <CircleAlert size={18} aria-hidden="true" />
              <div><strong>History unavailable.</strong><p>{historyError ?? "Saved checks could not be loaded."}</p></div>
              <button type="button" onClick={() => void loadSavedSnapshot()}>Retry</button>
            </div>
          ) : history.length ? (
            <div className="history-table-wrap">
              <table className="history-table">
                <caption className="sr-only">Saved security check snapshots</caption>
                <thead>
                  <tr>
                    <th scope="col">Checked</th>
                    <th scope="col">Run mode</th>
                    <th scope="col">Findings</th>
                    <th scope="col">Critical</th>
                    <th scope="col">Platforms</th>
                  </tr>
                </thead>
                <tbody>
                  {history.map((snapshot) => (
                    <tr key={snapshot.id} className={selectedSnapshotId === snapshot.id ? "history-row-selected" : undefined}>
                      <td>
                        <button
                          type="button"
                          className="history-row-button"
                          onClick={() => void loadSavedSnapshot(snapshot.id)}
                          disabled={isRefreshing}
                          aria-label={`Open saved check from ${historyTime(snapshot.checkedAt)}`}
                        >
                          <time dateTime={snapshot.checkedAt}>{historyTime(snapshot.checkedAt)}</time>
                        </button>
                      </td>
                      <td><span className={`history-trigger history-trigger-${snapshot.trigger}`}>{snapshot.trigger === "automatic" ? "Hourly" : "Manual"}</span></td>
                      <td>{String(snapshot.findingCount).padStart(2, "0")}</td>
                      <td className={snapshot.criticalCount ? "history-critical" : undefined}>{String(snapshot.criticalCount).padStart(2, "0")}</td>
                      <td>{String(snapshot.platformCount).padStart(2, "0")}/04</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="history-empty">
              <Clock3 size={18} aria-hidden="true" />
              <div>
                <strong>No saved checks yet.</strong>
                <p>Completed manual and hourly checks will remain available here after a refresh.</p>
              </div>
            </div>
          )}
        </section>

        <footer className="page-footer">
          <span><TriangleAlert size={14} aria-hidden="true" /> Findings are signals for review, not proof of compromise.</span>
          <span>NIMBLE <span className="footer-slash">/</span> WATCHTOWER</span>
        </footer>
      </div>
    </main>
  );
}
