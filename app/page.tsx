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
  Info,
  RefreshCw,
  ShieldCheck,
  TriangleAlert,
} from "lucide-react";
import {
  DEMO_FINDINGS,
  PLATFORM_META,
  SOURCE_CATALOG,
  type Finding,
  type PlatformKey,
  type Severity,
} from "@/lib/watchtower";

type FeedMode = "demo" | "live" | "fallback" | "pending";

type FeedResponse = {
  agentId?: string;
  checkedAt?: string;
  findings?: Finding[];
  message?: string;
  mode?: FeedMode;
  runId?: string;
  status?: "running" | "completed";
};

type ActiveRun = {
  agentId: string;
  runId: string;
};

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

export default function Home() {
  const [findings, setFindings] = useState<Finding[]>(DEMO_FINDINGS);
  const [mode, setMode] = useState<FeedMode>("demo");
  const [lastChecked, setLastChecked] = useState<string>();
  const [activeRun, setActiveRun] = useState<ActiveRun | null>(null);
  const [selectedPlatform, setSelectedPlatform] = useState<PlatformKey>("all");
  const [expandedId, setExpandedId] = useState<string | null>(DEMO_FINDINGS[0].id);
  const [technicalId, setTechnicalId] = useState<string | null>(null);
  const [reviewedIds, setReviewedIds] = useState<Set<string>>(new Set());
  const [isRefreshing, setIsRefreshing] = useState(false);
  const isRefreshingRef = useRef(false);
  const [error, setError] = useState<string>();
  const [announcement, setAnnouncement] = useState("Loading current findings.");

  const loadFindings = useCallback(async () => {
    if (isRefreshingRef.current) return;

    isRefreshingRef.current = true;
    setIsRefreshing(true);
    setError(undefined);
    setMode("pending");

    try {
      const response = await fetch("/api/findings", {
        method: "POST",
        cache: "no-store",
      });
      const payload = (await response.json()) as FeedResponse;

      if (!response.ok) {
        throw new Error(payload.message ?? "The latest findings could not be loaded.");
      }

      if (payload.mode === "demo") {
        if (Array.isArray(payload.findings)) setFindings(payload.findings);
        setMode("demo");
        if (payload.checkedAt) setLastChecked(payload.checkedAt);
        setAnnouncement(payload.message ?? "Showing the demo findings.");
        isRefreshingRef.current = false;
        setIsRefreshing(false);
        return;
      }

      if (payload.mode === "live") {
        if (Array.isArray(payload.findings)) setFindings(payload.findings);
        setMode("live");
        if (payload.checkedAt) setLastChecked(payload.checkedAt);
        setAnnouncement(payload.message ?? "Findings refreshed.");
        isRefreshingRef.current = false;
        setIsRefreshing(false);
        return;
      }

      if (!payload.runId || !payload.agentId) {
        throw new Error("Nimble returned an incomplete monitoring run.");
      }

      setActiveRun({ runId: payload.runId, agentId: payload.agentId });
      setAnnouncement(payload.message ?? "Nimble research is running.");
    } catch (loadError) {
      setMode("fallback");
      setError(loadError instanceof Error ? loadError.message : "The latest findings could not be loaded.");
      setAnnouncement("The latest findings could not be loaded. Showing the last available view.");
      isRefreshingRef.current = false;
      setIsRefreshing(false);
    }
  }, []);

  useEffect(() => {
    if (!activeRun) return;

    let cancelled = false;
    let timer: number | undefined;

    async function pollRun() {
      try {
        const params = new URLSearchParams({
          agentId: activeRun.agentId,
          runId: activeRun.runId,
        });
        const response = await fetch(`/api/findings?${params.toString()}`, {
          cache: "no-store",
        });
        const payload = (await response.json()) as FeedResponse;

        if (cancelled) return;

        if (response.status === 202 || payload.status === "running" || payload.mode === "pending") {
          setAnnouncement(payload.message ?? "Nimble research is still running.");
          timer = window.setTimeout(() => void pollRun(), 10_000);
          return;
        }

        if (!response.ok) {
          throw new Error(payload.message ?? "The Nimble monitoring run could not be read.");
        }

        if (Array.isArray(payload.findings)) setFindings(payload.findings);
        setMode(payload.mode ?? "live");
        if (payload.checkedAt) setLastChecked(payload.checkedAt);
        setAnnouncement(payload.message ?? "Findings refreshed.");
        setActiveRun(null);
        isRefreshingRef.current = false;
        setIsRefreshing(false);
      } catch (pollError) {
        if (cancelled) return;
        setActiveRun(null);
        isRefreshingRef.current = false;
        setIsRefreshing(false);
        setMode("fallback");
        setError(pollError instanceof Error ? pollError.message : "The Nimble monitoring run could not be read.");
        setAnnouncement("The latest findings could not be loaded. Showing the last available view.");
      }
    }

    timer = window.setTimeout(() => void pollRun(), 2_000);
    return () => {
      cancelled = true;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [activeRun]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void loadFindings();
    }, 0);
    return () => window.clearTimeout(timer);
  }, [loadFindings]);

  const visibleFindings = useMemo(() => {
    const scoped = selectedPlatform === "all"
      ? findings
      : findings.filter((finding) => finding.platform === selectedPlatform);
    return scoped.filter((finding) => !reviewedIds.has(finding.id));
  }, [findings, reviewedIds, selectedPlatform]);

  const openCount = findings.filter((finding) => !reviewedIds.has(finding.id)).length;
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

  return (
    <main className="watchtower-shell">
      <header className="topbar">
        <div className="topbar-inner">
          <div className="brand-lockup">
            <div className="brand-mark" aria-hidden="true">
              <ShieldCheck size={20} strokeWidth={2.2} />
            </div>
            <div>
              <p className="brand-kicker">NIMBLE / SECURITY</p>
              <p className="brand-name">Watchtower</p>
            </div>
          </div>

          <div className="topbar-status" aria-label="Monitoring status">
            <span className="status-dot" aria-hidden="true" />
            <span>Monitoring active</span>
            <span className="topbar-divider" aria-hidden="true" />
            <span>Last checked {formatCheckedAt(lastChecked)}</span>
          </div>

          <button
            className="refresh-button"
            type="button"
            onClick={() => void loadFindings()}
            disabled={isRefreshing}
          >
            <RefreshCw size={16} className={isRefreshing ? "spin" : ""} aria-hidden="true" />
            <span>{isRefreshing ? "Checking" : "Refresh"}</span>
          </button>
        </div>
      </header>

      <div className="page-wrap">
        <section className="intro-row" aria-labelledby="page-title">
          <div>
            <div className="eyebrow"><Activity size={14} aria-hidden="true" /> Threat review surface</div>
            <h1 id="page-title">Security signals, reduced to next steps.</h1>
            <p className="intro-copy">
              A plain-language view of current findings across devices, systems, and AI prompt safety.
            </p>
          </div>
          <div className="attention-summary" aria-live="polite">
            <span className="summary-number">{openCount}</span>
            <span>{openCount === 1 ? "finding" : "findings"} need attention</span>
            {criticalCount > 0 ? <span className="summary-critical">{criticalCount} critical</span> : null}
          </div>
        </section>

        <div className={`feed-notice ${mode === "live" ? "feed-notice-live" : ""} ${mode === "pending" ? "feed-notice-pending" : ""}`} role="status">
          {mode === "live" ? <CheckCircle2 size={15} aria-hidden="true" /> : <Info size={15} aria-hidden="true" />}
          <span>
            {mode === "demo"
              ? "Demo feed — connect Nimble to replace these examples with live findings."
              : mode === "pending"
                ? "Nimble research is running — this multi-source check can take several minutes."
                : mode === "fallback"
                  ? "Showing the last available view — the latest check needs attention."
                  : "Live Nimble feed connected — findings are sourced from the configured monitoring agent."}
          </span>
        </div>

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
                  <p>{count ? `${count} ${count === 1 ? "finding" : "findings"} need review` : "No urgent findings"}</p>
                </div>
              </button>
            );
          })}
        </section>

        <section className="coverage-strip" aria-label="Monitored sources">
          <div className="coverage-label">
            <span className="coverage-pulse" aria-hidden="true" />
            <span>Coverage</span>
          </div>
          <div className="source-list">
            {SOURCE_CATALOG.map((source) => (
              <a key={source.name} href={source.url} target="_blank" rel="noopener noreferrer">
                {source.name}
                <ExternalLink size={12} aria-hidden="true" />
              </a>
            ))}
          </div>
        </section>

        <section className="findings-section" aria-labelledby="findings-title">
          <div className="section-heading">
            <div>
              <p className="section-kicker">Review queue</p>
              <h2 id="findings-title">Needs attention</h2>
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
              <button type="button" onClick={() => void loadFindings()}>Try again</button>
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
                  <article key={finding.id} className={`finding-card ${expanded ? "finding-card-expanded" : ""}`}>
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
                            Mark as reviewed
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
                  ? `Monitoring is on. The latest check completed ${formatCheckedAt(lastChecked).toLowerCase()}.`
                  : "Try the full view to see findings from every monitored scope."}
              </p>
              {selectedPlatform !== "all" ? (
                <button type="button" onClick={() => setSelectedPlatform("all")}>Show all environments</button>
              ) : null}
            </div>
          )}
        </section>

        <footer className="page-footer">
          <span><TriangleAlert size={14} aria-hidden="true" /> Findings are signals for review, not proof of compromise.</span>
          <span>Read-only monitoring surface</span>
        </footer>
      </div>
    </main>
  );
}
