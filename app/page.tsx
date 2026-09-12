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
  DEMO_FINDINGS,
  PLATFORM_META,
  SOURCE_CATALOG,
  type Finding,
  type PlatformKey,
  type Severity,
} from "@/lib/watchtower";
import { VulnerabilityTicker } from "@/components/vulnerability-ticker";
import { ThreatAnalytics } from "@/components/threat-analytics";

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
  const [dataIsDemo, setDataIsDemo] = useState(true);
  const [lastChecked, setLastChecked] = useState<string>();
  const [activeRun, setActiveRun] = useState<ActiveRun | null>(null);
  const [selectedPlatform, setSelectedPlatform] = useState<PlatformKey>("all");
  const [expandedId, setExpandedId] = useState<string | null>(null);
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
        setDataIsDemo(true);
        setMode("demo");
        if (payload.checkedAt) setLastChecked(payload.checkedAt);
        setAnnouncement(payload.message ?? "Showing the demo findings.");
        isRefreshingRef.current = false;
        setIsRefreshing(false);
        return;
      }

      if (payload.mode === "live") {
        if (Array.isArray(payload.findings)) setFindings(payload.findings);
        setDataIsDemo(false);
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
    const run = activeRun;

    let cancelled = false;
    let timer: number | undefined;

    async function pollRun() {
      try {
        const params = new URLSearchParams({
          agentId: run.agentId,
          runId: run.runId,
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
        if (Array.isArray(payload.findings)) setDataIsDemo(payload.mode === "demo");
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

  return (
    <main className="watchtower-shell">
      <aside className="command-rail" aria-label="Dashboard navigation">
        <a className="rail-brand" href="#overview" aria-label="Watchtower overview"><Radar size={28} /></a>
        <nav>
          <a href="#overview" aria-label="Overview" title="Overview"><LayoutDashboard size={21} /></a>
          <a href="#findings-title" aria-label="Review queue" title="Review queue"><ShieldCheck size={21} /></a>
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
            <div>
              <p className="brand-name">WATCHTOWER<span className="brand-slash">/</span><span className="brand-section">Security operations</span></p>
            </div>
          </div>

          <div className="topbar-status" aria-label="Monitoring status">
            <span className="status-dot" aria-hidden="true" />
            <span>{isRefreshing ? "Research in progress" : "On-demand monitoring"}</span>
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
            <span>{isRefreshing ? "Checking sources" : "Run new check"}</span>
          </button>
        </div>
      </header>

      <div className="page-wrap" id="overview">
        <section className="command-heading" aria-labelledby="page-title">
          <div><p className="section-kicker">Security intelligence</p><h1 id="page-title">Command center<span className="heading-period">.</span></h1></div>
          <span className="operation-label"><ScanLine size={16} /> macOS · Windows · Linux · AI</span>
        </section>
        <VulnerabilityTicker
          findings={findings.filter((finding) => !reviewedIds.has(finding.id))}
          mode={mode}
          isDemo={dataIsDemo}
          onSelectFinding={focusFinding}
        />

        <div className={`feed-notice ${mode === "live" ? "feed-notice-live" : ""} ${mode === "pending" ? "feed-notice-pending" : ""}`} role="status">
          {mode === "live" ? <CheckCircle2 size={15} aria-hidden="true" /> : <Info size={15} aria-hidden="true" />}
          <span>
            {mode === "demo"
              ? "Demo data · Illustrative findings. Run a check to request current intelligence."
              : mode === "pending"
                ? `${dataIsDemo ? "Demo data shown" : "Previous findings shown"} · Nimble is checking sources. Research can take several minutes.`
                : mode === "fallback"
                  ? `${dataIsDemo ? "Demo data shown" : "Previous findings shown"} · The latest check needs attention.`
                  : "Nimble results · Findings from the latest completed check. Monitoring runs on demand."}
          </span>
          <span className="feed-snapshot-tag">{dataIsDemo ? "DEMO SNAPSHOT" : "LATEST SNAPSHOT"}</span>
        </div>

        <section className="metrics-grid" aria-label="Current feed overview">
          <div className="metric-card"><div className="metric-heading"><span>Open findings</span><ShieldCheck size={17}/></div><div className="metric-value-row"><strong>{String(openCount).padStart(2, "0")}</strong><div className="metric-mini-bars" aria-hidden="true">{platformOrder.map(platform => <i key={platform} style={{ height: `${5 + countFor(platform) / Math.max(1, openCount) * 38}px` }}/>)}</div></div><div className="metric-caption">Across all platforms<span>{findings.length} in current feed</span></div></div>
          <div className="metric-card metric-critical"><div className="metric-heading"><span>Critical alerts</span><TriangleAlert size={17}/></div><div className="metric-value-row"><strong>{String(criticalCount).padStart(2, "0")}</strong><span className="critical-marker" aria-hidden="true"><CircleAlert size={30} strokeWidth={1.25}/></span></div><div className="metric-caption">{criticalCount ? "Priority review required" : "No critical findings open"}<span className="critical-tag">P1</span></div></div>
          <div className="metric-card"><div className="metric-heading"><span>Platforms represented</span><Layers3 size={17}/></div><div className="metric-value-row"><strong>{String(platformsRepresented).padStart(2, "0")}<small>/04</small></strong><div className="metric-platform-dots" aria-hidden="true">{platformOrder.map(platform => <i key={platform} className={findings.some(f => f.platform === platform) ? 'represented' : ''}/>)}</div></div><div className="metric-caption">OS & AI security<span>Current feed</span></div></div>
          <div className="metric-card"><div className="metric-heading"><span>Reviewed</span><CheckCircle2 size={17}/></div><div className="metric-value-row"><strong>{String(reviewedCount).padStart(2, "0")}</strong><span className="review-fraction">of {findings.length}</span></div><div className="metric-caption">This session{reviewedCount > 0 ? <button type="button" onClick={() => { setReviewedIds(new Set()); setAnnouncement("Reviewed findings restored to the queue."); }}>Reset reviews</button> : <span>Ready for triage</span>}</div></div>
        </section>

        <div className="analytics-context"><span>01 <span className="context-rule"/> Intelligence overview</span><span>{selectedPlatform === "all" ? "All platforms" : PLATFORM_META[selectedPlatform].label} · {dataIsDemo ? "Demo data" : "Latest results"}</span></div>
        <ThreatAnalytics findings={scopeFindings} isDemo={dataIsDemo} checkedAt={lastChecked}/>

        <div className="queue-context"><span>02 <span className="context-rule"/> Platform scope</span><button type="button" onClick={() => setSelectedPlatform("all")} aria-pressed={selectedPlatform === "all"}>All platforms <ArrowUpRight size={13}/></button></div>

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
              <p className="section-kicker">Triage workspace</p>
              <h2 id="findings-title">Review queue <span className="queue-count">{visibleFindings.length}</span></h2>
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
                  ? "All available findings have been reviewed, or this feed is empty. Run a new check for current results."
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
          <div className="research-state"><div><Activity size={15}/><span>Research status</span><span className={`research-status ${isRefreshing ? 'research-running' : ''}`}>{isRefreshing ? 'Running' : mode === 'fallback' ? 'Needs attention' : dataIsDemo ? 'Demo' : 'Complete'}</span></div><p>{isRefreshing ? 'Collecting and assessing public advisories.' : 'A new check runs on page load or on request.'}</p><div className="research-progress" aria-hidden="true"><span className={isRefreshing ? 'progress-scanning' : ''}/></div><small>Schedule <strong>On demand</strong></small></div>
        </aside>
        </div>

        <footer className="page-footer">
          <span><TriangleAlert size={14} aria-hidden="true" /> Findings are signals for review, not proof of compromise.</span>
          <span>NIMBLE <span className="footer-slash">/</span> WATCHTOWER</span>
        </footer>
      </div>
    </main>
  );
}
