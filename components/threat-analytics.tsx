"use client";

import { useEffect, useId, useMemo, useRef, useState, type CSSProperties } from "react";
import { ArrowUpRight, ChartNoAxesCombined, ChevronDown, Layers3 } from "lucide-react";
import { type Finding, type Severity } from "@/lib/watchtower";

const DAY = 86_400_000;
const HOUR = 3_600_000;
const severityOrder: Severity[] = ["critical", "high", "medium", "low"];
const colors: Record<Severity, string> = { critical: "#f46b2b", high: "#707c60", medium: "#adb599", low: "#d6dcca" };
const names: Record<Severity, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };
type Range = "feed" | "7" | "30" | "90";
type Bucket = { start: number; end: number; counts: Record<Severity, number>; total: number };

export function detectionBuckets(findings: Finding[], range: Range, reference: number) {
  const dated = [...new Map(findings.map(finding => [finding.id, finding])).values()]
    .map(finding => ({ ...finding, time: Date.parse(finding.detectedAt) }))
    .filter(finding => Number.isFinite(finding.time));
  const latest = dated.length ? Math.max(...dated.map(f => f.time)) : reference;
  const earliest = dated.length ? Math.min(...dated.map(f => f.time)) : reference;
  let step: number;
  let end: number;
  let count: number;
  if (range === "feed") {
    const span = latest - earliest;
    step = span < DAY ? HOUR : Math.max(1, Math.ceil((span / DAY + 1) / 12)) * DAY;
    end = Math.floor(latest / step) * step + step;
    count = Math.max(8, Math.ceil((end - earliest) / step));
  } else {
    const days = Number(range);
    step = (days === 7 ? 1 : days === 30 ? 2 : 6) * DAY;
    end = Math.floor(reference / DAY) * DAY + DAY;
    count = days / (step / DAY);
  }
  const start = end - count * step;
  const buckets: Bucket[] = Array.from({ length: count }, (_, i) => ({ start: start + i * step, end: start + (i + 1) * step, counts: { critical: 0, high: 0, medium: 0, low: 0 }, total: 0 }));
  for (const finding of dated) {
    const index = Math.floor((finding.time - start) / step);
    if (index >= 0 && index < buckets.length) {
      buckets[index].counts[finding.severity]++;
      buckets[index].total++;
    }
  }
  return { buckets, hourly: step === HOUR, invalidCount: findings.filter(f => !Number.isFinite(Date.parse(f.detectedAt))).length };
}

function timeLabel(time: number, hourly = false) {
  return new Intl.DateTimeFormat("en-US", hourly
    ? { hour: "2-digit", minute: "2-digit", hourCycle: "h23", timeZone: "UTC" }
    : { month: "short", day: "numeric", timeZone: "UTC" }).format(time);
}

function Timeline({ findings, isDemo, checkedAt }: { findings: Finding[]; isDemo: boolean; checkedAt?: string }) {
  const [range, setRange] = useState<Range>("feed");
  const [active, setActive] = useState<number | null>(null);
  const [clock] = useState(() => Date.now());
  const plot = useRef<HTMLDivElement>(null);
  const [plotWidth, setPlotWidth] = useState(740);
  useEffect(() => {
    if (!plot.current) return;
    const observer = new ResizeObserver(entries => setPlotWidth(Math.max(240, Math.round(entries[0].contentRect.width))));
    observer.observe(plot.current);
    return () => observer.disconnect();
  }, []);
  const reference = checkedAt && Number.isFinite(Date.parse(checkedAt)) ? Date.parse(checkedAt) : clock;
  const { buckets, hourly, invalidCount } = useMemo(() => detectionBuckets(findings, range, reference), [findings, range, reference]);
  const max = Math.max(2, ...buckets.map(b => b.total));
  const total = buckets.reduce((sum, b) => sum + b.total, 0);
  const peak = buckets.reduce((best, b) => Math.max(best, b.total), 0);
  const baseline = 210;
  const chartHeight = 154;
  const left = plotWidth < 400 ? 27 : 37;
  const right = plotWidth - 19;
  const width = right - left;
  const cell = width / buckets.length;
  const barWidth = Math.min(32, cell * .57);
  const selectedIndex = active !== null && active < buckets.length ? active : buckets.findLastIndex(b => b.total > 0);
  const selected = selectedIndex >= 0 ? buckets[selectedIndex] : undefined;
  const chartId = useId();

  return (
    <section className="analytics-panel activity-panel" aria-labelledby={`${chartId}-title`}>
      <div className="panel-heading">
        <div><p className="panel-eyebrow"><ChartNoAxesCombined size={14} /> Threat telemetry</p><h2 id={`${chartId}-title`}>Detection timeline</h2></div>
        <div className="range-control" role="group" aria-label="Timeline date range">
          {([['7', '7D'], ['30', '30D'], ['90', '90D'], ['feed', 'All']] as const).map(([value, label]) => (
            <button type="button" key={value} aria-pressed={range === value} onClick={() => { setRange(value); setActive(null); }}>{label}</button>
          ))}
        </div>
      </div>
      <div className="chart-summary"><strong>{total.toString().padStart(2, "0")}</strong><div><span>dated findings</span><small>{isDemo ? "Illustrative feed" : "Current feed snapshot"} · UTC</small></div><span className="peak-label">Peak <b>{peak}</b><ArrowUpRight size={13} /></span></div>
      <div className="timeline-graphic" ref={plot}>
        <svg viewBox={`0 0 ${plotWidth} 251`} role="group" aria-label="Findings grouped by detection date. Focus a column for exact counts.">
          <defs>
            <linearGradient id={`${chartId}-floor`} x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#dce1d0" stopOpacity=".5"/><stop offset="1" stopColor="#fdfcf9" stopOpacity="0"/></linearGradient>
          </defs>
          <path d={`M${left},${baseline} H${right} l12,14 H${left + 12} Z`} fill={`url(#${chartId}-floor)`} />
          {[0, 1, 2].map(i => { const value = Math.ceil(max * i / 2); const y = baseline - value / max * chartHeight; return <g key={i}><line x1={left} x2={right} y1={y} y2={y} stroke="#e2e5db" strokeDasharray={i ? "3 5" : "0"}/><text x={left - 12} y={y + 4} textAnchor="end" className="chart-axis">{value}</text></g>; })}
          <text x={left} y="23" className="chart-unit">FINDINGS</text>
          {buckets.map((bucket, index) => {
            const x = left + cell * index + (cell - barWidth) / 2;
            let accumulated = 0;
            const pieces = [...severityOrder].reverse().filter(s => bucket.counts[s] > 0).map(severity => {
              const h = bucket.counts[severity] / max * chartHeight;
              const y = baseline - accumulated - h;
              accumulated += h;
              return <g key={severity}>
                <rect x={x} y={y} width={barWidth} height={h} fill={colors[severity]} />
                <path d={`M${x + barWidth},${y} l7,-6 v${h} l-7,6 Z`} fill={colors[severity]} />
                <path d={`M${x + barWidth},${y} l7,-6 v${h} l-7,6 Z`} fill="#252c22" opacity=".22" />
                <path d={`M${x},${y} l7,-6 h${barWidth} l-7,6 Z`} fill={colors[severity]} />
                <path d={`M${x},${y} l7,-6 h${barWidth} l-7,6 Z`} fill="#fff" opacity=".22" />
              </g>;
            });
            return <g key={`${range}-${bucket.start}`} className={`chart-column ${selectedIndex === index ? "chart-column-active" : ""}`} tabIndex={0} role="button" aria-label={`${timeLabel(bucket.start)} ${hourly ? timeLabel(bucket.start, true) : ''} UTC: ${bucket.total} findings, ${bucket.counts.critical} critical`} onMouseEnter={() => setActive(index)} onFocus={() => setActive(index)} onClick={() => setActive(index)} onKeyDown={event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); setActive(index); } }}>
              <rect className="chart-hitbox" x={x - 7} y="38" width={barWidth + 18} height="181" rx="5" fill="transparent" />
              <g className="bar-reveal" style={{ transformOrigin: `${x}px ${baseline}px`, animationDelay: `${index * 28}ms` } as CSSProperties}>{pieces}</g>
              {!bucket.total && <line x1={x} x2={x + barWidth} y1={baseline - 1} y2={baseline - 1} stroke="#d8ddcc" strokeWidth="2"/>}
              {bucket.total > 0 && <text x={x + barWidth / 2 + 3} y={baseline - accumulated - 16} className="chart-value" textAnchor="middle">{bucket.total}</text>}
              {index % Math.ceil(buckets.length / (plotWidth < 400 ? 4 : 7)) === 0 && <text x={x + barWidth / 2 + 2} y="240" textAnchor="middle" className="chart-axis">{timeLabel(bucket.start, hourly)}</text>}
            </g>;
          })}
        </svg>
      </div>
      <div className="chart-readout" aria-live="polite">
        <span><span className="legend-square" style={{ background: colors.critical }}/>{selected ? `${timeLabel(selected.start)}${hourly ? ` · ${timeLabel(selected.start, true)}` : ''}` : 'No dated findings'}<span className="readout-divider">/</span><b>{selected?.total ?? 0}</b> findings · <b>{selected?.counts.critical ?? 0}</b> critical</span>
        <span className="chart-readout-hint">Select a column</span>
      </div>
      <div className="chart-footnote">Dates supplied by the current feed. Empty periods do not confirm an absence of threats.{invalidCount > 0 ? ` ${invalidCount} undated findings excluded.` : ''}</div>
      <details className="chart-data"><summary>View chart data <ChevronDown size={12}/></summary><div className="chart-data-scroll"><table><caption>{isDemo ? 'Illustrative findings' : 'Current snapshot'} by detection time (UTC)</caption><thead><tr><th>Period start</th><th>Total</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th></tr></thead><tbody>{buckets.map(b => <tr key={b.start}><td>{new Date(b.start).toISOString().slice(0, 16).replace('T', ' ')}</td><td>{b.total}</td>{severityOrder.map(s => <td key={s}>{b.counts[s]}</td>)}</tr>)}</tbody></table></div></details>
    </section>
  );
}

function ringPath(start: number, end: number, offset = 0) {
  const point = (angle: number, radius: number) => [180 + Math.cos(angle) * radius, 114 + offset + Math.sin(angle) * radius * .58].map(value => Number(value.toFixed(3)));
  const outerStart = point(start, 123), innerStart = point(start, 79), outerEnd = point(end, 123), innerEnd = point(end, 79);
  const large = end - start > Math.PI ? 1 : 0;
  return `M${outerStart} A123,71.34 0 ${large},1 ${outerEnd} L${innerEnd} A79,45.82 0 ${large},0 ${innerStart} Z`;
}

function SeverityChart({ findings }: { findings: Finding[] }) {
  const [active, setActive] = useState<Severity | null>(null);
  const chartId = useId();
  const counts = Object.fromEntries(severityOrder.map(s => [s, findings.filter(f => f.severity === s).length])) as Record<Severity, number>;
  let cursor = -Math.PI * .75;
  const segments = severityOrder.filter(s => counts[s]).map(s => {
    const start = cursor;
    cursor += counts[s] / findings.length * Math.PI * 2;
    return { severity: s, start: start + .012, end: cursor - .012 };
  });
  return <section className="analytics-panel severity-panel" aria-labelledby={`${chartId}-title`}>
    <div className="panel-heading"><div><p className="panel-eyebrow"><Layers3 size={14}/> Risk distribution</p><h2 id={`${chartId}-title`}>Severity breakdown</h2></div><span className="panel-index">02</span></div>
    <div className="severity-graphic">
      <svg viewBox="0 0 360 241" role="img" aria-label={severityOrder.map(s => `${counts[s]} ${names[s]}`).join(', ')}>
        <defs><filter id={`${chartId}-shadow`} x="-50%" y="-100%" width="200%" height="300%"><feGaussianBlur stdDeviation="10"/></filter></defs>
        <ellipse cx="180" cy="186" rx="102" ry="21" fill="#465036" opacity=".12" filter={`url(#${chartId}-shadow)`}/>
        {!segments.length && <ellipse cx="180" cy="114" rx="123" ry="71" fill="none" stroke="#e3e7dc" strokeWidth="25"/>}
        {segments.map(({ severity, start, end }) => <g key={severity} className={`ring-segment ${active === severity ? 'ring-segment-active' : ''}`} onMouseEnter={() => setActive(severity)} onMouseLeave={() => setActive(null)}>
          {Array.from({ length: 18 }, (_, i) => <path key={i} d={ringPath(start, end, 18 - i)} fill={colors[severity]} style={{ filter: 'brightness(.72)' }}/>) }
          <path d={ringPath(start, end)} fill={colors[severity]}/>
          <path d={ringPath(start, end)} fill="none" stroke="#fffdf4" strokeOpacity=".28" strokeWidth="1"/>
        </g>)}
        <text x="180" y="109" textAnchor="middle" className="donut-count">{active ? counts[active] : findings.length}</text>
        <text x="180" y="130" textAnchor="middle" className="donut-label">{active ? names[active].toUpperCase() : 'FINDINGS'}</text>
      </svg>
    </div>
    <div className="severity-legend">{severityOrder.map(s => <button key={s} type="button" className={active === s ? 'severity-legend-active' : ''} aria-pressed={active === s} onClick={() => setActive(active === s ? null : s)} onFocus={() => setActive(s)} onBlur={() => setActive(null)}><span className="legend-square" style={{ background: colors[s] }}/><span>{names[s]}</span><strong>{counts[s].toString().padStart(2, '0')}</strong><span className="legend-percent">{findings.length ? Math.round(counts[s] / findings.length * 100) : 0}%</span></button>)}</div>
    <p className="severity-caption">All findings in the selected platform scope.</p>
  </section>;
}

export function ThreatAnalytics(props: { findings: Finding[]; isDemo: boolean; checkedAt?: string }) {
  return <div className="analytics-grid"><Timeline {...props}/><SeverityChart findings={props.findings}/></div>;
}
