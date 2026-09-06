import type { ReactNode } from "react";
import type { Scan } from "@/lib/types";
import type { IntelligenceData } from "@/lib/securityIntelligence";
import { formatDate } from "@/lib/format";
import {
  DatabaseIcon,
  FingerprintIcon,
  GlobeIcon,
  ImageIcon,
  LayersIcon,
  RadarIcon,
  ShieldAlertIcon,
} from "../Icons";

function display(value: number | null): string {
  return value === null ? "—" : value.toLocaleString();
}

function MetricCard({ label, value, icon, tone }: { label: string; value: number | null; icon: ReactNode; tone: string }) {
  return (
    <article className={`intel-metric-card tone-${tone}`}>
      <span className="intel-metric-icon">{icon}</span>
      <div><small>{label}</small><strong>{display(value)}</strong></div>
    </article>
  );
}

function SeverityDonut({ data }: { data: IntelligenceData }) {
  const entries = [
    ["critical", data.severityCounts.critical],
    ["high", data.severityCounts.high],
    ["medium", data.severityCounts.medium],
    ["low", data.severityCounts.low],
    ["info", data.severityCounts.info],
  ] as const;
  const total = entries.reduce((sum, [, value]) => sum + value, 0);
  const weights = entries.map(([severity, value]) => ({ severity, value, portion: total ? (value / total) * 100 : 0 }));
  let cursor = 0;
  const gradient = total
    ? `conic-gradient(${weights.map(({ severity, portion }) => {
        const start = cursor;
        cursor += portion;
        return `var(--severity-${severity}) ${start}% ${cursor}%`;
      }).join(",")})`
    : "conic-gradient(var(--panel-border) 0 100%)";

  return (
    <section className="intel-panel risk-distribution-panel">
      <header className="panel-heading"><div><small>Risk intelligence</small><h3>Security risk distribution</h3></div><span>{total} findings</span></header>
      <div className="risk-donut-layout">
        <div className="risk-donut" style={{ background: gradient }}><div><strong>{total}</strong><small>findings</small></div></div>
        <div className="risk-legend">
          {entries.map(([severity, value]) => <div key={severity}><i className={`severity-dot ${severity}`} /><span>{severity}</span><strong>{value}</strong></div>)}
        </div>
      </div>
    </section>
  );
}

function ActivityBar({ metric, max }: { metric: any; max: number }) {
  const width = metric.value === null || max <= 0 ? 0 : Math.max(4, (metric.value / max) * 100);
  return (
    <div className="activity-row">
      <div><span>{metric.label}</span><strong>{display(metric.value)}</strong></div>
      <div className="activity-track"><span className={`tone-${metric.tone}`} style={{ width: `${width}%` }} /></div>
    </div>
  );
}

function ReconAnalytics({ data }: { data: IntelligenceData }) {
  return (
    <section className="intel-panel recon-analytics-panel">
      <header className="panel-heading"><div><small>Recon activity</small><h3>Evidence acquisition</h3></div><span>Latest scan</span></header>
      <div className="activity-list">
        <ActivityBar metric={{ label: "DNS discoveries", value: data.metrics.subdomains, tone: "cyan" }} max={data.metrics.subdomains || 1} />
        <ActivityBar metric={{ label: "HTTP assets", value: data.metrics.liveAssets, tone: "blue" }} max={data.metrics.liveAssets || 1} />
      </div>
    </section>
  );
}

function ExecutiveSummary({ data }: { data: IntelligenceData }) {
  return (
    <section className="intel-panel executive-summary-panel">
      <header className="panel-heading"><div><small>Decision support</small><h3>Executive summary</h3></div><ShieldAlertIcon /></header>
      <div className="summary-orb"><ShieldAlertIcon /></div>
      <ul>
        <li>{data.metrics.totalAssets} canonical assets are represented in the latest normalized inventory.</li>
        <li>{data.metrics.technologies} technology fingerprints were consolidated.</li>
      </ul>
    </section>
  );
}

export function SecurityOverview({ data, scan }: { data: IntelligenceData; scan: Scan }) {
  return (
    <div className="security-overview">
      <div className="intel-title-row">
        <div><small>Target intelligence</small><h2>{scan.target}</h2></div>
        <div className="intel-last-scan"><span>Last scan</span><strong>{formatDate(scan.completed_at || scan.started_at)}</strong></div>
      </div>

      <div className="intel-metric-grid">
        <MetricCard label="Total assets" value={data.metrics.totalAssets} icon={<DatabaseIcon />} tone="violet" />
        <MetricCard label="Subdomains discovered" value={data.metrics.subdomains} icon={<GlobeIcon />} tone="blue" />
        <MetricCard label="URLs discovered" value={data.metrics.urls} icon={<RadarIcon />} tone="cyan" />
        <MetricCard label="Endpoints discovered" value={data.metrics.endpoints} icon={<LayersIcon />} tone="blue" />
        <MetricCard label="Technologies detected" value={data.metrics.technologies} icon={<FingerprintIcon />} tone="violet" />
        <MetricCard label="Open ports" value={data.metrics.openPorts} icon={<ShieldAlertIcon />} tone="amber" />
        <MetricCard label="Screenshots captured" value={data.metrics.screenshots} icon={<ImageIcon />} tone="cyan" />
      </div>

      <div className="overview-analytics-grid">
        <SeverityDonut data={data} />
        <ReconAnalytics data={data} />
        <ExecutiveSummary data={data} />
      </div>
    </div>
  );
}
