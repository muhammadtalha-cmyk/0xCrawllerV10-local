import type { IntelligenceData, TechnologyIntel } from "@/lib/securityIntelligence";
import { FingerprintIcon, ShieldAlertIcon } from "../Icons";
import { TechnologyLogo } from "./TechnologyLogo";

function versionLabel(technology: TechnologyIntel): string {
  return technology.version || "Version not exposed";
}

function confidenceLabel(technology: TechnologyIntel): string {
  if (technology.confidenceScore !== null) return `${Math.round(technology.confidenceScore * 100)}%`;
  return technology.confidence || "Unknown";
}

function toneForTechnology(technology: TechnologyIntel): string {
  if (technology.risk === "critical" || technology.risk === "high") return "danger";
  if (technology.risk === "medium") return "amber";
  if (technology.confidenceScore !== null && technology.confidenceScore >= 0.9) return "cyan";
  return "blue";
}

function TechnologyCard({ technology }: { technology: TechnologyIntel }) {
  return (
    <article className={`technology-card tone-${toneForTechnology(technology)}`}>
      <div className="technology-card-head">
        <span className="technology-logo"><TechnologyLogo name={technology.name} /></span>
        <div><h3>{technology.name}</h3><small>{technology.category}</small></div>
      </div>
      <dl>
        <div><dt>Version</dt><dd>{versionLabel(technology)}</dd></div>
        <div><dt>Confidence</dt><dd>{confidenceLabel(technology)}</dd></div>
        <div><dt>Detection</dt><dd>{technology.sources.join(", ") || "Evidence correlation"}</dd></div>
        <div><dt>Host</dt><dd>{technology.host || "Multiple assets"}</dd></div>
      </dl>
      <footer><span className={`risk-chip ${technology.risk}`}>Risk: {technology.risk === "unrated" ? "Not rated" : technology.risk}</span>{technology.serviceConfirmed && <span className="service-confirmed">Service confirmed</span>}</footer>
    </article>
  );
}

const CATEGORY_LAYER: Array<{ key: string; label: string; matcher: RegExp }> = [
  { key: "edge", label: "CDN / WAF", matcher: /cdn|security edge|waf|cloudflare|front door/i },
  { key: "server", label: "Web server", matcher: /web server|server|proxy/i },
  { key: "frontend", label: "Frontend", matcher: /frontend|javascript|ui framework|cms|wordpress|react|angular|vue|next/i },
  { key: "backend", label: "Backend", matcher: /backend|runtime|programming language|php|python|node|java/i },
  { key: "database", label: "Database", matcher: /database|cache|queue|search/i },
];

function TechnologyStack({ data }: { data: IntelligenceData }) {
  const layers = CATEGORY_LAYER.map((layer) => ({
    ...layer,
    items: data.technologies.filter((technology) => layer.matcher.test(`${technology.category} ${technology.name}`)),
  })).filter((layer) => layer.items.length);

  return (
    <section className="intel-panel technology-stack-panel">
      <header className="panel-heading"><div><small>Architecture inference</small><h3>Technology stack</h3></div><FingerprintIcon /></header>
      <div className="stack-diagram">
        <div className="stack-user-node">User / Client</div>
        {layers.map((layer, index) => (
          <div className="stack-layer-wrap" key={layer.key}>
            <span className="stack-connector" />
            <div className={`stack-layer layer-${layer.key}`}>
              <small>{layer.label}</small>
              <div>{layer.items.slice(0, 4).map((technology) => <span key={`${layer.key}-${technology.host}-${technology.name}`}><TechnologyLogo name={technology.name} />{technology.name}{technology.version ? ` ${technology.version}` : ""}</span>)}</div>
            </div>
            {index === layers.length - 1 && <span className="stack-terminal" />}
          </div>
        ))}
        {!layers.length && <p className="coverage-note">No technology categories were available to assemble a stack.</p>}
      </div>
      <p className="provider-footnote">This diagram groups observed fingerprints by category. It does not claim unobserved architectural relationships.</p>
    </section>
  );
}

function SeverityBars({ data }: { data: IntelligenceData }) {
  const entries = [
    ["Critical", data.severityCounts.critical, "critical"],
    ["High", data.severityCounts.high, "high"],
    ["Medium", data.severityCounts.medium, "medium"],
    ["Low", data.severityCounts.low, "low"],
  ] as const;
  const max = Math.max(1, ...entries.map(([, value]) => value));
  return (
    <section className="intel-panel severity-bars-panel">
      <header className="panel-heading"><div><small>Vulnerability intelligence</small><h3>Severity distribution</h3></div><span>{data.findings.length} findings</span></header>
      <div className="severity-bars">{entries.map(([label, value, tone]) => <div key={label}><span>{label}</span><i><b className={tone} style={{ height: `${value ? Math.max(12, (value / max) * 100) : 3}%` }} /></i><strong>{value}</strong></div>)}</div>
    </section>
  );
}

function RiskHeatmap({ data }: { data: IntelligenceData }) {
  const rows = [
    ["Critical", data.severityCounts.critical],
    ["High", data.severityCounts.high],
    ["Medium", data.severityCounts.medium],
    ["Low", data.severityCounts.low],
  ] as const;
  const activity = [data.metrics.subdomains || 0, data.metrics.liveAssets || 0, data.metrics.endpoints || 0, data.metrics.screenshots || 0];
  const maxActivity = Math.max(1, ...activity);
  return (
    <section className="intel-panel risk-heatmap-panel">
      <header className="panel-heading"><div><small>Evidence matrix</small><h3>Recon and risk heatmap</h3></div><span>Real scan counts</span></header>
      <div className="heatmap-labels"><span>DNS</span><span>HTTP</span><span>Endpoints</span><span>Screenshots</span></div>
      <div className="heatmap-grid">
        {rows.map(([label, severityValue], rowIndex) => (
          <div className="heatmap-row" key={label}><strong>{label}</strong>{activity.map((value, columnIndex) => {
            const activityOpacity = value / maxActivity;
            const riskBoost = severityValue ? Math.min(1, severityValue / 5) : 0;
            const opacity = Math.max(.08, Math.min(.95, activityOpacity * .6 + riskBoost * .4));
            return <i key={`${rowIndex}-${columnIndex}`} style={{ opacity }} />;
          })}</div>
        ))}
      </div>
      <p className="provider-footnote">Color intensity combines observed activity volume with indexed severity counts; it is a visualization, not an additional finding.</p>
    </section>
  );
}

function FindingSummary({ data }: { data: IntelligenceData }) {
  const top = [...data.findings].sort((a, b) => {
    const ranks = { critical: 5, high: 4, medium: 3, low: 2, info: 1, unknown: 0 };
    return ranks[b.severity] - ranks[a.severity];
  }).slice(0, 4);
  return (
    <section className="intel-panel finding-summary-panel">
      <header className="panel-heading"><div><small>Priority queue</small><h3>Critical findings summary</h3></div><ShieldAlertIcon /></header>
      {top.length ? <div className="finding-summary-list">{top.map((finding, index) => <article key={`${finding.template}-${index}`}><span className={`severity-dot ${finding.severity}`} /><div><strong>{finding.template}</strong><small>{finding.host}</small></div><b>{finding.severity}</b></article>)}</div> : <p className="coverage-note">No indexed findings are available for prioritization.</p>}
    </section>
  );
}

export function TechnologyView({ data }: { data: IntelligenceData }) {
  const unique = new Map<string, TechnologyIntel>();
  for (const technology of data.technologies) {
    const key = `${technology.name.toLowerCase()}|${technology.version || ""}`;
    const existing = unique.get(key);
    if (!existing || (technology.confidenceScore || 0) > (existing.confidenceScore || 0)) unique.set(key, technology);
  }
  const technologies = [...unique.values()].sort((a, b) => (b.confidenceScore || 0) - (a.confidenceScore || 0));

  return (
    <div className="technology-view">
      <div className="intel-title-row"><div><small>Evidence-backed fingerprints</small><h2>Technology Intelligence</h2></div><span className="intelligence-badge"><FingerprintIcon /> {technologies.length} unique components</span></div>
      <div className="technology-layout">
        <div className="technology-grid">{technologies.length ? technologies.map((technology) => <TechnologyCard key={`${technology.name}-${technology.version}-${technology.host}`} technology={technology} />) : <div className="empty-compact"><FingerprintIcon /><span>No technology inventory was indexed.</span></div>}</div>
        <aside className="technology-side"><RiskHeatmap data={data} /><SeverityBars data={data} /><FindingSummary data={data} /></aside>
      </div>
      <TechnologyStack data={data} />
    </div>
  );
}
