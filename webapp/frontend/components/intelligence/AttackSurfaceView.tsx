import { api } from "@/lib/api";
import type { IntelligenceData, AssetIntel } from "@/lib/securityIntelligence";
import type { Artifact, Scan } from "@/lib/types";
import { ImageIcon, RadarIcon, ShieldAlertIcon } from "../Icons";
import { TechnologyLogo } from "./TechnologyLogo";

function hostFromArtifact(artifact: Artifact): string {
  const normalized = artifact.relative_path.replace(/\\/g, "/");
  const marker = "/screenshot/";
  const index = normalized.toLowerCase().indexOf(marker);
  if (index >= 0) return normalized.slice(index + marker.length).split("/")[0] || artifact.name;
  return artifact.name.replace(/\.(png|jpe?g|webp|svg)$/i, "");
}

function assetStatus(asset: AssetIntel): string {
  if (asset.live === true) return asset.statusCode ? `Live · HTTP ${asset.statusCode}` : "Live";
  if (asset.live === false) return "Not live";
  return "Status unknown";
}

function nodeTone(asset: AssetIntel): string {
  if (asset.risk === "critical" || asset.risk === "high") return "danger";
  if (asset.priority.toLowerCase() === "high") return "amber";
  if (asset.live) return "cyan";
  return "muted";
}

function AssetGraph({ data, target }: { data: IntelligenceData; target: string }) {
  const sorted = [...data.assets].sort((a, b) => {
    const weight = (asset: AssetIntel) => (asset.host === target ? 100 : 0) + (asset.live ? 20 : 0) + (asset.priority.toLowerCase() === "high" ? 10 : 0);
    return weight(b) - weight(a);
  });
  const nodes = sorted.filter((asset) => asset.host !== target).slice(0, 8);
  const radius = 38;

  return (
    <section className="attack-graph-panel">
      <div className="graph-grid-bg" />
      <div className="graph-rays" />
      <svg className="graph-lines" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">
        {nodes.map((asset, index) => {
          const angle = (Math.PI * 2 * index) / Math.max(1, nodes.length) - Math.PI / 2;
          const x = 50 + Math.cos(angle) * radius;
          const y = 50 + Math.sin(angle) * 34;
          return <line key={asset.host} x1="50" y1="50" x2={x} y2={y} />;
        })}
      </svg>
      <div className="root-asset-node"><span>{target}</span><small>Authorized root</small></div>
      {nodes.map((asset, index) => {
        const angle = (Math.PI * 2 * index) / Math.max(1, nodes.length) - Math.PI / 2;
        const x = 50 + Math.cos(angle) * radius;
        const y = 50 + Math.sin(angle) * 34;
        return (
          <article
            className={`asset-node tone-${nodeTone(asset)}`}
            key={asset.host}
            style={{ left: `${x}%`, top: `${y}%` }}
          >
            <div className="asset-node-head"><strong>{asset.host}</strong><span><TechnologyLogo name={asset.technologies[0] || asset.provider || "Asset"} /></span></div>
            <small>{asset.category}</small>
            <p>{assetStatus(asset)}</p>
          </article>
        );
      })}
      {!nodes.length && <div className="graph-empty">Asset relationships will appear after normalization data is indexed.</div>}
    </section>
  );
}

function AssetStatistics({ data }: { data: IntelligenceData }) {
  const values = [
    ["Live assets", data.metrics.liveAssets, "cyan"],
    ["Dead assets", data.metrics.deadAssets, "muted"],
    ["High-risk assets", data.metrics.highRiskAssets, "danger"],
    ["Suspicious endpoints", data.metrics.suspiciousEndpoints, "amber"],
  ] as const;
  return <div className="asset-stat-grid">{values.map(([label, value, tone]) => <article className={`asset-stat tone-${tone}`} key={label}><small>{label}</small><strong>{value === null ? "—" : value.toLocaleString()}</strong></article>)}</div>;
}

function ProviderDistribution({ data }: { data: IntelligenceData }) {
  const max = Math.max(1, ...data.providers.map((provider) => provider.count));
  return (
    <section className="intel-panel provider-panel">
      <header className="panel-heading"><div><small>Infrastructure context</small><h3>Provider distribution</h3></div><span>{data.providers.length} providers</span></header>
      {data.providers.length ? <div className="provider-list">{data.providers.slice(0, 6).map((provider) => <div key={provider.name}><div><span>{provider.name}</span><strong>{provider.count}</strong></div><i><b style={{ width: `${(provider.count / max) * 100}%` }} /></i></div>)}</div> : <p className="coverage-note">Provider data is not present in the indexed asset inventory.</p>}
      <p className="provider-footnote">Geographic placement is intentionally not inferred from IP addresses without a trusted geolocation source.</p>
    </section>
  );
}

function ScreenshotStrip({ screenshots, data, onOpen }: { screenshots: Artifact[]; data: IntelligenceData; onOpen: (artifact: Artifact) => void }) {
  return (
    <section className="screenshot-intelligence">
      <header className="panel-heading"><div><small>Visual evidence</small><h3>Screenshot intelligence</h3></div><span>{screenshots.length} captures</span></header>
      {screenshots.length ? (
        <div className="screenshot-carousel">
          {screenshots.map((artifact) => {
            const host = hostFromArtifact(artifact);
            const asset = data.assets.find((item) => item.host === host);
            return (
              <button key={artifact.id} onClick={() => onOpen(artifact)}>
                <div className="screenshot-thumb"><img src={api.artifactUrl(artifact.id)} alt={`Captured page for ${host}`} loading="lazy" /></div>
                <span><strong>{host}</strong><small>{asset?.technologies.slice(0, 2).join(" · ") || "Technology not indexed"}</small><em className={`shot-risk ${asset?.risk || "unrated"}`}>{asset?.risk && asset.risk !== "unrated" ? asset.risk : asset?.priority || "Unrated"}</em></span>
              </button>
            );
          })}
        </div>
      ) : <div className="empty-compact"><ImageIcon /><span>No screenshots indexed for this scan.</span></div>}
    </section>
  );
}

export function AttackSurfaceView({ data, scan, onOpenArtifact }: { data: IntelligenceData; scan: Scan; onOpenArtifact: (artifact: Artifact) => void }) {
  const screenshots = data.sourceArtifacts.filter((artifact) => artifact.kind === "screenshot" || artifact.kind === "image");
  return (
    <div className="attack-surface-view">
      <div className="intel-title-row"><div><small>Asset relationships</small><h2>Attack Surface Intelligence</h2></div><span className="intelligence-badge"><RadarIcon /> Live normalized inventory</span></div>
      <div className="attack-surface-grid">
        <AssetGraph data={data} target={scan.target} />
        <aside className="attack-side-column">
          <section className="intel-panel"><header className="panel-heading"><div><small>Inventory</small><h3>Asset statistics</h3></div><ShieldAlertIcon /></header><AssetStatistics data={data} /></section>
          <ProviderDistribution data={data} />
        </aside>
      </div>
      <ScreenshotStrip screenshots={screenshots} data={data} onOpen={onOpenArtifact} />
    </div>
  );
}
