import { api } from "@/lib/api";
import type { IntelligenceData } from "@/lib/securityIntelligence";
import type { Artifact, Scan } from "@/lib/types";
import { ImageIcon, RadarIcon, ShieldAlertIcon } from "../Icons";
import { TechnologyLogo } from "./TechnologyLogo";
import { useEffect, useState } from "react";

function AssetGraph({ scanId, target }: { scanId: string; target: string }) {
  const [nodes, setNodes] = useState<any[]>([]);

  useEffect(() => {
    api.getAssets(scanId, 8, 0).then((res) => {
      setNodes(res.items.filter((asset: any) => asset.hostname !== target).slice(0, 8));
    });
  }, [scanId, target]);

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
          return <line key={asset.hostname} x1="50" y1="50" x2={x} y2={y} />;
        })}
      </svg>
      <div className="root-asset-node"><span>{target}</span><small>Authorized root</small></div>
      {nodes.map((asset, index) => {
        const angle = (Math.PI * 2 * index) / Math.max(1, nodes.length) - Math.PI / 2;
        const x = 50 + Math.cos(angle) * radius;
        const y = 50 + Math.sin(angle) * 34;
        return (
          <article
            className={`asset-node tone-cyan`}
            key={asset.hostname}
            style={{ left: `${x}%`, top: `${y}%` }}
          >
            <div className="asset-node-head"><strong>{asset.hostname}</strong><span><TechnologyLogo name="Asset" /></span></div>
            <small>{asset.asset_types?.[0] || "Asset"}</small>
            <p>Live</p>
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

export function AttackSurfaceView({ data, scan, onOpenArtifact }: { data: IntelligenceData; scan: Scan; onOpenArtifact: (artifact: Artifact) => void }) {
  const screenshots = data.sourceArtifacts.filter((artifact) => artifact.kind === "screenshot" || artifact.kind === "image");
  return (
    <div className="attack-surface-view">
      <div className="intel-title-row"><div><small>Asset relationships</small><h2>Attack Surface Intelligence</h2></div><span className="intelligence-badge"><RadarIcon /> Live normalized inventory</span></div>
      <div className="attack-surface-grid">
        <AssetGraph scanId={data.scanId} target={scan.target} />
        <aside className="attack-side-column">
          <section className="intel-panel"><header className="panel-heading"><div><small>Inventory</small><h3>Asset statistics</h3></div><ShieldAlertIcon /></header><AssetStatistics data={data} /></section>
        </aside>
      </div>
    </div>
  );
}
