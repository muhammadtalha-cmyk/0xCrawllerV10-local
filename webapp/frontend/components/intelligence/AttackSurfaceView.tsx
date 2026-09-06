import { api } from "@/lib/api";
import type { IntelligenceData } from "@/lib/securityIntelligence";
import type { Artifact, Scan } from "@/lib/types";
import { ImageIcon, RadarIcon, ShieldAlertIcon } from "../Icons";
import { TechnologyLogo } from "./TechnologyLogo";
import { useEffect, useState } from "react";

// Best-effort field lookup: backend relationship/endpoint shapes aren't
// strongly typed on the frontend, so we probe the common key spellings
// instead of assuming one and silently rendering nothing (or worse, guessing).
function pick(obj: any, keys: string[]): string | null {
  for (const key of keys) {
    if (obj && obj[key] !== undefined && obj[key] !== null) return String(obj[key]);
  }
  return null;
}

function relationshipEndpoints(rel: any): { source: string | null; target: string | null } {
  return {
    source: pick(rel, ["source", "source_hostname", "from", "from_hostname", "src", "src_hostname", "parent", "parent_hostname"]),
    target: pick(rel, ["target", "target_hostname", "to", "to_hostname", "dst", "dst_hostname", "child", "child_hostname"]),
  };
}

function AssetGraph({ scanId, target }: { scanId: string; target: string }) {
  const [assets, setAssets] = useState<any[]>([]);
  const [relationships, setRelationships] = useState<any[]>([]);
  const [endpoints, setEndpoints] = useState<any[]>([]);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    let cancelled = false;
    Promise.all([
      api.getAssets(scanId, 50, 0),
      api.getRelationships(scanId, 200, 0),
      api.getEndpoints(scanId, 200, 0),
    ])
      .then(([assetsRes, relRes, endpointsRes]) => {
        if (cancelled) return;
        setAssets(assetsRes.items || []);
        setRelationships(relRes.items || []);
        setEndpoints(endpointsRes.items || []);
      })
      .catch(() => {
        if (!cancelled) {
          setAssets([]);
          setRelationships([]);
          setEndpoints([]);
        }
      })
      .finally(() => {
        if (!cancelled) setLoaded(true);
      });
    return () => {
      cancelled = true;
    };
  }, [scanId]);

  const nodes = assets.filter((asset: any) => asset.hostname !== target).slice(0, 8);
  const nodeByHostname = new Map(nodes.map((n: any) => [n.hostname, n]));
  const nodeIndex = new Map(nodes.map((n: any, i: number) => [n.hostname, i]));

  // Only draw an edge when both ends of a real relationship resolve to
  // hostnames we're actually rendering as nodes (or the root target itself).
  const edges = relationships
    .map(relationshipEndpoints)
    .filter(({ source, target: t }) => {
      if (!source || !t) return false;
      const sourceKnown = source === target || nodeByHostname.has(source);
      const targetKnown = t === target || nodeByHostname.has(t);
      return sourceKnown && targetKnown && (source === target || t === target);
    });

  const radius = 38;

  return (
    <section className="attack-graph-panel">
      <div className="graph-grid-bg" />
      <div className="graph-rays" />
      <svg className="graph-lines" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">
        {edges.map(({ source, target: t }, i) => {
          const other = source === target ? t! : source!;
          const index = nodeIndex.get(other);
          if (index === undefined) return null;
          const angle = (Math.PI * 2 * index) / Math.max(1, nodes.length) - Math.PI / 2;
          const x = 50 + Math.cos(angle) * radius;
          const y = 50 + Math.sin(angle) * 34;
          return <line key={`${source}-${t}-${i}`} x1="50" y1="50" x2={x} y2={y} />;
        })}
      </svg>
      <div className="root-asset-node"><span>{target}</span><small>Authorized root</small></div>
      {nodes.map((asset, index) => {
        const angle = (Math.PI * 2 * index) / Math.max(1, nodes.length) - Math.PI / 2;
        const x = 50 + Math.cos(angle) * radius;
        const y = 50 + Math.sin(angle) * 34;
        const assetEndpointCount = endpoints.filter((ep: any) => pick(ep, ["hostname", "host"]) === asset.hostname).length;
        return (
          <article
            className={`asset-node tone-cyan`}
            key={asset.hostname}
            style={{ left: `${x}%`, top: `${y}%` }}
          >
            <div className="asset-node-head"><strong>{asset.hostname}</strong><span><TechnologyLogo name="Asset" /></span></div>
            <small>{asset.metadata?.asset_types?.[0] || asset.asset_types?.[0] || asset.asset_type?.split(",")[0] || "Asset"}</small>
            <p>{assetEndpointCount > 0 ? `${assetEndpointCount} endpoint${assetEndpointCount === 1 ? "" : "s"}` : "No indexed endpoints"}</p>
          </article>
        );
      })}
      {loaded && !nodes.length && <div className="graph-empty">Asset relationships will appear after normalization data is indexed.</div>}
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
