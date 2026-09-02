import { api } from "@/lib/api";
import type { Artifact } from "@/lib/types";
import type { IntelligenceData } from "@/lib/securityIntelligence";
import { ImageIcon } from "../Icons";

function hostName(artifact: Artifact): string {
  const path = artifact.relative_path.replace(/\\/g, "/");
  const marker = "/screenshot/";
  const index = path.toLowerCase().indexOf(marker);
  return index >= 0 ? path.slice(index + marker.length).split("/")[0] : artifact.name;
}

import { useEffect, useState } from "react";

export function ScreenshotView({ screenshots, data, onOpenArtifact }: { screenshots: Artifact[]; data: IntelligenceData; onOpenArtifact: (artifact: Artifact) => void }) {
  const [assets, setAssets] = useState<any[]>([]);

  useEffect(() => {
    api.getAssets(data.scanId, 200, 0).then((res) => setAssets(res.items));
  }, [data.scanId]);

  return (
    <div className="screenshot-view">
      <div className="intel-title-row"><div><small>Browser-rendered evidence</small><h2>Screenshot Intelligence</h2></div><span className="intelligence-badge"><ImageIcon /> {screenshots.length} captures</span></div>
      {screenshots.length ? <div className="premium-screenshot-grid">{screenshots.map((artifact) => {
        const host = hostName(artifact);
        const asset = assets.find((item: any) => item.hostname === host);
        return (
          <button key={artifact.id} onClick={() => onOpenArtifact(artifact)}>
            <div className="premium-shot-image"><img src={api.artifactUrl(artifact.id)} alt={`Screenshot of ${host}`} loading="lazy" /><span>Open evidence</span></div>
            <div><strong>{host}</strong><small>{asset?.technologies?.slice(0, 3).join(" · ") || artifact.name}</small><em className={`shot-risk ${asset?.risk || "unrated"}`}>{asset?.risk && asset.risk !== "unrated" ? asset.risk : asset?.priority || "Unrated"}</em></div>
          </button>
        );
      })}</div> : <div className="empty-state"><ImageIcon /><h3>No screenshots indexed</h3><p>HTTPX screenshot artifacts will appear here after reconnaissance completes.</p></div>}
    </div>
  );
}
